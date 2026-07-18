"""
reconchain.ai_triage — AI-powered vulnerability triage and severity scoring.

Post-scan analysis that uses an LLM to:
  1. Classify findings by severity with justifications
  2. Estimate false positive probability
  3. Generate an executive summary

Usage:
    from reconchain.ai_triage import run_triage
    results = await run_triage(outdir, domain)
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from reconchain.ai import get_provider, parse_json_response
from reconchain.artifacts import get_findings_for_triage
from reconchain.utils import ensure, log

_SEVERITY_PROMPT_TEMPLATE = """You are a cybersecurity expert triaging vulnerability findings from a bug bounty / penetration test scan of {domain}.

Classify each finding below into one of: critical, high, medium, low, info.
Also estimate the probability that each finding is a false positive (0.0 to 1.0).
Provide a 1-line justification for each.

Findings:
{findings}

Return a JSON array where each element is:
{{"finding": "...", "severity": "critical|high|medium|low|info", "false_positive_probability": 0.0-1.0, "justification": "..."}}

Only return the JSON array, no other text."""

_SUMMARY_PROMPT_TEMPLATE = """You are a cybersecurity expert writing an executive summary for a bug bounty / penetration test scan.

Target: {domain}
Scan Duration: {duration}
Total Findings: {total_findings}

Critical Findings ({critical_count}):
{critical_list}

High Findings ({high_count}):
{high_list}

Medium Findings ({medium_count}):
{medium_list}

Low/Info Findings ({low_count}):
{low_list}

Write a concise 2-paragraph executive summary:
1. First paragraph: Key risks and most critical issues found
2. Second paragraph: Recommended immediate actions and overall risk assessment

Be specific about the findings. Do not use markdown formatting."""


def _load_all_findings(outdir: Path, max_per_file: int = 30) -> List[Dict[str, str]]:
    """Load findings from artifact files with source metadata (via registry)."""
    return get_findings_for_triage(outdir, max_per_file=max_per_file)


def _chunk_findings(findings: List[Dict[str, str]], chunk_size: int = 40) -> List[List[Dict[str, str]]]:
    """Split findings into chunks for batch LLM processing."""
    return [findings[i : i + chunk_size] for i in range(0, len(findings), chunk_size)]


def _format_findings_for_prompt(findings: List[Dict[str, str]]) -> str:
    lines = []
    for i, f in enumerate(findings, 1):
        lines.append(f"{i}. [{f['source']}] {f['finding']}")
    return "\n".join(lines)


async def _triage_batch(
    batch: List[Dict[str, str]], domain: str
) -> List[Dict[str, Any]]:
    """Send a batch of findings to the LLM for triage."""
    provider = get_provider()

    prompt = _SEVERITY_PROMPT_TEMPLATE.format(
        domain=domain,
        findings=_format_findings_for_prompt(batch),
    )

    response = await provider.complete(prompt, max_tokens=4096, temperature=0.2)
    result = parse_json_response(response)

    if isinstance(result, list):
        return result

    # Fallback: try to salvage partial results
    return [
        {
            "finding": f.get("finding", ""),
            "severity": "info",
            "false_positive_probability": 0.5,
            "justification": "LLM classification unavailable",
        }
        for f in batch
    ]


async def _generate_summary(
    domain: str,
    duration: str,
    triaged: List[Dict[str, Any]],
) -> str:
    """Generate an executive summary using the LLM."""
    provider = get_provider()

    by_severity: Dict[str, List[str]] = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
    }
    for t in triaged:
        sev = t.get("severity", "info")
        if sev in by_severity:
            by_severity[sev].append(t.get("finding", ""))

    def _fmt(items: List[str]) -> str:
        if not items:
            return "  (none)"
        return "\n".join(f"  - {x}" for x in items[:20])

    prompt = _SUMMARY_PROMPT_TEMPLATE.format(
        domain=domain,
        duration=duration,
        total_findings=len(triaged),
        critical_count=len(by_severity["critical"]),
        critical_list=_fmt(by_severity["critical"]),
        high_count=len(by_severity["high"]),
        high_list=_fmt(by_severity["high"]),
        medium_count=len(by_severity["medium"]),
        medium_list=_fmt(by_severity["medium"]),
        low_count=len(by_severity["low"]),
        low_list=_fmt(by_severity["low"]),
    )

    response = await provider.complete(prompt, max_tokens=1024, temperature=0.4)
    return response.strip()


async def run_triage(
    outdir: Path,
    domain: str,
    duration: str = "unknown",
) -> Dict[str, Any]:
    """Run the full AI triage pipeline.

    Returns dict with keys: findings, summary, stats, severity_counts
    Also writes ai_triage.json, ai_fps.json, ai_summary.txt to outdir.
    """
    log("AI Triage: loading findings...")
    findings = _load_all_findings(outdir)

    if not findings:
        log("info", "info: no findings to triage")
        return {"findings": [], "summary": "", "stats": {}, "severity_counts": {}}

    log("info", f"AI Triage: {len(findings)} findings loaded, chunking for analysis...")

    # Process in batches
    chunks = _chunk_findings(findings)
    all_triaged: List[Dict[str, Any]] = []

    for i, chunk in enumerate(chunks):
        log("info", f"AI Triage: processing batch {i + 1}/{len(chunks)} ({len(chunk)} findings)...")
        triaged = await _triage_batch(chunk, domain)
        all_triaged.extend(triaged)

    # Merge back source info
    for t, f in zip(all_triaged, findings):
        t["source"] = f.get("source", "")
        t["file"] = f.get("file", "")

    # Compute stats
    severity_counts: Dict[str, int] = {}
    fp_count = 0
    for t in all_triaged:
        sev = t.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        if t.get("false_positive_probability", 0) > 0.7:
            fp_count += 1

    stats = {
        "total": len(all_triaged),
        "likely_false_positives": fp_count,
        "high_confidence_findings": len(all_triaged) - fp_count,
    }

    log("info", f"AI Triage: severity distribution: {severity_counts}")

    # Generate executive summary
    log("AI Triage: generating executive summary...")
    summary = await _generate_summary(domain, duration, all_triaged)

    # Write outputs
    out_triage = ensure(outdir / "ai_triage.json")
    out_triage.write_text(json.dumps(all_triaged, indent=2, default=str))

    out_fps = ensure(outdir / "ai_fps.json")
    fps_list = [t for t in all_triaged if t.get("false_positive_probability", 0) > 0.5]
    fps_list.sort(key=lambda x: x.get("false_positive_probability", 0), reverse=True)
    out_fps.write_text(json.dumps(fps_list, indent=2, default=str))

    out_summary = ensure(outdir / "ai_summary.txt")
    out_summary.write_text(summary)

    log("ok", f"ok: AI triage complete — {stats['total']} findings, {fp_count} likely FPs")
    log("  Written: ai_triage.json, ai_fps.json, ai_summary.txt")

    return {
        "findings": all_triaged,
        "summary": summary,
        "stats": stats,
        "severity_counts": severity_counts,
    }
