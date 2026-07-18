"""Collaboration module — team findings sharing, export formats, integration hooks."""
from __future__ import annotations

import json
import csv
import io
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from reconchain.artifacts import ARTIFACTS, get_counts, guess_severity
from reconchain.utils import ensure, log, read_lines


def export_findings_csv(outdir: Path, domain: str) -> Path:
    """Export all findings to a CSV file for team review/import."""
    out = ensure(outdir / "findings_export.csv")
    rows: List[Dict[str, str]] = []

    for art in ARTIFACTS:
        if not art.vuln_type:
            continue
        fpath = outdir / art.filename
        if not fpath.exists():
            continue
        for line in read_lines(fpath):
            text = line.strip()
            if not text:
                continue
            rows.append({
                "domain": domain,
                "source": art.display_name,
                "file": art.filename,
                "vuln_type": art.vuln_type,
                "severity": guess_severity(text),
                "finding": text,
                "phase": art.phase,
            })

    if not rows:
        log("info", "collaboration: no findings to export")
        return out

    with out.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["domain", "source", "file", "vuln_type", "severity", "finding", "phase"])
        writer.writeheader()
        writer.writerows(rows)

    log("ok", f"exported {len(rows)} findings → {out}")
    return out


def export_findings_jsonl(outdir: Path, domain: str) -> Path:
    """Export findings as JSON Lines (one JSON object per line) for streaming ingestion."""
    out = ensure(outdir / "findings_export.jsonl")

    with out.open("w") as f:
        for art in ARTIFACTS:
            if not art.vuln_type:
                continue
            fpath = outdir / art.filename
            if not fpath.exists():
                continue
            for line in read_lines(fpath):
                text = line.strip()
                if not text:
                    continue
                entry = {
                    "domain": domain,
                    "source": art.display_name,
                    "file": art.filename,
                    "vuln_type": art.vuln_type,
                    "severity": guess_severity(text),
                    "finding": text,
                    "phase": art.phase,
                    "timestamp": datetime.now().isoformat(timespec="seconds"),
                }
                f.write(json.dumps(entry) + "\n")

    log("ok", f"exported JSONL → {out}")
    return out


def generate_slack_summary(counts: Dict[str, int], domain: str) -> str:
    """Generate a Slack-formatted summary message."""
    total = sum(counts.values())
    lines = [
        f"*Recon Scan Complete* — `{domain}`",
        f"Total findings: *{total}*",
    ]

    critical_findings = counts.get("cmdi", 0) + counts.get("exposed_databases", 0) + counts.get("default_creds", 0)
    high_findings = counts.get("nuclei", 0) + counts.get("vulns", 0) + counts.get("xss_findings", 0) + counts.get("ssrf_meta", 0)

    if critical_findings:
        lines.append(f":rotating_light: *Critical:* {critical_findings}")
    if high_findings:
        lines.append(f":warning: *High:* {high_findings}")

    top_findings = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:5]
    if top_findings:
        lines.append("\n_Top artifacts:_")
        for k, v in top_findings:
            lines.append(f"  • {k}: {v}")

    return "\n".join(lines)


def generate_github_issue_body(
    counts: Dict[str, int],
    domain: str,
    outdir: Path,
) -> str:
    """Generate a GitHub issue body for the scan results."""
    total = sum(counts.values())
    lines = [
        f"## Recon Scan Results — `{domain}`",
        "",
        f"**Total findings:** {total}",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "### Summary",
        "",
        "| Category | Count |",
        "|---|---:|",
    ]

    categories: Dict[str, int] = {}
    for art in ARTIFACTS:
        if not art.vuln_type:
            continue
        cat = art.vuln_type
        count = counts.get(art.key, 0)
        if count > 0:
            categories[cat] = categories.get(cat, 0) + count

    for cat, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
        lines.append(f"| {cat} | {count} |")

    exploit_chains = outdir / "exploit_chains.json"
    if exploit_chains.exists():
        try:
            chains = json.loads(exploit_chains.read_text())
            if chains:
                lines.extend(["", "### Exploit Chains", ""])
                for chain in chains[:5]:
                    sev = chain.get("severity", "?")
                    name = chain.get("name", "?")
                    lines.append(f"- **[{sev.upper()}]** {name}")
        except Exception:
            pass

    return "\n".join(lines)
