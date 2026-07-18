"""Report generation: summary JSON, HTML, Markdown, text, SARIF, Faraday, dashboard."""
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from reconchain.artifacts import (
    get_counts,
    get_coverage,
    get_report_files,
)
from reconchain.config import __version__
from reconchain.utils import ensure, read_lines, count_nonblank, log, html_escape, md_escape

# Shared CSS stylesheet used by all HTML report variants.
HTML_CSS = """
:root{--fg:#e6edf3;--bg:#0d1117;--mut:#8b949e;--acc:#58a6ff;--warn:#d29922;--ok:#3fb950;--err:#f85149;}
*{box-sizing:border-box}body{font-family:ui-monospace,Menlo,Consolas,monospace;
background:var(--bg);color:var(--fg);margin:0;padding:32px;line-height:1.5}
h1{font-size:1.6em;margin:0 0 4px;color:var(--acc)}
h2{font-size:1.2em;border-bottom:1px solid #30363d;padding-bottom:6px;margin-top:32px}
small{color:var(--mut)}.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:12px;margin-top:12px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px}
.card b{color:var(--acc);font-size:1.4em;display:block}.card span{color:var(--mut);font-size:.85em}
pre{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:12px;overflow:auto;font-size:.85em;max-height:480px}
.miss{color:var(--warn)}footer{margin-top:48px;color:var(--mut);font-size:.8em}
"""


def _counts(outdir: Path) -> Dict[str, int]:
    """Count findings in all artifact files using the centralized registry."""
    return get_counts(outdir)


def _coverage(outdir: Path, all_phases: List[str]) -> Dict[str, Any]:
    """Compute coverage metrics using the artifact registry."""
    return get_coverage(outdir, all_phases)


def write_summary(outdir: Path, domain: str, state: dict, counts: Dict[str, int]) -> Path:
    """Write ``summary.json`` with scan metadata, artifact counts, and coverage.

    The JSON payload includes the domain, generation timestamp, tool version,
    missing tools, per-artifact counts, and phase coverage metrics.

    Returns the path to the written ``summary.json``.
    """
    payload = {
        "domain": domain,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "toolchain": f"reconchain v{__version__}",
        "missing_tools": sorted(set(state.get("missing_tools", []))),
        "tool_failures": dict(state.get("tool_failures", {})),
        "artifacts": {k: v for k, v in state.get("artifacts", {}).items()},
        "counts": counts,
        "coverage": state.get("coverage", {}),
    }
    out = ensure(outdir / "summary.json")
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, default=str))
    os.replace(tmp, out)
    return out




def write_html(outdir: Path, domain: str, counts: Dict[str, int], missing: List[str]) -> Path:
    """Write ``report.html`` -- a single-page HTML report with summary cards and artifact contents.

    Each artifact file is rendered inside a ``<pre>`` block (truncated at 50 KB).
    Missing tools are shown as a warning banner.

    Returns the path to the written ``report.html``.
    """
    cards = "\n".join(
        f'<div class="card"><b>{n}</b><span>{html_escape(k)}</span></div>'
        for k, n in counts.items()
    )
    sections = []
    for key in get_report_files():
        p = outdir / key
        if p.exists():
            txt = p.read_text(encoding="utf-8", errors="ignore")
            if len(txt) > 50_000:
                orig_size = len(txt)
                log("warn", f"report.html: {key} truncated from {orig_size} to 50KB")
                txt = txt[:50_000] + f"\n\n{'='*60}\n[WARNING: File truncated at 50KB — original size: {orig_size:,} bytes]\nFull content available in: {key}\n{'='*60}\n"
            sections.append(f"<h2>{html_escape(key)}</h2><pre>{html_escape(txt)}</pre>")
    oast_file = outdir / "oast" / "callbacks.txt"
    if oast_file.exists() and count_nonblank(oast_file):
        txt = oast_file.read_text(encoding="utf-8", errors="ignore")
        sections.append(f"<h2>oast/callbacks.txt</h2><pre>{html_escape(txt)}</pre>")
    miss_html = (
        "<p class='miss'>missing: " + ", ".join(html_escape(m) for m in missing) + "</p>"
        if missing
        else ""
    )
    html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>recon report \u2014 {html_escape(domain)}</title>
<style>{HTML_CSS}</style></head><body>
<h1>Recon Report: {html_escape(domain)}</h1>
<small>generated {datetime.now().isoformat(timespec="seconds")} \u00b7 reconchain v{__version__}</small>
{miss_html}
<h2>Summary</h2><div class="grid">{cards}</div>
{"".join(sections)}
<footer>chained recon \u00b7 all artifacts in <code>{html_escape(str(outdir))}</code></footer>
</body></html>"""
    out = ensure(outdir / "report.html")
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_text(html)
    os.replace(tmp, out)
    return out


def write_full_summary(outdir: Path, domain: str, counts: Dict[str, int], missing: List[str]) -> Path:
    """Write ``summary.txt`` -- a plain-text summary with artifact counts and key findings.

    The first 5 lines of each non-empty artifact are included as a preview.
    OOB callback data is appended when present.

    Returns the path to the written ``summary.txt``.
    """
    lines = [
        "=" * 60,
        f"  Recon Summary \u2014 {domain}",
        f"  generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * 60,
        "",
    ]
    if missing:
        lines += ["\u26a0 MISSING TOOLS (install via ./install.sh)", ""]
        for m in missing:
            lines.append(f"  \u2022 {m}")
        lines.append("")
    lines += ["RESULTS", "-------", ""]
    if counts:
        lines.append(f"{'Artifact':<30} {'Count':>8}")
        lines.append("-" * 40)
        for k, n in sorted(counts.items()):
            if n > 0:
                lines.append(f"{k:<30} {n:>8}")
    lines.append("")
    lines += ["KEY FINDINGS", "------------", ""]
    for key in get_report_files():
        p = outdir / key
        if not p.exists():
            continue
        entries = read_lines(p)
        if not entries:
            continue
        first = entries[0] if entries else ""
        if "No " in first and (" found" in first or " detected" in first or " discovered" in first or "completed" in first):
            continue
        lines.append(f"\u2500\u2500 {key} ({len(entries)} entries)")
        for i, entry in enumerate(entries[:5]):
            lines.append(f"  {entry[:120]}")
        if len(entries) > 5:
            lines.append(f"  \u2026 and {len(entries) - 5} more")
        lines.append("")
    oast = outdir / "oast" / "callbacks.txt"
    if oast.exists() and count_nonblank(oast):
        lines.append(f"\u2500\u2500 OOB callbacks ({count_nonblank(oast)} entries)")
        for ln in read_lines(oast)[:5]:
            lines.append(f"  {ln[:120]}")
        lines.append("")
    lines.append("=" * 60)
    out = ensure(outdir / "summary.txt")
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_text("\n".join(lines) + "\n")
    os.replace(tmp, out)
    return out



def write_markdown(outdir: Path, domain: str, counts: Dict[str, int], missing: List[str]) -> Path:
    """Write ``report.md`` -- a Markdown report with summary table and artifact listing.

    Includes a Markdown table of artifact counts, a list of all ``*.txt`` artifact
    files, and up to 50 OOB callback entries when present.

    Returns the path to the written ``report.md``.
    """
    lines = [
        f"# Recon Report \u2014 {md_escape(domain)}",
        f"_generated {datetime.now().isoformat(timespec='seconds')}_",
        "",
    ]
    if missing:
        lines += ["## \u26a0 Missing tools", ", ".join(f"`{md_escape(m)}`" for m in missing), ""]
    lines += ["## Summary", "", "| Artifact | Count |", "|---|---:|"]
    for k, n in counts.items():
        lines.append(f"| `{md_escape(k)}` | {n} |")
    lines += ["", "## Artifacts", ""]
    for f in sorted(outdir.glob("*.txt")):
        lines.append(f"- `{md_escape(f.name)}`")
    oast = outdir / "oast" / "callbacks.txt"
    if oast.exists():
        lines += ["", "## OOB callbacks", ""]
        for ln in read_lines(oast)[:50]:
            lines.append(f"- `{md_escape(ln)}`")
    out = ensure(outdir / "report.md")
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_text("\n".join(lines) + "\n")
    os.replace(tmp, out)
    return out


def write_sarif(outdir: Path, domain: str, counts: Dict[str, int], state: dict) -> Path:
    """Generate SARIF v2.1 output for GitHub Advanced Security / GitLab SAST."""
    sarif: Dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/openc2-json-schema/master/sarif/sarif-2-1.schema.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ReconChain",
                    "version": __version__,
                    "informationUri": "https://github.com/franz88-scr/BugBountyV2tool",
                }
            },
            "results": [],
            "properties": {
                "domain": domain,
                "generated_at": datetime.now().isoformat(timespec="seconds"),
            }
        }]
    }
    rule_ids: Dict[str, str] = {}
    for artifact_name, artifact_path_str in state.get("artifacts", {}).items():
        if not isinstance(artifact_path_str, str):
            continue
        p = Path(artifact_path_str)
        if not p.exists():
            continue
        lines = read_lines(p)
        for line_idx, line in enumerate(lines, 1):
            if not line.strip():
                continue
            parts = line.split(None, 1)
            tag = parts[0].strip("[]") if parts else "finding"
            tag_clean = tag.replace("-", "_").upper()[:30]
            if tag_clean not in rule_ids:
                rule_ids[tag_clean] = f"RC{len(rule_ids) + 1:04d}"
                sarif["runs"][0]["tool"]["driver"].setdefault("rules", []).append({
                    "id": rule_ids[tag_clean],
                    "name": tag_clean,
                    "shortDescription": {"text": tag_clean.replace("_", " ")},
                    "properties": {"tags": [tag]},
                })
            result = {
                "ruleId": rule_ids[tag_clean],
                "message": {"text": line[:200]},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": artifact_name},
                        "region": {"startLine": line_idx},
                    }
                }],
            }
            sarif["runs"][0]["results"].append(result)
    out = ensure(outdir / "results.sarif")
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_text(json.dumps(sarif, indent=2, default=str))
    os.replace(tmp, out)
    log("ok", f"sarif report → {out}")
    return out


def write_faraday(outdir: Path, domain: str, counts: Dict[str, int], state: dict) -> Path:
    """Generate Faraday-compatible JSON report for Faraday/CRITs."""
    faraday = {
        "host": domain,
        "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "tool": "ReconChain",
        "version": __version__,
        "vulnerabilities": [],
    }
    severity_map = {
        "nuclei": "critical",
        "sqlmap": "high",
        "xss": "high",
        "ssrf": "high",
        "lfi": "high",
        "rce": "critical",
        "idor": "medium",
        "open_redirect": "medium",
        "clickjacking": "low",
        "cors": "low",
        "info": "information",
    }
    for artifact_name, artifact_path_str in state.get("artifacts", {}).items():
        if not isinstance(artifact_path_str, str):
            continue
        p = Path(artifact_path_str)
        if not p.exists():
            continue
        lines = read_lines(p)
        for line in lines:
            line = line.strip()
            if not line:
                continue
            sev = "info"
            lower = line.lower()
            if "nuclei" in lower or "critical" in lower:
                sev = "critical"
            elif "sqlmap" in lower or "sqli" in lower:
                sev = "high"
            elif "xss" in lower or "ssrf" in lower or "lfi" in lower:
                sev = "high"
            elif "idor" in lower or "redirect" in lower:
                sev = "medium"
            elif "clickjack" in lower or "cors" in lower:
                sev = "low"
            faraday["vulnerabilities"].append({
                "name": line[:200],
                "severity": sev,
                "description": f"Finding from {artifact_name}",
                "data": line,
                "status": "open",
                "type": "vulnerability",
            })
    out = ensure(outdir / "results.faraday.json")
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_text(json.dumps(faraday, indent=2, default=str))
    os.replace(tmp, out)
    log("ok", f"faraday report → {out}")
    return out


def write_html_dashboard(outdir: Path, domain: str, counts: Dict[str, int], missing: List[str]) -> Path:
    """Generate enhanced interactive HTML dashboard with charts and filtering."""
    total_findings = sum(counts.values())
    critical = sum(v for k, v in counts.items() if any(x in k for x in ["nuclei", "sqlmap", "rce"]))
    high = sum(v for k, v in counts.items() if any(x in k for x in ["xss", "ssrf", "lfi", "idor"]))
    medium = sum(v for k, v in counts.items() if any(x in k for x in ["redirect", "cors"]))
    low = sum(v for k, v in counts.items() if any(x in k for x in ["clickjack", "info"]))
    cards_html = "\n".join(
        f'<div class="card"><b>{n}</b><span>{html_escape(k)}</span></div>'
        for k, n in counts.items() if n > 0
    )
    html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>ReconChain Dashboard — {html_escape(domain)}</title>
<style>
{HTML_CSS}
.chart {{ display: flex; gap: 4px; margin: 16px 0; height: 20px; }}
.chart div {{ border-radius: 4px; min-width: 10px; }}
.critical {{ background: var(--err); }}
.high {{ background: #f0883e; }}
.medium {{ background: var(--warn); }}
.low {{ background: var(--ok); }}
.filter {{ margin: 12px 0; padding: 8px; background: #161b22; border: 1px solid #30363d; border-radius: 6px; }}
.filter input {{ background: #0d1117; border: 1px solid #30363d; color: var(--fg); padding: 6px 10px; border-radius: 4px; width: 300px; }}
.stats {{ display: flex; gap: 24px; margin: 16px 0; }}
.stat {{ text-align: center; }}
.stat b {{ display: block; font-size: 2em; }}
.stat span {{ color: var(--mut); font-size: 0.85em; }}
</style>
<script>
function filterCards() {{
    const q = document.getElementById('search').value.toLowerCase();
    document.querySelectorAll('.card').forEach(c => {{
        c.style.display = c.textContent.toLowerCase().includes(q) ? '' : 'none';
    }});
}}
</script>
</head><body>
<h1>ReconChain Dashboard: {html_escape(domain)}</h1>
<small>generated {datetime.now().isoformat(timespec="seconds")} · reconchain v{__version__}</small>
<div class="stats">
    <div class="stat"><b>{total_findings:,}</b><span>Total Findings</span></div>
    <div class="stat"><b>{critical}</b><span>Critical</span></div>
    <div class="stat"><b>{high}</b><span>High</span></div>
    <div class="stat"><b>{medium}</b><span>Medium</span></div>
    <div class="stat"><b>{low}</b><span>Low</span></div>
</div>
<h2>Severity Distribution</h2>
<div class="chart">
    <div class="critical" style="width:{critical*100//max(total_findings,1)}%"></div>
    <div class="high" style="width:{high*100//max(total_findings,1)}%"></div>
    <div class="medium" style="width:{medium*100//max(total_findings,1)}%"></div>
    <div class="low" style="width:{low*100//max(total_findings,1)}%"></div>
</div>
<div class="filter">
    <input type="text" id="search" placeholder="Filter findings..." oninput="filterCards()">
</div>
<h2>Findings by Category</h2>
<div class="grid">{cards_html}</div>
{"<p class='miss'>missing: " + ", ".join(html_escape(m) for m in missing) + "</p>" if missing else ""}
<footer>reconchain v{__version__} · all artifacts in <code>{html_escape(str(outdir))}</code></footer>
</body></html>"""
    out = ensure(outdir / "dashboard.html")
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_text(html)
    os.replace(tmp, out)
    log("ok", f"interactive dashboard → {out}")
    return out
