"""Scan comparison — diff two scan outputs to track changes over time."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Set

from reconchain.artifacts import ARTIFACTS
from reconchain.utils import ensure, log, read_lines


class ScanDiff:
    """Compare two scan output directories."""

    def __init__(self, old_dir: Path, new_dir: Path) -> None:
        self.old_dir = old_dir
        self.new_dir = new_dir
        self.new_findings: Dict[str, List[str]] = {}
        self.resolved_findings: Dict[str, List[str]] = {}
        self.unchanged: Dict[str, int] = {}

    def compute(self) -> "ScanDiff":
        """Compute the diff between old and new scan outputs."""
        for art in ARTIFACTS:
            old_file = self.old_dir / art.filename
            new_file = self.new_dir / art.filename

            old_lines = set(read_lines(old_file)) if old_file.exists() else set()
            new_lines = set(read_lines(new_file)) if new_file.exists() else set()

            added = sorted(new_lines - old_lines)
            removed = sorted(old_lines - new_lines)
            kept = len(old_lines & new_lines)

            if added:
                self.new_findings[art.key] = added
            if removed:
                self.resolved_findings[art.key] = removed
            if kept:
                self.unchanged[art.key] = kept

        return self

    def summary(self) -> Dict[str, Any]:
        total_new = sum(len(v) for v in self.new_findings.values())
        total_resolved = sum(len(v) for v in self.resolved_findings.values())
        return {
            "total_new": total_new,
            "total_resolved": total_resolved,
            "artifacts_with_changes": len(self.new_findings) + len(self.resolved_findings),
            "new_by_artifact": {k: len(v) for k, v in self.new_findings.items()},
            "resolved_by_artifact": {k: len(v) for k, v in self.resolved_findings.items()},
        }

    def write_markdown(self, outdir: Path) -> Path:
        lines = ["# Scan Comparison Report\n"]
        s = self.summary()
        lines.append(f"**New findings:** {s['total_new']} | **Resolved:** {s['total_resolved']}\n")

        if self.new_findings:
            lines.append("## New Findings\n")
            for key, findings in sorted(self.new_findings.items()):
                lines.append(f"### {key} ({len(findings)} new)\n")
                for f in findings[:10]:
                    lines.append(f"- {f}")
                if len(findings) > 10:
                    lines.append(f"- ... and {len(findings) - 10} more")
                lines.append("")

        if self.resolved_findings:
            lines.append("## Resolved Findings\n")
            for key, findings in sorted(self.resolved_findings.items()):
                lines.append(f"### {key} ({len(findings)} resolved)\n")
                for f in findings[:5]:
                    lines.append(f"- ~~{f}~~")
                lines.append("")

        out = ensure(outdir / "scan_diff.md")
        out.write_text("\n".join(lines))
        return out

    def write_json(self, outdir: Path) -> Path:
        data = {
            "summary": self.summary(),
            "new_findings": self.new_findings,
            "resolved_findings": self.resolved_findings,
        }
        out = ensure(outdir / "scan_diff.json")
        out.write_text(json.dumps(data, indent=2, default=str))
        return out


def compare_scans(old_dir: Path, new_dir: Path, output_dir: Path) -> Dict[str, Any]:
    """Compare two scan outputs and write diff reports."""
    diff = ScanDiff(old_dir, new_dir).compute()
    diff.write_markdown(output_dir)
    diff.write_json(output_dir)
    summary = diff.summary()
    log("ok", f"Scan diff: {summary['total_new']} new, {summary['total_resolved']} resolved")
    return summary
