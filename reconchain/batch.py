"""Batch scanning — multi-target support with shared state and unified reporting."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from reconchain.utils import ensure, log, read_lines


class BatchScan:
    """Manage batch scanning of multiple targets."""

    def __init__(self, targets_file: Optional[Path] = None, outdir: Optional[Path] = None) -> None:
        self.targets: List[str] = []
        self.results: Dict[str, Dict[str, Any]] = {}
        self._outdir = outdir

        if targets_file and targets_file.exists():
            from reconchain.config import _is_valid_hostname
            self.targets = [
                line.split("#")[0].strip()
                for line in read_lines(targets_file)
                if line.strip() and not line.strip().startswith("#")
            ]
            self.targets = [t for t in self.targets if t and _is_valid_hostname(t)]

    @classmethod
    def from_file(cls, path: Path, outdir: Path) -> "BatchScan":
        return cls(targets_file=path, outdir=outdir)

    def add_target(self, domain: str) -> None:
        if domain not in self.targets:
            self.targets.append(domain)

    def record_result(self, domain: str, result: Dict[str, Any]) -> None:
        self.results[domain] = result

    def write_batch_summary(self) -> Optional[Path]:
        """Write unified batch scan summary."""
        if not self._outdir:
            return None

        summary = {
            "total_targets": len(self.targets),
            "completed": len(self.results),
            "targets": {},
        }

        for domain in self.targets:
            if domain in self.results:
                r = self.results[domain]
                summary["targets"][domain] = {
                    "status": "completed",
                    "findings": r.get("total_findings", 0),
                    "critical": r.get("critical", 0),
                    "high": r.get("high", 0),
                    "duration": r.get("duration", 0),
                }
            else:
                summary["targets"][domain] = {"status": "pending"}

        out = ensure(self._outdir / "batch_summary.json")
        out.write_text(json.dumps(summary, indent=2))
        return out

    def write_batch_markdown(self) -> Optional[Path]:
        """Write batch scan results as markdown."""
        if not self._outdir:
            return None

        lines = ["# Batch Scan Summary\n"]

        for domain in self.targets:
            if domain in self.results:
                r = self.results[domain]
                total = r.get("total_findings", 0)
                crit = r.get("critical", 0)
                high = r.get("high", 0)
                lines.append(f"## {domain}")
                lines.append(f"- **Status:** Completed")
                lines.append(f"- **Total Findings:** {total}")
                lines.append(f"- **Critical:** {crit} | **High:** {high}")
                lines.append("")
            else:
                lines.append(f"## {domain}")
                lines.append("- **Status:** Pending")
                lines.append("")

        out = ensure(self._outdir / "batch_report.md")
        out.write_text("\n".join(lines))
        return out
