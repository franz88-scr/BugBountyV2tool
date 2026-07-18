"""Collaborative scanning module for ReconChain team workspaces.

Provides team workspace management, shared finding deduplication across
multiple scans, conflict resolution, and real-time collaboration hooks.

Usage:
    from reconchain.collaborative import TeamWorkspace
    ws = TeamWorkspace("workspace-name")
    ws.add_scan(outdir, scanner="alice")
    ws.merge_findings()
"""
from __future__ import annotations

import hashlib
import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from reconchain.artifacts import ARTIFACTS, get_counts, guess_severity
from reconchain.utils import ensure, log, read_lines


@dataclass
class ScanEntry:
    """A scan submission to a team workspace."""
    scanner: str
    domain: str
    submitted_at: float = field(default_factory=time.time)
    outdir: str = ""
    finding_count: int = 0
    scan_id: str = ""
    status: str = "pending"  # pending, merged, conflict, rejected

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scanner": self.scanner,
            "domain": self.domain,
            "submitted_at": self.submitted_at,
            "outdir": self.outdir,
            "finding_count": self.finding_count,
            "scan_id": self.scan_id,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ScanEntry":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class FindingRecord:
    """A deduplicated finding with provenance."""
    fingerprint: str
    text: str
    vuln_type: str
    severity: str
    discovered_by: List[str] = field(default_factory=list)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    hosts: Set[str] = field(default_factory=set)
    confirmed: bool = False
    false_positive: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "text": self.text,
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "discovered_by": list(self.discovered_by),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "hosts": list(self.hosts),
            "confirmed": self.confirmed,
            "false_positive": self.false_positive,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "FindingRecord":
        return cls(
            fingerprint=d["fingerprint"],
            text=d["text"],
            vuln_type=d.get("vuln_type", ""),
            severity=d.get("severity", "info"),
            discovered_by=d.get("discovered_by", []),
            first_seen=d.get("first_seen", 0.0),
            last_seen=d.get("last_seen", 0.0),
            hosts=set(d.get("hosts", [])),
            confirmed=d.get("confirmed", False),
            false_positive=d.get("false_positive", False),
        )


def _fingerprint(text: str) -> str:
    """Create a stable fingerprint for deduplication."""
    normalized = text.strip().lower()
    # Remove common variations that don't change the finding
    for prefix in ("https://", "http://"):
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix):]
            break
    normalized = normalized.rstrip("/")
    return hashlib.sha256(normalized.encode()).hexdigest()[:16]


class TeamWorkspace:
    """Team workspace for collaborative scan management.

    Features:
    - Multi-scanner submission with deduplication
    - Finding conflict resolution
    - Consensus-based confirmation
    - Export for team review
    """

    def __init__(self, workspace_name: str, workspace_dir: Optional[Path] = None) -> None:
        self.name = workspace_name
        self._dir = workspace_dir or Path.home() / ".reconchain" / "workspaces" / workspace_name
        self._scans_path = self._dir / "scans.json"
        self._findings_path = self._dir / "findings.json"
        self._scans: List[ScanEntry] = []
        self._findings: Dict[str, FindingRecord] = {}
        self._load()

    def _load(self) -> None:
        if self._scans_path.exists():
            try:
                data = json.loads(self._scans_path.read_text(encoding="utf-8"))
                self._scans = [ScanEntry.from_dict(s) for s in data.get("scans", [])]
            except Exception:
                pass
        if self._findings_path.exists():
            try:
                data = json.loads(self._findings_path.read_text(encoding="utf-8"))
                self._findings = {
                    k: FindingRecord.from_dict(v)
                    for k, v in data.get("findings", {}).items()
                }
            except Exception:
                pass

    def _save(self) -> None:
        ensure(self._scans_path)
        ensure(self._findings_path)
        self._scans_path.write_text(json.dumps(
            {"scans": [s.to_dict() for s in self._scans]}, indent=2
        ))
        self._findings_path.write_text(json.dumps(
            {"findings": {k: v.to_dict() for k, v in self._findings.items()}},
            indent=2,
        ))

    def add_scan(self, outdir: Path, *, scanner: str = "", domain: str = "") -> ScanEntry:
        """Register a scan output directory with the workspace.

        Args:
            outdir: Output directory containing scan results.
            scanner: Name/identifier of the scanner.
            domain: Target domain.

        Returns:
            The ScanEntry record.
        """
        finding_count = 0
        for art in ARTIFACTS:
            fpath = outdir / art.filename
            if fpath.exists():
                finding_count += len(list(read_lines(fpath)))

        scan_id = hashlib.sha256(
            f"{scanner}:{domain}:{time.time()}".encode()
        ).hexdigest()[:12]

        entry = ScanEntry(
            scanner=scanner,
            domain=domain,
            submitted_at=time.time(),
            outdir=str(outdir),
            finding_count=finding_count,
            scan_id=scan_id,
            status="pending",
        )
        self._scans.append(entry)
        self._save()
        log("ok", f"workspace: registered scan {scan_id} from {scanner} "
            f"({finding_count} findings)")
        return entry

    def merge_findings(self) -> Dict[str, Any]:
        """Merge findings from all registered scans with deduplication.

        Returns:
            Summary of merge operation.
        """
        total_new = 0
        total_updated = 0

        for scan in self._scans:
            if scan.status != "pending" or not scan.outdir:
                continue

            outdir = Path(scan.outdir)
            if not outdir.exists():
                continue

            for art in ARTIFACTS:
                fpath = outdir / art.filename
                if not fpath.exists():
                    continue
                for line in read_lines(fpath):
                    text = line.strip()
                    if not text:
                        continue
                    fp = _fingerprint(text)
                    if fp in self._findings:
                        rec = self._findings[fp]
                        if scan.scanner not in rec.discovered_by:
                            rec.discovered_by.append(scan.scanner)
                        rec.last_seen = time.time()
                        if art.vuln_type:
                            rec.hosts.add(scan.domain)
                        total_updated += 1
                    else:
                        sev = guess_severity(text)
                        self._findings[fp] = FindingRecord(
                            fingerprint=fp,
                            text=text,
                            vuln_type=art.vuln_type or "",
                            severity=sev,
                            discovered_by=[scan.scanner] if scan.scanner else [],
                            first_seen=time.time(),
                            last_seen=time.time(),
                            hosts={scan.domain} if scan.domain else set(),
                        )
                        total_new += 1

            scan.status = "merged"

        self._save()
        summary = {
            "total_findings": len(self._findings),
            "new_findings": total_new,
            "updated_findings": total_updated,
            "scans_merged": sum(1 for s in self._scans if s.status == "merged"),
        }
        log("ok", f"workspace: merged {total_new} new, {total_updated} updated "
            f"(total: {len(self._findings)})")
        return summary

    def confirm_finding(self, fingerprint: str, confirmed: bool = True) -> bool:
        """Mark a finding as confirmed (true positive) or false positive."""
        if fingerprint in self._findings:
            self._findings[fingerprint].confirmed = confirmed
            self._findings[fingerprint].false_positive = not confirmed
            self._save()
            return True
        return False

    def get_consensus_findings(self, *, min_scanners: int = 2) -> List[FindingRecord]:
        """Return findings discovered by multiple scanners (consensus).

        Args:
            min_scanners: Minimum number of independent scanners who found it.

        Returns:
            List of FindingRecord sorted by severity then scanner count.
        """
        result = [
            f for f in self._findings.values()
            if len(f.discovered_by) >= min_scanners and not f.false_positive
        ]
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        result.sort(key=lambda f: (
            sev_order.get(f.severity, 5),
            -len(f.discovered_by),
        ))
        return result

    def get_unconfirmed(self) -> List[FindingRecord]:
        """Return findings not yet confirmed or marked as false positive."""
        return [
            f for f in self._findings.values()
            if not f.confirmed and not f.false_positive
        ]

    def get_statistics(self) -> Dict[str, Any]:
        """Return workspace statistics."""
        total = len(self._findings)
        by_severity: Dict[str, int] = defaultdict(int)
        by_type: Dict[str, int] = defaultdict(int)
        confirmed_count = 0
        fp_count = 0

        for f in self._findings.values():
            by_severity[f.severity] += 1
            if f.vuln_type:
                by_type[f.vuln_type] += 1
            if f.confirmed:
                confirmed_count += 1
            if f.false_positive:
                fp_count += 1

        scanners = set()
        for scan in self._scans:
            if scan.scanner:
                scanners.add(scan.scanner)

        return {
            "workspace": self.name,
            "total_findings": total,
            "confirmed": confirmed_count,
            "false_positives": fp_count,
            "by_severity": dict(by_severity),
            "by_type": dict(by_type),
            "scans": len(self._scans),
            "scanners": list(scanners),
        }

    def export_report(self) -> Path:
        """Export a consolidated workspace report."""
        out = ensure(self._dir / "workspace_report.json")
        report = {
            "workspace": self.name,
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "statistics": self.get_statistics(),
            "consensus_findings": [
                f.to_dict() for f in self.get_consensus_findings(min_scanners=1)
            ],
        }
        out.write_text(json.dumps(report, indent=2, default=str))
        log("ok", f"workspace: report exported → {out}")
        return out

    def list_scans(self) -> List[Dict[str, Any]]:
        return [s.to_dict() for s in self._scans]
