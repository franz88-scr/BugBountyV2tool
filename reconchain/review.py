"""Interactive finding review — post-scan CLI for marking findings as confirmed/FP."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from reconchain.artifacts import ARTIFACTS, guess_severity
from reconchain.utils import ensure, log, read_lines


class FindingReview:
    """Interactive review of scan findings."""

    def __init__(self, outdir: Path) -> None:
        self.outdir = outdir
        self.reviews: Dict[str, Dict[str, str]] = {}  # finding_text -> review
        self._load()

    def _load(self) -> None:
        path = self.outdir / "finding_reviews.json"
        if path.exists():
            try:
                self.reviews = json.loads(path.read_text())
            except Exception:
                self.reviews = {}

    def _save(self) -> None:
        out = self.outdir / "finding_reviews.json"
        out.write_text(json.dumps(self.reviews, indent=2))

    def review_finding(self, finding_text: str, status: str, notes: str = "") -> None:
        """Mark a finding as confirmed, false_positive, or needs_review."""
        self.reviews[finding_text] = {
            "status": status,
            "notes": notes,
        }
        self._save()

    def get_unreviewed(self) -> List[Dict[str, str]]:
        """Get all findings not yet reviewed."""
        unreviewed = []
        for art in ARTIFACTS:
            if not art.vuln_type:
                continue
            p = self.outdir / art.filename
            if not p.exists():
                continue
            for line in read_lines(p):
                text = line.strip()
                if text and text not in self.reviews:
                    sev = guess_severity(text)
                    unreviewed.append({
                        "finding": text,
                        "source": art.display_name,
                        "severity": sev,
                        "file": art.filename,
                    })
        return unreviewed

    def get_stats(self) -> Dict[str, int]:
        stats: Dict[str, int] = {"confirmed": 0, "false_positive": 0, "needs_review": 0, "total": 0}
        for review in self.reviews.values():
            status = review.get("status", "")
            if status in stats:
                stats[status] += 1
            stats["total"] += 1
        return stats

    def export_report(self) -> Path:
        """Export review results as a report."""
        stats = self.get_stats()
        confirmed = [f for f, r in self.reviews.items() if r.get("status") == "confirmed"]
        fps = [f for f, r in self.reviews.items() if r.get("status") == "false_positive"]

        report = {
            "stats": stats,
            "confirmed_findings": [{"finding": f, "notes": self.reviews[f].get("notes", "")} for f in confirmed],
            "false_positives": [{"finding": f, "notes": self.reviews[f].get("notes", "")} for f in fps],
        }

        out = ensure(self.outdir / "review_report.json")
        out.write_text(json.dumps(report, indent=2))
        return out


def run_interactive_review(outdir: Path) -> None:
    """Run interactive finding review in the terminal."""
    review = FindingReview(outdir)
    unreviewed = review.get_unreviewed()

    if not unreviewed:
        log("ok", "No unreviewed findings — all findings have been reviewed!")
        return

    log("info", f"Found {len(unreviewed)} unreviewed findings. Press Ctrl+C to stop.")
    log("info", "Commands: [c]onfirm, [f]alse positive, [n]eeds review, [s]kip, [q]uit\n")

    reviewed = 0
    for item in unreviewed:
        sev_color = {"critical": "err", "high": "warn", "medium": "y", "low": "ok"}.get(item["severity"], "d")
        print(f"\n  [{sev_color}]{item['severity'].upper()}[r] {item['source']}")
        print(f"  {item['finding'][:120]}")

        try:
            cmd = input("  Review [c/f/n/s/q]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        if cmd == "q":
            break
        elif cmd == "c":
            notes = input("  Notes (optional): ").strip()
            review.review_finding(item["finding"], "confirmed", notes)
            reviewed += 1
        elif cmd == "f":
            notes = input("  Why false positive (optional): ").strip()
            review.review_finding(item["finding"], "false_positive", notes)
            reviewed += 1
        elif cmd == "n":
            notes = input("  Notes (optional): ").strip()
            review.review_finding(item["finding"], "needs_review", notes)
            reviewed += 1
        # 's' = skip

    stats = review.get_stats()
    log("ok", f"Reviewed {reviewed} findings: {stats['confirmed']} confirmed, {stats['false_positive']} FPs")
    review.export_report()
