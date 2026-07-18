"""Severity classification and risk scoring for findings.

Provides consistent severity classification across all report formats
and a composite risk score for the entire scan.
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

from reconchain.artifacts import guess_severity, ARTIFACTS
from reconchain.utils import ensure, log, read_lines


# Severity weights for risk score calculation.
# Higher weight = more impact on the composite score.
# Weights are deliberately non-linear: critical findings dominate.
SEVERITY_WEIGHTS = {
    "critical": 10.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 1.5,
    "info": 0.5,
}


@dataclass
class RiskScore:
    """Composite risk score for a scan target."""
    score: float  # 0-100
    grade: str  # A-F
    severity_counts: Dict[str, int]
    total_findings: int
    critical_paths: int
    recommendations: List[str]

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the risk score to a JSON-compatible dictionary."""
        return {
            "score": round(self.score, 1),
            "grade": self.grade,
            "severity_counts": self.severity_counts,
            "total_findings": self.total_findings,
            "critical_paths": self.critical_paths,
            "recommendations": self.recommendations,
        }


def calculate_risk_score(outdir: Path) -> RiskScore:
    """Calculate composite risk score from all scan findings."""
    severity_counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    # Count findings by severity
    for art in ARTIFACTS:
        if not art.vuln_type:
            continue
        p = outdir / art.filename
        if not p.exists():
            continue
        for line in read_lines(p):
            text = line.strip()
            if not text:
                continue
            sev = guess_severity(text)
            # Use artifact severity hint if text classification is info
            if sev == "info" and art.severity_hint != "info":
                sev = art.severity_hint
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

    total = sum(severity_counts.values())

    # Calculate weighted score (0-100)
    if total == 0:
        raw_score = 0.0
    else:
        weighted_sum = sum(
            severity_counts[sev] * SEVERITY_WEIGHTS[sev]
            for sev in severity_counts
        )
        # Normalize to 0-100 using log scale to prevent huge scan counts from dominating
        raw_score = min(100.0, math.log1p(weighted_sum) * 15)

    # Map to grade.
    # The scale is inverted: a *low* score means few findings (good) = grade A,
    # while a *high* score means many severe findings (bad) = grade F.
    # Thresholds: 0-4 = A, 5-19 = B+, 20-39 = B, 40-59 = C, 60-79 = D, 80+ = F.
    if raw_score >= 80:
        grade = "F"
    elif raw_score >= 60:
        grade = "D"
    elif raw_score >= 40:
        grade = "C"
    elif raw_score >= 20:
        grade = "B"
    elif raw_score >= 5:
        grade = "B+"
    else:
        grade = "A"

    # Count critical paths (chains)
    chains_file = outdir / "exploit_chains.json"
    critical_paths = 0
    if chains_file.exists():
        try:
            chains = json.loads(chains_file.read_text())
            critical_paths = sum(1 for c in chains if c.get("severity") == "critical")
        except Exception:
            pass

    # Generate recommendations
    recommendations = []
    if severity_counts["critical"] > 0:
        recommendations.append(f"URGENT: {severity_counts['critical']} critical vulnerabilities require immediate remediation")
    if severity_counts["high"] > 10:
        recommendations.append(f"High volume of high-severity findings ({severity_counts['high']}) — review attack surface")
    if critical_paths > 0:
        recommendations.append(f"{critical_paths} critical exploit chains identified — prioritize chain breaking")
    if severity_counts["critical"] == 0 and severity_counts["high"] == 0:
        recommendations.append("No critical or high-severity findings — good security posture")
    if total > 100:
        recommendations.append("Large number of findings — consider targeted re-scan with --fast for quick wins")

    return RiskScore(
        score=raw_score,
        grade=grade,
        severity_counts=severity_counts,
        total_findings=total,
        critical_paths=critical_paths,
        recommendations=recommendations,
    )


def write_risk_score(outdir: Path, risk: RiskScore) -> Path:
    """Write risk score to JSON."""
    out = ensure(outdir / "risk_score.json")
    out.write_text(json.dumps(risk.to_dict(), indent=2))
    return out
