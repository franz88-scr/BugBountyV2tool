"""Confidence scoring for vulnerability findings.

Every finding gets a confidence rating based on tool reliability,
response evidence, cross-validation, and context.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from reconchain.utils import read_lines


class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    UNVERIFIED = "unverified"
    SUSPECTED = "suspected"
    FALSE_POSITIVE = "false_positive"


# Tool reliability scores (higher = more reliable)
TOOL_RELIABILITY: Dict[str, float] = {
    "nuclei": 0.9,
    "sqlmap": 0.85,
    "nmap": 0.9,
    "httpx": 0.85,
    "subfinder": 0.9,
    "dalfox": 0.8,
    "ffuf": 0.85,
    "naabu": 0.85,
    "testssl": 0.9,
    "corsy": 0.75,
    "secretfinder": 0.7,
    "custom": 0.6,
}

# Evidence patterns that increase/decrease confidence
HIGH_CONFIDENCE_PATTERNS = [
    (re.compile(r'(verified|confirmed|valid|exploitable)', re.I), 0.15),
    (re.compile(r'status[=:]\s*(200|301|302)', re.I), 0.1),
    (re.compile(r'response.*contains.*payload', re.I), 0.2),
    (re.compile(r'reflect.*param', re.I), 0.1),
]

LOW_CONFIDENCE_PATTERNS = [
    (re.compile(r'(potential|possible|maybe|might)', re.I), -0.15),
    (re.compile(r'(error|timeout|connection refused)', re.I), -0.2),
    (re.compile(r'(no .* found|0 results)', re.I), -0.3),
    (re.compile(r'(waf|blocked|403)', re.I), -0.1),
]


@dataclass
class FindingScore:
    """Confidence score for a single finding."""
    finding_text: str
    confidence: Confidence
    score: float
    reasons: List[str] = field(default_factory=list)
    source_tool: str = ""
    vuln_type: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding": self.finding_text,
            "confidence": self.confidence.value,
            "score": round(self.score, 3),
            "reasons": self.reasons,
            "source_tool": self.source_tool,
            "vuln_type": self.vuln_type,
        }


def score_finding(
    text: str,
    source_tool: str = "",
    vuln_type: str = "",
    cross_validated: bool = False,
    has_response_evidence: bool = False,
) -> FindingScore:
    """Score a single finding's confidence level."""
    score = 0.5  # Base score
    reasons: List[str] = []

    # Tool reliability
    if source_tool:
        tool_key = source_tool.lower().split()[0] if source_tool else ""
        if tool_key in TOOL_RELIABILITY:
            tool_score = TOOL_RELIABILITY[tool_key]
            score = (score + tool_score) / 2
            reasons.append(f"tool reliability: {tool_key}={tool_score:.2f}")

    # Pattern-based evidence
    for pattern, adjustment in HIGH_CONFIDENCE_PATTERNS:
        if pattern.search(text):
            score += adjustment
            reasons.append(f"high-confidence pattern: {pattern.pattern[:30]}")

    for pattern, adjustment in LOW_CONFIDENCE_PATTERNS:
        if pattern.search(text):
            score += adjustment
            reasons.append(f"low-confidence pattern: {pattern.pattern[:30]}")

    # Cross-validation bonus
    if cross_validated:
        score += 0.15
        reasons.append("cross-validated by multiple tools")

    # Response evidence bonus
    if has_response_evidence:
        score += 0.1
        reasons.append("response evidence present")

    # Cap score
    score = max(0.0, min(1.0, score))

    # Map to confidence level
    if score >= 0.8:
        confidence = Confidence.CONFIRMED
    elif score >= 0.6:
        confidence = Confidence.LIKELY
    elif score >= 0.4:
        confidence = Confidence.UNVERIFIED
    elif score >= 0.2:
        confidence = Confidence.SUSPECTED
    else:
        confidence = Confidence.FALSE_POSITIVE

    return FindingScore(
        finding_text=text,
        confidence=confidence,
        score=score,
        reasons=reasons,
        source_tool=source_tool,
        vuln_type=vuln_type,
    )


def score_all_findings(outdir: Path) -> List[FindingScore]:
    """Score all findings in scan output."""
    from reconchain.artifacts import ARTIFACTS

    scored: List[FindingScore] = []

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
            score = score_finding(
                text,
                source_tool=art.display_name,
                vuln_type=art.vuln_type,
            )
            scored.append(score)

    return scored


def write_confidence_report(outdir: Path, scores: List[FindingScore]) -> Path:
    """Write confidence scores to JSON."""
    import json
    from reconchain.utils import ensure

    data = [s.to_dict() for s in scores]
    out = ensure(outdir / "confidence_scores.json")
    out.write_text(json.dumps(data, indent=2, default=str))
    return out
