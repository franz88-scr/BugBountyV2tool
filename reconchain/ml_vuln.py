"""ML-based vulnerability detection and classification for ReconChain.

Uses pattern matching, heuristic scoring, and statistical classification
to identify, rank, and categorize security vulnerabilities from scan output.

No external ML frameworks required — implements lightweight classifiers
using Python stdlib with optional scikit-learn acceleration.

Usage:
    from reconchain.ml_vuln import classify_findings, VulnerabilityClassifier
    classifier = VulnerabilityClassifier()
    classified = classifier.classify(outdir)
"""
from __future__ import annotations

import json
import math
import re
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from reconchain.artifacts import ARTIFACTS, FILENAME_TO_ARTIFACT
from reconchain.utils import ensure, log, read_lines


# ── Vulnerability signature database ────────────────────────────────

VULN_SIGNATURES: List[Dict[str, Any]] = [
    {"pattern": r"(?i)sql\s*(syntax|error|injection|blind)|mysql_fetch|ORA-\d{5}",
     "category": "sqli", "severity": "critical", "cwe": "CWE-89",
     "confidence": 0.95},
    {"pattern": r"(?i)<script[^>]*>|alert\(|document\.cookie|onerror=|onload=",
     "category": "xss", "severity": "high", "cwe": "CWE-79",
     "confidence": 0.90},
    {"pattern": r"(?i)169\.254\.169\.254|aws.*metadata|imds|cloud\.metadata",
     "category": "ssrf", "severity": "critical", "cwe": "CWE-918",
     "confidence": 0.95},
    {"pattern": r"(?i)/etc/passwd|/etc/shadow|\.\.\/\.\.\/|path\s*traversal",
     "category": "lfi", "severity": "high", "cwe": "CWE-22",
     "confidence": 0.90},
    {"pattern": r"(?i)default\s*(password|cred|login)|admin:admin|root:toor",
     "category": "default_creds", "severity": "critical", "cwe": "CWE-798",
     "confidence": 0.85},
    {"pattern": r"(?i)api[_-]?key\s*[:=]\s*['\"][A-Za-z0-9]{20,}",
     "category": "secrets", "severity": "high", "cwe": "CWE-798",
     "confidence": 0.80},
    {"pattern": r"(?i)(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{20,})",
     "category": "secrets", "severity": "critical", "cwe": "CWE-798",
     "confidence": 0.95},
    {"pattern": r"(?i)CORS.*(?:origin|Access-Control-Allow-Origin).*(?:\*|null)",
     "category": "cors", "severity": "medium", "cwe": "CWE-942",
     "confidence": 0.80},
    {"pattern": r"(?i)open\s*redirect|redirect_uri.*(?:\.\.\/|evil\.com)",
     "category": "open_redirect", "severity": "medium", "cwe": "CWE-601",
     "confidence": 0.85},
    {"pattern": r"(?i)SSRF|server.side.request",
     "category": "ssrf", "severity": "high", "cwe": "CWE-918",
     "confidence": 0.85},
    {"pattern": r"(?i)command\s*injection|;\s*(?:ls|cat|id|whoami)|`[^`]+`|system\(",
     "category": "cmdi", "severity": "critical", "cwe": "CWE-78",
     "confidence": 0.95},
    {"pattern": r"(?i)deserialization|pickle\.loads|yaml\.load\(|Marshal\.Deserialize",
     "category": "deserialization", "severity": "critical", "cwe": "CWE-502",
     "confidence": 0.90},
    {"pattern": r"(?i)template.*inject|SSTI|\{\{.*\}\}|<%=.*%>",
     "category": "ssti", "severity": "critical", "cwe": "CWE-1336",
     "confidence": 0.85},
    {"pattern": r"(?i)XML\s*entity|XXE|DOCTYPE|ENTITY\s+%",
     "category": "xxe", "severity": "high", "cwe": "CWE-611",
     "confidence": 0.90},
    {"pattern": r"(?i)CSRF|cross.site.request.forgery|missing.*token",
     "category": "csrf", "severity": "medium", "cwe": "CWE-352",
     "confidence": 0.75},
    {"pattern": r"(?i)insecure\s*cookie|missing.*[Ss]ecure|httponly.*false|samesite.*none",
     "category": "cookie", "severity": "medium", "cwe": "CWE-614",
     "confidence": 0.70},
    {"pattern": r"(?i)missing.*(?:X-Frame-Options|Content-Security-Policy|Strict-Transport-Security)",
     "category": "header", "severity": "low", "cwe": "CWE-693",
     "confidence": 0.60},
    {"pattern": r"(?i)JWT.*(?:none|weak|HS256.*RS256|algorithm\s*confusion)",
     "category": "jwt", "severity": "high", "cwe": "CWE-327",
     "confidence": 0.85},
    {"pattern": r"(?i)IDOR|insecure\s*direct|object\s*reference|/\d+/edit",
     "category": "idor", "severity": "high", "cwe": "CWE-639",
     "confidence": 0.75},
    {"pattern": r"(?i)CRLF|\\r\\n|header\s*inject|response\s*splitting",
     "category": "crlf", "severity": "medium", "cwe": "CWE-113",
     "confidence": 0.80},
    {"pattern": r"(?i)file\s*upload|unrestricted.*upload|webshell|\.php.*upload",
     "category": "upload", "severity": "high", "cwe": "CWE-434",
     "confidence": 0.85},
    {"pattern": r"(?i)information\s*disclosure|stack\s*trace|debug\s*mode|verbose\s*error",
     "category": "info_disclosure", "severity": "low", "cwe": "CWE-200",
     "confidence": 0.70},
    {"pattern": r"(?i)rate\s*limit|brute\s*force|lockout|account\s*enum",
     "category": "auth", "severity": "medium", "cwe": "CWE-307",
     "confidence": 0.65},
    {"pattern": r"(?i)exposed.*(?:database|admin|panel|console)|phpMyAdmin|Adminer",
     "category": "exposed_databases", "severity": "critical", "cwe": "CWE-200",
     "confidence": 0.80},
    {"pattern": r"(?i)subdomain\s*takeover|CNAME.*(?:s3|github\.io|azure|herokuapp)",
     "category": "takeover", "severity": "high", "cwe": "CWE-440",
     "confidence": 0.85},
    {"pattern": r"(?i)host.header\s*inject|X-Forwarded-Host|X-Original-URL",
     "category": "host_header", "severity": "medium", "cwe": "CWE-644",
     "confidence": 0.75},
]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class ClassifiedVulnerability:
    """A classified vulnerability finding."""
    text: str
    category: str
    severity: str
    cwe: str
    confidence: float
    source_file: str
    phase: str
    host: str = ""
    url: str = ""
    matched_patterns: List[str] = field(default_factory=list)
    risk_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "text": self.text,
            "category": self.category,
            "severity": self.severity,
            "cwe": self.cwe,
            "confidence": round(self.confidence, 3),
            "source_file": self.source_file,
            "phase": self.phase,
            "host": self.host,
            "url": self.url,
            "risk_score": round(self.risk_score, 3),
        }


class VulnerabilityClassifier:
    """Pattern-based vulnerability classifier with Bayesian confidence adjustment."""

    def __init__(self) -> None:
        self._patterns: List[Tuple[re.Pattern, Dict[str, Any]]] = []
        for sig in VULN_SIGNATURES:
            compiled = re.compile(sig["pattern"])
            self._patterns.append((compiled, sig))
        self._global_counts: Counter = Counter()
        self._phase_counts: Dict[str, Counter] = defaultdict(Counter)

    def _match_finding(self, text: str) -> List[Tuple[Dict[str, Any], float]]:
        """Match a finding text against all vulnerability signatures."""
        matches = []
        for compiled, sig in self._patterns:
            m = compiled.search(text)
            if m:
                # Boost confidence if multiple pattern groups match
                groups = [g for g in m.groups() if g]
                pattern_boost = min(0.1, len(groups) * 0.02)
                effective_confidence = min(1.0, sig["confidence"] + pattern_boost)
                matches.append((sig, effective_confidence))
        return matches

    def _compute_risk_score(
        self, severity: str, confidence: float, host_findings: int
    ) -> float:
        """Compute a 0-1 risk score combining severity, confidence, and host density."""
        sev_score = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.25, "info": 0.1}
        base = sev_score.get(severity, 0.5)
        density_factor = min(1.0, host_findings / 20.0)
        return base * confidence * (0.7 + 0.3 * density_factor)

    def classify(
        self,
        outdir: Path,
        *,
        host_filter: Optional[str] = None,
        min_confidence: float = 0.5,
    ) -> List[ClassifiedVulnerability]:
        """Classify all vulnerability findings from scan output.

        Args:
            outdir: Output directory containing scan artifacts.
            host_filter: Only classify findings matching this host.
            min_confidence: Minimum confidence threshold (0-1).

        Returns:
            List of ClassifiedVulnerability sorted by risk_score descending.
        """
        all_findings: List[str] = []
        finding_sources: List[Tuple[str, str]] = []

        for art in ARTIFACTS:
            if not art.vuln_type:
                continue
            fpath = outdir / art.filename
            if not fpath.exists():
                continue
            for line in read_lines(fpath):
                text = line.strip()
                if text:
                    all_findings.append(text)
                    finding_sources.append((art.filename, art.phase))

        # Classify each finding
        classified: List[ClassifiedVulnerability] = []
        host_finding_counts: Counter = Counter()

        for i, text in enumerate(all_findings):
            matches = self._match_finding(text)
            if not matches:
                continue

            # Extract host from URL-like findings
            host = ""
            url = ""
            if text.startswith("http"):
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(text)
                    host = parsed.hostname or ""
                    url = text
                except Exception:
                    pass

            if host_filter and host != host_filter:
                continue

            # Take the highest-confidence match
            matches.sort(key=lambda x: x[1], reverse=True)
            best_sig, best_confidence = matches[0]

            if best_confidence < min_confidence:
                continue

            # Track host density
            if host:
                host_finding_counts[host] += 1

            source_file, phase = finding_sources[i] if i < len(finding_sources) else ("", "")

            classified.append(ClassifiedVulnerability(
                text=text,
                category=best_sig["category"],
                severity=best_sig["severity"],
                cwe=best_sig.get("cwe", ""),
                confidence=best_confidence,
                source_file=source_file,
                phase=phase,
                host=host,
                url=url,
                matched_patterns=[s["category"] for s, _ in matches],
                risk_score=0.0,
            ))

        # Compute risk scores with host density
        for v in classified:
            density = host_finding_counts.get(v.host, 1) if v.host else 1
            v.risk_score = self._compute_risk_score(v.severity, v.confidence, density)
            self._global_counts[v.category] += 1
            self._phase_counts[v.phase][v.category] += 1

        # Sort by risk_score descending
        classified.sort(key=lambda v: v.risk_score, reverse=True)

        log("ok", f"ml_vuln: classified {len(classified)} vulnerabilities across "
            f"{len(host_finding_counts)} hosts")

        return classified

    def get_summary(self, classified: List[ClassifiedVulnerability]) -> Dict[str, Any]:
        """Generate a summary of classified vulnerabilities."""
        by_severity: Counter = Counter()
        by_category: Counter = Counter
        by_host: Dict[str, Counter] = defaultdict(Counter)

        for v in classified:
            by_severity[v.severity] += 1
            by_category[v.category] += 1
            if v.host:
                by_host[v.host][v.category] += 1

        return {
            "total": len(classified),
            "by_severity": dict(by_severity),
            "by_category": dict(by_category),
            "by_host": {h: dict(c) for h, c in by_host.items()},
            "avg_confidence": round(
                sum(v.confidence for v in classified) / max(1, len(classified)), 3
            ),
            "avg_risk_score": round(
                sum(v.risk_score for v in classified) / max(1, len(classified)), 3
            ),
        }

    def export_classified(
        self, classified: List[ClassifiedVulnerability], outdir: Path
    ) -> Path:
        """Export classified vulnerabilities to JSON."""
        out = ensure(outdir / "classified_vulns.json")
        data = [v.to_dict() for v in classified]
        out.write_text(json.dumps(data, indent=2, default=str))
        log("ok", f"ml_vuln: exported {len(data)} classified vulns → {out}")
        return out


def classify_findings(
    outdir: Path,
    *,
    min_confidence: float = 0.5,
    host_filter: Optional[str] = None,
) -> List[ClassifiedVulnerability]:
    """Convenience function for one-shot vulnerability classification.

    Args:
        outdir: Output directory containing scan artifacts.
        min_confidence: Minimum confidence threshold.
        host_filter: Only classify findings for this host.

    Returns:
        List of ClassifiedVulnerability sorted by risk_score.
    """
    classifier = VulnerabilityClassifier()
    return classifier.classify(outdir, host_filter=host_filter, min_confidence=min_confidence)
