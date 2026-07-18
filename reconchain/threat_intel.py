"""MITRE ATT&CK mapping and threat intelligence integration for ReconChain.

Maps scan findings to ATT&CK techniques, provides threat feed queries,
and generates threat intelligence reports.

Usage:
    from reconchain.threat_intel import map_to_mitre, ThreatIntelEngine
    engine = ThreatIntelEngine()
    mapping = map_to_mitre(outdir)
"""
from __future__ import annotations

import json
import re
import time
import urllib.request
import urllib.error
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from reconchain.utils import ensure, log, read_lines


# ── ATT&CK Technique Mappings ───────────────────────────────────────

ATTACK_TECHNIQUES: List[Dict[str, Any]] = [
    {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "finding_types": ["xss", "sqli", "ssrf", "lfi", "cmdi", "ssti", "xxe", "idor", "upload"],
        "severity_threshold": "high",
    },
    {
        "technique_id": "T1133",
        "technique_name": "External Remote Services",
        "tactic": "Initial Access",
        "finding_types": ["exposed_databases", "default_creds", "auth"],
        "severity_threshold": "critical",
    },
    {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Initial Access",
        "finding_types": ["default_creds", "password_spray", "auth"],
        "severity_threshold": "high",
    },
    {
        "technique_id": "T1566",
        "technique_name": "Phishing",
        "tactic": "Initial Access",
        "finding_types": ["open_redirect", "cors"],
        "severity_threshold": "medium",
    },
    {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "finding_types": ["cmdi", "ssti"],
        "severity_threshold": "critical",
    },
    {
        "technique_id": "T1053",
        "technique_name": "Scheduled Task/Job",
        "tactic": "Execution",
        "finding_types": ["cicd"],
        "severity_threshold": "high",
    },
    {
        "technique_id": "T1070",
        "technique_name": "Indicator Removal",
        "tactic": "Defense Evasion",
        "finding_types": ["info_disclosure"],
        "severity_threshold": "low",
    },
    {
        "technique_id": "T1222",
        "technique_name": "File and Directory Permissions Modification",
        "tactic": "Defense Evasion",
        "finding_types": ["upload", "lfi"],
        "severity_threshold": "high",
    },
    {
        "technique_id": "T1552",
        "technique_name": "Unsecured Credentials",
        "tactic": "Credential Access",
        "finding_types": ["secrets", "git", "lfi", "cicd"],
        "severity_threshold": "critical",
    },
    {
        "technique_id": "T1555",
        "technique_name": "Credentials from Password Stores",
        "tactic": "Credential Access",
        "finding_types": ["default_creds", "secrets"],
        "severity_threshold": "high",
    },
    {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "finding_types": ["auth", "password_spray"],
        "severity_threshold": "medium",
    },
    {
        "technique_id": "T1562",
        "technique_name": "Impair Defenses",
        "tactic": "Defense Evasion",
        "finding_types": ["cors", "header"],
        "severity_threshold": "medium",
    },
    {
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "tactic": "Lateral Movement",
        "finding_types": ["upload", "ssrf"],
        "severity_threshold": "high",
    },
    {
        "technique_id": "T1048",
        "technique_name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "finding_types": ["ssrf", "xss", "stored_xss", "open_redirect"],
        "severity_threshold": "high",
    },
    {
        "technique_id": "T1567",
        "technique_name": "Exfiltration Over Web Service",
        "tactic": "Exfiltration",
        "finding_types": ["xss", "stored_xss", "ssrf"],
        "severity_threshold": "high",
    },
    {
        "technique_id": "T1485",
        "technique_name": "Data Destruction",
        "tactic": "Impact",
        "finding_types": ["sqli", "cmdi"],
        "severity_threshold": "critical",
    },
    {
        "technique_id": "T1491",
        "technique_name": "Defacement",
        "tactic": "Impact",
        "finding_types": ["xss", "stored_xss", "upload"],
        "severity_threshold": "medium",
    },
    {
        "technique_id": "T1195",
        "technique_name": "Supply Chain Compromise",
        "tactic": "Initial Access",
        "finding_types": ["cicd", "git", "docker", "k8s"],
        "severity_threshold": "critical",
    },
    {
        "technique_id": "T1610",
        "technique_name": "Deploy Container",
        "tactic": "Execution",
        "finding_types": ["docker", "k8s"],
        "severity_threshold": "high",
    },
    {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "finding_types": ["port_scan", "subdomain_takeover"],
        "severity_threshold": "medium",
    },
]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class TechniqueMatch:
    """A matched ATT&CK technique."""
    technique_id: str
    technique_name: str
    tactic: str
    matched_findings: List[Dict[str, Any]]
    confidence: float
    risk_level: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "matched_findings_count": len(self.matched_findings),
            "confidence": round(self.confidence, 3),
            "risk_level": self.risk_level,
            "sample_findings": [f.get("text", f.get("finding", ""))[:120] for f in self.matched_findings[:3]],
        }


@dataclass
class ThreatFeed:
    """A threat intelligence feed entry."""
    source: str
    indicator: str
    indicator_type: str  # ip, domain, hash, url
    confidence: float
    tags: List[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "indicator": self.indicator,
            "indicator_type": self.indicator_type,
            "confidence": self.confidence,
            "tags": list(self.tags),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "description": self.description,
        }


def _load_vuln_findings(outdir: Path) -> List[Dict[str, Any]]:
    """Load vulnerability findings from scan output."""
    findings: List[Dict[str, Any]] = []

    # Try classified vulns
    classified_path = outdir / "classified_vulns.json"
    if classified_path.exists():
        try:
            data = json.loads(classified_path.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return data
        except Exception:
            pass

    # Fall back to raw artifacts
    from reconchain.artifacts import ARTIFACTS
    for art in ARTIFACTS:
        if not art.vuln_type:
            continue
        fpath = outdir / art.filename
        if not fpath.exists():
            continue
        for line in read_lines(fpath):
            text = line.strip()
            if text:
                findings.append({
                    "text": text,
                    "category": art.vuln_type,
                    "severity": "high" if art.vuln_type in (
                        "sqli", "xss", "ssrf", "cmdi", "ssti"
                    ) else "medium",
                })

    return findings


def map_to_mitre(
    outdir: Path,
    *,
    min_confidence: float = 0.3,
) -> List[Dict[str, Any]]:
    """Map scan findings to MITRE ATT&CK techniques.

    Args:
        outdir: Output directory with scan artifacts.
        min_confidence: Minimum confidence for inclusion.

    Returns:
        List of technique matches sorted by confidence descending.
    """
    findings = _load_vuln_findings(outdir)
    return _map_findings_to_techniques(findings, min_confidence=min_confidence)


def _map_findings_to_techniques(
    findings: List[Dict[str, Any]],
    *,
    min_confidence: float = 0.3,
) -> List[Dict[str, Any]]:
    """Core mapping logic: findings → ATT&CK techniques."""
    if not findings:
        return []

    # Build category → findings index
    by_category: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for f in findings:
        cat = f.get("category", f.get("vuln_type", ""))
        if cat:
            by_category[cat].append(f)

    matches: List[TechniqueMatch] = []
    for tech in ATTACK_TECHNIQUES:
        matched: List[Dict[str, Any]] = []
        for ft in tech["finding_types"]:
            matched.extend(by_category.get(ft, []))

        if not matched:
            continue

        # Confidence based on finding diversity and count
        categories_found = len({f.get("category", f.get("vuln_type", "")) for f in matched})
        total_findings = len(matched)
        confidence = min(1.0, (categories_found * 0.3) + (min(total_findings, 10) * 0.05))

        # Risk level from finding severity
        worst_sev = "info"
        for f in matched:
            sev = f.get("severity", "medium")
            if SEVERITY_ORDER.get(sev, 5) < SEVERITY_ORDER.get(worst_sev, 5):
                worst_sev = sev

        if SEVERITY_ORDER.get(worst_sev, 5) > SEVERITY_ORDER.get(tech["severity_threshold"], 5):
            continue

        risk_level = worst_sev if confidence >= 0.5 else "medium"

        matches.append(TechniqueMatch(
            technique_id=tech["technique_id"],
            technique_name=tech["technique_name"],
            tactic=tech["tactic"],
            matched_findings=matched,
            confidence=confidence,
            risk_level=risk_level,
        ))

    matches.sort(key=lambda m: m.confidence, reverse=True)
    result = [m.to_dict() for m in matches if m.confidence >= min_confidence]
    log("ok", f"threat_intel: mapped {len(findings)} findings → {len(result)} ATT&CK techniques")
    return result


class ThreatIntelEngine:
    """Threat intelligence engine with indicator matching and feed queries."""

    def __init__(self) -> None:
        self._feeds: List[ThreatFeed] = []
        self._indicator_cache: Dict[str, ThreatFeed] = {}

    def load_feeds(self, feed_path: Path) -> int:
        """Load threat feeds from a JSON file."""
        if not feed_path.exists():
            return 0
        try:
            data = json.loads(feed_path.read_text(encoding="utf-8"))
            for item in data.get("feeds", []):
                feed = ThreatFeed(
                    source=item.get("source", ""),
                    indicator=item.get("indicator", ""),
                    indicator_type=item.get("indicator_type", ""),
                    confidence=item.get("confidence", 0.5),
                    tags=item.get("tags", []),
                    first_seen=item.get("first_seen", ""),
                    last_seen=item.get("last_seen", ""),
                    description=item.get("description", ""),
                )
                self._feeds.append(feed)
                self._indicator_cache[feed.indicator] = feed
            log("ok", f"threat_intel: loaded {len(self._feeds)} threat feed entries")
            return len(self._feeds)
        except Exception as e:
            log("warn", f"threat_intel: failed to load feeds: {e}")
            return 0

    def check_indicator(self, indicator: str) -> Optional[ThreatFeed]:
        """Check if an indicator (IP, domain, hash) appears in threat feeds."""
        return self._indicator_cache.get(indicator)

    def check_findings(self, outdir: Path) -> List[Dict[str, Any]]:
        """Check all scan findings against loaded threat feeds."""
        if not self._feeds:
            return []

        findings = _load_vuln_findings(outdir)
        matches: List[Dict[str, Any]] = []

        ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        domain_pattern = re.compile(r"\b([a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,})\b")

        for finding in findings:
            text = finding.get("text", finding.get("finding", ""))
            # Check IPs
            for ip_match in ip_pattern.finditer(text):
                ip = ip_match.group()
                feed_match = self.check_indicator(ip)
                if feed_match:
                    matches.append({
                        "finding": text[:200],
                        "indicator": ip,
                        "indicator_type": "ip",
                        "feed": feed_match.to_dict(),
                    })
            # Check domains
            for dom_match in domain_pattern.finditer(text):
                domain = dom_match.group(1)
                feed_match = self.check_indicator(domain)
                if feed_match:
                    matches.append({
                        "finding": text[:200],
                        "indicator": domain,
                        "indicator_type": "domain",
                        "feed": feed_match.to_dict(),
                    })

        log("ok", f"threat_intel: {len(matches)} findings matched threat feed indicators")
        return matches

    def generate_report(
        self, outdir: Path, domain: str = ""
    ) -> Path:
        """Generate a threat intelligence report."""
        mitre_mapping = map_to_mitre(outdir)
        indicator_matches = self.check_findings(outdir)

        report = {
            "domain": domain,
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "mitre_attack_mapping": mitre_mapping,
            "threat_feed_matches": indicator_matches,
            "summary": {
                "techniques_identified": len(mitre_mapping),
                "indicators_matched": len(indicator_matches),
                "tactics_covered": list({
                    m.get("tactic", "") for m in mitre_mapping
                }),
            },
        }

        out = ensure(outdir / "threat_intel_report.json")
        out.write_text(json.dumps(report, indent=2, default=str))
        log("ok", f"threat_intel: report → {out}")
        return out


def generate_threat_intel_report(
    outdir: Path,
    *,
    domain: str = "",
    feed_path: Optional[Path] = None,
) -> Path:
    """Convenience function: generate full threat intel report.

    Args:
        outdir: Output directory with scan results.
        domain: Target domain.
        feed_path: Optional path to threat feed JSON.

    Returns:
        Path to generated report.
    """
    engine = ThreatIntelEngine()
    if feed_path:
        engine.load_feeds(feed_path)
    return engine.generate_report(outdir, domain=domain)
