"""Compliance reporting module for ReconChain.

Generates compliance-focused reports mapping findings to regulatory frameworks:
- PCI DSS v4.0
- HIPAA Security Rule
- SOC 2 Type II

Usage:
    from reconchain.compliance import generate_compliance_report, Framework
    report = generate_compliance_report(outdir, Framework.PCI_DSS)
"""
from __future__ import annotations

import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from reconchain.utils import ensure, log, read_lines


class Framework(str, Enum):
    """Supported compliance frameworks."""
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    SOC2 = "soc2"


@dataclass
class ComplianceControl:
    """A single compliance control requirement."""
    framework: Framework
    control_id: str
    title: str
    description: str
    category: str
    finding_types: List[str]  # reconchain vuln categories that map to this control
    severity_mapping: Dict[str, str]  # reconchain severity → compliance impact
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "framework": self.framework.value,
            "control_id": self.control_id,
            "title": self.title,
            "description": self.description,
            "category": self.category,
            "finding_types": list(self.finding_types),
            "severity_mapping": dict(self.severity_mapping),
            "references": list(self.references),
        }


# ── PCI DSS v4.0 Controls ──────────────────────────────────────────

PCI_DSS_CONTROLS = [
    ComplianceControl(
        framework=Framework.PCI_DSS,
        control_id="PCI-1.2.1",
        title="Network security controls configured and functioning",
        description="Firewall and router configurations protect cardholder data",
        category="Network Security",
        finding_types=["cors", "header", "host_header"],
        severity_mapping={"critical": "non_compliant", "high": "non_compliant", "medium": "gap", "low": "observation"},
        references=["https://www.pcisecuritystandards.org/document_library/"],
    ),
    ComplianceControl(
        framework=Framework.PCI_DSS,
        control_id="PCI-2.2.1",
        title="System configurations hardened",
        description="System configurations are hardened per vendor guidance",
        category="Secure Configuration",
        finding_types=["default_creds", "exposed_databases", "info_disclosure", "cookie"],
        severity_mapping={"critical": "non_compliant", "high": "non_compliant", "medium": "gap", "low": "observation"},
    ),
    ComplianceControl(
        framework=Framework.PCI_DSS,
        control_id="PCI-3.4.1",
        title="PAN rendered unreadable",
        description="Primary account number is unreadable anywhere it is stored",
        category="Data Protection",
        finding_types=["secrets", "lfi"],
        severity_mapping={"critical": "non_compliant", "high": "non_compliant", "medium": "gap", "low": "observation"},
    ),
    ComplianceControl(
        framework=Framework.PCI_DSS,
        control_id="PCI-6.2.4",
        title="Secure development processes address common vulnerabilities",
        description="Custom software is protected against common vulnerabilities",
        category="Secure Development",
        finding_types=["xss", "sqli", "ssrf", "cmdi", "ssti", "lfi", "idor", "upload", "xxe", "deserialization"],
        severity_mapping={"critical": "non_compliant", "high": "non_compliant", "medium": "gap", "low": "observation"},
    ),
    ComplianceControl(
        framework=Framework.PCI_DSS,
        control_id="PCI-6.3.1",
        title="Vulnerabilities identified and managed",
        description="Vulnerabilities are identified via authorized scanning",
        category="Vulnerability Management",
        finding_types=["takeover", "secrets", "jwt"],
        severity_mapping={"critical": "non_compliant", "high": "non_compliant", "medium": "gap", "low": "observation"},
    ),
    ComplianceControl(
        framework=Framework.PCI_DSS,
        control_id="PCI-8.3.6",
        title="Password complexity requirements",
        description="Passwords/passphrases meet minimum complexity requirements",
        category="Access Control",
        finding_types=["auth", "default_creds"],
        severity_mapping={"critical": "non_compliant", "high": "non_compliant", "medium": "gap", "low": "observation"},
    ),
    ComplianceControl(
        framework=Framework.PCI_DSS,
        control_id="PCI-10.2.1",
        title="Audit trails implemented",
        description="Audit trails log all access to cardholder data",
        category="Logging & Monitoring",
        finding_types=["open_redirect", "csrf"],
        severity_mapping={"critical": "non_compliant", "high": "non_compliant", "medium": "gap", "low": "observation"},
    ),
    ComplianceControl(
        framework=Framework.PCI_DSS,
        control_id="PCI-11.3.1",
        title="External vulnerability scans performed",
        description="External vulnerability scans are conducted by qualified personnel",
        category="Testing",
        finding_types=["crlf", "cookie", "header"],
        severity_mapping={"critical": "non_compliant", "high": "gap", "medium": "observation", "low": "observation"},
    ),
]


# ── HIPAA Security Rule Controls ────────────────────────────────────

HIPAA_CONTROLS = [
    ComplianceControl(
        framework=Framework.HIPAA,
        control_id="HIPAA-164.312(a)(1)",
        title="Access control",
        description="Implement technical policies to allow access only to authorized persons",
        category="Access Control",
        finding_types=["auth", "default_creds", "idor", "jwt"],
        severity_mapping={"critical": "non_compliant", "high": "non_compliant", "medium": "gap", "low": "observation"},
        references=["https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html"],
    ),
    ComplianceControl(
        framework=Framework.HIPAA,
        control_id="HIPAA-164.312(a)(2)(iv)",
        title="Encryption and decryption",
        description="Implement mechanism to encrypt and decrypt ePHI",
        category="Data Protection",
        finding_types=["secrets", "cookie", "header"],
        severity_mapping={"critical": "non_compliant", "high": "non_compliant", "medium": "gap", "low": "observation"},
    ),
    ComplianceControl(
        framework=Framework.HIPAA,
        control_id="HIPAA-164.312(b)",
        title="Audit controls",
        description="Implement hardware, software, and procedural mechanisms to record and examine access",
        category="Logging & Monitoring",
        finding_types=["open_redirect", "csrf", "info_disclosure"],
        severity_mapping={"critical": "non_compliant", "high": "non_compliant", "medium": "gap", "low": "observation"},
    ),
    ComplianceControl(
        framework=Framework.HIPAA,
        control_id="HIPAA-164.312(c)(1)",
        title="Integrity controls",
        description="Implement policies to protect ePHI from improper alteration or destruction",
        category="Data Integrity",
        finding_types=["xss", "stored_xss", "sqli", "upload"],
        severity_mapping={"critical": "non_compliant", "high": "non_compliant", "medium": "gap", "low": "observation"},
    ),
    ComplianceControl(
        framework=Framework.HIPAA,
        control_id="HIPAA-164.312(d)",
        title="Person or entity authentication",
        description="Implement procedures to verify identity of persons seeking ePHI access",
        category="Authentication",
        finding_types=["auth", "session_fixation", "password_spray"],
        severity_mapping={"critical": "non_compliant", "high": "non_compliant", "medium": "gap", "low": "observation"},
    ),
    ComplianceControl(
        framework=Framework.HIPAA,
        control_id="HIPAA-164.312(e)(1)",
        title="Transmission security",
        description="Implement technical security measures to guard against unauthorized access during transmission",
        category="Network Security",
        finding_types=["cors", "host_header", "smuggle", "crlf"],
        severity_mapping={"critical": "non_compliant", "high": "non_compliant", "medium": "gap", "low": "observation"},
    ),
]


# ── SOC 2 Type II Controls ──────────────────────────────────────────

SOC2_CONTROLS = [
    ComplianceControl(
        framework=Framework.SOC2,
        control_id="CC6.1",
        title="Logical access controls",
        description="The entity implements logical access security measures",
        category="Access Control",
        finding_types=["auth", "default_creds", "idor", "jwt", "session_fixation"],
        severity_mapping={"critical": "non_compliant", "high": "partial", "medium": "observation", "low": "observation"},
    ),
    ComplianceControl(
        framework=Framework.SOC2,
        control_id="CC6.6",
        title="Boundary protection",
        description="The entity implements measures to restrict access at system boundaries",
        category="Network Security",
        finding_types=["cors", "ssrf", "host_header", "smuggle"],
        severity_mapping={"critical": "non_compliant", "high": "partial", "medium": "observation", "low": "observation"},
    ),
    ComplianceControl(
        framework=Framework.SOC2,
        control_id="CC7.1",
        title="Vulnerability management",
        description="The entity detects and monitors for vulnerabilities",
        category="Vulnerability Management",
        finding_types=["xss", "sqli", "lfi", "cmdi", "ssti", "xxe", "takeover"],
        severity_mapping={"critical": "non_compliant", "high": "partial", "medium": "observation", "low": "observation"},
    ),
    ComplianceControl(
        framework=Framework.SOC2,
        control_id="CC7.2",
        title="Incident monitoring and response",
        description="The entity monitors system components for anomalies",
        category="Monitoring",
        finding_types=["info_disclosure", "secrets", "open_redirect"],
        severity_mapping={"critical": "non_compliant", "high": "partial", "medium": "observation", "low": "observation"},
    ),
    ComplianceControl(
        framework=Framework.SOC2,
        control_id="CC8.1",
        title="Change management",
        description="The entity authorizes, tests, and approves changes",
        category="Change Management",
        finding_types=["cicd", "git", "docker", "k8s"],
        severity_mapping={"critical": "non_compliant", "high": "partial", "medium": "observation", "low": "observation"},
    ),
    ComplianceControl(
        framework=Framework.SOC2,
        control_id="CC9.1",
        title="Risk mitigation",
        description="The entity identifies, selects, and develops risk mitigation activities",
        category="Risk Management",
        finding_types=["deserialization", "upload", "cookie"],
        severity_mapping={"critical": "non_compliant", "high": "partial", "medium": "observation", "low": "observation"},
    ),
]


# ── Control lookup ──────────────────────────────────────────────────

ALL_CONTROLS: Dict[Framework, List[ComplianceControl]] = {
    Framework.PCI_DSS: PCI_DSS_CONTROLS,
    Framework.HIPAA: HIPAA_CONTROLS,
    Framework.SOC2: SOC2_CONTROLS,
}


@dataclass
class ControlStatus:
    """Status of a compliance control after assessment."""
    control: ComplianceControl
    status: str  # "compliant", "partial", "non_compliant", "not_applicable"
    findings_matched: List[Dict[str, Any]] = field(default_factory=list)
    impact: str = ""
    remediation_needed: List[str] = field(default_factory=list)


def _load_vuln_findings(outdir: Path) -> List[Dict[str, Any]]:
    """Load classified or raw vulnerability findings from the output directory."""
    # Try classified_vulns.json first
    classified_path = outdir / "classified_vulns.json"
    if classified_path.exists():
        try:
            return json.loads(classified_path.read_text(encoding="utf-8"))
        except Exception:
            pass

    # Fall back to exploit_chains.json
    chains_path = outdir / "exploit_chains.json"
    findings: List[Dict[str, Any]] = []
    if chains_path.exists():
        try:
            chains = json.loads(chains_path.read_text(encoding="utf-8"))
            for chain in chains:
                for step in chain.get("steps", []):
                    findings.append(step)
        except Exception:
            pass

    # Also scan raw artifact files for matching patterns
    from reconchain.artifacts import ARTIFACTS
    import re
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
                    "category": art.vuln_type,
                    "text": text,
                    "severity": "high" if art.vuln_type in ("sqli", "xss", "ssrf", "cmdi") else "medium",
                })

    return findings


def assess_control(
    control: ComplianceControl,
    findings: List[Dict[str, Any]],
) -> ControlStatus:
    """Assess a single compliance control against findings."""
    matched: List[Dict[str, Any]] = []
    for finding in findings:
        category = finding.get("category", finding.get("vuln_type", ""))
        if category in control.finding_types:
            matched.append(finding)

    if not matched:
        return ControlStatus(
            control=control,
            status="compliant",
            impact="No matching vulnerabilities detected",
        )

    # Determine worst severity
    worst_severity = "info"
    for f in matched:
        sev = f.get("severity", "medium")
        if SEVERITY_ORDER.get(sev, 5) < SEVERITY_ORDER.get(worst_severity, 5):
            worst_severity = sev

    status = control.severity_mapping.get(worst_severity, "gap")
    remediation = []
    if status in ("non_compliant", "partial"):
        remediation.append(
            f"Remediate {len(matched)} finding(s) in categories: "
            f"{', '.join(sorted({f.get('category', 'unknown') for f in matched}))}"
        )

    return ControlStatus(
        control=control,
        status=status,
        findings_matched=matched,
        impact=f"{len(matched)} finding(s) with worst severity: {worst_severity}",
        remediation_needed=remediation,
    )


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def generate_compliance_report(
    outdir: Path,
    framework: Framework,
    *,
    domain: str = "",
) -> Path:
    """Generate a compliance report for the specified framework.

    Args:
        outdir: Output directory with scan results.
        framework: Compliance framework (PCI_DSS, HIPAA, SOC2).
        domain: Target domain for the report header.

    Returns:
        Path to the generated compliance report.
    """
    controls = ALL_CONTROLS.get(framework, [])
    if not controls:
        log("warn", f"compliance: unknown framework: {framework}")
        return ensure(outdir / f"compliance_{framework.value}.json")

    findings = _load_vuln_findings(outdir)
    log("info", f"compliance: assessing {len(controls)} {framework.value} controls against {len(findings)} findings")

    statuses: List[ControlStatus] = []
    for ctrl in controls:
        status = assess_control(ctrl, findings)
        statuses.append(status)

    # Build report
    compliant = sum(1 for s in statuses if s.status == "compliant")
    partial = sum(1 for s in statuses if s.status == "partial")
    non_compliant = sum(1 for s in statuses if s.status == "non_compliant")

    report = {
        "framework": framework.value,
        "domain": domain,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "summary": {
            "total_controls": len(statuses),
            "compliant": compliant,
            "partial": partial,
            "non_compliant": non_compliant,
            "compliance_score": round(compliant / max(1, len(statuses)) * 100, 1),
        },
        "controls": [],
    }

    for s in statuses:
        ctrl_dict = s.control.to_dict()
        ctrl_dict["status"] = s.status
        ctrl_dict["impact"] = s.impact
        ctrl_dict["findings_count"] = len(s.findings_matched)
        ctrl_dict["remediation"] = s.remediation_needed
        report["controls"].append(ctrl_dict)

    # Write JSON report
    out_json = ensure(outdir / f"compliance_{framework.value}.json")
    out_json.write_text(json.dumps(report, indent=2, default=str))
    log("ok", f"compliance: {framework.value} report → {out_json}")

    # Write Markdown report
    md_path = ensure(outdir / f"compliance_{framework.value}.md")
    md_lines = [
        f"# Compliance Report — {framework.value.upper().replace('_', ' ')}",
        "",
        f"**Domain:** {domain}",
        f"**Generated:** {report['generated_at']}",
        "",
        "## Summary",
        "",
        f"| Metric | Value |",
        f"|---|---|",
        f"| Total Controls | {len(statuses)} |",
        f"| Compliant | {compliant} |",
        f"| Partial | {partial} |",
        f"| Non-Compliant | {non_compliant} |",
        f"| Compliance Score | {report['summary']['compliance_score']}% |",
        "",
        "## Control Details",
        "",
    ]

    for s in statuses:
        icon = {"compliant": "✅", "partial": "⚠️", "non_compliant": "❌"}.get(s.status, "❓")
        md_lines.append(f"### {icon} {s.control.control_id} — {s.control.title}")
        md_lines.append(f"**Status:** {s.status}")
        md_lines.append(f"**Impact:** {s.impact}")
        if s.remediation_needed:
            for r in s.remediation_needed:
                md_lines.append(f"- **Action:** {r}")
        md_lines.append("")

    md_path.write_text("\n".join(md_lines))
    log("ok", f"compliance: {framework.value} markdown → {md_path}")

    return out_json


def generate_all_compliance_reports(
    outdir: Path,
    *,
    domain: str = "",
) -> Dict[str, Path]:
    """Generate compliance reports for all supported frameworks.

    Returns:
        Dict mapping framework name to report path.
    """
    results: Dict[str, Path] = {}
    for framework in Framework:
        results[framework.value] = generate_compliance_report(
            outdir, framework, domain=domain
        )
    return results


def get_frameworks() -> List[Dict[str, Any]]:
    """Return information about all supported compliance frameworks."""
    return [
        {
            "name": f.value,
            "display_name": f.value.upper().replace("_", " "),
            "controls_count": len(ALL_CONTROLS.get(f, [])),
        }
        for f in Framework
    ]
