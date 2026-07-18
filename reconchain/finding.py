"""Structured Finding dataclass — single source of truth for vulnerability findings.

Replaces plain-text finding lines with structured objects that carry
severity, CWE, CVSS, remediation, and metadata.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from reconchain.utils import log, read_lines

# ── Auto-classification mappings ──────────────────────────────────────────────

_VULN_TYPE_CWE: Dict[str, str] = {
    "xss": "CWE-79",
    "dom_xss": "CWE-79",
    "stored_xss": "CWE-79",
    "sqli": "CWE-89",
    "nosqli": "CWE-943",
    "ssrf": "CWE-918",
    "lfi": "CWE-98",
    "rfi": "CWE-98",
    "ssti": "CWE-1336",
    "xxe": "CWE-611",
    "rce": "CWE-78",
    "cmdi": "CWE-78",
    "idor": "CWE-639",
    "auth_bypass": "CWE-287",
    "jwt": "CWE-347",
    "oauth": "CWE-269",
    "open_redirect": "CWE-601",
    "csrf": "CWE-352",
    "clickjacking": "CWE-1021",
    "crlf": "CWE-113",
    "file_upload": "CWE-434",
    "deserialization": "CWE-502",
    "ldap": "CWE-90",
    "race_condition": "CWE-362",
    "smuggle": "CWE-444",
    "cache_poison": "CWE-446",
    "cve": "CWE-1104",
    "cors": "CWE-942",
    "secrets": "CWE-798",
    "exposed_db": "CWE-200",
    "default_creds": "CWE-798",
    "takeover": "CWE-284",
    "mass_assign": "CWE-915",
    "session_fixation": "CWE-384",
    "saml": "CWE-290",
    "session": "CWE-614",
    "hpp": "CWE-235",
    "host_header": "CWE-644",
    "websocket": "CWE-346",
    "forced_browse": "CWE-284",
    "csp": "CWE-693",
    "sri": "CWE-829",
    "doc_attack": "CWE-451",
    "workflow": "CWE-670",
    "method_override": "CWE-706",
    "json_inject": "CWE-943",
    "csv_inject": "CWE-1236",
    "log_inject": "CWE-117",
    "jsonp": "CWE-346",
    "info_leak": "CWE-200",
    "serverless": "CWE-284",
    "framework": "CWE-693",
    "cloud": "CWE-538",
    "git": "CWE-538",
    "graphql": "CWE-200",
    "cicd": "CWE-538",
    "docker": "CWE-284",
    "k8s": "CWE-284",
    "terraform": "CWE-538",
    "sspp": "CWE-1321",
    "account_enum": "CWE-204",
    "password_reset": "CWE-640",
    "password_spray": "CWE-307",
    "cookie": "CWE-614",
    "api_abuse": "CWE-770",
    "tabnabbing": "CWE-1021",
    "ratelimit_bypass": "CWE-770",
    "mixed_content": "CWE-346",
    "hsts": "CWE-319",
}

_VULN_TYPE_CVSS: Dict[str, float] = {
    "rce": 9.8, "cmdi": 9.8, "sqli": 9.8, "deserialization": 9.8,
    "takeover": 9.1, "default_creds": 9.1, "exposed_db": 9.0,
    "ssrf": 8.6, "lfi": 8.6, "rfi": 8.6, "ssti": 8.6,
    "xss": 6.1, "dom_xss": 6.1, "stored_xss": 8.0,
    "idor": 5.3, "auth_bypass": 7.5, "jwt": 7.5,
    "open_redirect": 6.1, "csrf": 8.0, "crlf": 5.3,
    "file_upload": 7.2, "race_condition": 6.5, "smuggle": 7.5,
    "secrets": 7.5, "cloud": 7.5, "git": 7.5,
    "clickjacking": 4.3, "cors": 5.3, "csp": 4.3,
    "oauth": 6.5, "session_fixation": 6.8, "saml": 6.5,
    "nosqli": 7.5, "xxe": 7.5, "ldap": 7.5,
    "mass_assign": 6.5, "hpp": 4.3, "host_header": 5.3,
    "websocket": 5.3, "forced_browse": 5.3, "session": 5.3,
}

_VULN_TYPE_SEVERITY: Dict[str, str] = {
    "rce": "critical", "cmdi": "critical", "sqli": "critical",
    "takeover": "critical", "default_creds": "critical", "exposed_db": "critical",
    "deserialization": "critical", "cloud": "high", "git": "high",
    "ssrf": "high", "lfi": "high", "rfi": "high", "ssti": "high",
    "xss": "high", "dom_xss": "high", "stored_xss": "high",
    "idor": "medium", "auth_bypass": "high", "jwt": "high",
    "open_redirect": "medium", "csrf": "high", "crlf": "medium",
    "file_upload": "high", "race_condition": "high", "smuggle": "high",
    "secrets": "high", "nosqli": "high", "xxe": "high", "ldap": "high",
    "clickjacking": "medium", "cors": "medium", "csp": "low",
    "oauth": "high", "session_fixation": "medium", "saml": "medium",
    "mass_assign": "medium", "hpp": "medium", "host_header": "medium",
    "websocket": "medium", "forced_browse": "low", "session": "medium",
    "info_leak": "low", "sri": "low", "mixed_content": "low", "hsts": "low",
    "jsonp": "low", "doc_attack": "medium", "workflow": "medium",
    "method_override": "medium", "json_inject": "high",
    "csv_inject": "medium", "log_inject": "low",
    "account_enum": "medium", "password_reset": "high",
    "password_spray": "high", "cookie": "medium",
    "api_abuse": "low", "tabnabbing": "low", "ratelimit_bypass": "low",
    "serverless": "medium", "framework": "medium",
    "cicd": "high", "docker": "high", "k8s": "high", "terraform": "high",
    "graphql": "high", "sspp": "high",
    "cache_poison": "medium", "cve": "high",
}


@dataclass
class Finding:
    """A single structured vulnerability finding."""
    id: str
    phase: str
    vuln_type: str
    severity: str
    confidence: float
    title: str
    evidence: str
    url: Optional[str] = None
    host: Optional[str] = None
    cwe: Optional[str] = None
    cvss: Optional[float] = None
    remediation: Optional[str] = None
    tool: Optional[str] = None
    timestamp: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None and v != "" and v != {}}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> Finding:
        return cls(
            id=d.get("id", ""),
            phase=d.get("phase", ""),
            vuln_type=d.get("vuln_type", ""),
            severity=d.get("severity", "info"),
            confidence=float(d.get("confidence", 0.5)),
            title=d.get("title", ""),
            evidence=d.get("evidence", ""),
            url=d.get("url"),
            host=d.get("host"),
            cwe=d.get("cwe"),
            cvss=d.get("cvss"),
            remediation=d.get("remediation"),
            tool=d.get("tool"),
            timestamp=d.get("timestamp"),
            metadata=d.get("metadata", {}),
        )

    def auto_cwe(self) -> str:
        return _VULN_TYPE_CWE.get(self.vuln_type, "CWE-0")

    def auto_severity(self) -> str:
        return _VULN_TYPE_SEVERITY.get(self.vuln_type, "info")

    def auto_cvss(self) -> float:
        return _VULN_TYPE_CVSS.get(self.vuln_type, 0.0)

    def ensure_classified(self) -> Finding:
        if not self.cwe:
            self.cwe = self.auto_cwe()
        if self.severity == "info" and self.vuln_type:
            self.severity = self.auto_severity()
        if self.cvss is None and self.vuln_type:
            self.cvss = self.auto_cvss()
        return self


def _generate_finding_id(phase: str, evidence: str) -> str:
    raw = f"{evidence[:120]}"
    h = hashlib.md5(raw.encode()).hexdigest()[:8]
    return f"RC-{h}"


def _extract_url(evidence: str) -> Optional[str]:
    m = re.search(r'https?://[^\s,;]+', evidence)
    return m.group(0) if m else None


def _extract_host(url: Optional[str]) -> Optional[str]:
    if not url:
        return None
    from urllib.parse import urlparse
    try:
        return urlparse(url).hostname
    except Exception:
        return None


def finding_from_text(text: str, phase: str, vuln_type: str = "",
                      tool: str = "", severity: str = "") -> Finding:
    """Parse a plain-text finding line into a structured Finding."""
    text = text.strip()
    if not text:
        return Finding(
            id="", phase=phase, vuln_type="", severity="info",
            confidence=0.0, title="", evidence="",
        )

    url = _extract_url(text)
    host = _extract_host(url)

    fv = vuln_type or _guess_vuln_type(text)
    sev = severity or _VULN_TYPE_SEVERITY.get(fv, "info")
    cwe = _VULN_TYPE_CWE.get(fv, "CWE-0")
    cvss = _VULN_TYPE_CVSS.get(fv, 0.0)

    title = text[:120]
    fid = _generate_finding_id(phase, text)

    return Finding(
        id=fid,
        phase=phase,
        vuln_type=fv,
        severity=sev,
        confidence=0.7 if fv else 0.3,
        title=title,
        evidence=text,
        url=url,
        host=host,
        cwe=cwe,
        cvss=cvss,
        tool=tool or None,
    )


def _guess_vuln_type(text: str) -> str:
    lower = text.lower()
    if any(kw in lower for kw in ("xss", "cross-site scripting", "dom xss")):
        return "xss" if "stored" not in lower else "stored_xss"
    if any(kw in lower for kw in ("sql injection", "sqli", "sqlmap")):
        return "sqli"
    if any(kw in lower for kw in ("ssrf", "server-side request forgery")):
        return "ssrf"
    if any(kw in lower for kw in ("lfi", "local file inclusion", "path traversal", "../")):
        return "lfi"
    if any(kw in lower for kw in ("rce", "remote code execution", "command injection", "cmdi")):
        return "rce"
    if any(kw in lower for kw in ("ssti", "template injection")):
        return "ssti"
    if any(kw in lower for kw in ("idor", "insecure direct")):
        return "idor"
    if any(kw in lower for kw in ("open redirect", "redirect")):
        return "open_redirect"
    if any(kw in lower for kw in ("csrf", "cross-site request")):
        return "csrf"
    if any(kw in lower for kw in ("clickjack", "click jacking", "ui redress")):
        return "clickjacking"
    if any(kw in lower for kw in ("cors misconfiguration", "cors ")):
        return "cors"
    if any(kw in lower for kw in ("jwt", "json web token")):
        return "jwt"
    if any(kw in lower for kw in ("oauth",)):
        return "oauth"
    if any(kw in lower for kw in ("xxe", "xml external")):
        return "xxe"
    if any(kw in lower for kw in ("nosql", "mongodb injection")):
        return "nosqli"
    if any(kw in lower for kw in ("crlf", "crlf injection")):
        return "crlf"
    if any(kw in lower for kw in ("file upload", "unrestricted upload")):
        return "file_upload"
    if any(kw in lower for kw in ("deserial", "unsafe deserialization")):
        return "deserialization"
    if any(kw in lower for kw in ("race condition", "race-condition")):
        return "race_condition"
    if any(kw in lower for kw in ("smuggling", "request smuggling", "cl.te", "te.cl")):
        return "smuggle"
    if any(kw in lower for kw in ("cache poison", "cache poisoning")):
        return "cache_poison"
    if any(kw in lower for kw in ("secret", "api key", "token leak", "credential")):
        return "secrets"
    if any(kw in lower for kw in ("s3 bucket", "azure blob", "gcs bucket", "cloud storage")):
        return "cloud"
    if any(kw in lower for kw in ("git exposure", ".git")):
        return "git"
    if any(kw in lower for kw in ("graphql",)):
        return "graphql"
    if any(kw in lower for kw in ("default cred", "default password")):
        return "default_creds"
    if any(kw in lower for kw in ("exposed database", "open database", "mongodb exposed")):
        return "exposed_db"
    if any(kw in lower for kw in ("takeover", "subdomain takeover")):
        return "takeover"
    if any(kw in lower for kw in ("mass assign", "mass assignment")):
        return "mass_assign"
    if any(kw in lower for kw in ("session fixation",)):
        return "session_fixation"
    if any(kw in lower for kw in ("ldap injection", "ldap")):
        return "ldap"
    if any(kw in lower for kw in ("prototype pollution", "sspp")):
        return "sspp"
    if any(kw in lower for kw in ("csv injection", "csv formula")):
        return "csv_inject"
    if any(kw in lower for kw in ("log injection", "log forge")):
        return "log_inject"
    if any(kw in lower for kw in ("cve-", "vulnerability")):
        return "cve"
    return ""


class FindingStore:
    """Load, deduplicate, and query all findings from an output directory."""

    def __init__(self, outdir: Path):
        self.outdir = outdir
        self._findings: Optional[List[Finding]] = None

    def load(self) -> List[Finding]:
        if self._findings is not None:
            return self._findings
        from reconchain.artifacts import ARTIFACTS, guess_severity
        findings: List[Finding] = []
        seen: set = set()
        for art in ARTIFACTS:
            if not art.vuln_type:
                continue
            p = self.outdir / art.filename
            if not p.exists():
                continue
            for line in read_lines(p):
                text = line.strip()
                if not text or text.startswith("[result]"):
                    continue
                fid = _generate_finding_id(art.phase, text)
                if fid in seen:
                    continue
                seen.add(fid)
                f = finding_from_text(
                    text, phase=art.phase, vuln_type=art.vuln_type,
                    tool=art.key, severity=guess_severity(text),
                )
                findings.append(f)
        self._findings = findings
        return findings

    def by_severity(self) -> Dict[str, List[Finding]]:
        result: Dict[str, List[Finding]] = {
            "critical": [], "high": [], "medium": [], "low": [], "info": [],
        }
        for f in self.load():
            bucket = result.get(f.severity)
            if bucket is None:
                bucket = result.setdefault(f.severity, [])
            bucket.append(f)
            result.setdefault(f.severity, []).append(f)
        return result

    def by_phase(self) -> Dict[str, List[Finding]]:
        result: Dict[str, List[Finding]] = {}
        for f in self.load():
            result.setdefault(f.phase, []).append(f)
        return result

    def by_vuln_type(self) -> Dict[str, List[Finding]]:
        result: Dict[str, List[Finding]] = {}
        for f in self.load():
            result.setdefault(f.vuln_type, []).append(f)
        return result

    def filter(self, severity: str = "", phase: str = "",
               vuln_type: str = "", host: str = "") -> List[Finding]:
        results = self.load()
        if severity:
            results = [f for f in results if f.severity == severity]
        if phase:
            results = [f for f in results if f.phase == phase]
        if vuln_type:
            results = [f for f in results if f.vuln_type == vuln_type]
        if host:
            results = [f for f in results if f.host == host]
        return results

    def to_json(self) -> str:
        return json.dumps([f.to_dict() for f in self.load()], indent=2, default=str)

    def save_json(self, path: Optional[Path] = None) -> Path:
        out = path or (self.outdir / "findings_structured.json")
        import tempfile, os as _os
        fd, tmp_path = tempfile.mkstemp(dir=str(out.parent), suffix=".tmp")
        try:
            with _os.fdopen(fd, "w") as f:
                json.dump([f.to_dict() for f in self.load()], f, indent=2, default=str)
                f.flush()
                _os.fsync(f.fileno())
            _os.replace(tmp_path, str(out))
        except Exception:
            import contextlib
            with contextlib.suppress(Exception):
                _os.unlink(tmp_path)
            raise
        return out
