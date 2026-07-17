"""Tests for the Finding dataclass and FindingStore."""
import json
from pathlib import Path

import pytest

from reconchain.finding import (
    Finding,
    FindingStore,
    _generate_finding_id,
    _guess_vuln_type,
    _extract_url,
    finding_from_text,
    _VULN_TYPE_CWE,
    _VULN_TYPE_SEVERITY,
    _VULN_TYPE_CVSS,
)


class TestFindingDataclass:
    def test_creation_minimal(self):
        f = Finding(id="RC-001", phase="11-INJECT", vuln_type="xss", severity="high",
                     confidence=0.8, title="XSS in search", evidence="<script>alert(1)</script>")
        assert f.id == "RC-001"
        assert f.phase == "11-INJECT"
        assert f.vuln_type == "xss"
        assert f.severity == "high"
        assert f.confidence == 0.8
        assert f.url is None
        assert f.cwe is None
        assert f.metadata == {}

    def test_creation_full(self):
        f = Finding(
            id="RC-002", phase="11b-SQLMAP", vuln_type="sqli", severity="critical",
            confidence=0.95, title="SQLi in login", evidence="UNION SELECT",
            url="https://example.com/login", host="example.com",
            cwe="CWE-89", cvss=9.8, remediation="Use parameterized queries",
            tool="sqlmap", timestamp="2025-01-01T00:00:00",
            metadata={"method": "POST", "parameter": "username"},
        )
        assert f.url == "https://example.com/login"
        assert f.host == "example.com"
        assert f.cwe == "CWE-89"
        assert f.cvss == 9.8
        assert f.tool == "sqlmap"
        assert f.metadata["method"] == "POST"

    def test_to_dict(self):
        f = Finding(id="RC-003", phase="09-VULNSCAN", vuln_type="rce", severity="critical",
                     confidence=1.0, title="RCE", evidence="bash -i", url="http://x.com")
        d = f.to_dict()
        assert d["id"] == "RC-003"
        assert d["url"] == "http://x.com"
        assert "metadata" not in d or d["metadata"] == {}
        assert "timestamp" not in d

    def test_to_dict_strips_none(self):
        f = Finding(id="RC-004", phase="test", vuln_type="", severity="info",
                     confidence=0.0, title="t", evidence="e")
        d = f.to_dict()
        assert "url" not in d
        assert "cwe" not in d
        assert "cvss" not in d

    def test_from_dict_roundtrip(self):
        f1 = Finding(id="RC-005", phase="24-JWT", vuln_type="jwt", severity="high",
                      confidence=0.85, title="Weak JWT", evidence="none algorithm",
                      url="https://api.example.com", host="api.example.com",
                      cwe="CWE-347", cvss=7.5, tool="jwt_tool")
        d = f1.to_dict()
        f2 = Finding.from_dict(d)
        assert f2.id == f1.id
        assert f2.phase == f1.phase
        assert f2.vuln_type == f1.vuln_type
        assert f2.severity == f1.severity
        assert f2.confidence == f1.confidence
        assert f2.cwe == f1.cwe

    def test_auto_cwe(self):
        f = Finding(id="x", phase="x", vuln_type="xss", severity="info",
                     confidence=0.5, title="x", evidence="x")
        assert f.auto_cwe() == "CWE-79"

    def test_auto_severity(self):
        f = Finding(id="x", phase="x", vuln_type="rce", severity="info",
                     confidence=0.5, title="x", evidence="x")
        assert f.auto_severity() == "critical"

    def test_auto_cvss(self):
        f = Finding(id="x", phase="x", vuln_type="sqli", severity="info",
                     confidence=0.5, title="x", evidence="x")
        assert f.auto_cvss() == 9.8

    def test_ensure_classified(self):
        f = Finding(id="x", phase="x", vuln_type="xss", severity="info",
                     confidence=0.5, title="x", evidence="x")
        f.ensure_classified()
        assert f.cwe == "CWE-79"
        assert f.severity == "high"
        assert f.cvss == 6.1

    def test_unknown_vuln_type(self):
        f = Finding(id="x", phase="x", vuln_type="unknown_vuln", severity="info",
                     confidence=0.5, title="x", evidence="x")
        assert f.auto_cwe() == "CWE-0"
        assert f.auto_severity() == "info"
        assert f.auto_cvss() == 0.0


class TestFindingHelpers:
    def test_generate_finding_id_deterministic(self):
        id1 = _generate_finding_id("11-INJECT", "xss at /search")
        id2 = _generate_finding_id("11-INJECT", "xss at /search")
        assert id1 == id2

    def test_generate_finding_id_different_for_different_input(self):
        id1 = _generate_finding_id("11-INJECT", "xss at /search")
        id2 = _generate_finding_id("11-INJECT", "sqli at /login")
        assert id1 != id2

    def test_extract_url(self):
        assert _extract_url("found xss at https://example.com/path?q=1") == "https://example.com/path?q=1"
        assert _extract_url("no url here") is None
        assert _extract_url("http://test.com") == "http://test.com"

    def test_guess_vuln_type_xss(self):
        assert _guess_vuln_type("Reflected XSS found in /search") == "xss"

    def test_guess_vuln_type_sqli(self):
        assert _guess_vuln_type("SQL injection in login parameter") == "sqli"

    def test_guess_vuln_type_ssrf(self):
        assert _guess_vuln_type("SSRF to http://169.254.169.254") == "ssrf"

    def test_guess_vuln_type_lfi(self):
        assert _guess_vuln_type("LFI: /etc/passwd leaked") == "lfi"

    def test_guess_vuln_type_rce(self):
        assert _guess_vuln_type("Remote code execution via command injection") == "rce"

    def test_guess_vuln_type_jwt(self):
        assert _guess_vuln_type("JWT none algorithm accepted") == "jwt"

    def test_guess_vuln_type_empty(self):
        assert _guess_vuln_type("") == ""
        assert _guess_vuln_type("some random text") == ""

    def test_finding_from_text(self):
        f = finding_from_text(
            "XSS at https://example.com/search?q=test",
            phase="11-INJECT", vuln_type="xss",
        )
        assert f.vuln_type == "xss"
        assert f.phase == "11-INJECT"
        assert f.url == "https://example.com/search?q=test"
        assert f.host == "example.com"
        assert f.severity == "high"
        assert f.cwe == "CWE-79"

    def test_finding_from_text_empty(self):
        f = finding_from_text("", phase="test")
        assert f.evidence == ""
        assert f.severity == "info"


class TestFindingCWE:
    def test_all_common_types_have_cwe(self):
        common = ["xss", "sqli", "ssrf", "lfi", "rce", "ssti", "xxe",
                   "idor", "auth_bypass", "jwt", "csrf", "open_redirect",
                   "clickjacking", "crlf", "file_upload", "deserialization",
                   "race_condition", "smuggle", "cors", "secrets",
                   "exposed_db", "default_creds", "takeover", "nosqli",
                   "ldap", "sspp"]
        for vt in common:
            assert vt in _VULN_TYPE_CWE, f"{vt} missing CWE mapping"
            assert _VULN_TYPE_CWE[vt].startswith("CWE-")

    def test_all_common_types_have_severity(self):
        for vt in _VULN_TYPE_CWE:
            assert vt in _VULN_TYPE_SEVERITY, f"{vt} missing severity mapping"
            assert _VULN_TYPE_SEVERITY[vt] in ("critical", "high", "medium", "low", "info")

    def test_all_common_types_have_cvss(self):
        for vt in ["rce", "sqli", "xss", "idor", "csrf", "clickjacking"]:
            assert vt in _VULN_TYPE_CVSS, f"{vt} missing CVSS mapping"
            assert 0.0 <= _VULN_TYPE_CVSS[vt] <= 10.0


class TestFindingStore:
    def test_empty_outdir(self, tmp_path):
        store = FindingStore(tmp_path)
        findings = store.load()
        assert findings == []

    def test_with_findings(self, tmp_path):
        (tmp_path / "xss_findings.txt").write_text(
            "XSS at https://example.com/search\n"
            "DOM XSS in /api\n"
            "\n"
        )
        store = FindingStore(tmp_path)
        findings = store.load()
        assert len(findings) >= 1

    def test_by_severity(self, tmp_path):
        (tmp_path / "xss_findings.txt").write_text("XSS at /search\n")
        store = FindingStore(tmp_path)
        by_sev = store.by_severity()
        assert isinstance(by_sev, dict)
        assert "critical" in by_sev
        assert "high" in by_sev

    def test_filter(self, tmp_path):
        (tmp_path / "xss_findings.txt").write_text("XSS at /search\n")
        store = FindingStore(tmp_path)
        store.load()
        # Filter by severity
        high = store.filter(severity="high")
        assert isinstance(high, list)

    def test_save_json(self, tmp_path):
        (tmp_path / "xss_findings.txt").write_text("XSS at /search\n")
        store = FindingStore(tmp_path)
        store.load()
        out = store.save_json(tmp_path / "structured.json")
        assert out.exists()
        data = json.loads(out.read_text())
        assert isinstance(data, list)

    def test_to_json(self, tmp_path):
        store = FindingStore(tmp_path)
        j = store.to_json()
        assert json.loads(j) == []
