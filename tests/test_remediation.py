"""Tests for the remediation module."""
import pytest

from reconchain.remediation import (
    REMEDIATIONS,
    Remediation,
    get_remediation,
    get_all_remediations,
    get_remediation_text,
    has_remediation,
)


class TestRemediationData:
    def test_all_remediations_have_cwe(self):
        for vt, r in REMEDIATIONS.items():
            assert r.cwe.startswith("CWE-"), f"{vt} missing CWE"
            assert r.title, f"{vt} missing title"
            assert r.description, f"{vt} missing description"
            assert r.remediation, f"{vt} missing remediation"

    def test_all_severities_valid(self):
        valid = {"critical", "high", "medium", "low", "info"}
        for vt, r in REMEDIATIONS.items():
            assert r.severity in valid, f"{vt} has invalid severity: {r.severity}"

    def test_all_have_references(self):
        for vt, r in REMEDIATIONS.items():
            assert isinstance(r.references, list), f"{vt} references not a list"

    def test_critical_vulns_have_urgent_remediation(self):
        for vt, r in REMEDIATIONS.items():
            if r.severity == "critical":
                assert len(r.remediation) > 50, f"{vt} critical vuln has short remediation"


class TestRemediationLookup:
    def test_get_remediation_xss(self):
        r = get_remediation("xss")
        assert r is not None
        assert r.cwe == "CWE-79"
        assert "XSS" in r.title

    def test_get_remediation_sqli(self):
        r = get_remediation("sqli")
        assert r is not None
        assert r.cwe == "CWE-89"

    def test_get_remediation_unknown(self):
        assert get_remediation("nonexistent_vuln") is None

    def test_get_all_remediations(self):
        all_rem = get_all_remediations()
        assert isinstance(all_rem, dict)
        assert len(all_rem) > 20
        assert "xss" in all_rem
        assert "sqli" in all_rem

    def test_get_remediation_text_known(self):
        text = get_remediation_text("xss")
        assert "CWE-79" in text
        assert "Cross-Site Scripting" in text
        assert "Encode" in text

    def test_get_remediation_text_unknown(self):
        text = get_remediation_text("unknown")
        assert "No specific remediation" in text

    def test_has_remediation(self):
        assert has_remediation("xss") is True
        assert has_remediation("sqli") is True
        assert has_remediation("nonexistent") is False

    def test_common_vuln_types_have_remediations(self):
        common = ["xss", "sqli", "ssrf", "lfi", "rce", "ssti", "xxe",
                   "idor", "auth_bypass", "jwt", "csrf", "open_redirect",
                   "clickjacking", "crlf", "file_upload", "deserialization",
                   "race_condition", "smuggle", "cors", "secrets",
                   "exposed_db", "default_creds", "takeover", "mass_assign",
                   "sspp"]
        for vt in common:
            assert has_remediation(vt), f"{vt} missing remediation"
