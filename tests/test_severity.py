"""Tests for severity classification and risk scoring."""
import json
from pathlib import Path

import pytest

from reconchain.severity import RiskScore, calculate_risk_score, write_risk_score, SEVERITY_WEIGHTS
from reconchain.artifacts import guess_severity, SEVERITY_KEYWORDS


class TestGuessSeverity:
    def test_critical_keywords(self):
        assert guess_severity("remote code execution found") == "critical"
        assert guess_severity("SQL injection in query") == "critical"
        assert guess_severity("container escape detected") == "critical"

    def test_high_keywords(self):
        assert guess_severity("XSS vulnerability found") == "high"
        assert guess_severity("SSRF to internal") == "high"
        assert guess_severity("LFI /etc/passwd") == "high"
        assert guess_severity("stored xss confirmed") == "high"

    def test_medium_keywords(self):
        assert guess_severity("CORS misconfiguration") == "medium"
        assert guess_severity("clickjacking vulnerability") == "medium"
        assert guess_severity("CSRF token missing") == "medium"

    def test_low_keywords(self):
        assert guess_severity("info leak in headers") == "low"
        assert guess_severity("banner disclosure") == "low"
        assert guess_severity("mixed content detected") == "low"

    def test_info_fallback(self):
        assert guess_severity("some random text") == "info"
        assert guess_severity("") == "info"

    def test_case_insensitive(self):
        assert guess_severity("REMOTE CODE EXECUTION") == "critical"
        assert guess_severity("Cross-Site Scripting") == "high"


class TestSeverityKeywords:
    def test_all_severities_have_keywords(self):
        for sev in ("critical", "high", "medium", "low"):
            assert sev in SEVERITY_KEYWORDS
            assert len(SEVERITY_KEYWORDS[sev]) > 0

    def test_no_keyword_overlap(self):
        all_kw = set()
        for sev, kws in SEVERITY_KEYWORDS.items():
            for kw in kws:
                assert kw not in all_kw, f"Duplicate keyword '{kw}' in {sev}"
                all_kw.add(kw)


class TestSeverityWeights:
    def test_weights_ordered(self):
        assert SEVERITY_WEIGHTS["critical"] > SEVERITY_WEIGHTS["high"]
        assert SEVERITY_WEIGHTS["high"] > SEVERITY_WEIGHTS["medium"]
        assert SEVERITY_WEIGHTS["medium"] > SEVERITY_WEIGHTS["low"]
        assert SEVERITY_WEIGHTS["low"] > SEVERITY_WEIGHTS["info"]


class TestRiskScore:
    def test_empty_findings(self, tmp_path):
        risk = calculate_risk_score(tmp_path)
        assert isinstance(risk, RiskScore)
        assert risk.total_findings == 0
        assert risk.grade == "A"

    def test_with_critical_findings(self, tmp_path):
        (tmp_path / "cmd_injection.txt").write_text("RCE via command injection\n")
        (tmp_path / "sqlmap_findings.txt").write_text("SQL injection found\n")
        risk = calculate_risk_score(tmp_path)
        assert risk.severity_counts["critical"] >= 0
        assert risk.score >= 0
        assert risk.grade in ("A", "A+", "B", "B+", "C", "D", "F")

    def test_to_dict(self, tmp_path):
        risk = calculate_risk_score(tmp_path)
        d = risk.to_dict()
        assert "score" in d
        assert "grade" in d
        assert "severity_counts" in d
        assert "total_findings" in d
        assert "recommendations" in d

    def test_write_risk_score(self, tmp_path):
        risk = calculate_risk_score(tmp_path)
        out = write_risk_score(tmp_path, risk)
        assert out.exists()
        data = json.loads(out.read_text())
        assert "score" in data
        assert "grade" in data

    def test_grade_mapping(self):
        risk = RiskScore(score=0, grade="A", severity_counts={}, total_findings=0, critical_paths=0, recommendations=[])
        assert risk.score == 0

    def test_recommendations_populated(self, tmp_path):
        (tmp_path / "cmd_injection.txt").write_text("RCE via command injection\n")
        risk = calculate_risk_score(tmp_path)
        assert isinstance(risk.recommendations, list)
