"""Tests for the threat intelligence module."""
import json
from pathlib import Path

import pytest

from vulnforge.threat_intel import (
    ATTACK_TECHNIQUES,
    ThreatFeed,
    ThreatIntelEngine,
    TechniqueMatch,
    _map_findings_to_techniques,
    map_to_mitre,
)


class TestMapToMitre:
    def test_empty_outdir_returns_empty(self, tmp_path: Path) -> None:
        assert map_to_mitre(tmp_path) == []

    def test_no_findings_returns_empty(self) -> None:
        assert _map_findings_to_techniques([]) == []

    def test_known_finding_maps_to_technique(self) -> None:
        findings = [
            {"text": "XSS on /search", "category": "xss", "severity": "high"},
        ]
        result = _map_findings_to_techniques(findings, min_confidence=0.0)
        assert len(result) >= 1
        matched = [r for r in result if r["technique_id"] == "T1190"]
        assert len(matched) == 1
        assert matched[0]["tactic"] == "Initial Access"

    def test_below_confidence_filtered(self) -> None:
        findings = [
            {"text": "low info finding", "category": "xss", "severity": "info"},
        ]
        result = _map_findings_to_techniques(findings, min_confidence=0.9)
        assert result == []

    def test_classified_vulns_json(self, tmp_path: Path) -> None:
        cv = tmp_path / "classified_vulns.json"
        cv.write_text(json.dumps([
            {"text": "SQLi on /login", "category": "sqli", "severity": "critical"},
        ]))
        result = map_to_mitre(tmp_path, min_confidence=0.0)
        t1190_matches = [r for r in result if r["technique_id"] == "T1190"]
        assert len(t1190_matches) >= 1

    def test_technique_match_to_dict(self) -> None:
        tm = TechniqueMatch(
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            tactic="Initial Access",
            matched_findings=[{"text": "test finding", "severity": "high"}],
            confidence=0.8,
            risk_level="high",
        )
        d = tm.to_dict()
        assert d["technique_id"] == "T1190"
        assert d["matched_findings_count"] == 1
        assert d["confidence"] == 0.8


class TestThreatIntelEngine:
    def test_init_empty(self) -> None:
        engine = ThreatIntelEngine()
        assert engine.check_indicator("1.2.3.4") is None
        assert engine.check_findings(Path("/nonexistent")) == []

    def test_load_feeds_nonexistent_path(self) -> None:
        engine = ThreatIntelEngine()
        n = engine.load_feeds(Path("/nonexistent/feeds.json"))
        assert n == 0

    def test_load_feeds_and_check_indicator(self, tmp_path: Path) -> None:
        feed_file = tmp_path / "feeds.json"
        feed_file.write_text(json.dumps({
            "feeds": [
                {
                    "source": "test",
                    "indicator": "evil.com",
                    "indicator_type": "domain",
                    "confidence": 0.9,
                    "tags": ["malware"],
                },
                {
                    "source": "test",
                    "indicator": "5.6.7.8",
                    "indicator_type": "ip",
                    "confidence": 0.8,
                    "tags": ["c2"],
                },
            ],
        }))
        engine = ThreatIntelEngine()
        assert engine.load_feeds(feed_file) == 2

        match = engine.check_indicator("evil.com")
        assert match is not None
        assert match.indicator_type == "domain"
        assert 0.9 == match.confidence

        assert engine.check_indicator("unknown.com") is None

    def test_check_findings_matches_indicator_ip(self, tmp_path: Path) -> None:
        feed_file = tmp_path / "feeds.json"
        feed_file.write_text(json.dumps({
            "feeds": [{"source": "test", "indicator": "1.2.3.4", "indicator_type": "ip", "confidence": 0.8}],
        }))
        cv = tmp_path / "classified_vulns.json"
        cv.write_text(json.dumps([
            {"text": "Server at 1.2.3.4 has open port", "category": "port_scan", "severity": "medium"},
        ]))
        engine = ThreatIntelEngine()
        engine.load_feeds(feed_file)
        matches = engine.check_findings(tmp_path)
        assert len(matches) >= 1
        assert matches[0]["indicator"] == "1.2.3.4"

    def test_generate_report(self, tmp_path: Path) -> None:
        engine = ThreatIntelEngine()
        report_path = engine.generate_report(tmp_path, domain="example.com")
        assert report_path.exists()
        data = json.loads(report_path.read_text())
        assert data["domain"] == "example.com"
        assert "mitre_attack_mapping" in data
        assert "summary" in data


class TestAttackTechniquesData:
    def test_all_techniques_have_required_fields(self) -> None:
        for t in ATTACK_TECHNIQUES:
            assert t["technique_id"], f"Missing technique_id"
            assert t["technique_name"], f"{t['technique_id']} missing name"
            assert t["tactic"], f"{t['technique_id']} missing tactic"
            assert t["finding_types"], f"{t['technique_id']} missing finding_types"
            assert t["severity_threshold"] in ("critical", "high", "medium", "low", "info"), \
                f"{t['technique_id']} invalid severity"

    def test_technique_ids_unique(self) -> None:
        ids = [t["technique_id"] for t in ATTACK_TECHNIQUES]
        assert len(ids) == len(set(ids))


class TestThreatFeedData:
    def test_to_dict(self) -> None:
        tf = ThreatFeed(
            source="test",
            indicator="evil.com",
            indicator_type="domain",
            confidence=0.9,
            tags=["malware", "c2"],
            first_seen="2024-01-01",
            last_seen="2024-06-01",
            description="Test indicator",
        )
        d = tf.to_dict()
        assert d["indicator"] == "evil.com"
        assert d["indicator_type"] == "domain"
        assert "malware" in d["tags"]
