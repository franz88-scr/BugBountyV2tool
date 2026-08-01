"""Tests for vulnforge.certainty — confidence scoring of findings."""

from vulnforge.certainty import (
    Confidence,
    FindingScore,
    score_all_findings,
    score_finding,
    write_confidence_report,
)


class TestScoreFinding:
    def test_baseline_is_unverified(self):
        s = score_finding("plain text")
        assert s.confidence == Confidence.UNVERIFIED
        assert 0.4 <= s.score < 0.6

    def test_tool_reliability_raises(self):
        s = score_finding("nuclei finding", source_tool="nuclei")
        assert s.score > 0.5
        assert any("tool reliability: nuclei" in r for r in s.reasons)

    def test_high_confidence_patterns(self):
        s = score_finding("confirmed and exploitable SQLi status: 200")
        assert s.confidence == Confidence.CONFIRMED

    def test_low_confidence_patterns(self):
        s = score_finding("possible xss maybe, no results found")
        assert s.score < 0.4

    def test_cross_validated_bonus(self):
        low = score_finding("reflected xss on /search?q=1")
        high = score_finding("reflected xss on /search?q=1", cross_validated=True)
        assert high.score > low.score

    def test_response_evidence_bonus(self):
        low = score_finding("reflected param")
        high = score_finding("reflected param", has_response_evidence=True)
        assert high.score > low.score

    def test_auto_cross_tool(self, tmp_path):
        from vulnforge.artifacts import ARTIFACTS
        other = next(a for a in ARTIFACTS if a.vuln_type and a.vuln_type != "xss" and a.filename)
        text = f"https://example.com/search?q=1 param=q reflected xss"
        (tmp_path / other.filename).write_text(
            f"https://example.com/search?q=1 param=q injected\n"
        )
        s = score_finding(text, vuln_type="xss", outdir=tmp_path)
        assert any("cross-tool corroboration" in r for r in s.reasons)

    def test_auto_cross_tool_skips_same_type(self, tmp_path):
        text = "https://example.com/search?q=1 param=q reflected xss"
        other = tmp_path / "xss_findings.txt"
        other.write_text("https://example.com/search?q=1 param=q reflected\n")
        s = score_finding(text, vuln_type="xss", outdir=tmp_path)
        assert not any("cross-tool corroboration" in r for r in s.reasons)

    def test_confidence_thresholds(self):
        assert score_finding(
            "verified exploitable status: 200 response contains payload"
        ).confidence == Confidence.CONFIRMED
        assert score_finding("possible issue").score >= 0.0
        assert score_finding("confirmed vulnerable").score <= 1.0

    def test_confirmed_keyword_bonus(self):
        base = score_finding("reflected on /x?p=1")
        boosted = score_finding("reflected vulnerable on /x?p=1")
        assert boosted.score > base.score

    def test_tentative_keyword_penalty(self):
        base = score_finding("reflected on /x?p=1")
        penalized = score_finding("possible reflected on /x?p=1")
        assert penalized.score < base.score

    def test_unknown_tool_ignored(self):
        s = score_finding("x", source_tool="mysterytool")
        assert s.score == 0.5

    def test_cross_detect_no_outdir(self):
        s = score_finding("x", vuln_type="xss")
        assert s.score >= 0.0


class TestFindingScore:
    def test_to_dict(self):
        fs = FindingScore(
            finding_text="t", confidence=Confidence.LIKELY, score=0.7, reasons=["r"],
            source_tool="nuclei", vuln_type="xss",
        )
        d = fs.to_dict()
        assert d["finding"] == "t"
        assert d["confidence"] == "likely"
        assert d["score"] == 0.7
        assert d["reasons"] == ["r"]


class TestScoreAllFindings:
    def test_empty_outdir(self, tmp_path):
        assert score_all_findings(tmp_path) == []

    def test_scores_artifact_lines(self, tmp_path):
        from vulnforge.artifacts import ARTIFACTS
        target = next(a for a in ARTIFACTS if a.vuln_type and a.filename)
        (tmp_path / target.filename).write_text("possible xss in /q?x=1\n")
        scored = score_all_findings(tmp_path)
        assert len(scored) == 1
        assert scored[0].source_tool == target.display_name
        assert scored[0].vuln_type == target.vuln_type


class TestWriteConfidenceReport:
    def test_writes_json(self, tmp_path):
        fs = [FindingScore("a", Confidence.LIKELY, 0.7)]
        out = write_confidence_report(tmp_path, fs)
        assert out.exists()
        assert '"confidence": "likely"' in out.read_text()
