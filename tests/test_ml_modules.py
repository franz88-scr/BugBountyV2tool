"""Tests for ML phase selection and vulnerability classification."""

import json
from pathlib import Path

from vulnforge.ml_phase_selector import MANDATORY_PHASES, PhaseSelector, select_optimal_phases
from vulnforge.ml_vuln import VulnerabilityClassifier, classify_findings


class TestPhaseSelector:
    def test_select_optimal_phases_respects_budget(self) -> None:
        sel = select_optimal_phases({}, budget_phases=8)
        assert len(sel) == 8
        assert len(set(sel)) == len(sel)

    def test_mandatory_phases_always_included(self) -> None:
        sel = set(select_optimal_phases({}, budget_phases=3))
        assert MANDATORY_PHASES.issubset(sel)

    def test_rank_phases_respects_only(self) -> None:
        selector = PhaseSelector()
        ranked = selector.rank_phases(only_phases={"00-SCOPE", "01-RECON"})
        assert {s.phase for s in ranked} == {"00-SCOPE", "01-RECON"}

    def test_rank_phases_sorted_by_score(self) -> None:
        selector = PhaseSelector()
        ranked = selector.rank_phases()
        scores = [s.score for s in ranked]
        assert scores == sorted(scores, reverse=True)

    def test_feedback_persists(self, tmp_path: Path) -> None:
        fb = tmp_path / "feedback.json"
        selector = PhaseSelector(feedback_path=fb)
        selector.record_result("01-RECON", 5)
        selector.record_result("01-RECON", 3)
        assert selector._history["01-RECON"] == [5.0, 3.0]
        assert fb.exists()
        data = json.loads(fb.read_text())
        assert data["history"]["01-RECON"] == [5.0, 3.0]

    def test_feedback_loaded_from_disk(self, tmp_path: Path) -> None:
        fb = tmp_path / "feedback.json"
        fb.write_text(json.dumps({"history": {"24-JWT": [7.0]}}))
        selector = PhaseSelector(feedback_path=fb)
        assert selector._history["24-JWT"] == [7.0]


class TestMlVuln:
    def _findings(self, tmp_path: Path) -> Path:
        (tmp_path / "xss_findings.txt").write_text(
            "https://example.com/search?q=<script>alert(1)</script>\n"
        )
        (tmp_path / "sqlmap_findings.txt").write_text("https://example.com/?id=1 AND 1=1\n")
        return tmp_path

    def test_classify_findings(self, tmp_path: Path) -> None:
        outdir = self._findings(tmp_path)
        classified = classify_findings(outdir, min_confidence=0.0)
        assert len(classified) > 0
        assert all(c.category for c in classified)
        assert all(c.host for c in classified)

    def test_empty_outdir_returns_empty(self, tmp_path: Path) -> None:
        assert classify_findings(tmp_path, min_confidence=0.0) == []

    def test_export_classified_writes_json(self, tmp_path: Path) -> None:
        outdir = self._findings(tmp_path)
        classified = classify_findings(outdir, min_confidence=0.0)
        classifier = VulnerabilityClassifier()
        path = classifier.export_classified(classified, outdir)
        assert path.exists()
        data = json.loads(path.read_text())
        assert len(data) == len(classified)
        assert {"category", "severity", "text"} <= set(data[0])

    def test_min_confidence_filters(self, tmp_path: Path) -> None:
        outdir = self._findings(tmp_path)
        low = classify_findings(outdir, min_confidence=0.0)
        high = classify_findings(outdir, min_confidence=1.0)
        assert len(high) <= len(low)
