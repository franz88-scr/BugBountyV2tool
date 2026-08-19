"""Phase/stage count consistency: code-derived numbers must match claims."""
from pathlib import Path

from vulnforge.config import VALID_PHASES
from vulnforge.phases import NUM_PHASES, NUM_STAGES, PIPELINE, STAGES, _RECON_LEVELS

README = Path(__file__).resolve().parent.parent / "README.md"


class TestPhaseCounts:
    def test_valid_phases_matches_pipeline(self):
        pipeline_names = {entry[0] for entry in PIPELINE}
        assert VALID_PHASES == pipeline_names

    def test_pipeline_matches_stages(self):
        staged = {p for stage in STAGES for p in stage}
        pipeline_names = {entry[0] for entry in PIPELINE}
        assert staged == pipeline_names

    def test_num_phases_derived(self):
        assert NUM_PHASES == len(PIPELINE) == len(VALID_PHASES) == 213

    def test_num_stages_derived(self):
        assert NUM_STAGES == len(STAGES) == 45

    def test_full_recon_level_uses_all_phases(self):
        assert len(_RECON_LEVELS["full"]["phases"]) == NUM_PHASES
        assert f"All {NUM_PHASES} phases" in _RECON_LEVELS["full"]["desc"]
        assert "185 phases" not in _RECON_LEVELS["full"]["desc"]

    def test_readme_counts_match_code(self):
        text = README.read_text(encoding="utf-8")
        assert f"{NUM_PHASES} phases" in text
        assert f"{NUM_STAGES} DAG stage" in text
