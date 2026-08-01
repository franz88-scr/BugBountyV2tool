"""Crash-guard invariants for the core DAG configuration.

These are the cheapest tests that protect a running scan: if a phase set
drifts out of sync with the pipeline registry, the DAG executor breaks.
"""

from vulnforge.config import (
    DOS_PHASES,
    FAST_PHASES,
    QUICK_SKIP_PHASES,
    VALID_PHASES,
)
from vulnforge.phases import PIPELINE


class TestPhaseSetInvariants:
    def test_fast_phases_are_valid(self) -> None:
        assert FAST_PHASES <= VALID_PHASES

    def test_dos_phases_are_valid(self) -> None:
        assert DOS_PHASES <= VALID_PHASES

    def test_quick_skip_phases_are_valid(self) -> None:
        assert QUICK_SKIP_PHASES <= VALID_PHASES

    def test_discovery_phases_are_valid(self) -> None:
        from vulnforge.config import DISCOVERY_PHASES

        assert DISCOVERY_PHASES <= VALID_PHASES

    def test_fast_and_dos_are_disjoint(self) -> None:
        assert FAST_PHASES.isdisjoint(DOS_PHASES)

    def test_fast_phases_exist_in_pipeline(self) -> None:
        pipeline_ids = {p[0] for p in PIPELINE}
        assert FAST_PHASES <= pipeline_ids

    def test_pipeline_phase_names_unique(self) -> None:
        names = [p[0] for p in PIPELINE]
        assert len(names) == len(set(names))

    def test_valid_phases_match_pipeline(self) -> None:
        assert set(VALID_PHASES) == {p[0] for p in PIPELINE}

    def test_phase_number_prefixes_unique(self) -> None:
        prefixes = [p.split("-", 1)[0] for p in VALID_PHASES]
        assert len(prefixes) == len(set(prefixes))

    def test_pipeline_entries_are_triples(self) -> None:
        for name, func, params in PIPELINE:
            assert isinstance(name, str)
            assert callable(func)
            assert isinstance(params, tuple)
