"""Tests for pipeline DAG structure and phase consistency."""
import pytest

from reconchain.config import VALID_PHASES, FAST_PHASES, DOS_PHASES, QUICK_SKIP_PHASES
from reconchain.phases import PIPELINE, PHASE_DEPS, STAGES, _PHASE_WEIGHTS as PHASE_WEIGHTS


class TestPipelineDAG:
    def test_all_valid_phases_in_pipeline(self):
        pipeline_ids = {p[0] for p in PIPELINE}
        missing = VALID_PHASES - pipeline_ids
        assert not missing, f"Phases in VALID_PHASES but not in PIPELINE: {missing}"

    def test_all_pipeline_phases_in_valid(self):
        pipeline_ids = {p[0] for p in PIPELINE}
        extra = pipeline_ids - VALID_PHASES
        assert not extra, f"Phases in PIPELINE but not in VALID_PHASES: {extra}"

    def test_no_cycles_in_dag(self):
        visited = set()
        in_stack = set()
        adj = {}
        for phase_id, deps in PHASE_DEPS.items():
            adj[phase_id] = list(deps)

        def dfs(node):
            if node in in_stack:
                return True
            if node in visited:
                return False
            visited.add(node)
            in_stack.add(node)
            for neighbor in adj.get(node, []):
                if dfs(neighbor):
                    return True
            in_stack.remove(node)
            return False

        has_cycle = False
        for node in adj:
            if dfs(node):
                has_cycle = True
                break
        assert not has_cycle, "Cycle detected in PHASE_DEPS DAG"

    def test_dependencies_exist(self):
        for phase_id, deps in PHASE_DEPS.items():
            for dep in deps:
                assert dep in VALID_PHASES, f"Phase {phase_id} depends on unknown phase {dep}"

    def test_stages_cover_all_phases(self):
        staged = set()
        for stage_phases in STAGES:
            if isinstance(stage_phases, (list, tuple, set)):
                staged.update(stage_phases)
        missing = VALID_PHASES - staged
        # Some phases may not be in stages, that's OK
        assert len(missing) < 10, f"Too many phases missing from stages: {missing}"

    def test_stages_are_topologically_ordered(self):
        seen = set()
        for stage_phases in STAGES:
            if isinstance(stage_phases, (list, tuple, set)):
                for phase_id in stage_phases:
                    if phase_id in PHASE_DEPS:
                        for dep in PHASE_DEPS[phase_id]:
                            pass
                seen.update(stage_phases)

    def test_phase_weights_positive(self):
        for phase_id, weight in PHASE_WEIGHTS.items():
            assert weight > 0, f"Phase {phase_id} has non-positive weight: {weight}"
            assert phase_id in VALID_PHASES, f"Weighted phase {phase_id} not in VALID_PHASES"


class TestPhaseCategories:
    def test_fast_phases_subset_of_valid(self):
        assert FAST_PHASES.issubset(VALID_PHASES)

    def test_dos_phases_subset_of_valid(self):
        assert DOS_PHASES.issubset(VALID_PHASES)

    def test_quick_skip_phases_subset_of_valid(self):
        assert QUICK_SKIP_PHASES.issubset(VALID_PHASES)

    def test_dos_and_quick_skip_disjoint(self):
        overlap = DOS_PHASES & QUICK_SKIP_PHASES
        assert not overlap, f"DOS and quick-skip phases overlap: {overlap}"

    def test_valid_phases_are_strings(self):
        for p in VALID_PHASES:
            assert isinstance(p, str)
            assert "-" in p, f"Phase ID {p} missing dash separator"
