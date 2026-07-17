"""Basic tests for ReconChain configuration."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from reconchain.config import VALID_PHASES, __version__
from reconchain.phases import PIPELINE, PHASE_DEPS, STAGES
from reconchain.conf import load_config, apply_config_to_args


def test_version():
    """Test that version is set correctly."""
    assert __version__ == "2.0.0"


def test_valid_phases():
    """Test that VALID_PHASES contains expected phases."""
    assert "00-SCOPE" in VALID_PHASES
    assert "01-RECON" in VALID_PHASES
    assert "148-GRPCURL" in VALID_PHASES
    assert len(VALID_PHASES) >= 137


def test_pipeline():
    """Test that PIPELINE is a valid list of phases."""
    assert isinstance(PIPELINE, list)
    assert len(PIPELINE) > 0
    for phase_name, phase_func, params in PIPELINE:
        assert phase_name in VALID_PHASES
        assert callable(phase_func)


def test_phase_deps():
    """Test that PHASE_DEPS covers all phases."""
    for phase_name, _, _ in PIPELINE:
        assert phase_name in PHASE_DEPS, f"Missing PHASE_DEPS for {phase_name}"


def test_stages():
    """Test that STAGES contains all phases."""
    all_staged = set()
    for stage in STAGES:
        all_staged.update(stage)
    for phase_name, _, _ in PIPELINE:
        assert phase_name in all_staged, f"Missing STAGES for {phase_name}"


def test_config_loading():
    """Test config loading with empty config."""
    # load_config() with no args should work (finds default config or empty)
    result = load_config()
    assert result is not None or result is None  # Just shouldn't crash


if __name__ == "__main__":
    test_version()
    test_valid_phases()
    test_pipeline()
    test_phase_deps()
    test_stages()
    test_config_loading()
    print("All tests passed!")
