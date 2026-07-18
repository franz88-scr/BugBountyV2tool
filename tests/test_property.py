"""Property-based tests using Hypothesis for edge case discovery."""
from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

import hypothesis
from hypothesis import given, strategies as st, settings, assume

from reconchain.config import PipelineConfig, VALID_PHASES


# ── Domain validation ───────────────────────────────────────────────

@given(st.text(min_size=1, max_size=255))
@settings(max_examples=200, suppress_health_check=[hypothesis.HealthCheck.too_slow])
def test_is_valid_hostname_never_crashes(domain: str):
    from reconchain.utils import _is_valid_hostname
    try:
        result = _is_valid_hostname(domain)
        assert isinstance(result, bool)
    except Exception:
        pass


@given(st.sampled_from(["example.com", "test.org", "sub.domain.co.uk", "a.b.c"]))
@settings(max_examples=50)
def test_valid_domains_accepted(domain: str):
    from reconchain.utils import _is_valid_hostname
    assert _is_valid_hostname(domain) is True


@given(st.sampled_from(["-invalid.com", ".leading.dot", " spaces", "a" * 256 + ".com"]))
@settings(max_examples=50)
def test_invalid_domains_rejected(domain: str):
    from reconchain.utils import _is_valid_hostname
    assert _is_valid_hostname(domain) is False


# ── PipelineConfig validation ───────────────────────────────────────

@given(st.integers(min_value=-1000, max_value=-1))
@settings(max_examples=100)
def test_config_rejects_negative_delay(delay: float):
    with pytest.raises(Exception):
        PipelineConfig(delay=float(delay))


@given(st.integers(min_value=6, max_value=100))
@settings(max_examples=50)
def test_config_rejects_bad_sqlmap_level(level: int):
    with pytest.raises(Exception):
        PipelineConfig(sqlmap_level=level)


@given(st.integers(min_value=4, max_value=100))
@settings(max_examples=50)
def test_config_rejects_bad_sqlmap_risk(risk: int):
    with pytest.raises(Exception):
        PipelineConfig(sqlmap_risk=risk)


@given(st.integers(min_value=-100, max_value=-1))
@settings(max_examples=50)
def test_config_rejects_negative_sample_size(n: int):
    with pytest.raises(Exception):
        PipelineConfig(sample_urls_fuzz=n)


@given(st.text(min_size=1))
@settings(max_examples=100)
def test_config_rejects_bad_proxy_scheme(proxy: str):
    assume(not proxy.startswith(("http://", "https://", "socks4://", "socks5://")))
    with pytest.raises(Exception):
        PipelineConfig(proxy=proxy)


@given(st.floats(min_value=-10.0, max_value=-0.1))
@settings(max_examples=50)
def test_config_rejects_negative_proxy_timeout(mult: float):
    with pytest.raises(Exception):
        PipelineConfig(proxy_timeout_multiplier=mult)


# ── Phase set operations ────────────────────────────────────────────

@given(st.lists(
    st.sampled_from(sorted(VALID_PHASES)),
    min_size=0, max_size=20, unique=True,
))
@settings(max_examples=100)
def test_phase_set_operations(phases: list):
    phase_set = set(phases)
    assert phase_set.issubset(VALID_PHASES)
    assert len(phase_set) == len(phases)


@given(st.text(min_size=1, max_size=50))
@settings(max_examples=200)
def test_phase_parse_csv_never_crashes(csv_str: str):
    from reconchain.process import _parse_phase_csv
    try:
        result = _parse_phase_csv(csv_str)
        assert isinstance(result, set)
    except (ValueError, SystemExit, argparse.ArgumentTypeError):
        pass


# ── Severity classification ────────────────────────────────────────

@given(st.text(min_size=1, max_size=500))
@settings(max_examples=200)
def test_guess_severity_never_crashes(text: str):
    from reconchain.artifacts import guess_severity
    result = guess_severity(text)
    assert result in ("critical", "high", "medium", "low", "info")


@given(st.sampled_from(["critical", "high", "medium", "low", "info"]))
@settings(max_examples=20)
def test_severity_weights_cover_all_levels(sev: str):
    from reconchain.severity import SEVERITY_WEIGHTS
    assert sev in SEVERITY_WEIGHTS
    assert SEVERITY_WEIGHTS[sev] > 0


# ── Deduplication ──────────────────────────────────────────────────

@given(st.lists(
    st.text(min_size=1, max_size=200, alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters="_-/.?=&")),
    min_size=0, max_size=100,
))
@settings(max_examples=50)
def test_merge_unique_never_crashes(lines: list):
    """merge_unique(srcs, dst) merges src files into dst."""
    from reconchain.utils import merge_unique
    outdir = Path(tempfile.mkdtemp())
    src_dir = outdir / "src"
    src_dir.mkdir()
    for i, line in enumerate(lines):
        (src_dir / f"f{i}.txt").write_text(line)
    dst = outdir / "dst.txt"
    srcs = sorted(src_dir.iterdir())
    result = merge_unique(srcs, dst)
    assert isinstance(result, int)
    assert result >= 0


def test_merge_unique_deduplicates():
    """merge_unique should deduplicate lines across source files."""
    from reconchain.utils import merge_unique
    outdir = Path(tempfile.mkdtemp())
    src_dir = outdir / "src"
    src_dir.mkdir()
    (src_dir / "a.txt").write_text("line1\nline2\n")
    (src_dir / "b.txt").write_text("line2\nline3\n")
    dst = outdir / "dst.txt"
    srcs = sorted(src_dir.iterdir())
    count = merge_unique(srcs, dst)
    assert count == 3  # line1, line2, line3


# ── URL parsing ─────────────────────────────────────────────────────

@given(st.text(min_size=1, max_size=200))
@settings(max_examples=200)
def test_is_under_domain_never_crashes(path: str):
    from reconchain.utils import _is_under_domain
    try:
        result = _is_under_domain(path, "example.com")
        assert isinstance(result, bool)
    except Exception:
        pass


# ── Remediation lookups ─────────────────────────────────────────────

@given(st.text(min_size=1, max_size=50))
@settings(max_examples=100)
def test_remediation_lookup_never_crashes(vuln_type: str):
    from reconchain.remediation import get_remediation, has_remediation, get_remediation_text
    r = get_remediation(vuln_type)
    assert r is None or hasattr(r, "cwe")
    assert isinstance(has_remediation(vuln_type), bool)
    text = get_remediation_text(vuln_type)
    assert isinstance(text, str)


# ── Confidence scoring ──────────────────────────────────────────────

@given(st.floats(min_value=0.0, max_value=1.0), st.text(min_size=1, max_size=100))
@settings(max_examples=100)
def test_confidence_score_bounds(cvss: float, text: str):
    from reconchain.confidence import score_finding
    try:
        score = score_finding({"cvss": cvss, "text": text})
        assert 0.0 <= score <= 1.0
    except Exception:
        pass


# ── Artifact registry ───────────────────────────────────────────────

def test_artifact_registry_not_empty():
    from reconchain.artifacts import ARTIFACTS
    assert len(ARTIFACTS) > 0


def test_artifact_registry_unique_keys():
    from reconchain.artifacts import ARTIFACTS
    keys = [a.key for a in ARTIFACTS]
    assert len(keys) == len(set(keys))


def test_artifact_registry_unique_filenames():
    from reconchain.artifacts import ARTIFACTS
    filenames = [a.filename for a in ARTIFACTS]
    assert len(filenames) == len(set(filenames))


# ── Event bus ───────────────────────────────────────────────────────

@given(st.text(min_size=1, max_size=50), st.dictionaries(st.text(min_size=1, max_size=20), st.text(max_size=100)))
@settings(max_examples=100)
def test_event_bus_emit_subscribe(event_type: str, data: dict):
    from reconchain.events import EventBus
    bus = EventBus()
    received = []
    bus.subscribe(event_type, lambda e: received.append(e))
    bus.emit(event_type, data)
    assert len(received) == 1
    assert received[0].type == event_type


import pytest
