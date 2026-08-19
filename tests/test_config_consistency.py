"""Config consistency: single source of truth for sample_* fields.

These tests fail when a sample_* knob is added/changed without the derived
defaults (wizard, pipeline) staying in sync with the dataclass.
"""
import dataclasses
import sys

from vulnforge.config import (
    PipelineConfig,
    SAMPLE_DEFAULTS,
    SAMPLE_SPEED_CAPS,
)


def _sample_fields():
    return [
        f
        for f in dataclasses.fields(PipelineConfig)
        if f.name.startswith("sample_") and isinstance(f.default, int)
    ]


class TestSampleDefaultsSingleSource:
    def test_sample_defaults_matches_dataclass(self):
        assert set(SAMPLE_DEFAULTS) == {f.name for f in _sample_fields()}
        for f in _sample_fields():
            assert SAMPLE_DEFAULTS[f.name] == f.default

    def test_pipeline_accepts_all_sample_fields(self):
        kwargs = dict(SAMPLE_DEFAULTS)
        cfg = PipelineConfig(**kwargs)
        for name, val in SAMPLE_DEFAULTS.items():
            assert getattr(cfg, name) == val


class TestWizardDerivedFromDataclass:
    def test_wizard_defaults_match_dataclass(self):
        import argparse

        from vulnforge.cli.wizard import _set_sample_defaults

        ns = argparse.Namespace()
        _set_sample_defaults(ns, speed=False)
        for name, val in SAMPLE_DEFAULTS.items():
            assert getattr(ns, name) == val, f"{name} drifted"

    def test_wizard_speed_caps_do_not_exceed_defaults(self):
        for name, cap in SAMPLE_SPEED_CAPS.items():
            assert cap <= SAMPLE_DEFAULTS[name], f"cap for {name} exceeds default"


class TestPostInitSamplingModes:
    def _cfg(self, **kw):
        kwargs = dict(SAMPLE_DEFAULTS)
        kwargs.update(kw)
        return PipelineConfig(**kwargs)

    def test_safe_mode_halves_samples(self):
        cfg = self._cfg(safe_mode=True)
        assert cfg.sample_urls_fuzz == 100  # 200 // 2
        assert cfg.sample_hosts_ssl == 5  # 10 // 2

    def test_minimal_mode_sets_one(self):
        cfg = self._cfg(sample_mode="minimal")
        assert cfg.sample_urls_fuzz == 1
        assert cfg.sample_urls_params == 1

    def test_all_mode_sets_maxsize(self):
        cfg = self._cfg(sample_mode="all")
        assert cfg.sample_urls_fuzz == sys.maxsize

    def test_odd_value_safe_halves_down(self):
        cfg = PipelineConfig(safe_mode=True, sample_mode="normal", sample_urls_ssti=5)
        assert cfg.sample_urls_ssti == 2  # 5 // 2 = 2, never below 1
