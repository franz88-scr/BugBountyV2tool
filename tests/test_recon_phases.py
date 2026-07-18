"""Tests for the recon phase sub-modules (reconchain.phases.recon.*)."""
import asyncio
from pathlib import Path

import pytest

from reconchain.phases.recon import (
    phase_00_SCOPE,
    phase_01_RECON,
    phase_02_RESOLVE,
    phase_03_PERMUTE,
    phase_04_SCAN,
    phase_04b_TAKEOVER_VALIDATE,
    phase_05_HARVEST,
    phase_05b_APISPEC,
    phase_06_JSINTEL,
    phase_07_PARAMS,
    phase_84_WHOIS,
    phase_85_ASN,
    phase_86_DORK,
    phase_87_SHODAN,
    phase_88_EMPLOYEE,
    phase_89_PASSIVEDNS,
    _JS_SECRET_PATTERNS,
    _SOURCE_MAP_RE,
)

from reconchain.tools import Tools


class TestReconSubModuleImports:
    def test_scope_import(self):
        from reconchain.phases.recon.scope import phase_00_SCOPE
        assert callable(phase_00_SCOPE)

    def test_subdomain_import(self):
        from reconchain.phases.recon.subdomain import phase_01_RECON, phase_03_PERMUTE
        assert callable(phase_01_RECON)
        assert callable(phase_03_PERMUTE)

    def test_dns_import(self):
        from reconchain.phases.recon.dns import phase_02_RESOLVE
        assert callable(phase_02_RESOLVE)

    def test_scan_import(self):
        from reconchain.phases.recon.scan import phase_04_SCAN, phase_04b_TAKEOVER_VALIDATE
        assert callable(phase_04_SCAN)
        assert callable(phase_04b_TAKEOVER_VALIDATE)

    def test_harvest_import(self):
        from reconchain.phases.recon.harvest import phase_05_HARVEST, phase_05b_APISPEC
        assert callable(phase_05_HARVEST)
        assert callable(phase_05b_APISPEC)

    def test_jsintel_import(self):
        from reconchain.phases.recon.jsintel import phase_06_JSINTEL, _JS_SECRET_PATTERNS, _SOURCE_MAP_RE
        assert callable(phase_06_JSINTEL)
        assert isinstance(_JS_SECRET_PATTERNS, list)
        assert _SOURCE_MAP_RE is not None

    def test_params_import(self):
        from reconchain.phases.recon.params import phase_07_PARAMS
        assert callable(phase_07_PARAMS)

    def test_osint_import(self):
        from reconchain.phases.recon.osint import (
            phase_84_WHOIS, phase_85_ASN, phase_86_DORK,
            phase_87_SHODAN, phase_88_EMPLOYEE, phase_89_PASSIVEDNS,
        )
        assert callable(phase_84_WHOIS)
        assert callable(phase_85_ASN)
        assert callable(phase_86_DORK)
        assert callable(phase_87_SHODAN)
        assert callable(phase_88_EMPLOYEE)
        assert callable(phase_89_PASSIVEDNS)


class TestBackwardCompatImports:
    def test_top_level_recon_imports(self):
        assert callable(phase_00_SCOPE)
        assert callable(phase_01_RECON)
        assert callable(phase_02_RESOLVE)
        assert callable(phase_03_PERMUTE)
        assert callable(phase_04_SCAN)
        assert callable(phase_04b_TAKEOVER_VALIDATE)
        assert callable(phase_05_HARVEST)
        assert callable(phase_05b_APISPEC)
        assert callable(phase_06_JSINTEL)
        assert callable(phase_07_PARAMS)
        assert callable(phase_84_WHOIS)
        assert callable(phase_85_ASN)
        assert callable(phase_86_DORK)
        assert callable(phase_87_SHODAN)
        assert callable(phase_88_EMPLOYEE)
        assert callable(phase_89_PASSIVEDNS)

    def test_phases_package_reexports(self):
        from reconchain.phases import (
            phase_00_SCOPE as p0,
            phase_01_RECON as p1,
            _JS_SECRET_PATTERNS as js,
            _SOURCE_MAP_RE as sm,
        )
        assert callable(p0)
        assert callable(p1)
        assert isinstance(js, list)
        assert sm is not None

    def test_secrets_git_still_imports(self):
        from reconchain.phases.secrets_git import _JS_SECRET_PATTERNS, _SOURCE_MAP_RE
        assert isinstance(_JS_SECRET_PATTERNS, list)

    def test_pipeline_data_structures(self):
        from reconchain.phases import PIPELINE, PHASE_DEPS, STAGES, _PHASE_WEIGHTS
        assert len(PIPELINE) == 164
        assert len(PHASE_DEPS) == 164
        assert len(STAGES) == 29
        assert len(_PHASE_WEIGHTS) == 164


class TestJSIntelPatterns:
    def test_js_secret_patterns_count(self):
        assert len(_JS_SECRET_PATTERNS) >= 15

    def test_js_secret_patterns_are_tuples(self):
        for name, pattern in _JS_SECRET_PATTERNS:
            assert isinstance(name, str)
            assert isinstance(pattern, str)

    def test_source_map_regex(self):
        test_line = "//# sourceMappingURL=bundle.js.map"
        match = _SOURCE_MAP_RE.search(test_line)
        assert match is not None
        assert match.group(1) == "bundle.js.map"


class TestPhaseSkipLogic:
    """Test that phases return {} when their skip set contains the phase name."""

    def test_scope_skip(self, tmp_path):
        t = Tools()
        result = asyncio.run(
            phase_00_SCOPE("example.com", tmp_path, t, set(), {"00-SCOPE"})
        )
        assert result == {}

    def test_recon_skip(self, tmp_path):
        t = Tools()
        result = asyncio.run(
            phase_01_RECON("example.com", tmp_path, t, set(), {"01-RECON"})
        )
        assert result == {}

    def test_recon_only_not_in_set(self, tmp_path):
        t = Tools()
        result = asyncio.run(
            phase_01_RECON("example.com", tmp_path, t, {"04-SCAN"}, set())
        )
        assert result == {}

    def test_params_skip(self, tmp_path):
        t = Tools()
        result = asyncio.run(
            phase_07_PARAMS(tmp_path, t, set(), {"07-PARAMS"}, {})
        )
        assert result == {}

    def test_scope_only_not_in_set(self, tmp_path):
        """phase_00_SCOPE doesn't check `only` — it only checks `skip`. Verify it still runs."""
        t = Tools()
        result = asyncio.run(
            phase_00_SCOPE("example.com", tmp_path, t, {"01-RECON"}, set())
        )
        # phase_00_SCOPE has no `only` guard, so it runs regardless
        assert "00-SCOPE" in result
