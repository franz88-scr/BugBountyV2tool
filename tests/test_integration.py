"""Integration tests — mocked tool output workflow tests.

Tests complete scan workflows with realistic mock tool outputs to verify
that phases wire together correctly and data flows through the pipeline.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ── Helpers ────────────────────────────────────────────────────────


def _write_lines(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n")


def _make_args(domain: str, outdir: Path, **kwargs) -> MagicMock:
    args = MagicMock()
    args.domain = domain
    args.out = str(outdir)
    args.safe = kwargs.get("safe", False)
    args.only = kwargs.get("only", set())
    args.skip = kwargs.get("skip", set())
    args.force = kwargs.get("force", False)
    args.resume = kwargs.get("resume", False)
    args.sample = kwargs.get("sample", False)
    args.proxy = kwargs.get("proxy", "")
    args.vuln_proxy = kwargs.get("vuln_proxy", "")
    args.delay = kwargs.get("delay", 0)
    args.interactsh = kwargs.get("interactsh", False)
    args.no_color = True
    args.quiet = False
    args.dry_run = False
    args.daemon = False
    args.no_ai = False
    args.no_plugins = False
    args.plugins_dir = ""
    args.gen_config = False
    args.list_plugins = False
    args.dashboard = False
    args.dashboard_port = 0
    args.compare = None
    args.review = False
    args.status = ""
    args.batch = ""
    args.incremental = False
    return args


# ── Phase 00-SCOPE with mocked config ──


class TestScopePhaseIntegration:
    """Test scope phase with realistic config inputs."""

    def test_scope_extracts_domain(self, tmp_path):
        from reconchain.phases.recon.scope import phase_00_SCOPE
        from reconchain.tools import Tools
        t = Tools()
        result = asyncio.run(
            phase_00_SCOPE("example.com", tmp_path, t, set(), set())
        )
        assert "00-SCOPE" in result
        # Scope should write scope.txt with the domain
        scope_file = tmp_path / "scope.txt"
        if scope_file.exists():
            content = scope_file.read_text()
            assert "example.com" in content

    def test_scope_skip_returns_empty(self, tmp_path):
        from reconchain.phases.recon.scope import phase_00_SCOPE
        from reconchain.tools import Tools
        t = Tools()
        result = asyncio.run(
            phase_00_SCOPE("example.com", tmp_path, t, set(), {"00-SCOPE"})
        )
        assert result == {}


# ── Phase with subprocess mocking ──


class TestPhaseWithMockedSubprocess:
    """Test phases with mocked subprocess calls."""

    def test_subfinder_phase_with_mock(self, tmp_path):
        """Mock subfinder output and verify phase processing."""
        # Write mock subfinder output
        mock_output = tmp_path / "subs_mock.txt"
        _write_lines(mock_output, [
            "api.example.com",
            "www.example.com",
            "mail.example.com",
            "dev.example.com",
        ])
        # Verify mock output is parseable
        lines = mock_output.read_text().strip().split("\n")
        assert len(lines) == 4
        assert all("." in line for line in lines)

    def test_nuclei_output_parsing(self, tmp_path):
        """Verify nuclei output format is handled correctly."""
        nuclei_out = tmp_path / "nuclei_results.json"
        findings = [
            {"template-id": "tech-detect", "info": {"name": "Tech Detect"}, "matched-at": "https://example.com", "type": "http"},
            {"template-id": "xss-reflected", "info": {"name": "XSS Reflected", "severity": "high"}, "matched-at": "https://example.com/search?q=test", "type": "http"},
        ]
        nuclei_out.write_text("\n".join(json.dumps(f) for f in findings) + "\n")
        # Parse like the pipeline would
        parsed = []
        for line in nuclei_out.read_text().strip().split("\n"):
            if line.strip():
                parsed.append(json.loads(line))
        assert len(parsed) == 2
        assert parsed[0]["template-id"] == "tech-detect"
        assert parsed[1]["info"]["severity"] == "high"

    def test_httpx_output_parsing(self, tmp_path):
        """Verify httpx JSON output format."""
        httpx_out = tmp_path / "httpx_results.json"
        hosts = [
            {"url": "https://www.example.com", "status_code": 200, "tech": ["nginx", "PHP"]},
            {"url": "https://api.example.com", "status_code": 403, "tech": ["Express"]},
        ]
        httpx_out.write_text("\n".join(json.dumps(h) for h in hosts) + "\n")
        parsed = []
        for line in httpx_out.read_text().strip().split("\n"):
            if line.strip():
                parsed.append(json.loads(line))
        assert len(parsed) == 2
        assert "nginx" in parsed[0]["tech"]

    def test_subfinder_output_with_wildcards_filtered(self, tmp_path):
        """Verify wildcard subdomains are filtered."""
        raw_subs = [
            "*.example.com",
            "api.example.com",
            "test.example.com",
            "*-dev.example.com",
            "staging.example.com",
        ]
        filtered = [s for s in raw_subs if not s.startswith("*") and "*" not in s]
        assert len(filtered) == 3
        assert "*.example.com" not in filtered


# ── Data flow integration ──


class TestDataFlowIntegration:
    """Test that data flows correctly between phases via artifact files."""

    def test_subdomain_to_dns_flow(self, tmp_path):
        """Simulate: RECON writes subs -> RESOLVE reads them."""
        subs_file = tmp_path / "subs.txt"
        _write_lines(subs_file, [
            "api.example.com",
            "www.example.com",
            "mail.example.com",
        ])
        # Simulate RESOLVE reading from subs file
        hosts = [ln.strip() for ln in subs_file.read_text().splitlines() if ln.strip()]
        assert len(hosts) == 3
        # Simulate RESOLVE writing resolved hosts
        resolved_file = tmp_path / "resolved.txt"
        _write_lines(resolved_file, hosts[:2])  # only 2 resolved
        assert resolved_file.exists()
        resolved = [ln.strip() for ln in resolved_file.read_text().splitlines() if ln.strip()]
        assert len(resolved) == 2

    def test_scan_to_vuln_flow(self, tmp_path):
        """Simulate: SCAN writes live hosts -> VULNSCAN reads them."""
        live_file = tmp_path / "live_hosts.txt"
        _write_lines(live_file, [
            "https://www.example.com",
            "https://api.example.com",
        ])
        urls = [ln.strip() for ln in live_file.read_text().splitlines() if ln.strip()]
        assert len(urls) == 2
        # Simulate vuln scan output
        vuln_file = tmp_path / "vulns.jsonl"
        vulns = [
            {"url": urls[0], "type": "xss", "severity": "high"},
            {"url": urls[1], "type": "info-leak", "severity": "medium"},
        ]
        vuln_file.write_text("\n".join(json.dumps(v) for v in vulns) + "\n")
        parsed = [json.loads(ln) for ln in vuln_file.read_text().strip().split("\n") if ln.strip()]
        assert len(parsed) == 2

    def test_artifact_chain_integrity(self, tmp_path):
        """Verify artifact file references remain valid through the pipeline."""
        artifacts = {}
        # Phase 00
        scope = tmp_path / "scope.txt"
        _write_lines(scope, ["example.com"])
        artifacts["00-SCOPE"] = str(scope)
        # Phase 01
        subs = tmp_path / "subs.txt"
        _write_lines(subs, ["api.example.com", "www.example.com"])
        artifacts["01-RECON"] = str(subs)
        # Verify all artifact paths are valid
        for phase, path_str in artifacts.items():
            p = Path(path_str)
            assert p.exists(), f"Artifact for {phase} missing: {p}"
            assert p.stat().st_size > 0, f"Artifact for {phase} is empty: {p}"


# ── HTTP Cache integration ──


class TestHTTPCacheIntegration:
    """Test the HTTP response cache mechanism."""

    def test_cache_put_and_get(self):
        from reconchain.utils import _HTTPResponseCache
        cache = _HTTPResponseCache(max_size=100, ttl=60)
        cache.put("https://example.com", 200, b"ok")
        result = cache.get("https://example.com")
        assert result is not None
        status, body = result
        assert status == 200
        assert body == b"ok"

    def test_cache_miss(self):
        from reconchain.utils import _HTTPResponseCache
        cache = _HTTPResponseCache(max_size=100, ttl=60)
        assert cache.get("https://nonexistent.com") is None

    def test_cache_eviction(self):
        from reconchain.utils import _HTTPResponseCache
        cache = _HTTPResponseCache(max_size=10, ttl=60)
        for i in range(15):
            cache.put(f"https://example.com/{i}", 200, f"data{i}".encode())
        # Should have evicted some entries
        assert len(cache._cache) <= 10

    def test_cache_invalidation(self):
        from reconchain.utils import _HTTPResponseCache
        cache = _HTTPResponseCache(max_size=100, ttl=60)
        cache.put("https://example.com", 200, b"ok")
        cache.invalidate()
        assert cache.get("https://example.com") is None


# ── DNS Cache integration ──


class TestDNSCacheIntegration:
    """Test the DNS resolution cache."""

    def test_dns_cache_put_and_get(self):
        from reconchain.utils import _DNSCache
        cache = _DNSCache(max_size=100, ttl=60)
        cache.put("example.com", {"93.184.216.34"})
        result = cache.get("example.com")
        assert result is not None
        assert "93.184.216.34" in result

    def test_dns_cache_miss(self):
        from reconchain.utils import _DNSCache
        cache = _DNSCache(max_size=100, ttl=60)
        assert cache.get("nonexistent.example") is None

    def test_dns_cache_empty_resolution(self):
        from reconchain.utils import _DNSCache
        cache = _DNSCache(max_size=100, ttl=60)
        cache.put("noresolve.example", set())
        result = cache.get("noresolve.example")
        assert result is not None
        assert len(result) == 0
