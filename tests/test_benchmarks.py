"""Performance benchmarks for critical ReconChain operations."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest


@pytest.mark.benchmark
class TestDedupBenchmarks:
    """Benchmark DedupEngine operations."""

    def test_dedup_1k_findings(self, benchmark):
        from reconchain.dedup import DedupEngine
        outdir = Path(tempfile.mkdtemp())
        engine = DedupEngine(state_path=outdir / ".dedup_state")
        lines = [f"https://example.com/path{i}?param={i}" for i in range(1000)]
        f = outdir / "bench.txt"
        f.write_text("\n".join(lines))
        def _do():
            for line in lines:
                engine.is_duplicate(line)
        benchmark(_do)

    def test_dedup_10k_findings(self, benchmark):
        from reconchain.dedup import DedupEngine
        outdir = Path(tempfile.mkdtemp())
        engine = DedupEngine(state_path=outdir / ".dedup_state")
        lines = [f"https://example.com/path{i % 200}?param={i}" for i in range(10000)]
        f = outdir / "bench.txt"
        f.write_text("\n".join(lines))
        def _do():
            for line in lines:
                engine.is_duplicate(line)
        benchmark(_do)


@pytest.mark.benchmark
class TestConfigBenchmarks:
    """Benchmark PipelineConfig construction and validation."""

    def test_config_construction_default(self, benchmark):
        from reconchain.config import PipelineConfig
        benchmark(PipelineConfig)

    def test_config_construction_custom(self, benchmark):
        from reconchain.config import PipelineConfig
        benchmark(
            PipelineConfig,
            delay=0.5,
            rate_limit=10,
            sample_urls_fuzz=100,
            safe_mode=True,
        )

    def test_config_repr_redaction(self, benchmark):
        from reconchain.config import PipelineConfig
        cfg = PipelineConfig(auth_bearer="secret_token_12345", auth_api_key="api_key_abc")
        benchmark(repr, cfg)


@pytest.mark.benchmark
class TestReportingBenchmarks:
    """Benchmark report generation."""

    def test_write_summary(self, benchmark):
        from reconchain.reporting import write_summary
        outdir = Path(tempfile.mkdtemp())
        state = {"artifacts": {"test.txt": str(outdir / "test.txt")}, "missing_tools": []}
        counts = {"xss": 5, "sqli": 3, "info": 100}
        benchmark(write_summary, outdir, "bench.example.com", state, counts)

    def test_write_markdown(self, benchmark):
        from reconchain.reporting import write_markdown
        outdir = Path(tempfile.mkdtemp())
        (outdir / "test.txt").write_text("finding1\nfinding2\n")
        counts = {"xss": 5, "sqli": 3}
        benchmark(write_markdown, outdir, "bench.example.com", counts, [])


@pytest.mark.benchmark
class TestSeverityBenchmarks:
    """Benchmark risk score calculation."""

    def test_risk_score_empty(self, benchmark):
        from reconchain.severity import calculate_risk_score
        outdir = Path(tempfile.mkdtemp())
        benchmark(calculate_risk_score, outdir)

    def test_risk_score_with_findings(self, benchmark):
        from reconchain.severity import calculate_risk_score
        from reconchain.artifacts import ARTIFACTS
        outdir = Path(tempfile.mkdtemp())
        for art in ARTIFACTS[:5]:
            if art.vuln_type:
                (outdir / art.filename).write_text("test finding\n" * 10)
        benchmark(calculate_risk_score, outdir)


@pytest.mark.benchmark
class TestCacheBenchmarks:
    """Benchmark HTTP and DNS caches."""

    def test_http_cache_set_get(self, benchmark):
        from reconchain.utils import _HTTPResponseCache
        cache = _HTTPResponseCache(max_size=1024, ttl=300)
        def _do():
            cache.put("https://example.com", 200, b"data", "GET")
            cache.get("https://example.com")
        benchmark(_do)

    def test_dns_cache_set_get(self, benchmark):
        from reconchain.utils import _DNSCache
        cache = _DNSCache(max_size=1024, ttl=600)
        def _do():
            cache.put("example.com", "1.2.3.4")
            cache.get("example.com")
        benchmark(_do)


@pytest.mark.benchmark
class TestExceptionBenchmarks:
    """Benchmark exception construction."""

    def test_exception_hierarchy(self, benchmark):
        from reconchain.exceptions import (
            ReconChainError, ToolError, ToolNotFoundError,
            NetworkError, ProxyError, PluginError,
        )
        def create_exceptions():
            try:
                raise ToolNotFoundError("nuclei not found")
            except ToolNotFoundError:
                pass
            try:
                raise ProxyError("proxy unreachable")
            except ProxyError:
                pass
            try:
                raise PluginError("load failed")
            except PluginError:
                pass
        benchmark(create_exceptions)
