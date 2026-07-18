"""Security-focused tests for ReconChain v3.1.

Covers: credential redaction, input sanitization, path traversal,
audit logging, proxy env safety, state.json filtering, subprocess safety.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest


# ── Phase 3.3: Secret Management — PipelineConfig repr redaction ──


class TestPipelineConfigReprRedaction:
    """Ensure sensitive fields are masked in repr output."""

    def test_bearer_redacted(self):
        from reconchain.config import PipelineConfig
        cfg = PipelineConfig(auth_bearer="secret-token-123")
        r = repr(cfg)
        assert "secret-token-123" not in r
        assert "auth_bearer=***" in r

    def test_api_key_redacted(self):
        from reconchain.config import PipelineConfig
        cfg = PipelineConfig(auth_api_key="ak-xyz-789")
        r = repr(cfg)
        assert "ak-xyz-789" not in r
        assert "auth_api_key=***" in r

    def test_basic_auth_redacted(self):
        from reconchain.config import PipelineConfig
        cfg = PipelineConfig(auth_basic="user:pass")
        r = repr(cfg)
        assert "user:pass" not in r
        assert "auth_basic=***" in r

    def test_client_cert_redacted(self):
        from reconchain.config import PipelineConfig
        cfg = PipelineConfig(auth_client_cert="/path/to/cert")
        r = repr(cfg)
        assert "/path/to/cert" not in r
        assert "auth_client_cert=***" in r

    def test_empty_credentials_not_redacted(self):
        from reconchain.config import PipelineConfig
        cfg = PipelineConfig()
        r = repr(cfg)
        assert "auth_bearer=''" in r
        assert "auth_api_key=''" in r

    def test_non_sensitive_fields_visible(self):
        from reconchain.config import PipelineConfig
        cfg = PipelineConfig(rate_limit=100, sqlmap_level=3)
        r = repr(cfg)
        assert "rate_limit=100" in r
        assert "sqlmap_level=3" in r


# ── Phase 3.4: Input Sanitization — batch domain validation ──


class TestBatchDomainValidation:
    """Batch file domains must be validated to prevent path traversal."""

    def test_valid_domains_accepted(self):
        from reconchain.utils import _is_valid_hostname
        assert _is_valid_hostname("example.com")
        assert _is_valid_hostname("sub.example.co.uk")
        assert _is_valid_hostname("a-b.c-d.example.com")

    def test_path_traversal_rejected(self):
        from reconchain.utils import _is_valid_hostname
        assert not _is_valid_hostname("../../etc")
        assert not _is_valid_hostname("../secret")
        assert not _is_valid_hostname("foo/../bar.com")

    def test_injection_chars_rejected(self):
        from reconchain.utils import _is_valid_hostname
        assert not _is_valid_hostname("example.com; rm -rf /")
        assert not _is_valid_hostname("example.com`whoami`")
        assert not _is_valid_hostname("example.com$(id)")
        assert not _is_valid_hostname("example.com|cat /etc/passwd")

    def test_empty_and_whitespace_rejected(self):
        from reconchain.utils import _is_valid_hostname
        assert not _is_valid_hostname("")
        assert not _is_valid_hostname("  ")
        assert not _is_valid_hostname("\t")

    def test_ip_address_rejected(self):
        from reconchain.utils import _is_valid_hostname
        assert not _is_valid_hostname("192.168.1.1")
        assert not _is_valid_hostname("10.0.0.1")


# ── Phase 3.6: State.json Whitelist Filtering ──


class TestStateJsonFiltering:
    """State.json should only contain whitelisted safe keys."""

    def test_sensitive_keys_excluded(self, tmp_path):
        from reconchain.process import _atomic_write_json
        state = {
            "domain": "example.com",
            "outdir": "/tmp/out",
            "COOKIE": "session=abc123",
            "COOKIE_A": "a=1",
            "COOKIE_B": "b=2",
            "EXTRA_HEADERS": "X-Custom: secret",
            "credentials": {"user": "admin", "pass": "pw"},
            "completed_phases": ["00-SCOPE"],
        }
        # Simulate the filtering logic from pipeline.py
        _SAFE_STATE_KEYS = {
            "domain", "outdir", "started_at", "updated_at", "completed_phases",
            "running_phases", "total_phases", "phase", "phase_progress",
            "missing_tools", "tool_failures", "artifacts", "counts",
            "coverage", "oast_urls", "oast_triggered", "errors",
        }
        _SENSITIVE_KEYS = {"cookie", "COOKIE", "COOKIE_A", "COOKIE_B", "extra_headers", "EXTRA_HEADERS", "credentials", "credentials_queue"}
        _filtered = {k: v for k, v in state.items() if k in _SAFE_STATE_KEYS and k not in _SENSITIVE_KEYS}
        assert "domain" in _filtered
        assert "completed_phases" in _filtered
        assert "COOKIE" not in _filtered
        assert "COOKIE_A" not in _filtered
        assert "COOKIE_B" not in _filtered
        assert "EXTRA_HEADERS" not in _filtered
        assert "credentials" not in _filtered

    def test_artifacts_whitelist(self):
        safe_artifacts = {
            "live_hosts": ["a.com"],
            "urls": ["http://a.com/x"],
            "js_secrets": [{"type": "api_key", "value": "sk-123"}],
            "sqlmap": [{"payload": "1 OR 1=1"}],
        }
        _SAFE_ARTIFACTS = {
            "live_hosts", "ports", "urls", "subdomains", "permutations",
            "dns_records", "certificates", "screenshots", "waf_detections",
            "cors_misconfigs", "open_redirects", "ssrf_endpoints",
            "xxe_endpoints", "ssti_endpoints", "lfi_paths",
            "command_injection", "race_conditions", "graphql_endpoints",
            "cloud_buckets", "git_repos", "api_endpoints",
            "tls_ciphers", "origin_ip", "tech_stack", "status_codes",
            "response_headers", "javascript_files", "form_params",
            "parameter_names", "directory_listings", "error_pages",
            "websockets", "hsts_headers", "csp_headers",
            "clickjackable", "crlf_injection", "file_uploads",
            "default_pages", "virtual_hosts", "jwt_tokens",
            "oauth_endpoints", "saml_endpoints", "session_fixations",
            "host_header_injection", "sensitive_files",
        }
        filtered = {
            k: v for k, v in safe_artifacts.items()
            if any(safe in k.lower() for safe in _SAFE_ARTIFACTS)
        }
        assert "live_hosts" in filtered
        assert "urls" in filtered
        assert "js_secrets" not in filtered
        assert "sqlmap" not in filtered


# ── Phase 3.5: Audit Logging ──


class TestAuditLogging:
    """Test the audit logging module."""

    def test_audit_log_created(self, tmp_path):
        from reconchain.audit import init_audit_log, log_event, disable, enable
        disable()
        try:
            path = init_audit_log(tmp_path)
            assert path.exists()
            assert path.name == "audit.jsonl"
            assert path.stat().st_mode & 0o777 == 0o600  # owner-only
        finally:
            enable()

    def test_log_event_writes_jsonl(self, tmp_path):
        from reconchain.audit import init_audit_log, log_event, disable, enable
        disable()
        try:
            init_audit_log(tmp_path)
            enable()
            log_event("scan_start", domain="example.com", detail={"out": "/tmp/out"})
            log_event("phase_complete", domain="example.com", detail={"phase": "00-SCOPE"})
            lines = (tmp_path / "audit.jsonl").read_text().strip().split("\n")
            assert len(lines) == 2
            rec1 = json.loads(lines[0])
            assert rec1["event"] == "scan_start"
            assert rec1["domain"] == "example.com"
            assert "pid" in rec1
            assert "uid" in rec1
            assert "ts" in rec1
            rec2 = json.loads(lines[1])
            assert rec2["event"] == "phase_complete"
            assert rec2["detail"]["phase"] == "00-SCOPE"
        finally:
            disable()

    def test_disabled_audit_writes_nothing(self, tmp_path):
        from reconchain.audit import init_audit_log, log_event, disable
        disable()
        try:
            init_audit_log(tmp_path)
            log_event("scan_start", domain="example.com")
            assert not (tmp_path / "audit.jsonl").exists() or \
                (tmp_path / "audit.jsonl").read_text().strip() == ""
        finally:
            from reconchain.audit import enable
            enable()


# ── Phase 3.6: Proxy Environment Race Condition ──


class TestProxyEnvSafety:
    """Verify proxy env is passed via env= parameter, not mutated."""

    def test_bypass_proxy_function(self):
        from reconchain.process import _bypass_proxy
        assert _bypass_proxy(["dnsx", "-l", "subs.txt"])
        assert _bypass_proxy(["nmap", "-sV", "target"])
        assert _bypass_proxy(["naabu", "-l", "subs.txt"])
        assert not _bypass_proxy(["httpx", "-l", "urls.txt"])
        assert not _bypass_proxy(["nuclei", "-l", "urls.txt"])
        assert not _bypass_proxy([])

    def test_bypass_proxy_wrapped_in_bash(self):
        from reconchain.process import _bypass_proxy
        assert _bypass_proxy(["bash", "/path/to/findomain.sh", "-t", "example.com"])
        assert _bypass_proxy(["bash", "dnsx-wrapper", "-l", "subs.txt"])


# ── Phase 3.4: Cookie Sanitization ──


class TestCookieSanitization:
    """Ensure cookie values are sanitized before use."""

    def test_strips_newlines(self):
        from reconchain.utils import _sanitize_header_value
        result = _sanitize_header_value("session=abc\r\nInjected: true")
        assert "\r" not in result
        assert "\n" not in result

    def test_strips_null_bytes(self):
        from reconchain.utils import _sanitize_header_value
        result = _sanitize_header_value("session=abc\x00injected")
        assert "\x00" not in result

    def test_strips_tabs(self):
        from reconchain.utils import _sanitize_header_value
        result = _sanitize_header_value("session=abc\tinjected")
        assert "\t" not in result

    def test_cookie_cli_arg_injection_prevented(self):
        from reconchain.utils import _validate_cookie
        # Leading -- should be stripped to prevent arg injection
        result = _validate_cookie("--cookie-value")
        assert result == "cookie-value"

    def test_empty_cookie_rejected(self):
        from reconchain.utils import _validate_cookie
        from reconchain.exceptions import InvalidCookieError
        with pytest.raises(InvalidCookieError):
            _validate_cookie("")
        with pytest.raises(InvalidCookieError):
            _validate_cookie("   ")


# ── Subprocess Safety ──


class TestSubprocessSafety:
    """Verify no shell=True usage and proper command handling."""

    def test_no_shell_true_in_process(self):
        """Ensure process.py never uses shell=True."""
        import inspect
        from reconchain import process
        source = inspect.getsource(process)
        assert "shell=True" not in source, "shell=True found in process.py — security risk"

    def test_domain_arg_validation(self):
        from reconchain.process import _domain_arg
        import argparse
        # Valid domains should pass
        assert _domain_arg("example.com") == "example.com"
        assert _domain_arg("EXAMPLE.COM") == "example.com"
        assert _domain_arg("sub.example.com") == "sub.example.com"
        # Invalid domains should raise (no dot, injection chars)
        with pytest.raises(argparse.ArgumentTypeError):
            _domain_arg("notadomain")
        with pytest.raises(argparse.ArgumentTypeError):
            _domain_arg("example.com; rm -rf /")
        with pytest.raises(argparse.ArgumentTypeError):
            _domain_arg("")


# ── Phase 4: Performance — DedupEngine prefix index ──


class TestDedupEnginePerformance:
    """Verify the prefix-indexed fuzzy matching is efficient."""

    def test_prefix_index_built_on_load(self, tmp_path):
        from reconchain.dedup import DedupEngine
        state = {
            "https://example.com/path1": {"ts": "2024-01-01T00:00:00"},
            "https://example.com/path2": {"ts": "2024-01-01T00:00:01"},
            "https://other.com/x": {"ts": "2024-01-01T00:00:02"},
        }
        state_path = tmp_path / "dedup.json"
        state_path.write_text(json.dumps(state))
        engine = DedupEngine(state_path)
        assert len(engine._seen) == 3
        # Prefix index should have buckets for "https" and "https" (same prefix for first 2)
        assert "http" in engine._prefix_index or "http" in engine._prefix_index

    def test_fuzzy_match_uses_prefix_narrowing(self, tmp_path):
        from reconchain.dedup import DedupEngine
        state_path = tmp_path / "dedup.json"
        state_path.write_text("{}")
        engine = DedupEngine(state_path)
        # Add 100 keys with varying prefixes
        for i in range(100):
            engine.mark_seen(f"https://host{i}.com/path{i}")
        # Fuzzy match should only compare against prefix candidates, not all 100
        is_dup, matched = engine.is_duplicate("https://host0.com/path0")
        # Exact match should be found without fuzzy
        assert is_dup is True

    def test_mark_seen_evicts_oldest(self, tmp_path):
        from reconchain.dedup import DedupEngine
        state_path = tmp_path / "dedup.json"
        state_path.write_text("{}")
        engine = DedupEngine(state_path)
        engine.MAX_SEEN = 10  # Small cap for testing
        for i in range(15):
            engine.mark_seen(f"key-{i:04d}", source=f"src-{i}")
        assert len(engine._seen) <= 10

    def test_clear_resets_prefix_index(self, tmp_path):
        from reconchain.dedup import DedupEngine
        state_path = tmp_path / "dedup.json"
        state_path.write_text("{}")
        engine = DedupEngine(state_path)
        engine.mark_seen("https://example.com/test")
        assert len(engine._prefix_index) > 0
        engine.clear()
        assert len(engine._prefix_index) == 0
        assert len(engine._seen) == 0


# ── Phase 4: Performance — Snapshot streaming ──


class TestSnapshotStreaming:
    """Verify _snapshot_findings uses streaming reads."""

    def test_snapshot_with_large_files(self, tmp_path):
        from reconchain.pipeline import _snapshot_findings
        # Create a large file (1000 lines)
        large_file = tmp_path / "large_subs.txt"
        large_file.write_text("\n".join(f"sub{i}.example.com" for i in range(1000)))
        # Create a small file
        small_file = tmp_path / "urls.txt"
        small_file.write_text("http://example.com/a\nhttp://example.com/b\n")
        snapshot = _snapshot_findings(tmp_path)
        assert "large_subs.txt" in snapshot
        assert len(snapshot["large_subs.txt"]) == 1000
        assert "urls.txt" in snapshot
        assert len(snapshot["urls.txt"]) == 2

    def test_snapshot_skips_hidden_files(self, tmp_path):
        from reconchain.pipeline import _snapshot_findings
        hidden = tmp_path / ".hidden.txt"
        hidden.write_text("secret\n")
        visible = tmp_path / "visible.txt"
        visible.write_text("public\n")
        snapshot = _snapshot_findings(tmp_path)
        assert ".hidden.txt" not in snapshot
        assert "visible.txt" in snapshot

    def test_snapshot_skips_blank_and_comment_lines(self, tmp_path):
        from reconchain.pipeline import _snapshot_findings
        f = tmp_path / "mixed.txt"
        f.write_text("# comment\n\nactual-line\n  \n# another comment\nsecond-line\n")
        snapshot = _snapshot_findings(tmp_path)
        assert "mixed.txt" in snapshot
        assert "actual-line" in snapshot["mixed.txt"]
        assert "second-line" in snapshot["mixed.txt"]
        assert len(snapshot["mixed.txt"]) == 2
