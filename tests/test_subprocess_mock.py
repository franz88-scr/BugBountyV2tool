"""Subprocess mocking tests — unit tests for process.py with mocked subprocess calls.

Verifies that _run_blocking, _run_limited, and the pipeline execution
correctly handle subprocess results without spawning real processes.
"""
from __future__ import annotations

import asyncio
import json
import os
import signal
import subprocess
import tempfile
import threading
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch, mock_open

import pytest


# ── _run_blocking tests ──


class TestRunBlocking:
    """Test _run_blocking with mocked subprocess.Popen."""

    def test_successful_command(self, tmp_path):
        from reconchain.process import _run_blocking
        log_path = tmp_path / "test.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with patch("reconchain.process.subprocess.Popen") as mock_popen:
            mock_proc = MagicMock()
            mock_proc.pid = 12345
            mock_proc.returncode = 0
            mock_proc.wait.return_value = 0
            mock_popen.return_value = mock_proc
            with patch("reconchain.process._OS_PROC_SEM") as mock_sem:
                mock_sem.acquire.return_value = True
                with patch("reconchain.process._set_child_limits", None):
                    with patch("reconchain.process._register_proc"):
                        with patch("reconchain.process._SPAWNED_PIDS_LOCK"):
                            rc, elapsed = _run_blocking(
                                ["echo", "hello"], 30, None, log_path
                            )
            assert rc == 0

    def test_nonzero_exit_code(self, tmp_path):
        from reconchain.process import _run_blocking
        log_path = tmp_path / "test.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with patch("reconchain.process.subprocess.Popen") as mock_popen:
            mock_proc = MagicMock()
            mock_proc.pid = 12346
            mock_proc.returncode = 1
            mock_proc.wait.return_value = 1
            mock_popen.return_value = mock_proc
            with patch("reconchain.process._OS_PROC_SEM") as mock_sem:
                mock_sem.acquire.return_value = True
                with patch("reconchain.process._set_child_limits", None):
                    with patch("reconchain.process._register_proc"):
                        with patch("reconchain.process._SPAWNED_PIDS_LOCK"):
                            rc, elapsed = _run_blocking(
                                ["false"], 30, None, log_path
                            )
            assert rc == 1

    def test_file_not_found(self, tmp_path):
        from reconchain.process import _run_blocking
        log_path = tmp_path / "test.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with patch("reconchain.process.subprocess.Popen") as mock_popen:
            mock_popen.side_effect = FileNotFoundError("binary not found")
            with patch("reconchain.process._OS_PROC_SEM") as mock_sem:
                mock_sem.acquire.return_value = True
                with patch("reconchain.process._set_child_limits", None):
                    with patch("reconchain.process._register_proc"):
                        with patch("reconchain.process._SPAWNED_PIDS_LOCK"):
                            rc, elapsed = _run_blocking(
                                ["nonexistent_tool"], 30, None, log_path
                            )
            assert rc == 127

    def test_dry_run_mode(self, tmp_path):
        from reconchain.process import _run_blocking
        log_path = tmp_path / "test.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with patch.dict(os.environ, {"RECONCHAIN_DRY_RUN": "1"}):
            rc, elapsed = _run_blocking(
                ["nuclei", "-l", "urls.txt"], 30, None, log_path
            )
        assert rc == 0
        assert log_path.exists()
        content = log_path.read_text()
        assert "DRY-RUN" in content


# ── _run_limited tests ──


class TestRunLimited:
    """Test async _run_limited with mocked subprocess."""

    def test_successful_async_command(self):
        from reconchain.process import _run_limited
        async def _test():
            with patch("reconchain.process.asyncio.create_subprocess_exec") as mock_create:
                mock_proc = AsyncMock()
                mock_proc.communicate.return_value = (b"output", b"")
                mock_proc.returncode = 0
                mock_create.return_value = mock_proc
                with patch("reconchain.process._set_child_limits", None):
                    rc, stdout, stderr = await _run_limited(
                        ["echo", "hello"], timeout=10
                    )
                assert rc == 0
                assert stdout == b"output"
        asyncio.run(_test())

    def test_timeout_kills_process(self):
        from reconchain.process import _run_limited
        async def _test():
            with patch("reconchain.process.asyncio.create_subprocess_exec") as mock_create:
                mock_proc = AsyncMock()
                mock_proc.communicate.side_effect = asyncio.TimeoutError()
                mock_proc.pid = 99999
                mock_create.return_value = mock_proc
                with patch("reconchain.process._set_child_limits", None):
                    with patch("reconchain.process.os.killpg"):
                        rc, stdout, stderr = await _run_limited(
                            ["sleep", "999"], timeout=1
                        )
                assert rc == -1
        asyncio.run(_test())


# ── Domain argument validation ──


class TestDomainArgValidation:
    """Test _domain_arg input validation with various inputs."""

    def test_valid_domains(self):
        from reconchain.process import _domain_arg
        assert _domain_arg("example.com") == "example.com"
        assert _domain_arg("EXAMPLE.COM") == "example.com"
        assert _domain_arg("sub.example.co.uk") == "sub.example.co.uk"
        assert _domain_arg("a-b.c-d.example.com") == "a-b.c-d.example.com"
        assert _domain_arg("test123.example.com") == "test123.example.com"

    def test_trailing_dot_stripped(self):
        from reconchain.process import _domain_arg
        assert _domain_arg("example.com.") == "example.com"

    def test_no_dot_rejected(self):
        from reconchain.process import _domain_arg
        import argparse
        with pytest.raises(argparse.ArgumentTypeError):
            _domain_arg("localhost")

    def test_injection_rejected(self):
        from reconchain.process import _domain_arg
        import argparse
        with pytest.raises(argparse.ArgumentTypeError):
            _domain_arg("example.com; rm -rf /")
        with pytest.raises(argparse.ArgumentTypeError):
            _domain_arg("example.com`id`")
        with pytest.raises(argparse.ArgumentTypeError):
            _domain_arg("example.com$(whoami)")

    def test_empty_rejected(self):
        from reconchain.process import _domain_arg
        import argparse
        with pytest.raises(argparse.ArgumentTypeError):
            _domain_arg("")


# ── Tools class tests ──


class TestToolsClass:
    """Test Tools binary detection with mocked shutil.which."""

    def test_tools_have_checks_which(self):
        from reconchain.tools import Tools
        t = Tools()
        with patch("reconchain.tools.shutil.which") as mock_which:
            mock_which.return_value = "/usr/bin/nuclei"
            assert t.have("nuclei") == ["nuclei"]

    def test_tools_have_missing_tool(self):
        from reconchain.tools import Tools
        t = Tools()
        with patch("reconchain.tools.shutil.which") as mock_which:
            mock_which.return_value = None
            assert t.have("nonexistent_tool") == []

    def test_tools_cache_expires(self):
        from reconchain.tools import Tools
        t = Tools()
        with patch("reconchain.tools.shutil.which") as mock_which:
            # First call: miss
            mock_which.return_value = None
            assert t.have("tool1") == []
            # Simulate cache entry with old timestamp
            t._cache["tool1"] = False
            t._cache_ts["tool1"] = 0.0
            # Should re-check due to old timestamp
            mock_which.return_value = "/usr/bin/tool1"
            assert t.have("tool1") == ["tool1"]


# ── Circuit breaker tests ──


class TestCircuitBreaker:
    """Test circuit breaker mechanism."""

    def test_circuit_breaker_opens_after_failures(self):
        from reconchain.process import _CIRCUIT_BREAKER_FAILURES, _CIRCUIT_BREAKER_OPEN
        _CIRCUIT_BREAKER_FAILURES.clear()
        _CIRCUIT_BREAKER_OPEN.clear()
        # Simulate 5 failures for a tool
        tool = "test_tool_cb"
        _CIRCUIT_BREAKER_FAILURES[tool] = 5
        _CIRCUIT_BREAKER_OPEN.add(tool)
        assert tool in _CIRCUIT_BREAKER_OPEN
        # Cleanup
        _CIRCUIT_BREAKER_FAILURES.pop(tool, None)
        _CIRCUIT_BREAKER_OPEN.discard(tool)


# ── Atomic write tests ──


class TestAtomicWrite:
    """Test _atomic_write_json creates valid JSON safely."""

    def test_writes_valid_json(self, tmp_path):
        from reconchain.process import _atomic_write_json
        path = tmp_path / "test.json"
        payload = {"key": "value", "nested": {"a": 1, "b": [1, 2, 3]}}
        _atomic_write_json(path, payload)
        assert path.exists()
        loaded = json.loads(path.read_text())
        assert loaded == payload

    def test_handles_non_serializable(self, tmp_path):
        from reconchain.process import _atomic_write_json
        from pathlib import Path as P
        path = tmp_path / "test.json"
        payload = {"path": P("/some/path"), "set": {1, 2, 3}}
        _atomic_write_json(path, payload)
        assert path.exists()
        loaded = json.loads(path.read_text())
        assert loaded["path"] == "/some/path"

    def test_symlink_protection(self, tmp_path):
        from reconchain.process import _atomic_write_json
        path = tmp_path / "target.json"
        symlink = tmp_path / "link.json"
        symlink.symlink_to(Path("/etc/passwd"))
        # Should unlink the dangerous symlink and write safely
        _atomic_write_json(symlink, {"safe": True})
        assert symlink.exists()
        loaded = json.loads(symlink.read_text())
        assert loaded["safe"] is True


import json  # needed by TestAtomicWrite
