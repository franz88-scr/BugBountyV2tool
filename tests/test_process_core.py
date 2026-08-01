"""Focused unit tests for core process/pipeline safety helpers.

Targets the pure, side-effect-free logic in vulnforge.process and
vulnforge.pipeline that the subprocess/spawn paths otherwise exercise
only in slow integration runs. No real subprocesses are spawned here.
"""

import argparse
import sys
from pathlib import Path
from typing import Any, Dict, Set

import pytest

from vulnforge.exceptions import InsufficientResourcesError

import vulnforge.process as proc
import vulnforge.pipeline as pipe


# ── vulnforge.process ──────────────────────────────────────────────────────


class TestNeedsProxychains:
    def test_disabled_returns_false(self) -> None:
        assert proc._needs_proxychains(["arjun", "-u", "x"], proxychains=False) is False

    def test_short_cmd_returns_false(self) -> None:
        assert proc._needs_proxychains(["arjun"], proxychains=True) is False

    def test_python_probe_script(self) -> None:
        assert proc._needs_proxychains(["python3", "probe.py"], proxychains=True) is True

    def test_non_probe_python(self) -> None:
        assert proc._needs_proxychains(["python3", "-m", "http.server"], proxychains=True) is False

    def test_raw_socket_tool(self) -> None:
        for tool in ("waymore", "gowitness", "arjun", "kxss"):
            assert proc._needs_proxychains([tool, "-x"], proxychains=True) is True

    def test_bash_runner_script(self) -> None:
        assert proc._needs_proxychains(["bash", "logs/run.sh"], proxychains=True) is True

    def test_dns_bash_wrapper_bypasses(self) -> None:
        assert proc._needs_proxychains(["bash", "logs/findomain.sh"], proxychains=True) is False
        assert proc._needs_proxychains(["bash", "logs/dnsx-1.sh"], proxychains=True) is False


class TestProxifyCmd:
    def test_prepends_proxychains_when_needed(self, monkeypatch) -> None:
        monkeypatch.setattr(
            proc, "_PROXY_SNAPSHOT", {"use_proxychains": True, "proxy": "socks5://x", "timeout_mult": 1.5}
        )
        assert proc._proxify_cmd(["arjun", "-u", "x"]) == ["proxychains4", "arjun", "-u", "x"]

    def test_unchanged_when_not_needed(self, monkeypatch) -> None:
        monkeypatch.setattr(
            proc, "_PROXY_SNAPSHOT", {"use_proxychains": True, "proxy": "socks5://x", "timeout_mult": 1.5}
        )
        assert proc._proxify_cmd(["httpx", "-l", "urls.txt"]) == ["httpx", "-l", "urls.txt"]

    def test_unchanged_when_proxy_inactive(self, monkeypatch) -> None:
        monkeypatch.setattr(
            proc, "_PROXY_SNAPSHOT", {"use_proxychains": False, "proxy": "", "timeout_mult": 1.5}
        )
        assert proc._proxify_cmd(["arjun", "-u", "x"]) == ["arjun", "-u", "x"]


class TestMaybeTimeout:
    def test_multiplied_under_proxychains(self, monkeypatch) -> None:
        monkeypatch.setattr(
            proc, "_PROXY_SNAPSHOT", {"use_proxychains": True, "proxy": "socks5://x", "timeout_mult": 1.5}
        )
        assert proc._maybe_timeout(300) == 450

    def test_unchanged_without_proxy(self, monkeypatch) -> None:
        monkeypatch.setattr(
            proc, "_PROXY_SNAPSHOT", {"use_proxychains": False, "proxy": "", "timeout_mult": 1.5}
        )
        assert proc._maybe_timeout(300) == 300


class TestAppendLog:
    def test_appends_bytes_and_creates_file(self, tmp_path: Path) -> None:
        log_path = tmp_path / "tool.log"
        proc._append_log(log_path, "first line\n")
        proc._append_log(log_path, "second line\n")
        assert log_path.read_bytes() == b"first line\nsecond line\n"
        assert (log_path.stat().st_mode & 0o777) == 0o644

    def test_missing_parent_swallowed(self, tmp_path: Path) -> None:
        proc._append_log(tmp_path / "nonexistent" / "x.log", "text")


class TestParsePhaseCsv:
    def test_case_insensitive_matching(self) -> None:
        assert proc._parse_phase_csv("04B-takeover-validate") == {"04b-TAKEOVER-VALIDATE"}

    def test_multiple_phases(self) -> None:
        got = proc._parse_phase_csv("01-RECON, 05-HARVEST, 09-VULNSCAN")
        assert got == {"01-RECON", "05-HARVEST", "09-VULNSCAN"}

    def test_empty_string(self) -> None:
        assert proc._parse_phase_csv("") == set()

    def test_invalid_phase_raises(self) -> None:
        with pytest.raises(argparse.ArgumentTypeError):
            proc._parse_phase_csv("99-NOPE")


class TestCsvFromPhases:
    def test_set_passthrough(self) -> None:
        assert proc._csv_from_phases({"01-RECON"}) == {"01-RECON"}

    def test_string_delegates(self) -> None:
        assert proc._csv_from_phases("01-RECON") == {"01-RECON"}

    def test_other_types_return_empty(self) -> None:
        assert proc._csv_from_phases(None) == set()
        assert proc._csv_from_phases(["01-RECON"]) == set()


class TestResetGlobals:
    def test_resets_state(self) -> None:
        proc.reset_globals()
        assert proc._USE_PROXYCHAINS is False
        assert proc._JOB_SEM is None
        assert proc._CIRCUIT_BREAKER_FAILURES == {}
        assert proc._CIRCUIT_BREAKER_OPEN == set()


class TestAsyncJobScheduler:
    def test_stats_initial(self) -> None:
        sched = proc.AsyncJobScheduler(max_concurrent=2, adaptive=False)
        stats = sched.stats
        assert stats["base_concurrency"] == 2
        assert stats["current_concurrency"] == 2
        assert stats["completed"] == 0
        assert stats["failed"] == 0

    def test_default_concurrency_at_least_four(self) -> None:
        sched = proc.AsyncJobScheduler(adaptive=False)
        assert sched._base_concurrency >= 4


# ── vulnforge.pipeline ─────────────────────────────────────────────────────


class TestSnapshotFindings:
    def _write(self, tmp_path: Path, name: str, lines: list) -> None:
        (tmp_path / name).write_text("\n".join(lines) + "\n")

    def test_reads_txt_files_skipping_blanks_and_comments(self, tmp_path: Path) -> None:
        self._write(tmp_path, "a.txt", ["host1", "# comment", "", "host2"])
        self._write(tmp_path, "b.txt", ["item"])
        snap: Dict[str, Set[str]] = pipe._snapshot_findings(tmp_path)
        assert snap["a.txt"] == {"host1", "host2"}
        assert snap["b.txt"] == {"item"}

    def test_ignores_dotfiles(self, tmp_path: Path) -> None:
        self._write(tmp_path, ".hidden.txt", ["secret"])
        assert pipe._snapshot_findings(tmp_path) == {}


class TestDiffFindings:
    def test_writes_new_entries_and_summary(self, tmp_path: Path) -> None:
        before = {"urls.txt": {"a", "b"}}
        after = {"urls.txt": {"a", "b", "c"}}
        pipe._diff_findings(before, after, tmp_path)
        diff_dir = tmp_path / "diff"
        assert (diff_dir / "new_urls.txt").read_text().strip() == "c"
        assert "New findings: 1" in (diff_dir / "summary.txt").read_text()

    def test_no_changes_writes_no_files(self, tmp_path: Path) -> None:
        before = {"urls.txt": {"a"}}
        pipe._diff_findings(before, dict(before), tmp_path)
        assert not (tmp_path / "diff" / "new_urls.txt").exists()


def _install_fake_psutil(
    monkeypatch: pytest.MonkeyPatch, *, total_gb: float, avail_gb: float, swap_gb: float
) -> None:
    class _Mem:
        total = int(total_gb * 1024**3)
        available = int(avail_gb * 1024**3)
        percent = 50.0

    class _Swap:
        total = int(swap_gb * 1024**3)
        used = int(swap_gb * 1024**3 * 0.1)

    fake = type("psutil", (), {"virtual_memory": lambda: _Mem(), "swap_memory": lambda: _Swap()})
    monkeypatch.setitem(sys.modules, "psutil", fake)


class TestPreflightMemoryCheck:
    def test_raises_when_total_ram_below_minimum(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_psutil(monkeypatch, total_gb=3.0, avail_gb=2.5, swap_gb=4.0)
        with pytest.raises(InsufficientResourcesError):
            pipe._preflight_memory_check()

    def test_raises_when_available_ram_below_minimum(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_psutil(monkeypatch, total_gb=16.0, avail_gb=1.5, swap_gb=4.0)
        with pytest.raises(InsufficientResourcesError):
            pipe._preflight_memory_check()

    def test_passes_with_adequate_ram(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_psutil(monkeypatch, total_gb=16.0, avail_gb=8.0, swap_gb=4.0)
        pipe._preflight_memory_check()
