"""Subprocess management, job scheduling, and pipeline helpers."""
from __future__ import annotations
import argparse
import asyncio
import contextlib
import json
import math
import os
import resource
import shutil
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

from reconchain.config import VALID_PHASES, _HOSTNAME_RE, PipelineConfig, DISCOVERY_PHASES
from reconchain.utils import ensure, log, _set_proxy_env, _patch_socks, _unpatch_socks

try:
    from tqdm import tqdm
except ImportError:
    class tqdm:
        def __init__(self, *args, **kwargs): pass
        def update(self, n=1): pass
        def set_description(self, desc=None, refresh=True): pass
        def close(self): pass
        @classmethod
        def write(cls, msg="", *args, **kwargs): print(msg, flush=True)


@dataclass
class StepResult:
    name: str
    cmd: List[str]
    rc: int
    duration: float
    log_path: Optional[Path] = None
    note: str = ""


MAX_PARALLEL_JOBS = max(4, os.cpu_count() or 4)
_USE_PROXYCHAINS = False
_SPAWNED_PIDS: List[int] = []
_SPAWNED_PIDS_LOCK = threading.Lock()
_JOB_SEM: Optional[asyncio.Semaphore] = None
_PIPELINE_CFG: PipelineConfig = PipelineConfig()
_PROXY_TIMEOUT_MULTIPLIER: float = 1.5
_PROXY_LOCK: Optional[asyncio.Lock] = None
_TOOL_RC_REGISTRY: Dict[str, int] = {}
_TOOL_RC_LOCK = threading.Lock()  # protects _TOOL_RC_REGISTRY
_ENV_LOCK = threading.Lock()  # protects os.environ mutations from thread pool

# Circuit breaker: skip tools that fail repeatedly
_CIRCUIT_BREAKER_FAILURES: Dict[str, int] = {}
_CIRCUIT_BREAKER_THRESHOLD = 3  # After N consecutive failures, skip tool
_CIRCUIT_BREAKER_OPEN: Set[str] = set()
_CIRCUIT_BREAKER_LOCK = threading.Lock()

# Hard OS-level process counter — limits total concurrent subprocesses
# across all semaphore/gather paths. Scales with CPU count and available RAM.
# Each tool subprocess uses 100-500MB RAM, so cap accordingly.
from reconchain.resource_monitor import AdaptiveThreadSemaphore
_cpu_count = os.cpu_count() or 4
try:
    import psutil
    _avail_ram_gb = psutil.virtual_memory().available / (1024 ** 3)
except Exception:
    _avail_ram_gb = 8.0  # conservative default
# Allow 1 process per 500MB RAM, capped by CPU count, absolute max 12
_max_from_ram = max(2, int(_avail_ram_gb / 0.5))
MAX_OS_PROCS = min(12, max(4, min(_cpu_count * 2, _max_from_ram)))
_OS_PROC_SEM = AdaptiveThreadSemaphore(MAX_OS_PROCS)
_OS_PROC_ACTIVE = 0
_OS_PROC_ACTIVE_LOCK = threading.Lock()

# Per-child resource limits (in bytes / counts)
_CHILD_VMEM_LIMIT = 4 * 1024 * 1024 * 1024  # 4 GB virtual address space (safe for 15 GB VMs)
_CHILD_NPROC_LIMIT = 2048                    # max child processes per tool (xargs/nmap scripts need headroom)
_CHILD_FSIZE_LIMIT = 512 * 1024 * 1024        # 512 MB max output file size


def reset_globals() -> None:
    """Reset module-level globals for clean re-invocation (e.g., in tests).

    IMPORTANT: _PIPELINE_CFG is reset in-place (not replaced) so that
    references held by phase modules (via helpers.py) remain valid.
    Replacing the object would break _PIPELINE_CFG.safe_mode checks in phases.
    """
    global _USE_PROXYCHAINS, _JOB_SEM, _PROXY_TIMEOUT_MULTIPLIER
    global _OS_PROC_ACTIVE, _OS_PROC_SEM
    global _CIRCUIT_BREAKER_FAILURES, _CIRCUIT_BREAKER_OPEN
    # BUG 18 FIX: Stop monitor FIRST before replacing semaphores
    # to prevent old monitor thread from resizing stale semaphore
    from reconchain.resource_monitor import reset_resource_monitor
    reset_resource_monitor()
    _USE_PROXYCHAINS = False
    _JOB_SEM = None
    # Reset _PIPELINE_CFG in-place so phase modules keep a valid reference
    import dataclasses
    _default = PipelineConfig()
    for _f in dataclasses.fields(_default):
        setattr(_PIPELINE_CFG, _f.name, getattr(_default, _f.name))
    _PROXY_TIMEOUT_MULTIPLIER = 1.5
    _OS_PROC_ACTIVE = 0
    _OS_PROC_SEM = AdaptiveThreadSemaphore(MAX_OS_PROCS)
    _CIRCUIT_BREAKER_FAILURES = {}
    _CIRCUIT_BREAKER_OPEN = set()
    with _SPAWNED_PIDS_LOCK:
        _SPAWNED_PIDS.clear()
    with _TOOL_RC_LOCK:
        _TOOL_RC_REGISTRY.clear()
    from reconchain.utils import _unpatch_socks
    _unpatch_socks()


def _set_child_limits() -> None:
    """preexec_fn: apply resource limits to every spawned child process.

    Caps max child processes and max file size to prevent a single tool from
    exhausting the host's resources.  RLIMIT_AS is intentionally NOT set
    because Go binaries (amass, subfinder, etc.) allocate large *virtual*
    address spaces (>2 GB) while only using a fraction as RSS (~400 MB).
    Capping RLIMIT_AS kills Go processes with exit code 2.  Actual RAM
    pressure is handled by the ResourceMonitor's RSS-based circuit breaker.
    """
    _nproc = _CHILD_NPROC_LIMIT
    _fsize = _CHILD_FSIZE_LIMIT
    if _PIPELINE_CFG.safe_mode:
        _nproc = min(_nproc, 512)
        _fsize = min(_fsize, 128 * 1024 * 1024)       # 128 MB
    # NOTE: RLIMIT_AS is intentionally NOT set for safe mode.
    # Go binaries (amass, subfinder, etc.) need >2 GB virtual address space
    # but only use ~400 MB RSS.  Capping RLIMIT_AS kills them with exit code 2.
    # RAM pressure is handled by ResourceMonitor's RSS-based circuit breaker.
    try:
        resource.setrlimit(resource.RLIMIT_NPROC, (_nproc, _nproc))
    except (ValueError, OSError):
        pass
    try:
        resource.setrlimit(resource.RLIMIT_NPROC, (_nproc, _nproc))
    except (ValueError, OSError):
        pass
    try:
        resource.setrlimit(resource.RLIMIT_FSIZE, (_fsize, _fsize))
    except (ValueError, OSError):
        pass
    # Disable core dumps entirely — prevents coredump storm from broken
    # binaries (e.g. testssl openssl 1.0.2 segfaulting 80+ times)
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ValueError, OSError):
        pass


def _get_proxy_lock() -> asyncio.Lock:
    """Lazy-initialize _PROXY_LOCK on the running event loop."""
    global _PROXY_LOCK
    if _PROXY_LOCK is None:
        _PROXY_LOCK = asyncio.Lock()
    return _PROXY_LOCK


async def _run_limited(cmd: List[str], *, stdout: int = asyncio.subprocess.DEVNULL,
                       stderr: int = asyncio.subprocess.DEVNULL,
                       stdin: int = asyncio.subprocess.DEVNULL,
                       env: Optional[Dict[str, str]] = None,
                       timeout: float = 300) -> Tuple[int, bytes, bytes]:
    """Run a subprocess with RLIMIT_AS/RLIMIT_NPROC/RLIMIT_FSIZE applied.

    Like asyncio.create_subprocess_exec but with preexec_fn=_set_child_limits.
    Returns (returncode, stdout_bytes, stderr_bytes).
    """
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=stdout, stderr=stderr, stdin=stdin,
        start_new_session=True,
        preexec_fn=_set_child_limits,
        env=env,
    )
    try:
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return proc.returncode or 0, stdout_b or b"", stderr_b or b""
    except asyncio.TimeoutError:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            pass
        try:
            await asyncio.wait_for(proc.wait(), timeout=5)
        except (asyncio.TimeoutError, Exception):
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                pass
        return -1, b"", b""


def _needs_proxychains(cmd: List[str], *, proxychains: Optional[bool] = None) -> bool:
    if proxychains is None:
        proxychains = _USE_PROXYCHAINS
    if not proxychains:
        return False
    if len(cmd) < 2:
        return False
    # Python probe scripts (TLS check, SSRF, blind XSS) use raw sockets
    # that don't respect HTTP_PROXY env vars — they need proxychains.
    if cmd[0] in ("python3", "python") and isinstance(cmd[1], str) and cmd[1].endswith(".py"):
        return True
    # Standalone tools that don't respect proxy env vars natively
    if cmd[0] in ("waymore", "cloud_enum",
                   "wafw00f", "wafw00f.py", "gowitness", "gitdumper",
                   "Gxss", "kxss", "interactsh-client", "arjun"):
        return True
    # Bash runner scripts (generated by the pipeline in out_*/logs/) need proxychains,
    # except DNS tool wrappers — proxychains slows DNS queries unnecessarily.
    if cmd[0] == "bash" and isinstance(cmd[1], str) and cmd[1].endswith((".sh", ".bash")):
        script_name = Path(cmd[1]).stem.lower()
        for _t in _DNS_TOOLS:
            if _t == script_name or script_name.startswith(_t + ".") or script_name.startswith(_t + "-"):
                return False
        return True
    return False


def _proxify_cmd(cmd: List[str]) -> List[str]:
    """Prepend proxychains4 when SOCKS proxy is active and tool needs it."""
    snap = get_proxy_state()
    if _needs_proxychains(cmd, proxychains=snap["use_proxychains"]):
        return ["proxychains4"] + cmd
    return cmd


_PROXY_VARS = ["ALL_PROXY", "all_proxy", "HTTPS_PROXY", "https_proxy",
               "HTTP_PROXY", "http_proxy", "PROXY"]

_DNS_TOOLS = {"massdns", "dnsx", "puredns", "dig", "nslookup", "host", "subfinder", "amass"}
_RAW_TOOLS = {"nmap", "naabu"}

def _bypass_proxy(cmd: List[str]) -> bool:
    """Return True if the command should bypass the proxy entirely.
    DNS tools should NEVER go through SOCKS/proxychains — DNS resolution does
    not need anonymity and DNS-over-SOCKS is notoriously slow.
    Port scanners (nmap, naabu) also bypass — they use raw/stealth packets that
    cannot be routed through a TCP-only proxy."""
    if not cmd:
        return False
    if cmd[0] in _DNS_TOOLS | _RAW_TOOLS:
        return True
    # Bash wrappers of DNS tools (e.g., amass.sh) should also bypass proxy
    if cmd[0] == "bash" and len(cmd) > 1:
        script_name = Path(cmd[1]).stem.lower()
        for _t in _DNS_TOOLS | _RAW_TOOLS:
            if script_name == _t or script_name.startswith(_t + ".") or script_name.startswith(_t + "-"):
                return True
    return False


def _run_blocking(cmd: List[str], timeout: int, cwd: Optional[Path], log_path: Path) -> Tuple[int, float]:
    global _OS_PROC_ACTIVE
    cmd = _proxify_cmd(cmd)

    # Dry-run mode: print command and skip execution
    if os.environ.get("RECONCHAIN_DRY_RUN") == "1":
        dry_log = f"[DRY-RUN] {' '.join(cmd)}"
        log("info", dry_log)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("w") as f:
            f.write(dry_log + "\n")
        return 0, 0.0

    t0 = time.monotonic()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    err_path = log_path.with_suffix(log_path.suffix + ".stderr")

    # Save and clear proxy env for DNS tools (Go tools like dnsx respect ALL_PROXY natively)
    _saved_proxy: Dict[str, Optional[str]] = {}
    if _bypass_proxy(cmd):
        with _ENV_LOCK:
            for v in _PROXY_VARS:
                _saved_proxy[v] = os.environ.pop(v, None)

    # Block until we're within the hard OS process cap
    # BUG 14 FIX: Add timeout to prevent thread pool exhaustion
    if not _OS_PROC_SEM.acquire(blocking=True, timeout=120):
        log("warn", f"_OS_PROC_SEM acquire timed out after 120s, skipping: {cmd[0]}")
        return 125, time.monotonic() - t0  # 125 = resource unavailable
    with _OS_PROC_ACTIVE_LOCK:
        _OS_PROC_ACTIVE += 1
    try:
        with log_path.open("wb") as logf, err_path.open("wb") as errf:
            proc: Optional[subprocess.Popen[bytes]] = None
            try:
                proc = subprocess.Popen(
                    cmd,
                    cwd=str(cwd) if cwd else None,
                    stdin=subprocess.DEVNULL,
                    stdout=logf,
                    stderr=errf,
                    start_new_session=True,
                    preexec_fn=_set_child_limits,
                )
                _register_proc(proc)
                if not _wait_proc(proc, timeout):
                    _kill_proc(proc)
                    with log_path.open("ab") as f:
                        f.write(f"\n[timeout after {timeout}s]\n".encode("utf-8"))
                    return 124, time.monotonic() - t0
                return proc.returncode, time.monotonic() - t0
            except FileNotFoundError as e:
                with log_path.open("ab") as f:
                    f.write(f"\n[binary not found: {e}]\n".encode("utf-8"))
                return 127, time.monotonic() - t0
            except (PermissionError, OSError) as e:
                with log_path.open("ab") as f:
                    f.write(f"\n[exec error: {e}]\n".encode("utf-8"))
                return 127, time.monotonic() - t0
            finally:
                if proc is not None:
                    with _SPAWNED_PIDS_LOCK, contextlib.suppress(ValueError):
                        _SPAWNED_PIDS.remove(proc.pid)
    finally:
        with _OS_PROC_ACTIVE_LOCK:
            _OS_PROC_ACTIVE = max(0, _OS_PROC_ACTIVE - 1)
        _OS_PROC_SEM.release()
        # Restore proxy env vars after DNS tool completes
        if _saved_proxy:
            with _ENV_LOCK:
                for v, val in _saved_proxy.items():
                    if val is not None:
                        os.environ[v] = val


async def _run(name: str, cmd: List[str], timeout: int, outdir: Path, note: str = "", quiet: bool = False) -> StepResult:
    # Circuit breaker: skip tools that have failed too many times
    tool_name = cmd[0] if cmd else ""
    with _CIRCUIT_BREAKER_LOCK:
        if tool_name and tool_name in _CIRCUIT_BREAKER_OPEN:
            if not quiet:
                log("warn", f"{name}: skipping {tool_name} (circuit breaker open after {_CIRCUIT_BREAKER_FAILURES.get(tool_name, 0)} failures)")
            return StepResult(name, cmd, 0, 0.0, outdir / "logs" / f"{name}.log", note=note or "circuit breaker")

    if not cmd:
        log("skip", f"{name} (missing tool)")
        return StepResult(name, [], 0, 0.0, outdir / "logs" / f"{name}.log", note=note or "skipped")
    logp = outdir / "logs" / f"{name}.log"
    if not quiet:
        log("info", f"{name}  $ {cmd[0]} {(' '.join(cmd[1:3]))}{' ...' if len(cmd) > 3 else ''}")

    async def _exec() -> StepResult:
        rc, dur = await asyncio.to_thread(_run_blocking, cmd, timeout, outdir, logp)
        lvl = "ok" if rc == 0 else "warn" if rc in (1, 2, 124, 127) or rc < 0 else "err"
        if not quiet:
            log(lvl, f"{name} -> rc={rc} in {dur:.1f}s")
        if rc not in (0, None) and note != "skipped":
            with _TOOL_RC_LOCK:
                _TOOL_RC_REGISTRY[name] = rc
        # Circuit breaker tracking — only count real failures, not normal exit codes (1-2 = no findings)
        if tool_name:
            with _CIRCUIT_BREAKER_LOCK:
                if rc not in (0, 1, 2, None):
                    _CIRCUIT_BREAKER_FAILURES[tool_name] = _CIRCUIT_BREAKER_FAILURES.get(tool_name, 0) + 1
                    if _CIRCUIT_BREAKER_FAILURES[tool_name] >= _CIRCUIT_BREAKER_THRESHOLD:
                        _CIRCUIT_BREAKER_OPEN.add(tool_name)
                        log("warn", f"Circuit breaker OPEN for {tool_name}: {_CIRCUIT_BREAKER_FAILURES[tool_name]} consecutive failures — skipping for rest of scan")
                else:
                    _CIRCUIT_BREAKER_FAILURES[tool_name] = 0
        return StepResult(name, cmd, rc, dur, logp, note=note)

    sem = _JOB_SEM
    if sem is not None:
        async with sem:
            return await _exec()
    return await _exec()


def _wait_proc(proc: subprocess.Popen, timeout: int) -> bool:
    try:
        proc.wait(timeout=timeout)
        return True
    except subprocess.TimeoutExpired:
        return False


def _kill_proc(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        return
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
    # Final reap to prevent zombie
    try:
        proc.wait(timeout=1)
    except (subprocess.TimeoutExpired, OSError):
        pass


def _cleanup_child_procs() -> None:
    if not _SPAWNED_PIDS_LOCK.acquire(timeout=5):
        return
    try:
        pids_to_kill = list(_SPAWNED_PIDS)
        _SPAWNED_PIDS.clear()
    finally:
        _SPAWNED_PIDS_LOCK.release()
    for pid in pids_to_kill:
        try:
            os.kill(pid, 0)  # Check if process exists
        except (ProcessLookupError, PermissionError, OSError):
            continue
        with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
            os.killpg(pid, signal.SIGTERM)


def _register_proc(proc: subprocess.Popen) -> None:
    with _SPAWNED_PIDS_LOCK:
        _SPAWNED_PIDS.append(proc.pid)


def _maybe_timeout(base: int) -> int:
    snap = get_proxy_state()
    return int(base * snap["timeout_mult"]) if snap["use_proxychains"] else base


_PROXY_STATE_STACK: List[Dict[str, Any]] = []
_PROXY_SNAPSHOT: Dict[str, Any] = {"use_proxychains": False, "proxy": "", "timeout_mult": 1.5}
_PROXY_SNAPSHOT_LOCK = threading.Lock()


def get_proxy_state() -> Dict[str, Any]:
    """Thread-safe snapshot of current proxy state for readers."""
    with _PROXY_SNAPSHOT_LOCK:
        return dict(_PROXY_SNAPSHOT)

async def _push_phase_proxy(name: str, proxy: str, vuln_proxy: str) -> None:
    """Save current proxy state and set it for the given phase.
    Vuln phases use `vuln_proxy` (or `proxy` as fallback).
    Discovery phases bypass proxy entirely (DNS/port tools don't work over SOCKS)."""
    global _USE_PROXYCHAINS, _PIPELINE_CFG, _PROXY_TIMEOUT_MULTIPLIER, _PROXY_STATE_STACK
    lock = _get_proxy_lock()
    async with lock:
        is_discovery = name in DISCOVERY_PHASES
        phase_proxy = proxy if is_discovery else (vuln_proxy or proxy)

        _PROXY_STATE_STACK.append({
            "_USE_PROXYCHAINS": _USE_PROXYCHAINS,
            "_PIPELINE_CFG_proxy": _PIPELINE_CFG.proxy,
            "_PROXY_TIMEOUT_MULTIPLIER": _PROXY_TIMEOUT_MULTIPLIER,
            "_env": {v: os.environ.get(v) for v in _PROXY_VARS},
        })

        if phase_proxy and not is_discovery:
            _set_proxy_env(phase_proxy)
            _USE_PROXYCHAINS = bool(shutil.which("proxychains4") and phase_proxy.startswith("socks"))
            _PIPELINE_CFG.proxy = phase_proxy
            _PROXY_TIMEOUT_MULTIPLIER = _PIPELINE_CFG.proxy_timeout_multiplier
            if phase_proxy.startswith(("socks4://", "socks5://", "socks5h://", "socks4a://")):
                _patch_socks(phase_proxy)
        else:
            _USE_PROXYCHAINS = False
            _PIPELINE_CFG.proxy = ""
            with _ENV_LOCK:
                for v in _PROXY_VARS:
                    os.environ.pop(v, None)
            _unpatch_socks()
        with _PROXY_SNAPSHOT_LOCK:
            _PROXY_SNAPSHOT["use_proxychains"] = _USE_PROXYCHAINS
            _PROXY_SNAPSHOT["proxy"] = _PIPELINE_CFG.proxy
            _PROXY_SNAPSHOT["timeout_mult"] = _PROXY_TIMEOUT_MULTIPLIER


async def _pop_phase_proxy() -> None:
    """Restore the proxy state saved by _push_phase_proxy."""
    global _USE_PROXYCHAINS, _PIPELINE_CFG, _PROXY_TIMEOUT_MULTIPLIER, _PROXY_STATE_STACK
    lock = _get_proxy_lock()
    async with lock:
        if not _PROXY_STATE_STACK:
            return
        saved = _PROXY_STATE_STACK.pop()
        _unpatch_socks()
        _USE_PROXYCHAINS = saved["_USE_PROXYCHAINS"]
        _PIPELINE_CFG.proxy = saved["_PIPELINE_CFG_proxy"]
        _PROXY_TIMEOUT_MULTIPLIER = saved["_PROXY_TIMEOUT_MULTIPLIER"]
        for v, val in saved["_env"].items():
            with _ENV_LOCK:
                if val is not None:
                    os.environ[v] = val
                else:
                    os.environ.pop(v, None)
        if _PIPELINE_CFG.proxy and _PIPELINE_CFG.proxy.startswith(("socks4://", "socks5://", "socks5h://", "socks4a://")):
            _patch_socks(_PIPELINE_CFG.proxy)
        with _PROXY_SNAPSHOT_LOCK:
            _PROXY_SNAPSHOT["use_proxychains"] = _USE_PROXYCHAINS
            _PROXY_SNAPSHOT["proxy"] = _PIPELINE_CFG.proxy
            _PROXY_SNAPSHOT["timeout_mult"] = _PROXY_TIMEOUT_MULTIPLIER


async def run_parallel(jobs: List[Tuple[str, List[str], int]], outdir: Path, desc: str = "jobs", quiet: bool = False) -> List[StepResult]:
    pbar = tqdm(total=len(jobs), desc=desc, leave=False)

    async def _run_and_update(n: str, c: List[str], t: int) -> StepResult:
        res = await _run(n, c, t, outdir, quiet=quiet)
        pbar.update(1)
        return res

    # Safe mode: run jobs serially to avoid memory spikes from parallel tools
    if _PIPELINE_CFG.safe_mode and len(jobs) > 1:
        results: List[StepResult] = []
        for n, c, t in jobs:
            results.append(await _run_and_update(n, c, t))
        pbar.close()
        return results
    coros = [_run_and_update(n, c, t) for n, c, t in jobs]
    try:
        return await asyncio.gather(*coros)
    finally:
        pbar.close()


async def _update_nuclei_templates(outdir: Path, proxy: str = "") -> None:
    if not shutil.which("nuclei"):
        return
    cache_stamp = outdir / ".nuclei_update_stamp"
    if cache_stamp.exists():
        try:
            age = time.time() - float(cache_stamp.read_text(encoding="utf-8", errors="ignore").strip())
            if age < 86400:
                return
        except (ValueError, OSError):
            pass
    log("info", "Updating nuclei templates...")
    _proxy = proxy or _PIPELINE_CFG.proxy
    _nu_cmd = ["nuclei", "-update-templates", "-silent"]
    if _proxy:
        _nu_cmd += ["-proxy", _proxy]
    _nu_cmd = _proxify_cmd(_nu_cmd)
    # Gate behind OS process counter so template updates don't consume
    # a slot that could be used by actual recon tools.
    if not await asyncio.to_thread(_OS_PROC_SEM.acquire, blocking=True, timeout=120):
        log("warn", "nuclei template update: OS process semaphore timed out")
        return
    try:
        rc, _, _ = await _run_limited(_nu_cmd, timeout=120)
        if rc == 0:
            cache_stamp.write_text(str(time.time()))
        else:
            log("warn", f"nuclei -update-templates returned {rc}")
    finally:
        _OS_PROC_SEM.release()


def _atomic_write_json(path: Path, payload: dict) -> None:
    import tempfile
    ensure(path)
    if path.is_symlink():
        real = path.resolve()
        if not real.is_relative_to(path.parent.resolve()):
            path.unlink()
    fd, tmp_path = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(payload, f, indent=2, default=str)
        os.replace(tmp_path, path)
    except Exception:
        with contextlib.suppress(Exception):
            os.unlink(tmp_path)
        raise
    # Verify the write succeeded and the target is a regular file (not a symlink
    # swapped by an attacker between mkstemp and os.replace)
    if path.is_symlink():
        real = path.resolve()
        if not real.is_relative_to(path.parent.resolve()):
            path.unlink()


def _parse_phase_csv(value: str) -> Set[str]:
    """Parse comma-separated phase list, case-insensitively matching VALID_PHASES.
    Accepts e.g. '04b-TAKEOVER-VALIDATE' or '04B-takeover-validate'."""
    normalized_map = {p.upper(): p for p in VALID_PHASES}
    raw = {p.strip() for p in value.split(",") if p.strip()}
    phases = set()
    for p in raw:
        p_upper = p.upper()
        if p_upper in normalized_map:
            phases.add(normalized_map[p_upper])
        elif p in VALID_PHASES:
            phases.add(p)
        else:
            invalid = sorted(raw - set(normalized_map.values()) - set(normalized_map.keys()))
            raise argparse.ArgumentTypeError(
                f"unknown phase(s): {', '.join(invalid)}; valid phases: "
                f"{', '.join(sorted(VALID_PHASES))}"
            )
    return phases


def _domain_arg(value: str) -> str:
    domain = value.rstrip(".").lower()
    if not _HOSTNAME_RE.match(domain) or "." not in domain:
        raise argparse.ArgumentTypeError(
            "domain must be a valid DNS name with at least one dot, for example example.com"
        )
    return domain


def _csv_from_phases(value: object) -> Set[str]:
    if isinstance(value, set):
        return set(value)
    if isinstance(value, str):
        return _parse_phase_csv(value)
    return set()
