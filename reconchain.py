#!/usr/bin/env python3
"""
reconchain.py — orchestrator for a chained recon pipeline.
Pipeline
========
A1  subfinder | amass | assetfinder  --> all_subs.txt
A2  dnsx                            --> resolved.txt
B1  naabu | httpx | subjack         --> ports.txt / hosts.txt / takeover.txt
C1  gau+waybackurls | gospider      --> urls_gau.txt  (parallel)
    katana | subjs                  --> urls_katana.txt
C2  LinkFinder | SecretFinder       --> js_secrets.txt
D   ParamSpider | Arjun | x8        --> params.txt
E   ffuf | kiterunner | feroxbuster --> fuzz.txt
F1  nuclei (full) | tech-scanner    --> nuclei.txt
F2  testssl.sh | wpscan             --> tls_wp.txt
G   dalfox | sqlmap | ssrf-probes   --> vulns.txt
H   interactsh (background since E) --> oast/callbacks.txt
I   dedup + summary.json / report.html / report.md
Usage
-----
  reconchain.py -d example.com -o ./out
  reconchain.py -d example.com --only A1,A2,B1
  reconchain.py -d example.com --skip F2,G
  reconchain.py -d example.com --resume           # reuse ./out/state.json
  reconchain.py -d example.com --fast             # fast: A1→A2→B1→C1→report
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
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
# tqdm is an OPTIONAL dependency. The orchestrator must stay runnable with the
# stdlib alone (see module docstring + empty pyproject `dependencies`), so when
# tqdm is absent we fall back to a tiny no-op shim that preserves the small
# surface we use (`tqdm(...)` bars with update/set_description/close and the
# `tqdm.write` classmethod). Install tqdm for live progress bars.
try:
    from tqdm import tqdm
except ImportError:
    class tqdm:  # type: ignore[no-redef]
        def __init__(self, *args: Any, total: Optional[int] = None,
                     desc: Optional[str] = None, **kwargs: Any) -> None:
            self.total = total
            self.desc = desc

        def update(self, n: int = 1) -> None:
            pass

        def set_description(self, desc: Optional[str] = None,
                            refresh: bool = True) -> None:
            self.desc = desc

        def close(self) -> None:
            pass

        @classmethod
        def write(cls, msg: str = "", *args: Any, **kwargs: Any) -> None:
            print(msg, flush=True)
# ─────────────────────── hostname validation (chain glue) ────────────────────
# Used by the A1 merge and the A2 parse to filter obvious garbage out of the
# chain. Accepts DNS hostnames: 1-253 chars, dot-separated labels of
# [a-z0-9-], with no leading or trailing hyphen in labels.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)
__version__ = "1.2.0"
VALID_PHASES = {"A1", "A2", "B1", "C1", "C2", "D", "E", "F1", "F2", "G", "G2",
                "H", "I", "J", "K", "L"}
FAST_PHASES = {"A1", "A2", "B1", "C1", "I"}
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
    "r":  "\033[0m" if _color() else "",
    "d":  "\033[2m"  if _color() else "",
    "g":  "\033[32m" if _color() else "",
    "y":  "\033[33m" if _color() else "",
    "b":  "\033[34m" if _color() else "",
    "c":  "\033[36m" if _color() else "",
    "m":  "\033[35m" if _color() else "",
    "red": "\033[31m" if _color() else "",
}
LVL = {"info": C["c"], "ok": C["g"], "warn": C["y"],
       "err": C["red"], "skip": C["d"]}
def disable_color() -> None:
    for key in C:
        C[key] = ""
    for key in LVL:
        LVL[key] = ""

def log(lvl: str, msg: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    tqdm.write(
        f"{C['d']}{ts}{C['r']} {LVL[lvl]}[{lvl.upper():4}]{C['r']} {msg}"
    )
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
class StepResult:
    name: str
    cmd: List[str]
    rc: int
    duration: float
    log_path: Optional[Path] = None
    note: str = ""
def _run_blocking(cmd: List[str], timeout: int, cwd: Optional[Path],
                  log_path: Path) -> Tuple[int, float]:
    t0 = time.monotonic()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("wb") as logf:
        proc: Optional[subprocess.Popen[bytes]] = None
        try:
            proc = subprocess.Popen(
                cmd, cwd=str(cwd) if cwd else None,
                stdout=logf, stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            proc.wait(timeout=timeout)
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
            with log_path.open("ab") as f:
                f.write(f"\n[timeout after {timeout}s]\n".encode("utf-8"))
            return 124, time.monotonic() - t0
        except FileNotFoundError as e:
            with log_path.open("ab") as f:
                f.write(f"\n[binary not found: {e}]\n".encode("utf-8"))
            return 127, time.monotonic() - t0
async def _run(name: str, cmd: List[str], timeout: int, outdir: Path,
               note: str = "") -> StepResult:
    logp = outdir / "logs" / f"{name}.log"
    if not cmd:
        log("skip", f"{name} (missing tool)")
        return StepResult(name, [], 0, 0.0, logp, note=note or "skipped")
    log("info", f"{name}  $ {cmd[0]} {(' '.join(cmd[1:3]))}{' …' if len(cmd) > 3 else ''}")
    rc, dur = await asyncio.to_thread(_run_blocking, cmd, timeout, outdir, logp)
    lvl = "ok" if rc == 0 else "warn" if rc in (124, 127) else "err"
    log(lvl, f"{name} → rc={rc} in {dur:.1f}s")
    return StepResult(name, cmd, rc, dur, logp, note=note)
# Concurrency cap so a phase with many jobs (e.g. phase E: 5 URLs × 3 fuzzers)
# does not fork-bomb the host. 16 parallel external procs is a good default;
# pass -j/--jobs to override.
MAX_PARALLEL_JOBS = 16
# Process-wide job semaphore. When several independent phases run concurrently
# (see STAGES), they all draw from this single semaphore so the total number of
# live external processes stays bounded by MAX_PARALLEL_JOBS regardless of how
# many phases are in flight. Created on the running loop in run_pipeline; falls
# back to a fresh per-call semaphore when unset (e.g. a phase called directly
# from a test).
_JOB_SEM: Optional[asyncio.Semaphore] = None
class Progress:
    def __init__(self, total: int):
        self.bar = tqdm(total=total, desc="Pipeline", position=0)

    def next(self, name: str):
        self.bar.set_description(f"Phase {name}")
        self.bar.update(1)

    def close(self):
        self.bar.close()
async def run_parallel(jobs: List[Tuple[str, List[str], int]],
    outdir: Path,
    desc: str = "jobs") -> List[StepResult]:
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
    return [ln.strip() for ln in p.read_text(errors="ignore").splitlines()
            if ln.strip() and not ln.startswith("#")]
def count_nonblank(p: Path) -> int:
    """Count of non-blank lines (does NOT drop `#`-prefixed lines)."""
    if not p.is_file():
        return 0
    return sum(1 for ln in p.read_text(errors="ignore").splitlines() if ln.strip())
def merge_unique(srcs: List[Path], dst: Path,
                 validator: Optional[Callable[[str], bool]] = None) -> int:
    seen: Set[str] = set()
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
                seen.add(ln)
    ensure(dst)
    dst.write_text("\n".join(sorted(seen)) + ("\n" if seen else ""))
    return len(seen)
def safe_suffix(s: str) -> str:
    """Deterministic, low-collision file suffix. Uses the first 12 hex
    chars of sha1(s) — collision odds are astronomically small for any
    realistic input set, unlike the old `(int(h[:8],16) % 9999)`."""
    return hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()[:12]
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
    """Background OOB collector. Start before phase E, stop at phase H."""
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
            self.proc = subprocess.Popen(cmd, stdout=self._log_fh,
                                         stderr=subprocess.STDOUT)
        except FileNotFoundError:
            return False
        except Exception as e:
            log("err", f"interactsh start failed: {e}")
            self._kill_proc()
            return False
        # remember the byte offset where this run's output begins
        self._start_pos = self.log.stat().st_size
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
                    clean = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', ln).strip()
                    # Old format: "Domain: <domain>"
                    if "Domain" in clean and ":" in clean:
                        cand = clean.split(":", 1)[1].strip()
                        if cand and "." in cand and " " not in cand:
                            self.domain = cand
                            log("ok", f"interactsh domain: {self.domain}")
                            return True
                    # New format: "[INF] <subdomain>.oast.<tld>"
                    # Match lines that look like a bare hostname after [INF]
                    if re.search(r'[a-zA-Z0-9-]+\.oast\.[a-z]+', clean):
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
                            events.append({
                                "ts":   ev.get("timestamp"),
                                "proto": ev.get("protocol"),
                                "id":   ev.get("unique-id"),
                                "from": ev.get("remote-address"),
                                "domain": self.domain,
                            })
        except FileNotFoundError:
            pass
        with out.open("w") as f:
            for e in events:
                f.write(json.dumps(e) + "\n")
        log("ok", f"interactsh: {len(events)} OOB callback(s) captured")
        return out
# ─────────────────────────── phase implementations ─────────────────────────
# small helper: hostname token safety check
_SAFE_HOST = re.compile(r"^[A-Za-z0-9.\-]+$")
async def phase_A1(domain: str, outdir: Path, t: Tools,
                   only: PhaseSet, skip: PhaseSet,
                   resume: bool = False) -> Dict[str, Any]:
    if skip & {"A1"}:
        return {}
    out = outdir / "all_subs.txt"
    # Skip when output already exists, EITHER because --resume is set OR
    # because the user didn't pin A1 with --only. The previous condition
    # (`only.isdisjoint({"A1"})`) silently disabled resume for any
    # --only invocation, forcing a re-run even though the file was good.
    if out.exists() and (resume or only.isdisjoint({"A1"})):
        return {"A1": str(out), "count": count_nonblank(out)}
    log("info", "Phase A1: subdomain enumeration")
    jobs: List[Tuple[str, List[str], int]] = []
    if t.has("subfinder"):
        jobs.append(("subfinder",
                     ["subfinder", "-d", domain, "-silent",
                      "-o", str(outdir / "subs_subfinder.txt")], 900))
    if t.has("amass"):
        # amass v4: passive is the default (the old `-passive` flag is
        # deprecated) and `enum` emits *relationship* records on stdout, e.g.
        #   `sub.example.com (FQDN) --> a_record --> 1.2.3.4 (IPAddress)`
        # (the `-o` file holds the same raw terminal text, NOT a clean list).
        # Feeding those lines straight into the merge made every line fail the
        # hostname validator, so amass silently contributed zero subdomains.
        # Run via a runner that extracts the `<name> (FQDN)` tokens; the A1
        # merge's _under_domain validator then keeps only in-scope hosts.
        runner = outdir / "logs" / "amass.sh"
        ensure(runner)
        runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -u\n"
            f"OUT={shlex.quote(str(outdir / 'subs_amass.txt'))}\n"
            f"DOMAIN={shlex.quote(domain)}\n"
            ": > \"$OUT\"\n"
            "amass enum -d \"$DOMAIN\" -nocolor 2>/dev/null "
            "| grep --line-buffered -oE '[A-Za-z0-9._-]+ \\(FQDN\\)' "
            "| sed 's/ (FQDN)$//' >> \"$OUT\" || true\n"
        )
        runner.chmod(0o755)
        jobs.append(("amass", ["bash", str(runner)], 1800))
    if t.has("assetfinder"):
        # use a small runner so we invoke assetfinder directly with proper
        # argv quoting (no shell, no risk of injection from `domain`).
        runner = outdir / "logs" / "assetfinder.sh"
        ensure(runner)
        runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -u\n"
            f"OUT={shlex.quote(str(outdir / 'subs_assetfinder.txt'))}\n"
            f"DOMAIN={shlex.quote(domain)}\n"
            ": > \"$OUT\"\n"
            "assetfinder --subs-only \"$DOMAIN\" >> \"$OUT\" 2>/dev/null || true\n"
        )
        runner.chmod(0o755)
        jobs.append(("assetfinder", ["bash", str(runner)], 600))
    if not jobs:
        log("warn", "A1: no subdomain tools available")
    results = await run_parallel(jobs, outdir)
    # Surface partial tool failures in summary.json (BUG-5). rc==0 and
    # skipped are not failures; anything else (timeouts, crash, signal)
    # is recorded so the user knows the merged output may be partial.
    failures = {r.name: r.rc for r in results
                if r.rc not in (0, None) and r.note != "skipped"}
    # Merge + drop anything that isn't a hostname under `-d`. subfinder
    # frequently emits bare tokens (e.g. registered-domain-only entries
    # from CT logs) which would otherwise flow into A2 / naabu / httpx
    # as "hosts" and waste hours of scan time on unresolvable garbage.
    def _under_domain(s: str) -> bool:
        return _is_valid_hostname(s) and _is_under_domain(s, domain)
    n = merge_unique([outdir / "subs_subfinder.txt",
                      outdir / "subs_amass.txt",
                      outdir / "subs_assetfinder.txt"], out,
                     validator=_under_domain)
    log("ok", f"A1: {n} unique subdomains → {out}")
    ret: Dict[str, Any] = {"A1": str(out), "count": n}
    if failures:
        ret["failures"] = failures
        log("warn", f"A1: partial — failed tools: {failures}")
    return ret
async def phase_A2(domain: str, outdir: Path, t: Tools,
                   only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any],
                   resume: bool = False) -> Dict[str, Any]:
    if skip & {"A2"}:
        return {}
    out = outdir / "resolved.txt"
    # Same fix as A1: --resume must take precedence over --only for the
    # "skip if exists" decision.
    if out.exists() and (resume or only.isdisjoint({"A2"})):
        return {"A2": str(out), "count": count_nonblank(out)}
    subs = Path(prev.get("A1") or outdir / "all_subs.txt")
    # Existence check is "file is non-empty"; we do NOT use read_lines()
    # here because it drops `#`-prefixed lines, which would make A2 skip
    # on a file that contains only valid subdomains below a `#` header.
    if not subs.exists() or subs.stat().st_size == 0:
        log("warn", "A2: no input subdomains; skipping")
        return {"A2": str(out), "count": 0}
    log("info", "Phase A2: dnsx resolution")
    if not t.has("dnsx"):
        log("warn", "A2: dnsx missing, falling back to copy of subdomain list")
        merge_unique([subs], out)
        return {"A2": str(out), "count": len(read_lines(out))}
    # dnsx with `-resp` writes one line per record in the form
    # `host [TYPE] [value]`, e.g. `sub.example.com [A] [1.2.3.4]`.
    # Downstream tools (naabu/httpx/nuclei/testssl/wpscan) only accept
    # bare hostnames, so we keep the rich record-level output as
    # `resolved_full.txt` (for reporting / forensics) and produce a
    # deduped host-only list as `resolved.txt` for the rest of the
    # pipeline.
    full = outdir / "resolved_full.txt"
    res = await _run("dnsx",
        ["dnsx", "-silent", "-l", str(subs), "-o", str(full),
         "-a", "-aaaa", "-cname", "-resp"], 1800, outdir)
    if not full.exists() or not read_lines(full):
        # Defensive: dnsx failed or produced no output - fall back to
        # the raw subdomain list so B1 et al. still get something
        # usable.
        log("warn", "A2: dnsx produced no output; falling back to subdomain list")
        merge_unique([subs], out)
        return {"A2": str(out), "count": len(read_lines(out)), "rc": res.rc}
    seen: Set[str] = set()
    for ln in full.read_text(errors="ignore").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        # First whitespace-delimited token is the host we resolved;
        # this drops both the ` [A] [1.2.3.4]` and ` [CNAME] [target]`
        # suffixes. Validate it actually looks like a hostname before
        # adding it — a truncated / malformed dnsx line (e.g. a write
        # interrupted mid-flush) would otherwise leak bracket fragments
        # like `[A]` as "hosts" and poison every downstream phase.
        host = ln.split()[0].rstrip(".")
        if not _is_valid_hostname(host):
            continue
        if host not in seen:
            seen.add(host)
    ensure(out)
    out.write_text("\n".join(sorted(seen)) + ("\n" if seen else ""))
    n_records = len(read_lines(full))
    log("info", f"A2: {len(seen)} unique hosts (from {n_records} "
        f"A/AAAA/CNAME records in resolved_full.txt)")
    return {"A2": str(out), "count": len(seen), "rc": res.rc}
async def phase_B1(outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet,
                   prev: Dict[str, Any]) -> Dict[str, Any]:
    if skip & {"B1"}:
        return {}
    log("info", "Phase B1: ports / hosts / takeover (parallel)")
    # naabu/httpx/nuclei-takeover accept host:port (or hosts from httpx)
    hosts = Path(prev.get("A2") or outdir / "resolved.txt")
    # subjack needs CLEAN subdomains (no `[1.2.3.4]` suffix from dnsx -resp)
    subs = Path(prev.get("A1") or outdir / "all_subs.txt")
    ports_file = outdir / "ports.txt"
    jobs: List[Tuple[str, List[str], int]] = []
    have_hosts = hosts.exists() and bool(read_lines(hosts))
    have_subs = subs.exists() and bool(read_lines(subs))
    if not have_hosts and not have_subs:
        log("warn", "B1: no host or subdomain input; skipping")
        return {
            "B1.ports": str(ports_file),
            "B1.hosts": str(outdir / "hosts.txt"),
            "B1.targets": str(outdir / "host_targets.txt"),
            "B1.takeover": str(outdir / "takeover.txt"),
        }
    if have_hosts and t.has("naabu"):
        jobs.append(("naabu",
            ["naabu", "-silent", "-l", str(hosts),
             "-o", str(ports_file)], 1800))
    elif have_hosts and t.has("nmap"):
        jobs.append(("nmap",
             ["nmap", "-iL", str(hosts), "-Pn", "-p-", "--open",
              "-oG", str(outdir / "ports.gnmap")], 1800))
    if have_hosts and t.has("httpx"):
        jobs.append(("httpx",
            ["httpx", "-silent", "-l", str(hosts),
             "-o", str(outdir / "hosts.txt"),
             "-title", "-tech-detect", "-status-code", "-follow-redirects"],
            1800))
    if t.has("subjack") and have_subs:
        jobs.append(("subjack",
            ["subjack", "-w", str(subs), "-t", "100", "-ssl",
             "-o", str(outdir / "takeover.txt")], 1200))
    elif have_hosts and t.has("nuclei"):
        jobs.append(("nuclei-takeover",
            ["nuclei", "-silent", "-l", str(hosts),
             "-t", "http/takeovers", "-o", str(outdir / "takeover.txt")],
            1800))
    await run_parallel(jobs, outdir)
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
                ensure(ports_file).write_text(
                "\n".join(sorted(ports)) + ("\n" if ports else ""))
    raw_hosts = outdir / "hosts.txt"
    targets = outdir / "host_targets.txt"
    if raw_hosts.exists() and read_lines(raw_hosts):
        _write_target_tokens(raw_hosts, targets)
    elif have_hosts:
        merge_unique([hosts], targets)
    return {
        "B1.ports":   str(ports_file),
        "B1.hosts":   str(raw_hosts),
        "B1.targets": str(targets),
        "B1.takeover": str(outdir / "takeover.txt"),
    }
async def phase_C1(outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet,
                   prev: Dict[str, Any]) -> Dict[str, Any]:
    if skip & {"C1"}:
        return {}
    log("info", "Phase C1: URL harvesting (parallel groups)")
    hosts = Path(prev.get("B1.targets") or outdir / "host_targets.txt")
    if not hosts.exists() or not read_lines(hosts):
        hosts = Path(prev.get("B1.hosts") or outdir / "hosts.txt")
    if hosts.exists() and read_lines(hosts) and hosts.name == "hosts.txt":
        normalized = outdir / "host_targets.txt"
        _write_target_tokens(hosts, normalized)
        hosts = normalized
    if not hosts.exists() or not read_lines(hosts):
        hosts = Path(prev.get("A2") or outdir / "resolved.txt")
    if not hosts.exists() or not read_lines(hosts):
        log("warn", "C1: no host input; skipping")
        return {}
    g1: List[Tuple[str, List[str], int]] = []
    # gau v2 supports -l <file> for a list of domains; if the local
    # build doesn't, fall back to a per-host loop (also avoids ARG_MAX).
    if t.has("gau"):
        runner = outdir / "logs" / "gau_runner.sh"
        ensure(runner)
        runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -u\n"
            f"OUT={shlex.quote(str(outdir / 'urls_gau.txt'))}\n"
            f"IN={shlex.quote(str(hosts))}\n"
            ": > \"$OUT\"\n"
            "if gau -l \"$IN\" -o \"$OUT\" --subs --threads 5 "
            "--blacklist ttf,woff,svg,png,jpg,gif,ico,css >/dev/null 2>&1 "
            "&& [ -s \"$OUT\" ]; then\n"
            "  :\n"
            "else\n"
            "  : > \"$OUT\"\n"
            "  while IFS= read -r h || [[ -n \"$h\" ]]; do\n"
            "    [ -z \"$h\" ] && continue\n"
            "    gau --subs --threads 5 --blacklist "
            "ttf,woff,svg,png,jpg,gif,ico,css \"$h\" >> \"$OUT\" 2>/dev/null || true\n"
            "  done < \"$IN\"\n"
            "fi\n"
        )
        runner.chmod(0o755)
        g1.append(("gau", ["bash", str(runner)], 1800))
    # waybackurls takes one host; iterate from file via runner to avoid
    # embedding the host list in the bash argv (no ARG_MAX DoS).
    if t.has("waybackurls"):
        runner = outdir / "logs" / "wayback_runner.sh"
        ensure(runner)
        runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -u\n"
            f"OUT={shlex.quote(str(outdir / 'urls_wayback.txt'))}\n"
            f"IN={shlex.quote(str(hosts))}\n"
            ": > \"$OUT\"\n"
            "while IFS= read -r h || [[ -n \"$h\" ]]; do\n"
            "  [ -z \"$h\" ] && continue\n"
            "  waybackurls \"$h\" >> \"$OUT\" 2>/dev/null || true\n"
            "done < \"$IN\"\n"
        )
        runner.chmod(0o755)
        g1.append(("waybackurls", ["bash", str(runner)], 1800))
    if t.has("gospider"):
        # gospider's -o is an output *folder* (one file per site), not a file,
        # so we don't use it: run via a runner that captures stdout and extracts
        # the URL token from each line into a flat urls_gospider.txt.
        runner = outdir / "logs" / "gospider_runner.sh"
        ensure(runner)
        runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -u\n"
            f"OUT={shlex.quote(str(outdir / 'urls_gospider.txt'))}\n"
            f"IN={shlex.quote(str(hosts))}\n"
            "gospider -q -S \"$IN\" 2>/dev/null "
            "| grep -oE 'https?://[^[:space:]\"]+' | sort -u > \"$OUT\" || true\n"
        )
        runner.chmod(0o755)
        g1.append(("gospider", ["bash", str(runner)], 1800))
    g2: List[Tuple[str, List[str], int]] = []
    if t.has("katana"):
        g2.append(("katana",
            ["katana", "-silent", "-list", str(hosts),
             "-o", str(outdir / "urls_katana.txt"),
             "-jc", "-d", "3", "-kf", "all"], 1800))
    if t.has("subjs"):
        runner = outdir / "logs" / "subjs_runner.sh"
        ensure(runner)
        runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -u\n"
            f"OUT={shlex.quote(str(outdir / 'urls_subjs.txt'))}\n"
            f"IN={shlex.quote(str(hosts))}\n"
            ": > \"$OUT\"\n"
            "subjs -i \"$IN\" > \"$OUT\" 2>/dev/null || true\n"
        )
        runner.chmod(0o755)
        g2.append(("subjs", ["bash", str(runner)], 1200))
    if g1:
        await run_parallel(g1, outdir)
    if g2:
        await run_parallel(g2, outdir)
    harvested = [outdir / "urls_gau.txt", outdir / "urls_wayback.txt",
                 outdir / "urls_gospider.txt", outdir / "urls_katana.txt",
                 outdir / "urls_subjs.txt"]
    if not any(p.exists() and read_lines(p) for p in harvested):
        log("warn", "C1: no URL harvesters produced output")
    n = merge_unique(harvested, outdir / "urls_all.txt")
    log("ok", f"C1: {n} unique URLs")
    return {"C1": str(outdir / "urls_all.txt"), "count": n}
async def phase_C2(outdir: Path, t: Tools, only: PhaseSet,
                   skip: PhaseSet) -> Dict[str, Any]:
    if skip & {"C2"}:
        return {}
    log("info", "Phase C2: JS analysis (LinkFinder + SecretFinder)")
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
        log("warn", "C2: no JS URLs found; skipping")
        ensure(outdir / "js_secrets.txt").write_text("")
        return {"C2": str(outdir / "js_secrets.txt"), "count": 0}
    jobs: List[Tuple[str, List[str], int]] = []
    if t.has("linkfinder"):
        runner = outdir / "logs" / "linkfinder_runner.sh"
        ensure(runner)
        runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -u\n"
            f"OUT={shlex.quote(str(outdir / 'links.txt'))}\n"
            f"IN={shlex.quote(str(js_urls))}\n"
            "linkfinder -i \"$IN\" -o \"$OUT\" </dev/null >/dev/null 2>&1 || true\n"
        )
        runner.chmod(0o755)
        jobs.append(("linkfinder", ["bash", str(runner)], 1200))
    if t.has("secretfinder"):
        runner = outdir / "logs" / "secretfinder_runner.sh"
        ensure(runner)
        runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -u\n"
            f"OUT={shlex.quote(str(outdir / 'secrets.txt'))}\n"
            f"IN={shlex.quote(str(js_urls))}\n"
            "secretfinder -i \"$IN\" -o \"$OUT\" </dev/null >/dev/null 2>&1 || true\n"
        )
        runner.chmod(0o755)
        jobs.append(("secretfinder", ["bash", str(runner)], 1200))
    if t.has("nuclei"):
        jobs.append(("nuclei-exposures",
            ["nuclei", "-silent", "-l", str(js_urls),
             "-t", "http/exposed-panels", "-o", str(outdir / "nuclei_exposures.txt")],
            1500))
    await run_parallel(jobs, outdir)
    n = merge_unique([outdir / "links.txt", outdir / "secrets.txt",
                      outdir / "nuclei_exposures.txt"],
                     outdir / "js_secrets.txt")
    if n == 0:
        log("warn", "C2: no JS findings produced")
    return {"C2": str(outdir / "js_secrets.txt"), "count": n}
async def phase_D(outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet,
                  prev: Dict[str, Any]) -> Dict[str, Any]:
    if skip & {"D"}:
        return {}
    log("info", "Phase D: parameter discovery")
    urls = outdir / "urls_all.txt"
    if not urls.exists() or not read_lines(urls):
        log("warn", "D: no URLs; skipping")
        return {"D": str(outdir / "params.txt"), "count": 0}
    jobs: List[Tuple[str, List[str], int]] = []
    if t.has("paramspider"):
        for u in read_lines(urls)[:3]:
            # ParamSpider -d expects a domain, not a full URL
            domain_for_ps = _extract_domain(u)
            out_part = outdir / f"params_spider_{safe_suffix(u)}.txt"
            runner = outdir / "logs" / f"paramspider_{safe_suffix(u)}.sh"
            ensure(runner)
            runner.write_text(
                "#!/usr/bin/env bash\n"
                "set -u\n"
                f"OUT={shlex.quote(str(out_part))}\n"
                f"URL={shlex.quote(u)}\n"
                f"DOMAIN={shlex.quote(domain_for_ps)}\n"
                ": > \"$OUT\"\n"
                "paramspider -d \"$DOMAIN\" --quiet >> \"$OUT\" 2>/dev/null || true\n"
            )
            runner.chmod(0o755)
            jobs.append((f"paramspider-{u[:40]}",
                         ["bash", str(runner)], 900))
    # arjun and x8 write JSON, NOT plain text. We capture the JSON and
    # normalize to one URL per line in the .txt sibling below.
    if t.has("arjun"):
        jobs.append(("arjun",
            ["arjun", "-i", str(urls), "-o", str(outdir / "params_arjun.json")],
            1500))
    if t.has("x8"):
        jobs.append(("x8",
            ["x8", "-u", str(urls), "-o", str(outdir / "params_x8.json")], 1500))
    await run_parallel(jobs, outdir)
    # Normalize arjun / x8 JSON output to plain URL-per-line text.
    for raw in (outdir / "params_arjun.json", outdir / "params_x8.json"):
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
            # x8 v0.5+ output: {"results": [{"url": ..., "params": [...]}, ...]}
            if not urls_found:
                res = data.get("results") if isinstance(data, dict) else None
                if isinstance(res, list):
                    for r in res:
                        if isinstance(r, dict) and r.get("url"):
                            urls_found.append(str(r["url"]))
        # JSONL fallback
        if not urls_found:
            for rec in read_jsonl(raw):
                if isinstance(rec, dict) and rec.get("url"):
                    urls_found.append(str(rec["url"]))
        ensure(norm).write_text("\n".join(urls_found) + ("\n" if urls_found else ""))
    # Glob params_*.txt but EXCLUDE the params.txt we are about to write.
    parts = sorted(p for p in outdir.glob("params_*.txt")
                   if p.name != "params.txt")
    n = merge_unique(parts, outdir / "params.txt")
    return {"D": str(outdir / "params.txt"), "count": n}
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
def _extract_urls_from_kiterunner_jsonl(p: Path) -> List[str]:
    """kiterunner (`kr`) writes JSON-Lines, one record per matched endpoint."""
    out: List[str] = []
    if not p.exists():
        return out
    for rec in read_jsonl(p):
        if not isinstance(rec, dict):
            continue
        url = rec.get("url") or rec.get("matched-raw-url")
        if url:
            out.append(str(url))
    return out
async def phase_E(outdir: Path, t: Tools, only: PhaseSet,
                  skip: PhaseSet) -> Dict[str, Any]:
    if skip & {"E"}:
        return {}
    log("info", "Phase E: fuzzing")
    urls = outdir / "urls_all.txt"
    if not urls.exists() or not read_lines(urls):
        log("warn", "E: no URLs; skipping")
        return {"E": str(outdir / "fuzz.txt"), "count": 0}
    wordlist = os.environ.get(
        "FFUF_WORDLIST",
        "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    )
    if not Path(wordlist).exists():
        log("warn", f"E: FFUF_WORDLIST '{wordlist}' missing, ffuf disabled")
        wordlist = ""
    jobs: List[Tuple[str, List[str], int]] = []
    sample = read_lines(urls)[:5]
    if not Path(wordlist).exists():
        # fallback to any wordlist under /usr/share
        alt = sorted(Path("/usr/share/seclists/Discovery/Web-Content").glob("raft*.txt"))
        if alt:
            wordlist = str(alt[0])
            log("info", f"E: using fallback wordlist: {wordlist}")
    if t.has("ffuf") and wordlist:
        for u in sample:
            out_json = outdir / f"ffuf_{safe_suffix(u)}.json"
            jobs.append((f"ffuf-{u[:32]}",
                ["ffuf", "-s", "-u", u.rstrip("/") + "/FUZZ",
                 "-w", wordlist, "-mc", "200,301,302,403",
                 "-o", str(out_json)], 1500))
    if t.has("kr"):
        # Kiterunner needs .kite format wordlists. Try to find or generate one.
        kite_file = os.environ.get("KITE_FILE", "")
        if not kite_file or not Path(kite_file).exists():
            # Try common kite file paths
            for cand in [
                "/tmp/common.kite",
                os.path.expanduser("~/.kiterunner/wordlist.kite"),
            ]:
                if Path(cand).exists():
                    kite_file = cand
                    break
        if not kite_file or not Path(kite_file).exists():
            # Generate a .kite file from a text wordlist
            src_wordlist = Path(
                "/usr/share/seclists/Discovery/Web-Content/common.txt"
            )
            if src_wordlist.exists():
                kite_file = str(outdir / "kr_wordlist.kite")
                log("info", f"E: generating kite wordlist from {src_wordlist}")
                proc = await asyncio.create_subprocess_exec(
                    "kr", "kb", "convert", str(src_wordlist), kite_file,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await proc.wait()
                if not Path(kite_file).exists():
                    kite_file = ""
                    log("warn", "E: failed to generate kite wordlist")
            else:
                kite_file = ""
        if not kite_file:
            log("warn", "E: no kite wordlist available, skipping kiterunner")
        else:
            for u in sample:
                out_jsonl = outdir / f"kr_{safe_suffix(u)}.jsonl"
                jobs.append((f"kiterunner-{u[:32]}",
                    ["kr", "scan", u, "-w", kite_file,
                     "-o", str(out_jsonl)], 1500))
    if t.has("feroxbuster"):
        for u in sample:
            out_txt = outdir / f"fb_{safe_suffix(u)}.txt"
            jobs.append((f"feroxbuster-{u[:32]}",
                ["feroxbuster", "-q", "-u", u, "--no-state",
                 "-o", str(out_txt)], 1800))
    await run_parallel(jobs, outdir)
    # Normalize JSON fuzzer output into plain text lines BEFORE merging.
    # Clean up stale normalized .txt files from prior runs first
    for old in outdir.glob("ffuf_*.txt"):
        old.unlink(missing_ok=True)
    for old in outdir.glob("kr_*.txt"):
        old.unlink(missing_ok=True)
    normalized: List[Path] = []
    for ffp in outdir.glob("ffuf_*.json"):
        norm = ffp.with_suffix(".txt")
        ensure(norm).write_text(
            "\n".join(_extract_urls_from_ffuf_json(ffp)) + "\n")
        normalized.append(norm)
    for krp in outdir.glob("kr_*.jsonl"):
        norm = krp.with_suffix(".txt")
        ensure(norm).write_text(
            "\n".join(_extract_urls_from_kiterunner_jsonl(krp)) + "\n")
        normalized.append(norm)
    normalized.extend(outdir.glob("fb_*.txt"))
    n = merge_unique(normalized, outdir / "fuzz.txt")
    if n == 0:
        log("warn", "E: fuzzers produced no hits")
    return {"E": str(outdir / "fuzz.txt"), "count": n}
async def phase_F1(outdir: Path, t: Tools, only: PhaseSet,
                   skip: PhaseSet) -> Dict[str, Any]:
    if skip & {"F1"}:
        return {}
    log("info", "Phase F1: nuclei (full) + tech-scanner")
    hosts = outdir / "host_targets.txt"
    if not hosts.exists() or not read_lines(hosts):
        raw_hosts = outdir / "hosts.txt"
        if raw_hosts.exists() and read_lines(raw_hosts):
            _write_target_tokens(raw_hosts, hosts)
    if not hosts.exists() or not read_lines(hosts):
        hosts = outdir / "resolved.txt"
    if not hosts.exists() or not read_lines(hosts):
        log("warn", "F1: no hosts; skipping")
        return {"F1": str(outdir / "nuclei_combined.txt"), "count": 0}
    jobs: List[Tuple[str, List[str], int]] = []
    if t.has("nuclei"):
        jobs.append(("nuclei-full",
             ["nuclei", "-silent", "-l", str(hosts),
              "-severity", "low,medium,high,critical",
              "-o", str(outdir / "nuclei.txt")], 1800))
        # tech-scanner uses the same nuclei binary; do not double-gate on httpx.
        jobs.append(("tech-scanner",
            ["nuclei", "-silent", "-l", str(hosts),
             "-t", "http/technologies", "-o", str(outdir / "tech.txt")], 1800))
    await run_parallel(jobs, outdir)
    n = merge_unique([outdir / "nuclei.txt", outdir / "tech.txt"],
                     outdir / "nuclei_combined.txt")
    return {"F1": str(outdir / "nuclei_combined.txt"), "count": n}
async def phase_F2(outdir: Path, t: Tools, only: PhaseSet,
                   skip: PhaseSet) -> Dict[str, Any]:
    if skip & {"F2"}:
        return {}
    log("info", "Phase F2: testssl + wpscan")
    hosts = outdir / "host_targets.txt"
    if not hosts.exists() or not read_lines(hosts):
        raw_hosts = outdir / "hosts.txt"
        if raw_hosts.exists() and read_lines(raw_hosts):
            _write_target_tokens(raw_hosts, hosts)
    if not hosts.exists() or not read_lines(hosts):
        hosts = outdir / "resolved.txt"
    if not hosts.exists() or not read_lines(hosts):
        log("warn", "F2: no hosts; skipping")
        return {"F2": str(outdir / "tls_wp.txt"), "count": 0}
    sample = read_lines(hosts)[:5]
    testssl_bin = "testssl.sh" if t.has("testssl.sh") else (
        "testssl" if t.has("testssl") else None)
    # testssl: write PER-HOST files via a runner (no shared `>>` file ⇒ no race).
    testssl_jobs: List[Tuple[str, List[str], int]] = []
    if testssl_bin:
        for h in sample:
            per_host = outdir / f"testssl_{safe_suffix(h)}.txt"
            runner = outdir / "logs" / f"testssl_{safe_suffix(h)}.sh"
            ensure(runner)
            runner.write_text(
                "#!/usr/bin/env bash\n"
                "set -u\n"
                f"OUT={shlex.quote(str(per_host))}\n"
                f"H={shlex.quote(h)}\n"
                f"BIN={shlex.quote(testssl_bin)}\n"
                "\"$BIN\" --quiet --color 0 \"$H\" > \"$OUT\" 2>&1 || true\n"
            )
            runner.chmod(0o755)
            testssl_jobs.append((f"testssl-{h[:32]}",
                                 ["bash", str(runner)], 1800))
    # wpscan writes per-host files natively via --output.
    # Skip if the host doesn't appear to be WordPress (check for wp-content).
    wpscan_jobs: List[Tuple[str, List[str], int]] = []
    if t.has("wpscan"):
        for h in sample:
            if not h.startswith(("http://", "https://")):
                continue
            # Quick pre-check: is this WordPress?
            try:
                import urllib.request
                req = urllib.request.Request(h.rstrip("/") + "/wp-login.php",
                                             method="HEAD")
                with urllib.request.urlopen(req, timeout=10) as resp:
                    if resp.status not in (200, 301, 302):
                        log("warn", f"F2: {h} does not appear to be WordPress, skipping wpscan")
                        continue
            except Exception:
                log("warn", f"F2: {h} unreachable for WordPress check, skipping wpscan")
                continue
            wps_out = outdir / f"wpscan_{safe_suffix(h)}.txt"
            wpscan_jobs.append((f"wpscan-{h[:32]}",
                ["wpscan", "--url", h, "--no-banner",
                 "--output", str(wps_out)],
                1800))
    # run both groups in parallel; per-host files remove the race
    await run_parallel(testssl_jobs + wpscan_jobs, outdir)
    n = merge_unique(list(outdir.glob("testssl_*.txt")) +
                     list(outdir.glob("wpscan_*.txt")),
                     outdir / "tls_wp.txt")
    return {"F2": str(outdir / "tls_wp.txt"), "count": n}
async def phase_G(outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet,
                  oast_domain: Optional[str]) -> Dict[str, Any]:
    if skip & {"G"}:
        return {}
    log("info", "Phase G: dalfox → sqlmap → SSRF probes")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "G: no URLs; skipping")
        return {"G": str(outdir / "vulns.txt"), "count": 0}
    if oast_domain:
        os.environ["COLLABORATOR"] = oast_domain
    jobs: List[Tuple[str, List[str], int]] = []
    xss_urls = [u for u in all_urls if "=" in u]
    xss_in = ensure(outdir / "urls_xss.txt")
    if xss_urls:
        xss_in.write_text("\n".join(xss_urls) + "\n")
    if xss_urls and t.has("dalfox"):
        jobs.append(("dalfox",
            ["dalfox", "file", str(xss_in), "--silent",
             "--output", str(outdir / "xss.txt")], 1500))
    if t.has("sqlmap") and xss_urls:
        sqlmap_dir = outdir / "sqlmap"
        runner = outdir / "logs" / "sqlmap_runner.sh"
        ensure(runner)
        runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -u\n"
            f"OUT={shlex.quote(str(outdir / 'sqlmap.log'))}\n"
            f"IN={shlex.quote(str(xss_in))}\n"
            f"DIR={shlex.quote(str(sqlmap_dir))}\n"
            "mkdir -p \"$DIR\"\n"
            "sqlmap -m \"$IN\" --batch --level=1 --risk=1 --random-agent "
            "--output-dir=\"$DIR\" > \"$OUT\" 2>&1 || true\n"
        )
        runner.chmod(0o755)
        jobs.append(("sqlmap", ["bash", str(runner)], 3600))
    ssrf_urls = [u for u in all_urls
                 if any(k in u.lower() for k in
                        ("url=", "uri=", "path=", "dest=",
                         "redirect=", "img="))]
    ssrf_in = ensure(outdir / "urls_ssrf.txt")
    if ssrf_urls:
        ssrf_in.write_text("\n".join(ssrf_urls) + "\n")
    # Validate OAST hostname is a single safe token (alnum, dot, dash only)
    # BEFORE splicing it into a bash script. shlex.quote is belt-and-suspenders.
    if oast_domain and ssrf_urls and _SAFE_HOST.match(oast_domain):
        ssrf_script = outdir / "ssrf_probe.sh"
        ssrf_script.write_text(
            "#!/usr/bin/env bash\n"
            "set -u\n"
            f"OAST={shlex.quote(oast_domain)}\n"
            f"IN={shlex.quote(str(ssrf_in))}\n"
            "while IFS= read -r u || [[ -n \"$u\" ]]; do\n"
            "  [ -z \"$u\" ] && continue\n"
            "  for p in url uri path dest redirect img; do\n"
            "    # only rewrite if the parameter actually exists in the URL\n"
            "    case \"$u\" in\n"
            "      *\"&${p}=\"*) new=\"${u//&${p}=*/&${p}=http://${OAST}/ssrf-$RANDOM}\" ;;\n"
            "      *\"?${p}=\"*) new=\"${u//?${p}=*/?${p}=http://${OAST}/ssrf-$RANDOM}\" ;;\n"
            "      *) continue ;;\n"
            "    esac\n"
            "    curl -sS -o /dev/null --max-time 10 \"$new\" || true\n"
            "  done\n"
            "done < \"$IN\"\n"
        )
        ssrf_script.chmod(0o755)
        jobs.append(("ssrf-probe", ["bash", str(ssrf_script)], 1800))
    elif oast_domain and ssrf_urls:
        log("warn", "G: interactsh domain has unsafe characters, skipping SSRF probes")
    await run_parallel(jobs, outdir)
    parts = [outdir / "xss.txt", outdir / "sqlmap.log"]
    if (outdir / "sqlmap").exists():
        for fp in (outdir / "sqlmap").rglob("log"):
            parts.append(fp)
    n = merge_unique(parts, outdir / "vulns.txt")
    return {"G": str(outdir / "vulns.txt"), "count": n}
async def phase_G2(outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet,
                   prev: Dict[str, Any]) -> Dict[str, Any]:
    """Enhanced vuln fuzzing: SSTI, deeper XSS/SQLi on API endpoints."""
    if skip & {"G2"}:
        return {}
    log("info", "Phase G2: SSTI + deep XSS/SQLi fuzzing")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "G2: no URLs; skipping")
        return {"G2": str(outdir / "ssti.txt"), "count": 0}
    param_urls = [u for u in all_urls if "=" in u]
    if not param_urls:
        param_urls = all_urls[:5]
    jobs: List[Tuple[str, List[str], int]] = []
    ssti_payloads = (
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        "*{7*7}",
        "{{7*'7'}}",
        "<%= 7*7 %>",
        "${{7*7}}",
    )
    ssti_in = ensure(outdir / "urls_ssti.txt")
    ssti_urls: List[str] = []
    for u in param_urls:
        for payload in ssti_payloads:
            if "=" in u:
                base, _, val = u.partition("=")
                ssti_urls.append(f"{base}={payload}")
            else:
                ssti_urls.append(f"{u}?q={payload}")
    if ssti_urls:
        ssti_in.write_text("\n".join(ssti_urls[:200]) + "\n")
    if t.has("httpx"):
        jobs.append(("ssti-probe",
            ["httpx", "-silent", "-l", str(ssti_in), "-mc", "200",
             "-o", str(outdir / "ssti_raw.txt"), "-title"], 900))
    await run_parallel(jobs, outdir)
    # Check for reflection of SSTI payloads in response bodies
    ssti_findings: List[str] = []
    if (outdir / "ssti_raw.txt").exists():
        for ssti_url in read_lines(outdir / "ssti_raw.txt"):
            url_only = ssti_url.split()[0] if ssti_url.split() else ""
            if not url_only:
                continue
            try:
                req = _urllib.Request(url_only, headers={"User-Agent": "Mozilla/5.0"})
                with _urllib.urlopen(req, timeout=10) as resp:
                    body = resp.read().decode("utf-8", errors="ignore")
                # Check if any payload is reflected
                for payload in ssti_payloads:
                    if payload in body:
                        ssti_findings.append(f"[SSTI-reflected] {url_only} payload={payload}")
                        break
            except Exception:
                continue
    if ssti_findings:
        ensure(outdir / "ssti.txt").write_text("\n".join(ssti_findings) + "\n")
    log("ok", f"G2: {len(ssti_findings)} SSTI reflections detected")
    return {"G2": str(outdir / "ssti.txt"), "count": len(ssti_findings)}
# ─────────────────────────── manual-testing phases ──────────────────────────
# Phases J–L address gaps that automated scanners often miss but can be
# partially automated with targeted scripts and API calls.
# ───────────────────── Phase J: origin IP bypass ────────────────────────────
import urllib.request as _urllib
import struct as _struct
def _mmh3_hash(data: bytes) -> int:
    """Python implementation of mmh3 hash (used by Shodan favicon lookup)."""
    seed = 0
    c1 = 0xcc9e2d51
    c2 = 0x1b873593
    r1 = 15
    r2 = 13
    m = 5
    n = 0xe6546b64
    h = seed
    length = len(data)
    nblocks = length // 4
    for i in range(nblocks):
        k = _struct.unpack_from("<I", data, i * 4)[0]
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << r1) | (k >> (32 - r1))) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
        h = ((h << r2) | (h >> (32 - r2))) & 0xFFFFFFFF
        h = (h * m + n) & 0xFFFFFFFF
    tail = data[nblocks * 4:]
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
    h = (h * 0x85ebca6b) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xc2b2ae35) & 0xFFFFFFFF
    h ^= h >> 16
    return h
async def phase_J(domain: str, outdir: Path, t: Tools,
                  only: PhaseSet, skip: PhaseSet,
                  prev: Dict[str, Any]) -> Dict[str, Any]:
    if skip & {"J"}:
        return {}
    log("info", "Phase J: origin IP bypass enumeration")
    findings: List[str] = []
    hosts_file = Path(prev.get("B1.targets") or outdir / "host_targets.txt")
    if not hosts_file.exists():
        hosts_file = outdir / "resolved.txt"
    have_hosts = hosts_file.exists() and bool(read_lines(hosts_file))
    # 1. Favicon hash
    favicon_urls = []
    if have_hosts:
        for h in read_lines(hosts_file)[:3]:
            base = h if h.startswith("http") else f"https://{h}"
            favicon_urls.append(base.rstrip("/") + "/favicon.ico")
    if not favicon_urls:
        favicon_urls = [f"https://{domain}/favicon.ico"]
    for url in favicon_urls:
        try:
            req = _urllib.Request(url, headers={"User-Agent": "Mozilla/5.0"}, method="GET")
            with _urllib.urlopen(req, timeout=10) as resp:
                data = resp.read()
            if data:
                h = _mmh3_hash(data) & 0xFFFFFFFF
                findings.append(f"favicon_hash={h} (url={url})")
                findings.append(f"  Shodan: https://www.shodan.io/search?query=http.favicon.hash:{h}")
                findings.append(f"  Shodan (org): https://www.shodan.io/search?query=org:%22Cloudflare%22+http.favicon.hash:{h}")
                break
        except Exception:
            continue
    # 2. crt.sh certificate history
    crt_urls = [f"https://crt.sh/?q={domain}&output=json",
                f"https://crt.sh/?q=%25.{domain}&output=json"]
    crt_found_any = False
    for crt_url in crt_urls:
        if crt_found_any:
            break
        try:
            req = _urllib.Request(crt_url, headers={"User-Agent": "Mozilla/5.0"})
            with _urllib.urlopen(req, timeout=15) as resp:
                raw = resp.read().decode("utf-8", errors="ignore")
            import json as _json
            certs = _json.loads(raw)
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
            resolved = [s for s in subdomains if s != domain][:10]
            if t.has("dnsx") and resolved:
                crt_subs = outdir / "crt_subs.txt"
                ensure(crt_subs).write_text("\n".join(resolved) + "\n")
                crt_resolved = outdir / "crt_resolved.txt"
                await _run("dnsx-crt",
                    ["dnsx", "-silent", "-l", str(crt_subs),
                     "-o", str(crt_resolved), "-a", "-resp"], 300, outdir)
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
    mx_file = outdir / "mx_records.txt"
    if t.has("dig"):
        proc = await asyncio.create_subprocess_exec(
            "dig", "+short", "mx", domain,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
        except asyncio.TimeoutError:
            proc.kill()
            stdout = b""
        mx = stdout.decode("utf-8", errors="ignore").strip()
        if mx:
            ensure(mx_file).write_text(mx + "\n")
            for ln in mx.splitlines():
                ln = ln.strip()
                if ln:
                    findings.append(f"mx_record={ln}")
                    # Try resolving the MX target
                    mx_host = ln.split()[-1] if len(ln.split()) > 1 else ln
                    if t.has("dig"):
                        try:
                            proc2 = await asyncio.create_subprocess_exec(
                                "dig", "+short", mx_host.rstrip("."),
                                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
                            out2, _ = await asyncio.wait_for(proc2.communicate(), timeout=10)
                        except asyncio.TimeoutError:
                            proc2.kill()
                            out2 = b""
                        for mip in out2.decode().splitlines():
                            mip = mip.strip()
                            if mip and mip.count(".") == 3:
                                findings.append(f"  mx_ip={mip} (non-CF origin candidate)")
    # 4. Check resolved IPs against Cloudflare ASN
    resolved_path = Path(prev.get("A2") or outdir / "resolved_full.txt")
    if resolved_path.exists():
        resolved_ips: Set[str] = set()
        for ln in read_lines(resolved_path):
            parts = ln.split()
            if len(parts) >= 2:
                ip = parts[-1].strip("[]")
                if ip and ip.count(".") == 3:
                    resolved_ips.add(ip)
        if resolved_ips:
            cf_ips: Set[str] = set()
            non_cf_ips: Set[str] = set()
            for ip in sorted(resolved_ips)[:10]:
                try:
                    req = _urllib.Request(f"https://ipinfo.io/{ip}/json",
                                          headers={"User-Agent": "Mozilla/5.0"})
                    with _urllib.urlopen(req, timeout=10) as resp:
                        info = resp.read().decode("utf-8", errors="ignore")
                    import json as _json2
                    info_data = _json2.loads(info)
                    org = (info_data.get("org") or "").lower()
                    if "cloudflare" in org or "13335" in org:
                        cf_ips.add(ip)
                    else:
                        non_cf_ips.add(ip)
                        findings.append(f"  non_cloudflare_ip={ip}  org={info_data.get('org', 'unknown')}")
                except Exception:
                    findings.append(f"  unresolved_ip={ip} (check manually: curl -s https://ipinfo.io/{ip}/json)")
            if cf_ips:
                findings.append(f"  cloudflare_ips={', '.join(sorted(cf_ips))}")
            if non_cf_ips:
                findings.append(f"  non_cloudflare_candidates={', '.join(sorted(non_cf_ips))}")
    out = ensure(outdir / "origin.txt")
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"J: {len(findings)} origin findings → {out}")
    return {"J": str(out), "count": len(findings)}
# ──────────────────── Phase K: deep JS secret scanning ──────────────────────
import re as _re
_JS_SECRET_PATTERNS: List[Tuple[str, str]] = [
    ("firebase",    r"AIza[0-9A-Za-z\-_]{35}"),
    ("stripe-live", r"(?:sk|pk)_live_[0-9A-Za-z]{24,}"),
    ("stripe-test", r"(?:sk|pk)_test_[0-9A-Za-z]{24,}"),
    ("github-tok",  r"gh[opsu]_[0-9A-Za-z]{36,}"),
    ("aws-key",     r"AKIA[0-9A-Z]{16}"),
    ("aws-secret",  r"(?i)aws(.{0,20})?(?:secret|key).{0,20}[\"'][0-9a-zA-Z\/+=]{40}[\"']"),
    ("google-oauth", r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"),
    ("slack-tok",   r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
    ("jwt",         r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"),
    ("heroku",      r"https://api\.heroku\.com"),
    ("graphql",     r"(graphql|gql)\s*[=:]\s*[\"']https?://"),
    ("internal-ip", r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})"),
    ("internal-host", r"(?i)(?:internal|private|staging|dev|jenkins|gitlab|jira|confluence)\.(?:com|local|internal|corp)"),
]
_SOURCE_MAP_RE = re.compile(r'(?://#\s*sourceMappingURL=|sourceMappingURL=)([^\s"\']+)')
async def phase_K(outdir: Path, t: Tools, only: PhaseSet,
                  skip: PhaseSet) -> Dict[str, Any]:
    if skip & {"K"}:
        return {}
    log("info", "Phase K: deep JS secret scanning (custom regex + entropy + source maps)")
    js_urls = outdir / "urls_js.txt"
    if not js_urls.exists() or not read_lines(js_urls):
        log("warn", "K: no JS URLs; skipping")
        return {"K": str(outdir / "js_secrets_deep.txt"), "count": 0}
    findings: List[str] = []
    seen_secrets: Set[str] = set()
    seen_sourcemaps: Set[str] = set()
    for js_url in read_lines(js_urls):
        try:
            req = _urllib.Request(js_url, headers={"User-Agent": "Mozilla/5.0"})
            with _urllib.urlopen(req, timeout=15) as resp:
                body = resp.read().decode("utf-8", errors="ignore")
        except Exception:
            continue
        # Custom regex patterns
        for name, pattern in _JS_SECRET_PATTERNS:
            for m in _re.finditer(pattern, body):
                val = m.group()
                if val not in seen_secrets:
                    seen_secrets.add(val)
                    findings.append(f"[{name}] {val}  ({js_url})")
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
                sm_req = _urllib.Request(sm_url, headers={"User-Agent": "Mozilla/5.0"})
                with _urllib.urlopen(sm_req, timeout=15) as sm_resp:
                    sm_body = sm_resp.read().decode("utf-8", errors="ignore")
                import json as _json
                sm_data = _json.loads(sm_body)
                sources = sm_data.get("sources") or []
                for src in sources:
                    if isinstance(src, str):
                        for name2, pattern2 in _JS_SECRET_PATTERNS:
                            for m2 in _re.finditer(pattern2, src):
                                val2 = m2.group()
                                if val2 not in seen_secrets:
                                    seen_secrets.add(val2)
                                    findings.append(f"  [sourcemap-{name2}] {val2}")
            except Exception:
                continue
    out = ensure(outdir / "js_secrets_deep.txt")
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"K: {len(findings)} deep JS findings → {out}")
    return {"K": str(out), "count": len(findings)}
# ─────────────── Phase L: auth bypass + mass assignment ─────────────────────
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
    "admin", "is_admin", "role", "roles", "permissions",
    "is_teacher", "is_student", "group", "user_type",
    "balance", "points", "score", "grade", "completed",
    "approved", "verified", "active", "enabled",
    "plan", "tier", "subscription",
]
async def phase_L(outdir: Path, t: Tools, only: PhaseSet,
                  skip: PhaseSet) -> Dict[str, Any]:
    if skip & {"L"}:
        return {}
    log("info", "Phase L: auth bypass headers + mass assignment probes")
    findings: List[str] = []
    # 1. Collect API-like endpoints from urls_all.txt + ffuf output
    urls = outdir / "urls_all.txt"
    api_endpoints: Set[str] = set()
    if urls.exists():
        for u in read_lines(urls):
            path = u.split("?")[0].split("#")[0].lower()
            if "/api/" in path or path.endswith(("/api", "/account", "/login",
               "/register", "/password", "/user", "/admin", "/graphql")):
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
        api_endpoints = set(read_lines(urls)[:10]) if urls.exists() else set()
    if not api_endpoints:
        log("warn", "L: no endpoints found; skipping")
        return {"L": str(outdir / "auth_bypass.txt"), "count": 0}
    findings.append(f"target_endpoints={len(api_endpoints)}")
    for ep in sorted(api_endpoints)[:20]:
        findings.append(f"  endpoint={ep}")
    # 2. Auth bypass header probes (non-destructive)
    bypass_found: List[str] = []
    for ep in sorted(api_endpoints)[:15]:
        # Make a baseline request WITHOUT bypass headers first
        try:
            base_req = _urllib.Request(ep, method="GET")
            with _urllib.urlopen(base_req, timeout=8) as base_resp:
                baseline_status = base_resp.status
        except Exception:
            continue
        for hdr in _AUTH_BYPASS_HEADERS:
            try:
                req = _urllib.Request(ep, method="GET")
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
                with _urllib.urlopen(req, timeout=8) as resp:
                    if resp.status != baseline_status and resp.status in (200, 302, 403, 401):
                        bypass_found.append(f"  bypass={hdr} → {resp.status} (baseline={baseline_status}) on {ep}")
                        break
            except Exception:
                continue
    findings.append("auth_bypass_probes:")
    findings.extend(bypass_found or ["  none detected (expected)"])
    # 3. Mass assignment probes on API POST endpoints (dry-run)
    findings.append("mass_assignment_fields_to_test:")
    for field in _MASS_ASSIGN_FIELDS:
        findings.append(f"  try POST/PUT with body: {{\"{field}\": true}}")
    out = ensure(outdir / "auth_bypass.txt")
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"L: {len(findings)} auth bypass findings → {out}")
    return {"L": str(out), "count": len(bypass_found)}
# ───────────────────────────── report writers ──────────────────────────────
def _counts(outdir: Path) -> Dict[str, int]:
    keys = {
        "subdomains":  outdir / "all_subs.txt",
        "resolved":    outdir / "resolved.txt",
        "open_ports":  outdir / "ports.txt",
        "live_hosts":  outdir / "hosts.txt",
        "takeover":    outdir / "takeover.txt",
        "urls":        outdir / "urls_all.txt",
        "js_urls":     outdir / "urls_js.txt",
        "js_secrets":  outdir / "js_secrets.txt",
        "js_deep":     outdir / "js_secrets_deep.txt",
        "params":      outdir / "params.txt",
        "fuzz":        outdir / "fuzz.txt",
        "nuclei":      outdir / "nuclei_combined.txt",
        "tls_wp":      outdir / "tls_wp.txt",
        "origin":      outdir / "origin.txt",
        "auth_bypass": outdir / "auth_bypass.txt",
        "vulns":       outdir / "vulns.txt",
        "oast":        outdir / "oast" / "callbacks.txt",
    }
    # Use count_nonblank() instead of len(read_lines()) so `#`-prefixed
    # entries (e.g. a subfinder banner) aren't silently dropped from
    # the report. We still skip files that don't exist.
    return {k: count_nonblank(v) for k, v in keys.items() if v.exists()}
def write_summary(outdir: Path, domain: str, state: dict,
                  counts: Dict[str, int]) -> Path:
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
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;")
             .replace("'", "&#39;"))
def write_html(outdir: Path, domain: str, counts: Dict[str, int],
               missing: List[str]) -> Path:
    cards = "\n".join(
        f'<div class="card"><b>{n}</b><span>{html_escape(k)}</span></div>'
        for k, n in counts.items()
    )
    sections = []
    for key in ("all_subs.txt", "resolved.txt", "hosts.txt", "ports.txt",
                "takeover.txt", "urls_all.txt", "js_secrets.txt",
                "js_secrets_deep.txt", "params.txt", "fuzz.txt",
                "nuclei_combined.txt", "tls_wp.txt",
                "origin.txt", "auth_bypass.txt", "vulns.txt"):
        p = outdir / key
        if p.exists():
            txt = p.read_text(errors="ignore")
            if len(txt) > 50_000:
                txt = txt[:50_000] + "\n[…truncated…]"
            sections.append(
                f'<h2>{html_escape(key)}</h2><pre>{html_escape(txt)}</pre>')
    miss_html = ("<p class='miss'>missing: " +
                 ", ".join(html_escape(m) for m in missing) +
                 "</p>" if missing else "")
    html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>recon report — {html_escape(domain)}</title>
<style>{HTML_CSS}</style></head><body>
<h1>Recon Report: {html_escape(domain)}</h1>
<small>generated {datetime.now().isoformat(timespec='seconds')} · reconchain v{__version__}</small>
{miss_html}
<h2>Summary</h2><div class="grid">{cards}</div>
{''.join(sections)}
<footer>chained recon · all artifacts in <code>{html_escape(str(outdir))}</code></footer>
</body></html>"""
    out = ensure(outdir / "report.html")
    out.write_text(html)
    return out
def write_markdown(outdir: Path, domain: str, counts: Dict[str, int],
                   missing: List[str]) -> Path:
    lines = [f"# Recon Report — {domain}",
             f"_generated {datetime.now().isoformat(timespec='seconds')}_",
             ""]
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
    ("A1", phase_A1, ("domain", "outdir", "t", "only", "skip", "resume")),
    ("A2", phase_A2, ("domain", "outdir", "t", "only", "skip", "prev", "resume")),
    ("B1", phase_B1, ("outdir", "t", "only", "skip", "prev")),
    ("C1", phase_C1, ("outdir", "t", "only", "skip", "prev")),
    ("C2", phase_C2, ("outdir", "t", "only", "skip")),
    ("D",  phase_D,  ("outdir", "t", "only", "skip", "prev")),
    ("E",  phase_E,  ("outdir", "t", "only", "skip")),
    ("F1", phase_F1, ("outdir", "t", "only", "skip")),
    ("F2", phase_F2, ("outdir", "t", "only", "skip")),
    ("G",  phase_G,  ("outdir", "t", "only", "skip", "oast_domain")),
    ("G2", phase_G2, ("outdir", "t", "only", "skip", "prev")),
    ("J",  phase_J,  ("domain", "outdir", "t", "only", "skip", "prev")),
    ("K",  phase_K,  ("outdir", "t", "only", "skip")),
    ("L",  phase_L,  ("outdir", "t", "only", "skip")),
]
# Dependency-ordered execution stages. Phases in the same stage are independent
# of one another (they only read artifacts produced by *earlier* stages, never
# each other's output), so they run concurrently. A1→A2→B1→C1 form the linear
# spine; once URLs (C1) and live hosts (B1) exist, the analysis/scan phases
# C2/D/E/F1/F2/G all fan out in parallel. The process-wide _JOB_SEM keeps the
# total external-process count bounded across the whole fan-out.
STAGES: List[List[str]] = [
    ["A1"],
    ["A2"],
    ["B1"],
    ["C1"],
    ["C2", "D", "E", "F1", "F2", "G", "G2", "J", "K", "L"],
]
def _extract_domain(s: str) -> str:
    """Extract a bare domain from a URL or hostname."""
    s = s.strip()
    if s.startswith("http://"):
        s = s[7:]
    elif s.startswith("https://"):
        s = s[8:]
    s = s.split("/")[0].split(":")[0].split("?")[0]
    if _is_valid_hostname(s):
        return s
    return ""
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
            "domain must be a valid DNS name with at least one dot, "
            "for example example.com"
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
                log("warn",
                    f"state.json is for domain {saved.get('domain')!r}, "
                    f"not {args.domain!r}; ignoring and starting fresh")
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
    global _JOB_SEM
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
    progress = Progress(len(phases_to_run))
    active_needs_oast = any(name in {"E", "F1", "F2", "G"} for name in phases_to_run)
    if active_needs_oast and "H" not in skip:
        oast_started = oast.start()

    def _apply(name: str, result: Dict[str, Any]) -> None:
        """Fold a finished phase's result into prev/state. Runs in the single
        event-loop thread (synchronous, no await), so it is race-free even when
        phases in a stage complete concurrently."""
        prev.update(result or {})
        state["artifacts"].update({k: v for k, v in (result or {}).items()
                                   if isinstance(v, str)})
        # accumulate (not overwrite) missing tools across phases
        for m in t.missing:
            if m not in state["missing_tools"]:
                state["missing_tools"].append(m)
        # surface partial tool failures (BUG-5): non-zero exits / timeouts the
        # run survived but whose artifact is partial. Shown in summary.json.
        new_failures = (result or {}).get("failures") or {}
        if isinstance(new_failures, dict):
            state.setdefault("tool_failures", {}).update(
                {k: int(v) for k, v in new_failures.items()})

    async def _run_phase(name: str) -> Dict[str, Any]:
        fn = phase_map[name]
        kwargs = {"domain": args.domain, "outdir": outdir, "t": t,
                  "only": only, "skip": skip, "prev": prev,
                  "oast_domain": oast.domain,
                  "resume": bool(args.resume)}
        sig = inspect.signature(fn)
        call = {k: v for k, v in kwargs.items() if k in sig.parameters}
        try:
            result = await fn(**call)
        except Exception as e:
            log("err", f"phase {name} crashed: {e}")
            result = {}
        progress.next(name)
        return result or {}

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
            try:
                _atomic_write_json(state_path, state)
            except Exception as e:
                log("warn", f"state.json write failed: {e}")
    finally:
        _ = oast.stop() if oast_started else None
        _JOB_SEM = None
    counts = _counts(outdir)
    sj = write_summary(outdir, args.domain, state, counts)
    hj = write_html(outdir, args.domain, counts, t.missing)
    mj = write_markdown(outdir, args.domain, counts, t.missing)
    log("ok", f"summary → {sj}")
    log("ok", f"report  → {hj}")
    log("ok", f"report  → {mj}")
    progress.close()
    return 0
# ────────────────────────── interactive setup ──────────────────────────────
_RECON_LEVELS = {
    "1": {
        "name": "Basic reconnaissance",
        "desc": "Subdomains → DNS → Ports/HTTP → URLs → Report (fast, no vuln scanning)",
        "phases": {"A1", "A2", "B1", "C1", "I"},
    },
    "2": {
        "name": "Standard assessment",
        "desc": "Basic + JS secrets + params + fuzzing + nuclei + TLS/WordPress",
        "phases": {"A1", "A2", "B1", "C1", "C2", "D", "E", "F1", "F2", "I"},
    },
    "full": {
        "name": "Full audit",
        "desc": "Standard + SSTI + origin bypass + deep JS + auth bypass/mass assignment",
        "phases": VALID_PHASES - {"H"},
    },
}
def _prompt(prompt_text: str, default: str = "",
            validator: Optional[Callable[[str], bool]] = None,
            error_msg: str = "") -> str:
    while True:
        suffix = f" [{default}]" if default else ""
        val = input(f"  {prompt_text}{suffix}: ").strip()
        if not val and default:
            return default
        if not val:
            continue
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
{C['c']}╔══════════════════════════════════════════╗
║         {C['g']}ReconChain v{__version__}{C['c']}            ║
║   {C['d']}Automated recon & vulnerability pipeline{C['c']}   ║
╚══════════════════════════════════════════╝{C['r']}
"""
    print(banner, flush=True)
def interactive_setup() -> argparse.Namespace:
    _banner()
    log("info", "Interactive setup — press Ctrl+C anytime to abort\n")
    # 1. Domain
    domain = _prompt("Target domain (e.g. example.com)",
                     validator=_is_valid_hostname,
                     error_msg="Enter a valid domain with at least one dot")
    # 2. Recon level
    print(f"\n{C['b']}Recon levels:{C['r']}")
    for key, lvl in sorted(_RECON_LEVELS.items()):
        print(f"  {C['y']}{key:4}{C['r']} {lvl['name']}")
        print(f"       {C['d']}{lvl['desc']}{C['r']}")
    level = _prompt("Choose recon level", default="full",
                    validator=lambda v: v in _RECON_LEVELS,
                    error_msg="Enter 1, 2, or full")
    base_phases = _RECON_LEVELS[level]["phases"]
    # 3. Output directory
    out = _prompt("Output directory", default=f"./out_{domain}")
    # 4. Concurrent jobs
    jobs_str = _prompt("Max parallel processes", default=str(MAX_PARALLEL_JOBS),
                       validator=lambda v: v.isdigit() and int(v) > 0,
                       error_msg="Enter a positive number")
    jobs = int(jobs_str)
    # 5. Manual testing add-ons (only for level 2 / full)
    extra_phases: Set[str] = set()
    if level in ("2", "full"):
        print(f"\n{C['b']}Additional manual-testing phases:{C['r']}")
        for p, desc in [("G2", "SSTI fuzzing"),
                        ("J",  "Origin IP bypass (Cloudflare)"),
                        ("K",  "Deep JS secret scanning"),
                        ("L",  "Auth bypass + mass assignment probes")]:
            if _prompt_yes_no(f"Run {C['y']}{p}{C['r']} - {desc}",
                              default=(level == "full")):
                extra_phases.add(p)
    selected = base_phases | extra_phases
    # 6. Resume
    state_path = Path(out) / "state.json"
    resume = False
    if state_path.exists():
        resume = _prompt_yes_no("State file exists — resume previous scan", default=True)
    # 7. Summary
    print(f"\n{C['b']}{'─' * 50}{C['r']}")
    print(f" {C['g']}Scan summary:{C['r']}")
    print(f"   Domain:     {C['y']}{domain}{C['r']}")
    print(f"   Output:     {C['y']}{out}{C['r']}")
    print(f"   Level:      {C['y']}{level}{C['r']}")
    print(f"   Phases:     {C['y']}{', '.join(sorted(selected))}{C['r']}")
    print(f"   Jobs:       {C['y']}{jobs}{C['r']}")
    print(f"   Resume:     {C['y']}{'yes' if resume else 'no'}{C['r']}")
    print(f" {C['b']}{'─' * 50}{C['r']}")
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
    ns.quiet = False
    ns.no_color = False
    ns.interactive = False
    return ns
# ─────────────────────────────────── main ──────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="reconchain",
        description="Chain recon tools into a single orchestrated pipeline.")
    p.add_argument("-d", "--domain", type=str, default="",
                   help="target root domain, e.g. example.com")
    p.add_argument("-o", "--out", default="./out",
                   help="output directory (default: ./out)")
    p.add_argument("-i", "--interactive", action="store_true",
                   help="interactive setup wizard (prompts for domain, level, etc.)")
    p.add_argument("--only", default=set(), type=_parse_phase_csv,
                   help="comma-separated phases to run, e.g. A1,A2,B1")
    p.add_argument("--skip", default=set(), type=_parse_phase_csv,
                   help="comma-separated phases to skip, e.g. F2,G")
    p.add_argument("-j", "--jobs", type=int, default=MAX_PARALLEL_JOBS,
                   help=f"max parallel external processes (default: {MAX_PARALLEL_JOBS})")
    p.add_argument("--fast", action="store_true",
                   help="fast mode: only run essential recon phases "
                        "(A1, A2, B1, C1, I), skipping vuln scanning")
    p.add_argument("--resume", action="store_true",
                   help="resume from ./out/state.json if it exists "
                        "(only for the same target domain)")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="suppress info-level logs")
    p.add_argument("--no-color", action="store_true",
                   help="disable ANSI color output")
    return p
def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.interactive:
        args = interactive_setup()
    else:
        if not args.domain or not _is_valid_hostname(args.domain):
            parser.error("the following arguments are required: -d/--domain (or use -i for interactive)")
        args.domain = args.domain.rstrip(".").lower()
    if args.no_color:
        disable_color()
    if args.only and args.skip and (args.only & args.skip):
        parser.error(
            "phase(s) cannot be both --only and --skip: "
            + ", ".join(sorted(args.only & args.skip))
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
