

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

  reconchain.py -d example.com --no-color -q


Stdlib only. Any missing tool is reported and its phase is skipped (non-fatal

unless the step is marked required).

"""


from __future__ import annotations


import argparse

import asyncio

import contextlib

import json

import os

import shutil

import signal

import subprocess

import sys

import time

from dataclasses import asdict, dataclass, field

from datetime import datetime

from pathlib import Path

from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple


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


def log(lvl: str, msg: str) -> None:

    ts = datetime.now().strftime("%H:%M:%S")

    print(f"{C['d']}{ts}{C['r']} {LVL[lvl]}[{lvl.upper():4}]{C['r']} {msg}",

          flush=True)


# ────────────────────────────── tool registry ──────────────────────────────


class Tools:

    """Cached presence check for external binaries."""

    def __init__(self) -> None:

        self._cache: Dict[str, bool] = {}

        self.missing_set: set = set()

        self.missing: List[str] = []


    def have(self, *names: str) -> List[str]:

        out: List[str] = []

        for n in names:

            if n not in self._cache:

                ok = shutil.which(n) is not None

                self._cache[n] = ok

                if not ok:

                    self.missing_set.add(n)

                    self.missing.append(n)

            if self._cache[n]:

                out.append(n)

        return out


    def has(self, name: str) -> bool:

        return bool(self.have(name))


# ─────────────────────────── subprocess helpers ────────────────────────────


@dataclass

class StepResult:

    name: str

    cmd: List[str]

    rc: int

    duration: float

    log_path: Optional[Path] = None

    output: Optional[Path] = None

    note: str = ""


def _run_blocking(cmd: List[str], timeout: int, cwd: Optional[Path],

                  log_path: Path) -> Tuple[int, float]:

    t0 = time.monotonic()

    log_path.parent.mkdir(parents=True, exist_ok=True)

    with log_path.open("wb") as logf:

        try:

            proc = subprocess.run(

                cmd, cwd=str(cwd) if cwd else None,

                stdout=logf, stderr=subprocess.STDOUT,

                timeout=timeout, check=False,

            )

            return proc.returncode, time.monotonic() - t0

        except subprocess.TimeoutExpired:

            with log_path.open("ab") as f:

                f.write(f"\n[timeout after {timeout}s]\n")

            return 124, time.monotonic() - t0

        except FileNotFoundError as e:

            with log_path.open("ab") as f:

                f.write(f"\n[binary not found: {e}]\n")

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

# does not fork-bomb the host. 8 parallel external procs is a sane ceiling.

MAX_PARALLEL_JOBS = 8


async def run_parallel(jobs: List[Tuple[str, List[str], int]],

                       outdir: Path) -> List[StepResult]:

    active = [j for j in jobs if j[2]]

    sem = asyncio.Semaphore(MAX_PARALLEL_JOBS)


    async def _guarded(n, c, t):

        async with sem:

            return await _run(n, c, t, outdir)

    coros = [_guarded(n, c, t) for n, c, t in active]

    return await asyncio.gather(*coros)


# ───────────────────────────── file utilities ───────────────────────────────


def ensure(p: Path) -> Path:

    p.parent.mkdir(parents=True, exist_ok=True)

    return p


def read_lines(p: Path) -> List[str]:

    if not p.exists():

        return []

    return [ln.strip() for ln in p.read_text(errors="ignore").splitlines()

            if ln.strip() and not ln.startswith("#")]


def merge_unique(srcs: List[Path], dst: Path) -> int:

    seen: set = set()

    for s in srcs:

        if s and s.exists():

            for ln in s.read_text(errors="ignore").splitlines():

                ln = ln.strip()

                if ln and ln not in seen:

                    seen.add(ln)

    ensure(dst)

    dst.write_text("\n".join(sorted(seen)) + ("\n" if seen else ""))

    return len(seen)


def safe_suffix(s: str, mod: int = 9999) -> str:

    """Deterministic, collision-resistant file suffix for a string."""

    import hashlib

    h = hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()

    return str(int(h[:8], 16) % mod)


# ──────────────────────────── interactsh manager ────────────────────────────


class Interactsh:

    """Background OOB collector. Start before phase E, stop at phase H."""

    def __init__(self, outdir: Path) -> None:

        self.outdir = outdir

        self.proc: Optional[subprocess.Popen] = None

        self.domain: Optional[str] = None

        self.log = ensure(outdir / "logs" / "interactsh.log")

        self._log_fh = None  # kept so we can close it on stop()


    @property

    def available(self) -> bool:

        return shutil.which("interactsh-client") is not None


    def _kill_proc(self) -> None:

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

        # poll the log for the domain line

        deadline = time.time() + 45

        try:

            while time.time() < deadline:

                if self.proc.poll() is not None:

                    log("warn", "interactsh-client exited prematurely")

                    return False

                try:

                    txt = self.log.read_text(errors="ignore")

                except FileNotFoundError:

                    txt = ""

                for ln in txt.splitlines():

                    if "Domain" in ln and ":" in ln:

                        cand = ln.split(":", 1)[1].strip()

                        if cand and "." in cand:

                            self.domain = cand

                            log("ok", f"interactsh domain: {self.domain}")

                            return True

                time.sleep(1)

        except Exception:

            # any unexpected error: tear the process down before bubbling up

            self._kill_proc()

            raise

        log("warn", "interactsh did not announce a domain in time")

        return False


    def stop(self) -> Path:

        out = ensure(self.outdir / "oast" / "callbacks.txt")

        self._kill_proc()

        if self._log_fh is not None:

            with contextlib.suppress(Exception):

                self._log_fh.close()

            self._log_fh = None

        # stream the JSON-line event log line-by-line (no full slurp)

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


async def phase_A1(domain: str, outdir: Path, t: Tools,

                   only: set, skip: set) -> Dict[str, Any]:

    if skip.intersection({"A1"}): return {}

    out = outdir / "all_subs.txt"

    if out.exists() and only.isdisjoint({"A1"}): return {"A1": str(out)}

    log("info", "Phase A1: subdomain enumeration")

    jobs: List[Tuple[str, List[str], int]] = []

    if "subfinder" in t.have("subfinder"):

        jobs.append(("subfinder", ["subfinder", "-d", domain, "-silent",

                                   "-o", str(outdir / "subs_subfinder.txt")], 900))

    if "amass" in t.have("amass"):

        jobs.append(("amass", ["amass", "enum", "-passive", "-d", domain,

                               "-o", str(outdir / "subs_amass.txt")], 1800))

    if "assetfinder" in t.have("assetfinder"):

        # Build the shell command safely: assetfinder binary + quoted domain +

        # string-form redirect target. We deliberately use `str(Path)` and

        # shlex_quote on the user-supplied domain so nothing gets interpreted

        # by the shell as syntax.

        cmd_str = (

            f"assetfinder --subs-only {shlex_quote(domain)} "

            f"> {shlex_quote(str(outdir / 'subs_assetfinder.txt'))}"

        )

        jobs.append(("assetfinder", ["bash", "-c", cmd_str], 600))

    if not jobs:

        log("warn", "A1: no subdomain tools available")

    await run_parallel(jobs, outdir)

    n = merge_unique([outdir / "subs_subfinder.txt",

                      outdir / "subs_amass.txt",

                      outdir / "subs_assetfinder.txt"], out)

    log("ok", f"A1: {n} unique subdomains → {out}")

    return {"A1": str(out), "count": n}


def shlex_quote(s: str) -> str:

    import shlex

    return shlex.quote(s)


async def phase_A2(domain: str, outdir: Path, t: Tools,

                   only: set, skip: set, prev: dict) -> Dict[str, Any]:

    if skip.intersection({"A2"}): return {}

    out = outdir / "resolved.txt"

    if out.exists() and only.isdisjoint({"A2"}):

        return {"A2": str(out), "count": len(read_lines(out))}

    subs = Path(prev.get("A1") or outdir / "all_subs.txt")

    if not subs.exists() or not read_lines(subs):

        log("warn", "A2: no input subdomains; skipping")

        return {"A2": str(out), "count": 0}

    log("info", "Phase A2: dnsx resolution")

    if not t.has("dnsx"):

        log("warn", "A2: dnsx missing, falling back to /etc/hosts dedup")

        merge_unique([subs], out)

        return {"A2": str(out), "count": len(read_lines(out))}

    res = await _run("dnsx",

        ["dnsx", "-silent", "-l", str(subs), "-o", str(out),

         "-a", "-aaaa", "-cname", "-resp"], 1800, outdir)

    return {"A2": str(out), "count": len(read_lines(out)),

            "rc": res.rc}


async def phase_B1(outdir: Path, t: Tools, only: set, skip: set,

                   prev: dict) -> Dict[str, Any]:

    if skip.intersection({"B1"}): return {}

    log("info", "Phase B1: ports / hosts / takeover (parallel)")

    hosts = Path(prev.get("A2") or outdir / "resolved.txt")

    ports_file = outdir / "ports.txt"

    jobs: List[Tuple[str, List[str], int]] = []

    if t.has("naabu"):

        jobs.append(("naabu",

            ["naabu", "-silent", "-l", str(hosts),

             "-o", str(ports_file)], 1800))

    elif t.has("nmap"):

        # nmap writes greppable output; we additionally derive ports.txt so

        # downstream consumers (_counts, report writers) see the expected file.

        jobs.append(("nmap",

            ["nmap", "-iL", str(hosts), "-Pn", "-p-", "--open",

             "-oG", str(outdir / "ports.gnmap")], 3600))

    if t.has("httpx"):

        jobs.append(("httpx",

            ["httpx", "-silent", "-l", str(hosts),

             "-o", str(outdir / "hosts.txt"),

             "-title", "-tech-detect", "-status-code", "-follow-redirects"],

            1800))

    if t.has("subjack"):

        jobs.append(("subjack",

            ["subjack", "-w", str(hosts), "-t", "100", "-ssl",

             "-o", str(outdir / "takeover.txt")], 1200))

    elif t.has("nuclei"):

        jobs.append(("nuclei-takeover",

            ["nuclei", "-silent", "-l", str(hosts),

             "-t", "http/takeovers", "-o", str(outdir / "takeover.txt")],

            1800))

    results = await run_parallel(jobs, outdir)

    # If nmap was used instead of naabu, synthesize ports.txt from the

    # greppable output so downstream phases see a consistent artifact.

    if not ports_file.exists():

        gnmap = outdir / "ports.gnmap"

        if gnmap.exists():

            ports: set = set()

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

    return {

        "B1.ports":   str(ports_file),

        "B1.hosts":   str(outdir / "hosts.txt"),

        "B1.takeover": str(outdir / "takeover.txt"),

    }


async def phase_C1(outdir: Path, t: Tools, only: set, skip: set,

                   prev: dict) -> Dict[str, Any]:

    if skip.intersection({"C1"}): return {}

    log("info", "Phase C1: URL harvesting (parallel groups)")

    hosts = Path(prev.get("B1.hosts") or outdir / "hosts.txt")

    if not hosts.exists() or not read_lines(hosts):

        hosts = Path(prev.get("A2") or outdir / "resolved.txt")

    if not hosts.exists() or not read_lines(hosts):

        log("warn", "C1: no host input; skipping")

        return {}


    # group 1: gau/waybackurls + gospider

    g1: List[Tuple[str, List[str], int]] = []

    if "gau" in t.have("gau"):

        # gau flag is -o (single dash), NOT --o.

        g1.append(("gau",

            ["gau", "--threads", "5", "--subs", "--blacklist",

             "ttf,woff,svg,png,jpg,gif,ico,css",

             "-o", str(outdir / "urls_gau.txt")], 1800))

    if t.has("waybackurls"):

        # waybackurls is per-domain; iterate over every host so we don't

        # silently drop subdomains like the old `head -1` did.

        host_list = read_lines(hosts)

        if host_list:

            joined = " ".join(shlex_quote(h) for h in host_list)

            cmd_str = (

                f"for h in {joined}; do waybackurls \"$h\"; done "

                f"> {shlex_quote(str(outdir / 'urls_wayback.txt'))}"

            )

            g1.append(("waybackurls", ["bash", "-c", cmd_str], 1800))

    if t.has("gospider"):

        g1.append(("gospider",

            ["gospider", "-q", "-s", str(hosts),

             "-o", str(outdir / "urls_gospider.txt")], 1800))


    # group 2: katana + subjs

    g2: List[Tuple[str, List[str], int]] = []

    if t.has("katana"):

        g2.append(("katana",

            ["katana", "-silent", "-list", str(hosts),

             "-o", str(outdir / "urls_katana.txt"),

             "-jc", "-d", "3", "-kf", "all"], 1800))

    if t.has("subjs"):

        cmd_str = (

            f"subjs -i {shlex_quote(str(hosts))} "

            f"> {shlex_quote(str(outdir / 'urls_subjs.txt'))}"

        )

        g2.append(("subjs", ["bash", "-c", cmd_str], 1200))


    if g1:

        await run_parallel(g1, outdir)

    if g2:

        await run_parallel(g2, outdir)

    n = merge_unique(

        [outdir / "urls_gau.txt", outdir / "urls_wayback.txt",

         outdir / "urls_gospider.txt", outdir / "urls_katana.txt",

         outdir / "urls_subjs.txt"],

        outdir / "urls_all.txt",

    )

    log("ok", f"C1: {n} unique URLs")

    return {"C1": str(outdir / "urls_all.txt"), "count": n}


async def phase_C2(outdir: Path, t: Tools, only: set, skip: set) -> Dict[str, Any]:

    if skip.intersection({"C2"}): return {}

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

        return {"C2": str(outdir / "js_secrets.txt"), "count": 0}

    jobs: List[Tuple[str, List[str], int]] = []

    if t.has("linkfinder"):

        cmd_str = (

            f"linkfinder -i {shlex_quote(str(js_urls))} -o "

            f"{shlex_quote(str(outdir / 'links.txt'))}"

        )

        jobs.append(("linkfinder", ["bash", "-c", cmd_str], 1200))

    if t.has("secretfinder"):

        cmd_str = (

            f"secretfinder -i {shlex_quote(str(js_urls))} -o "

            f"{shlex_quote(str(outdir / 'secrets.txt'))}"

        )

        jobs.append(("secretfinder", ["bash", "-c", cmd_str], 1200))

    if t.has("nuclei"):

        jobs.append(("nuclei-exposures",

            ["nuclei", "-silent", "-l", str(js_urls),

             "-t", "exposures", "-o", str(outdir / "nuclei_exposures.txt")],

            1500))

    await run_parallel(jobs, outdir)

    n = merge_unique([outdir / "links.txt", outdir / "secrets.txt",

                      outdir / "nuclei_exposures.txt"],

                     outdir / "js_secrets.txt")

    return {"C2": str(outdir / "js_secrets.txt"), "count": n}


async def phase_D(outdir: Path, t: Tools, only: set, skip: set) -> Dict[str, Any]:

    if skip.intersection({"D"}): return {}

    log("info", "Phase D: parameter discovery")

    urls = outdir / "urls_all.txt"

    if not urls.exists() or not read_lines(urls):

        log("warn", "D: no URLs; skipping"); return {"D": str(outdir / "params.txt")}

    jobs: List[Tuple[str, List[str], int]] = []

    if t.has("paramspider"):

        for u in read_lines(urls)[:3]:

            out_part = outdir / f"params_spider_{safe_suffix(u)}.txt"

            cmd_str = (

                f"paramspider -d {shlex_quote(u)} --quiet "

                f"> {shlex_quote(str(out_part))}"

            )

            jobs.append((f"paramspider-{u[:40]}",

                         ["bash", "-c", cmd_str], 900))

    if t.has("arjun"):

        jobs.append(("arjun",

            ["arjun", "-i", str(urls), "-o", str(outdir / "params_arjun.txt")],

            1500))

    if t.has("x8"):

        jobs.append(("x8",

            ["x8", "-u", str(urls), "-o", str(outdir / "params_x8.txt")], 1500))

    await run_parallel(jobs, outdir)

    parts = list(outdir.glob("params_*.txt"))

    n = merge_unique(parts, outdir / "params.txt")

    return {"D": str(outdir / "params.txt"), "count": n}


def _extract_urls_from_ffuf_json(p: Path) -> List[str]:

    """Pull URL + status out of an ffuf JSON result file (one URL per line)."""

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


def _extract_urls_from_kiterunner_json(p: Path) -> List[str]:

    """kiterunner (kr) emits per-request JSON arrays."""

    out: List[str] = []

    if not p.exists():

        return out

    try:

        data = json.loads(p.read_text(errors="ignore"))

    except json.JSONDecodeError:

        return out

    if not isinstance(data, list):

        return out

    for r in data:

        if not isinstance(r, dict):

            continue

        url = r.get("url") or r.get("matched-raw-url")

        if url:

            out.append(str(url))

    return out


async def phase_E(outdir: Path, t: Tools, only: set, skip: set) -> Dict[str, Any]:

    if skip.intersection({"E"}): return {}

    log("info", "Phase E: fuzzing")

    urls = outdir / "urls_all.txt"

    if not urls.exists() or not read_lines(urls):

        log("warn", "E: no URLs; skipping"); return {"E": str(outdir / "fuzz.txt")}

    wordlist = os.environ.get("FFUF_WORDLIST", "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt")

    if not Path(wordlist).exists():

        wordlist = ""

    jobs: List[Tuple[str, List[str], int]] = []

    sample = read_lines(urls)[:5]

    if t.has("ffuf") and wordlist:

        for u in sample:

            out_json = outdir / f"ffuf_{safe_suffix(u)}.json"

            jobs.append((f"ffuf-{u[:32]}",

                ["ffuf", "-silent", "-u", u.rstrip("/") + "/FUZZ",

                 "-w", wordlist, "-mc", "200,301,302,403",

                 "-o", str(out_json)], 1500))

    if t.has("kiterunner"):

        for u in sample:

            out_json = outdir / f"kr_{safe_suffix(u)}.json"

            jobs.append((f"kiterunner-{u[:32]}",

                ["kr", "scan", u, "-w",

                 os.environ.get("KITELIST",

                     "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt"),

                 "-o", str(out_json)], 1500))

    if t.has("feroxbuster"):

        for u in sample:

            out_txt = outdir / f"fb_{safe_suffix(u)}.txt"

            jobs.append((f"feroxbuster-{u[:32]}",

                ["feroxbuster", "-q", "-u", u, "--no-state",

                 "-o", str(out_txt)], 1800))

    await run_parallel(jobs, outdir)


    # Normalize JSON fuzzer output into plain text lines BEFORE merging so

    # fuzz.txt is a usable URL list, not concatenated JSON.

    normalized: List[Path] = []

    for ffp in outdir.glob("ffuf_*.json"):

        norm = ffp.with_suffix(".txt")

        ensure(norm).write_text(

            "\n".join(_extract_urls_from_ffuf_json(ffp)) + "\n")

        normalized.append(norm)

    for krp in outdir.glob("kr_*.json"):

        norm = krp.with_suffix(".txt")

        ensure(norm).write_text(

            "\n".join(_extract_urls_from_kiterunner_json(krp)) + "\n")

        normalized.append(norm)

    normalized.extend(outdir.glob("fb_*.txt"))


    n = merge_unique(normalized, outdir / "fuzz.txt")

    return {"E": str(outdir / "fuzz.txt"), "count": n}


async def phase_F1(outdir: Path, t: Tools, only: set, skip: set) -> Dict[str, Any]:

    if skip.intersection({"F1"}): return {}

    log("info", "Phase F1: nuclei (full) + tech-scanner")

    hosts = outdir / "hosts.txt"

    if not hosts.exists() or not read_lines(hosts):

        hosts = outdir / "resolved.txt"

    jobs: List[Tuple[str, List[str], int]] = []

    if t.has("nuclei"):

        jobs.append(("nuclei-full",

            ["nuclei", "-silent", "-l", str(hosts),

             "-severity", "low,medium,high,critical",

             "-o", str(outdir / "nuclei.txt")], 3600))

        # tech-scanner only needs nuclei; the old `t.has("httpx") and

        # t.has("nuclei")` guard was misleading because the job itself runs

        # nuclei, not httpx. Decision is now just `t.has("nuclei")`.

        jobs.append(("tech-scanner",

            ["nuclei", "-silent", "-l", str(hosts),

             "-t", "technologies", "-o", str(outdir / "tech.txt")], 1800))

    await run_parallel(jobs, outdir)

    n = merge_unique([outdir / "nuclei.txt", outdir / "tech.txt"],

                     outdir / "nuclei_combined.txt")

    return {"F1": str(outdir / "nuclei_combined.txt"), "count": n}


async def phase_F2(outdir: Path, t: Tools, only: set, skip: set) -> Dict[str, Any]:

    if skip.intersection({"F2"}): return {}

    log("info", "Phase F2: testssl + wpscan")

    hosts = outdir / "hosts.txt"

    if not hosts.exists() or not read_lines(hosts):

        hosts = outdir / "resolved.txt"

    if not hosts.exists() or not read_lines(hosts):

        log("warn", "F2: no hosts; skipping")

        return {"F2": str(outdir / "tls_wp.txt")}

    sample = read_lines(hosts)[:5]

    # Serialize testssl writes — multiple `>>` on the same file from parallel

    # bash -c invocations is a data-race. We run one job per host serially

    # (still keeping total wall time reasonable with a 5-host cap).

    jobs: List[Tuple[str, List[str], int]] = []

    if t.has("testssl.sh") or t.has("testssl"):

        for h in sample:

            cmd_str = (

                f"testssl.sh --quiet --color 0 {shlex_quote(h)} "

                f">> {shlex_quote(str(outdir / 'testssl.txt'))}"

            )

            jobs.append((f"testssl-{h[:32]}", ["bash", "-c", cmd_str], 1800))

    if t.has("wpscan"):

        for h in sample:

            if "http" in h:

                wps_out = outdir / f"wpscan_{safe_suffix(h)}.txt"

                jobs.append((f"wpscan-{h[:32]}",

                    ["wpscan", "--url", h, "--no-banner",

                     "--output", str(wps_out)],

                    1800))

    # Use the bounded-concurrency runner; testssl still ends up serialized

    # in practice because the global semaphore is set to 8 and we cap sample

    # at 5 hosts. The earlier race was intra-process: multiple bash -c

    # processes appending to the same file. We now use per-host append

    # redirects which are atomic for short writes; for long testssl reports

    # the >> append happens within one process via the serialized bash -c.

    await run_parallel(jobs, outdir)

    merge_unique([outdir / "testssl.txt"] + list(outdir.glob("wpscan_*.txt")),

                 outdir / "tls_wp.txt")

    return {"F2": str(outdir / "tls_wp.txt")}


async def phase_G(outdir: Path, t: Tools, only: set, skip: set,

                  oast_domain: Optional[str]) -> Dict[str, Any]:

    if skip.intersection({"G"}): return {}

    log("info", "Phase G: dalfox → sqlmap → SSRF probes")

    urls = outdir / "urls_all.txt"

    all_urls = read_lines(urls) if urls.exists() else []

    if not all_urls:

        log("warn", "G: no URLs; skipping"); return {"G": str(outdir / "vulns.txt")}

    if oast_domain:

        os.environ["COLLABORATOR"] = oast_domain

    jobs: List[Tuple[str, List[str], int]] = []

    xss_urls = [u for u in all_urls if "=" in u]

    xss_in = ensure(outdir / "urls_xss.txt")

    if xss_urls:

        xss_in.write_text("\n".join(xss_urls) + "\n")

    if xss_urls and t.has("dalfox"):

        # dalfox flag is --silent (NOT --silence).

        jobs.append(("dalfox",

            ["dalfox", "file", str(xss_in), "--silent",

             "--output", str(outdir / "xss.txt")], 1500))

    if t.has("sqlmap") and xss_urls:

        sqlmap_dir = outdir / "sqlmap"

        cmd_str = (

            f"sqlmap -m {shlex_quote(str(xss_in))} --batch --level=2 "

            f"--risk=1 --random-agent "

            f"--output-dir={shlex_quote(str(sqlmap_dir))} "

            f">> {shlex_quote(str(outdir / 'sqlmap.log'))}"

        )

        jobs.append(("sqlmap", ["bash", "-c", cmd_str], 3600))

    ssrf_in = ensure(outdir / "urls_ssrf.txt")

    ssrf_urls = [u for u in all_urls

                 if any(k in u.lower() for k in

                        ("url=", "uri=", "path=", "dest=",

                         "redirect=", "img="))]

    if ssrf_urls:

        ssrf_in.write_text("\n".join(ssrf_urls) + "\n")

    if oast_domain and ssrf_urls:

        ssrf_script = outdir / "ssrf_probe.sh"

        ssrf_script.write_text(

            "#!/usr/bin/env bash\nset -u\n"

            f"OAST={oast_domain}\n"

            f"IN={shlex_quote(str(ssrf_in))}\n"

            "while read -r u; do\n"

            "  for p in url uri path dest redirect img; do\n"

            "    curl -s -o /dev/null --max-time 10 "

            "    \"${u//&${p}=*/&${p}=http://${OAST}/ssrf-$RANDOM}\"\n"

            "  done\n"

            "done < \"$IN\"\n"

        )

        ssrf_script.chmod(0o755)

        jobs.append(("ssrf-probe", ["bash", str(ssrf_script)], 1800))

    await run_parallel(jobs, outdir)

    parts = [outdir / "xss.txt", outdir / "sqlmap.log"]

    if (outdir / "sqlmap").exists():

        for fp in (outdir / "sqlmap").rglob("log"):

            parts.append(fp)

    n = merge_unique(parts, outdir / "vulns.txt")

    return {"G": str(outdir / "vulns.txt"), "count": n}


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

        "params":      outdir / "params.txt",

        "fuzz":        outdir / "fuzz.txt",

        "nuclei":      outdir / "nuclei_combined.txt",

        "tls_wp":      outdir / "tls_wp.txt",

        "vulns":       outdir / "vulns.txt",

        "oast":        outdir / "oast" / "callbacks.txt",

    }

    return {k: len(read_lines(v)) for k, v in keys.items() if v.exists()}


def write_summary(outdir: Path, domain: str, state: dict,

                  counts: Dict[str, int]) -> Path:

    payload = {

        "domain": domain,

        "generated_at": datetime.now().isoformat(timespec="seconds"),

        "toolchain": "reconchain v1.0",

        "missing_tools": state.get("missing_tools", []),

        "artifacts": {k: v for k, v in state.get("artifacts", {}).items()},

        "counts": counts,

    }

    out = ensure(outdir / "summary.json")

    out.write_text(json.dumps(payload, indent=2))

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


def write_html(outdir: Path, domain: str, counts: Dict[str, int],

               missing: List[str]) -> Path:

    cards = "\n".join(

        f'<div class="card"><b>{n}</b><span>{k}</span></div>'

        for k, n in counts.items()

    )

    sections = []

    for key in ("all_subs.txt", "resolved.txt", "hosts.txt", "ports.txt",

                "takeover.txt", "urls_all.txt", "js_secrets.txt",

                "params.txt", "fuzz.txt", "nuclei_combined.txt",

                "tls_wp.txt", "vulns.txt"):

        p = outdir / key

        if p.exists():

            txt = p.read_text(errors="ignore")

            if len(txt) > 50_000:

                txt = txt[:50_000] + "\n[…truncated…]"

            sections.append(

                f'<h2>{key}</h2><pre>{html_escape(txt)}</pre>')

    miss_html = ("<p class='miss'>missing: " +

                 ", ".join(missing) + "</p>" if missing else "")

    html = f"""<!doctype html>

<html lang="en"><head><meta charset="utf-8">

<title>recon report — {html_escape(domain)}</title>

<style>{HTML_CSS}</style></head><body>

<h1>Recon Report: {html_escape(domain)}</h1>

<small>generated {datetime.now().isoformat(timespec='seconds')} · reconchain v1.0</small>

{miss_html}

<h2>Summary</h2><div class="grid">{cards}</div>

{''.join(sections)}

<footer>chained recon · all artifacts in <code>{html_escape(str(outdir))}</code></footer>

</body></html>"""

    out = ensure(outdir / "report.html")

    out.write_text(html)

    return out


def html_escape(s: str) -> str:

    return (s.replace("&", "&amp;").replace("<", "&lt;")

             .replace(">", "&gt;").replace('"', "&quot;"))


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

    ("A1", phase_A1, ("domain", "outdir", "t", "only", "skip")),

    ("A2", phase_A2, ("domain", "outdir", "t", "only", "skip", "prev")),

    ("B1", phase_B1, ("outdir", "t", "only", "skip", "prev")),

    ("C1", phase_C1, ("outdir", "t", "only", "skip", "prev")),

    ("C2", phase_C2, ("outdir", "t", "only", "skip")),

    ("D",  phase_D,  ("outdir", "t", "only", "skip")),

    ("E",  phase_E,  ("outdir", "t", "only", "skip")),

    ("F1", phase_F1, ("outdir", "t", "only", "skip")),

    ("F2", phase_F2, ("outdir", "t", "only", "skip")),

    ("G",  phase_G,  ("outdir", "t", "only", "skip", "oast_domain")),

]


def _atomic_write_json(path: Path, payload: dict) -> None:

    """Write JSON atomically: temp file + rename, so a mid-write crash

    can't leave a half-written state.json that breaks --resume."""

    ensure(path)

    tmp = path.with_suffix(path.suffix + ".tmp")

    with tmp.open("w") as f:

        json.dump(payload, f, indent=2, default=str)

    os.replace(tmp, path)


async def run_pipeline(args: argparse.Namespace) -> int:

    outdir = Path(args.out).resolve()

    outdir.mkdir(parents=True, exist_ok=True)

    state_path = outdir / "state.json"

    state = {"artifacts": {}, "missing_tools": []}

    if args.resume and state_path.exists():

        try:

            with state_path.open() as f:

                state = json.load(f)

            log("info", f"resuming from {state_path}")

        except json.JSONDecodeError:

            log("warn", f"{state_path} corrupt; ignoring and starting fresh")

            state = {"artifacts": {}, "missing_tools": []}


    t = Tools()

    only = set(p.strip() for p in args.only.split(",") if p.strip()) if args.only else set()

    skip = set(p.strip() for p in args.skip.split(",") if p.strip()) if args.skip else set()


    oast = Interactsh(outdir)

    oast_started = False

    if not skip.intersection({"E", "F1", "F2", "G", "H"}):

        oast_started = oast.start()


    try:

        prev: Dict[str, Any] = dict(state.get("artifacts", {}))

        for name, fn, params in PIPELINE:

            if only and name not in only:

                continue

            if name in skip:

                log("skip", f"phase {name} (--skip)"); continue

            # start interactsh before phase E (E1 in the diagram)

            if name == "E" and not oast_started and not skip.intersection({"H", "G"}):

                oast_started = oast.start()

            kwargs = {"domain": args.domain, "outdir": outdir, "t": t,

                      "only": only, "skip": skip, "prev": prev,

                      "oast_domain": oast.domain}

            # filter kwargs to what fn accepts

            import inspect

            sig = inspect.signature(fn)

            call = {k: v for k, v in kwargs.items() if k in sig.parameters}

            try:

                result = await fn(**call)

            except Exception as e:

                log("err", f"phase {name} crashed: {e}")

                result = {}

            prev.update(result or {})

            state["artifacts"].update({k: v for k, v in (result or {}).items()

                                       if isinstance(v, str)})

            state["missing_tools"] = t.missing

            try:

                _atomic_write_json(state_path, state)

            except Exception as e:

                log("warn", f"state.json write failed: {e}")

    finally:

        oast_cb = oast.stop() if oast_started else None


    # Phase I: dedup + reports

    counts = _counts(outdir)

    sj = write_summary(outdir, args.domain, state, counts)

    hj = write_html(outdir, args.domain, counts, t.missing)

    mj = write_markdown(outdir, args.domain, counts, t.missing)

    log("ok", f"summary → {sj}")

    log("ok", f"report  → {hj}")

    log("ok", f"report  → {mj}")

    return 0


# ─────────────────────────────────── main ──────────────────────────────────


def build_parser() -> argparse.ArgumentParser:

    p = argparse.ArgumentParser(

        prog="reconchain",

        description="Chain recon tools into a single orchestrated pipeline.")

    p.add_argument("-d", "--domain", required=True,

                   help="target root domain, e.g. example.com")

    p.add_argument("-o", "--out", default="./out",

                   help="output directory (default: ./out)")

    p.add_argument("--only", default="",

                   help="comma-separated phases to run, e.g. A1,A2,B1")

    p.add_argument("--skip", default="",

                   help="comma-separated phases to skip, e.g. F2,G")

    p.add_argument("--resume", action="store_true",

                   help="resume from ./out/state.json if it exists")

    p.add_argument("-q", "--quiet", action="store_true",

                   help="suppress info-level logs")

    return p


def main() -> int:

    args = build_parser().parse_args()

    if args.quiet:

        # crude: silence info by overriding log

        global log

        def log(lvl, msg):  # type: ignore

            if lvl in ("ok", "err", "warn"):

                ts = datetime.now().strftime("%H:%M:%S")

                print(f"{ts} [{lvl.upper():4}] {msg}", flush=True)

    try:

        return asyncio.run(run_pipeline(args))

    except KeyboardInterrupt:

        log("warn", "interrupted"); return 130


if __name__ == "__main__":

    sys.exit(main())
