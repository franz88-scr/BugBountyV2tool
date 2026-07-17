"""Reconnaissance phases: scope, subdomain enum, DNS, port scan, URL harvest, JS intel, params, OSINT."""
from reconchain.phases.helpers import *


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
            _amass_flags = '-d "$DOMAIN" -nocolor'
            if _PIPELINE_CFG.safe_mode:
                _amass_flags += " -passive -dns-qps 50"
            runner.write_text(
                "#!/usr/bin/env bash\n"
                "set -eu\n"
                "# DNS enumeration — clear proxy env so Go SOCKS doesn't slow DNS queries\n"
                "unset ALL_PROXY all_proxy HTTPS_PROXY https_proxy HTTP_PROXY http_proxy PROXY\n"
                f"{_amass_proxy_lines}"
                f"OUT={shlex.quote(str(_amass_out))}\n"
                f"DOMAIN={shlex.quote(domain)}\n"
                ': > "$OUT"\n'
                f'amass enum {_amass_flags} '
                "| grep --line-buffered -oE '([A-Za-z0-9._-]+)( \\(FQDN\\))?' "
                "| sed 's/ (FQDN)$//' >> \"$OUT\"\n"
            )
            runner.chmod(0o700)
            jobs.append(("amass", ["bash", str(runner)], _maybe_timeout(300)))

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
        from reconchain.process import _PIPELINE_CFG, _USE_PROXYCHAINS
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
    log("info", "Phase 04-SCAN: ports / hosts / takeover (sequential)")
    # naabu/httpx/nuclei-takeover accept host:port (or hosts from httpx)
    hosts = Path(prev.get("02-RESOLVE") or outdir / "resolved.txt")
    # nuclei takeover templates need CLEAN subdomains (no `[1.2.3.4]` suffix from dnsx -resp)
    subs = Path(prev.get("01-RECON") or outdir / "all_subs.txt")
    ports_file = outdir / "ports.txt"
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
    # STEP 1: Port scan (naabu or nmap) — one tool at a time to keep RAM low
    if have_hosts and t.has("naabu"):
        await run_parallel([(
            "naabu",
            ["naabu", "-silent", "-l", str(hosts), "-o", str(ports_file), "-top-ports", "1000"],
            _maybe_timeout(1800),
        )], outdir)
    elif have_hosts and t.has("nmap"):
        _nmap_timing = ["-T3", "--max-retries", "1"] if _PIPELINE_CFG.safe_mode else []
        _nmap_cmd = ["nmap", "-iL", str(hosts), "-Pn", "--top-ports", "1000", "--open",
                     "--script=http-enum", "-oG", str(outdir / "ports.gnmap")] + _nmap_timing
        await run_parallel([("nmap", _nmap_cmd, _maybe_timeout(1800))], outdir)
    # STEP 2: HTTP probe (httpx or httprobe) — after port scan frees RAM
    if have_hosts and t.has("httpx"):
        _httpx_proxy = []
        if _PIPELINE_CFG.proxy:
            _httpx_proxy = ["-proxy", _PIPELINE_CFG.proxy]
        await run_parallel([(
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
        )], outdir)
    elif have_hosts and t.has("httprobe"):
        httprobe_out = outdir / "hosts_httprobe.txt"
        httprobe_runner = outdir / "logs" / "httprobe_runner.sh"
        ensure(httprobe_runner)
        _httprobe_conc = "50"
        _httprobe_rl = _rate_limit_args("httprobe")
        if _httprobe_rl:
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
        await run_parallel([(
            "httprobe",
            ["bash", str(httprobe_runner)],
            600,
        )], outdir)
    # STEP 3: Nuclei templates update (only once)
    if t.has("nuclei"):
        await _update_nuclei_templates(outdir)
    # STEP 4: Takeover detection (nuclei) — after httpx freed RAM
    if t.has("nuclei") and have_subs:
        _nuc_proxy = []
        if _PIPELINE_CFG.proxy:
            _nuc_proxy = ["-proxy", _PIPELINE_CFG.proxy]
        await run_parallel([(
            "nuclei-dns-takeover",
            [
                "nuclei", "-silent", "-l", str(subs),
                "-t", "dns/", "-tags", "takeover",
                "-timeout", "15", "-max-host-error", "10",
                "-o", str(outdir / "takeover_dns.txt"),
            ] + _nuc_proxy + _rate_limit_args("nuclei"),
            _maybe_timeout(1800),
        )], outdir)
    if have_hosts and t.has("nuclei"):
        _nuc_proxy = []
        if _PIPELINE_CFG.proxy:
            _nuc_proxy = ["-proxy", _PIPELINE_CFG.proxy]
        await run_parallel([(
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
        )], outdir)
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
        # Build set of non-404 hosts to allowlist during service detection.
        # Use allowlist instead of blocklist because permutation-generated hosts
        # (e.g. acc-acc-admin.api.*) aren't in hosts.txt and would bypass a blocklist.
        _live_hosts: Set[str] = set()
        _raw_hosts_file = outdir / "hosts.txt"
        if _raw_hosts_file.exists():
            for _ln in read_lines(_raw_hosts_file):
                if "[404]" not in _ln:
                    _h_match = _ln.split("]")[0].split("//")[-1].strip()
                    if _h_match:
                        _live_hosts.add(_h_match)
        _skipped = 0
        for ln in read_lines(ports_file):
            if ":" in ln:
                h, p = ln.rsplit(":", 1)
                # Only scan known live hosts — skip Caddy wildcard catchalls
                if _live_hosts and h not in _live_hosts:
                    _skipped += 1
                    continue
                host_ports.setdefault(h, []).append(p)
        if _skipped:
            log("info", f"04-SCAN: nmap-sv allowlist: {len(host_ports)} live hosts, skipped {_skipped} wildcard hosts")
        for h, pp in host_ports.items():
            ports_csv = ",".join(pp)
            out_sv = outdir / f"services_{safe_suffix(h)}.gnmap"
            _sv_timing = ["-T3", "--max-retries", "1"] if _PIPELINE_CFG.safe_mode else []
            _sv_cmd = ["nmap", "-Pn", "-sV", "--open",
                       "-p", ports_csv, str(h), "--host-timeout", "10m", "-oG", str(out_sv)] + _sv_timing
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
        # Filter out404 hosts — no point crawling wildcard Caddy catchalls
        _filtered = outdir / "hosts_active.txt"
        _active_lines = [ln for ln in read_lines(raw_hosts) if "[404]" not in ln]
        if _active_lines:
            ensure(_filtered).write_text("\n".join(_active_lines) + "\n")
            log("info", f"04-SCAN: {len(_active_lines)}/{len(read_lines(raw_hosts))} non-404 hosts for crawling")
            _write_target_tokens(_filtered, targets)
        else:
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
            # Fallback: filter 404s from hosts.txt
            h_raw = Path(prev.get("04-SCAN.hosts") or outdir / "hosts.txt")
            if h_raw.exists() and bool(read_lines(h_raw)):
                _active = [ln for ln in read_lines(h_raw) if "[404]" not in ln]
                if _active:
                    log("info", f"05-HARVEST: {len(_active)}/{len(read_lines(h_raw))} non-404 hosts")
                    ensure(h).write_text("\n".join(_active) + "\n")
                    h_ok = True
        if not h_ok:
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
                    _clean_probe = outdir / ".harvest_new_clean.txt"
                    _clean_lines = []
                    for _pl in read_lines(httpx_out):
                        _pt = _pl.strip().split()[0] if _pl.strip() else ""
                        if _pt.startswith("http"):
                            _clean_lines.append(_pt)
                    if _clean_lines:
                        _clean_probe.write_text("\n".join(_clean_lines) + "\n")
                        merge_unique([_clean_probe], targets_file)
                        merge_unique([httpx_out], outdir / "hosts.txt")
                        _clean_probe.unlink(missing_ok=True)
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
        # Cap input to avoid long hangs over Tor/proxy
        _nuc_exposure_input = _js_input
        _nuc_js_lines = read_lines(_js_input) if _js_input.exists() else []
        _nuc_cap = 20 if _USE_PROXYCHAINS or (
            _PIPELINE_CFG.proxy and _PIPELINE_CFG.proxy.startswith(("socks4", "socks5"))
        ) else 50
        if len(_nuc_js_lines) > _nuc_cap:
            _nuc_exposure_input = outdir / "urls_js_nuclei_sample.txt"
            ensure(_nuc_exposure_input).write_text("\n".join(_nuc_js_lines[:_nuc_cap]) + "\n")
            log("info", f"06-JSINTEL: capped nuclei-exposures input to {_nuc_cap} URLs (from {len(_nuc_js_lines)})")
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
                    "-timeout", "30", "-max-host-error", "10",
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


# --- JS secret patterns (used by phase_06_JSINTEL) ---
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



# --- OSINT phases (84-89) ---
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
            age_months = (datetime.now(tz=created.tzinfo) - created).days / 30
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
    out = ensure(_out)
    out.write_text("\n".join(sorted(set(clean_subs))) + ("\n" if clean_subs else "[no passive DNS subdomains found]\n"))
    if clean_subs:
        all_subs = outdir / "all_subs.txt"
        if all_subs.exists():
            merge_unique([_out], all_subs)
    log("ok", f"89-PASSIVEDNS: {len(clean_subs)} subdomains → {out}")
    return {"89-PASSIVEDNS": str(_out), "count": len(clean_subs)}
