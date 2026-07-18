"""Phases 01 and 03: subdomain enumeration and permutation."""
from reconchain.phases.helpers import *


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
    if t.has("findomain"):
        _fd_out = outdir / "subs_findomain.txt"
        if resume and _fd_out.exists() and count_nonblank(_fd_out) > 0:
            log("skip", "findomain (resume — output exists)")
        else:
            runner = outdir / "logs" / "findomain.sh"
            ensure(runner)
            _fd_proxy_lines = ""
            if _PIPELINE_CFG.proxy:
                _fd_proxy_lines = f"export ALL_PROXY={shlex.quote(_PIPELINE_CFG.proxy)}\n"
            _fd_flags = '-t "$DOMAIN"'
            if _PIPELINE_CFG.safe_mode:
                _fd_flags += " -q"
            runner.write_text(
                "#!/usr/bin/env bash\n"
                "set -eu\n"
                "# DNS enumeration — clear proxy env so queries aren't slowed\n"
                "unset ALL_PROXY all_proxy HTTPS_PROXY https_proxy HTTP_PROXY http_proxy PROXY\n"
                f"{_fd_proxy_lines}"
                f"OUT={shlex.quote(str(_fd_out))}\n"
                f"DOMAIN={shlex.quote(domain)}\n"
                ': > "$OUT"\n'
                f'findomain {_fd_flags} >> "$OUT"\n'
            )
            runner.chmod(0o700)
            jobs.append(("findomain", ["bash", str(runner)], _maybe_timeout(300)))

    _a1_sources = [
        outdir / "subs_subfinder.txt",
        outdir / "subs_findomain.txt",
    ]

    if not jobs:
        if any(p.exists() for p in _a1_sources):
            n = merge_unique(_a1_sources, out, validator=lambda s: _is_valid_hostname(s) and _is_under_domain(s, domain))
            if n == 0:
                out.touch()
            log("ok", f"01-RECON: {n} unique subdomains → {out}")
            return {"01-RECON": str(out), "count": n}
        log("warn", "01-RECON: no subdomain tools available")
        ensure(out)
        return {"01-RECON": str(out), "count": 0}

    def _under_domain(s: str) -> bool:
        return _is_valid_hostname(s) and _is_under_domain(s, domain)

    async def _incremental_merge() -> None:
        _last_mtimes: Dict[str, float] = {str(p): 0.0 for p in _a1_sources}
        _max_iterations = 120
        for _ in range(_max_iterations):
            await asyncio.sleep(30)
            changed = False
            for p in _a1_sources:
                if p.exists():
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

    failures = {r.name: r.rc for r in results if r.rc not in (0, None) and r.note != "skipped"}

    n = merge_unique(_a1_sources, out, validator=_under_domain)
    if n == 0:
        out.touch()
    log("ok", f"01-RECON: {n} unique subdomains → {out}")
    ret: Dict[str, Any] = {"01-RECON": str(out), "count": n}
    if failures:
        ret["failures"] = failures
        log("warn", f"01-RECON: partial — failed tools: {failures}")
    return ret


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
            "head -500 \"$IN\" | dnsgen | sort -u > \"$OUT\"\n"
        )
        runner.chmod(0o700)
        jobs.append(("dnsgen", ["bash", str(runner)], 600))
    if jobs:
        await run_parallel(jobs, outdir)
    if alt_out.exists() and read_lines(alt_out):
        alt_hosts = [ln for ln in read_lines(alt_out) if _is_valid_hostname(ln)]
        if alt_hosts:
            tmp_alt = outdir / ".permuted_alterx_valid.txt"
            tmp_alt.write_text("\n".join(alt_hosts) + "\n")
            merge_unique([subs_in, tmp_alt], subs_in)
            tmp_alt.unlink(missing_ok=True)
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
    merge_srcs = [subs_in]
    if resolved.exists() and read_lines(resolved):
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
    n = merge_unique(merge_srcs, subs_in, lambda h: _is_under_domain(h, domain))
    _a3_stamp.write_text("")
    permuted.unlink(missing_ok=True)
    resolved.unlink(missing_ok=True)
    log("ok", f"03-PERMUTE: {n} total subdomains (after permutation)")
    return {"01-RECON": str(subs_in), "03-PERMUTE": str(subs_in), "count": n}
