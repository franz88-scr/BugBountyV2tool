"""Phase 02: DNS resolution with parallel fallback chain."""
from reconchain.phases.helpers import *


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

    if not read_lines(subs_file, max_lines=1):
        is_done = isinstance(prev.get("01-RECON"), str) or subs_file.exists()
        if is_done:
            log("warn", "02-RESOLVE: 01-RECON produced no subdomains; skipping")
            out.touch()
            return {"02-RESOLVE": str(out), "count": 0}
        for _ in range(120):
            await asyncio.sleep(5)
            if next(iter_lines(subs_file), None):
                break
        if not next(iter_lines(subs_file), None):
            log("warn", "02-RESOLVE: 01-RECON produced no subdomains; skipping")
            out.touch()
            return {"02-RESOLVE": str(out), "count": 0}

    log("info", "Phase 02-RESOLVE: resolution with parallel fallback (massdns → dnsx → dig)")
    _a2_processed: Set[str] = set()
    if resume:
        for ln in read_lines(out):
            h = ln.strip().lower()
            if h:
                _a2_processed.add(h)
    _a2_stable_count = 0

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
        from reconchain.process import _PIPELINE_CFG, _USE_PROXYCHAINS
        from reconchain.utils import _socks_patched, get_dns_cache
        proxy = _PIPELINE_CFG.proxy or os.environ.get("PROXY", "")
        if proxy and not proxy.startswith(("http://", "https://")) and not _socks_patched:
            return None
        if _USE_PROXYCHAINS and not _socks_patched:
            return None
        # Check DNS cache first
        dns_cache = get_dns_cache()
        cached = dns_cache.get(host)
        if cached is not None:
            return host if cached else None
        try:
            infos = await asyncio.get_event_loop().getaddrinfo(host, 0, family=socket.AF_UNSPEC)
            ips = {info[4][0] for info in infos}
            dns_cache.put(host, ips)
            return host
        except Exception:
            dns_cache.put(host, set())
            return None

    async def _resolve_batch(hosts: List[str]) -> int:
        hosts = [h for h in hosts if h not in _a2_processed]
        if not hosts:
            return 0
        _a2_processed.update(h.lower() for h in hosts)
        tmp = outdir / ".a2_batch.txt"
        tmp.write_text("\n".join(hosts) + "\n")
        resolved_count = 0
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

    initial = await _read_subs()
    await _resolve_batch(initial)

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
