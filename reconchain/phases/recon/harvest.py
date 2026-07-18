"""Phases 05 and 05b: URL harvesting and API spec discovery."""
from reconchain.phases.helpers import *


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
                        except json.JSONDecodeError:
                            try:
                                import yaml
                                data = yaml.safe_load(body)
                            except Exception:
                                data = None
                        if data and "paths" in data:
                            endpoints = list(data["paths"].keys())
                            lines = [f"[openapi] {url} → {len(endpoints)} endpoints"]
                            lines += [f"  {ep}" for ep in endpoints[:20]]
                            return "\n".join(lines)
                        else:
                            return f"[openapi] {url} (unparseable)"
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
