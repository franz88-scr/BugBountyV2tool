"""Origin, cloud, and bucket phases."""
from reconchain.phases.helpers import *


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
