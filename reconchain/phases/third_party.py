"""Third-party and browser-related phases: SRI, mixed content, HSTS preload, third-party JS, browser storage."""
from reconchain.phases.helpers import *


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
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
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
        if "://" in host:
            host_clean = urllib.parse.urlparse(host).hostname or host
        else:
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
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
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
        if "://" in host:
            host_clean = urllib.parse.urlparse(host).hostname or host
        else:
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
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
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
        if "://" in host:
            host_clean = urllib.parse.urlparse(host).hostname or host
        else:
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
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
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
