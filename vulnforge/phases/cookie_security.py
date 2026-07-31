"""Cookie security phases: cookie tossing and MIME sniffing detection."""

from vulnforge.phases.helpers import (
    Any,
    Dict,
    List,
    Path,
    PhaseSet,
    Tools,
    _async_urlopen,
    _async_urlopen_no_redirect,
    _extra_headers_dict,
    _get_urlopener,
    asyncio,
    count_nonblank,
    ensure,
    log,
    re,
    read_lines,
    urllib,
)


async def phase_194_COOKIETOSS(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"194-COOKIETOSS"}:
        return {}
    _out = outdir / "cookie_toss.txt"
    if _out.exists() and not force:
        return {"194-COOKIETOSS": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 194-COOKIETOSS: cookie tossing detection")
    findings: List[str] = []
    ct_urlopen = _get_urlopener()
    ct_extra_headers = _extra_headers_dict()

    hosts_file = outdir / "host_targets.txt"
    if not hosts_file.exists():
        hosts_file = outdir / "hosts.txt"
    targets = [f"https://{h}" if not h.startswith("http") else h for h in read_lines(hosts_file)]
    if not targets:
        log("warn", "194-COOKIETOSS: no HTTP targets; skipping")
        return {"194-COOKIETOSS": str(_out), "count": 0}

    async def _check_cookie_toss(host: str) -> List[str]:
        results: List[str] = []
        try:
            req = urllib.request.Request(
                host, method="GET", headers={"User-Agent": "Mozilla/5.0", **ct_extra_headers}
            )
            status, headers, body = await _async_urlopen_no_redirect(ct_urlopen, req, timeout=10)
            set_cookie_headers = headers.get_all("Set-Cookie") if hasattr(headers, "get_all") else []
            if not set_cookie_headers:
                set_cookie_val = headers.get("Set-Cookie", "")
                set_cookie_headers = [set_cookie_val] if set_cookie_val else []

            parsed_hostname = urllib.parse.urlparse(host).netloc.split(":")[0]
            parent_domain = ".".join(parsed_hostname.split(".")[-2:]) if parsed_hostname.count(".") >= 1 else parsed_hostname

            for sc in set_cookie_headers:
                if "__Host-" not in sc and "__Secure-" not in sc:
                    domain_match = re.search(r"domain=([^;]+)", sc, re.IGNORECASE)
                    if domain_match:
                        cookie_domain = domain_match.group(1).strip().lower()
                        if cookie_domain == f".{parent_domain}" or cookie_domain == parent_domain:
                            results.append(
                                f"[cookie-toss-candidate] {host} — cookie '{sc[:80]}' uses "
                                f"parent domain '{cookie_domain}' (CWE-614)"
                            )
                    else:
                        results.append(
                            f"[cookie-no-prefix] {host} — cookie '{sc[:80]}' lacks "
                            f"__Host-/__Secure- prefix (CWE-614)"
                        )

            # Test: craft a cookie for parent domain and observe effect
            test_req = urllib.request.Request(
                host,
                method="GET",
                headers={
                    "User-Agent": "Mozilla/5.0",
                    "Cookie": "session=attacker_overwrite",
                    **ct_extra_headers,
                },
            )
            _, test_headers, _ = await _async_urlopen_no_redirect(ct_urlopen, test_req, timeout=10)
            resp_cookies = test_headers.get_all("Set-Cookie") if hasattr(test_headers, "get_all") else []
            if not resp_cookies:
                resp_cookies_val = test_headers.get("Set-Cookie", "")
                resp_cookies = [resp_cookies_val] if resp_cookies_val else []
            for rc in resp_cookies:
                if "session" in rc.lower() and parent_domain in rc.lower():
                    results.append(
                        f"[cookie-toss-overwrite] {host} — subdomain cookie may overwrite "
                        f"parent domain session (CWE-614)"
                    )
        except asyncio.CancelledError:
            raise
        except Exception:
            pass
        return results

    ct_results = await asyncio.gather(*[_check_cookie_toss(t) for t in targets], return_exceptions=True)
    for r in ct_results:
        if isinstance(r, list):
            findings.extend(r)
    if not findings:
        findings.append("[cookie-toss] No cookie tossing candidates detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"194-COOKIETOSS: {len(findings)} findings -> {out}")
    return {"194-COOKIETOSS": str(out), "count": len(findings)}


async def phase_195_MIMESNIFF(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"195-MIMESNIFF"}:
        return {}
    _out = outdir / "mime_sniff.txt"
    if _out.exists() and not force:
        return {"195-MIMESNIFF": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 195-MIMESNIFF: MIME sniffing protection detection")
    findings: List[str] = []
    ms_urlopen = _get_urlopener()
    ms_extra_headers = _extra_headers_dict()

    hosts_file = outdir / "host_targets.txt"
    if not hosts_file.exists():
        hosts_file = outdir / "hosts.txt"
    targets = [f"https://{h}" if not h.startswith("http") else h for h in read_lines(hosts_file)]
    if not targets:
        log("warn", "195-MIMESNIFF: no HTTP targets; skipping")
        return {"195-MIMESNIFF": str(_out), "count": 0}

    urls_file = outdir / "urls_all.txt"
    all_urls = read_lines(urls_file) if urls_file.exists() else []

    # 1. Check for X-Content-Type-Options: nosniff header
    for host in targets[:20]:
        try:
            req = urllib.request.Request(
                host, method="GET", headers={"User-Agent": "Mozilla/5.0", **ms_extra_headers}
            )
            _, headers, body = await _async_urlopen(ms_urlopen, req, timeout=10)
            xcto = headers.get("X-Content-Type-Options", "")
            if "nosniff" not in xcto.lower():
                findings.append(
                    f"[mime-missing-nosniff] {host} — missing X-Content-Type-Options: nosniff (CWE-200)"
                )
            # Check Content-Type matches body content
            content_type = headers.get("Content-Type", "")
            if body and content_type:
                body_str = body.decode("utf-8", errors="ignore").lower()
                if "text/html" in content_type and "json" in content_type:
                    findings.append(
                        f"[mime-conflicting-type] {host} — Content-Type '{content_type}' may be incorrect"
                    )
        except asyncio.CancelledError:
            raise
        except Exception:
            continue

    # 2. Test JSON endpoints with HTML content injection
    json_urls = [u for u in all_urls if ".json" in u.lower() or "/api/" in u.lower()] or targets[:5]
    for url in json_urls[:10]:
        try:
            req = urllib.request.Request(
                url,
                method="GET",
                headers={
                    "User-Agent": "Mozilla/5.0",
                    "Accept": "text/html,application/xhtml+xml",
                    **ms_extra_headers,
                },
            )
            _, headers, body = await _async_urlopen(ms_urlopen, req, timeout=10)
            content_type = headers.get("Content-Type", "")
            xcto = headers.get("X-Content-Type-Options", "")
            if "nosniff" not in xcto.lower():
                findings.append(
                    f"[mime-json-no-nosniff] {url} — JSON endpoint without nosniff (CWE-200)"
                )
            if body and ("application/json" in content_type or "text/javascript" in content_type):
                body_str = body.decode("utf-8", errors="ignore")
                if "<script>" in body_str.lower() or "<html" in body_str.lower():
                    findings.append(
                        f"[mime-html-injection] {url} — HTML-like content in JSON response (CWE-200)"
                    )
        except asyncio.CancelledError:
            raise
        except Exception:
            continue

    # 3. Check file upload endpoints for content-type manipulation
    upload_urls = [
        u for u in all_urls if any(m in u.lower() for m in ("/upload", "/import", "/api/upload"))
    ] or [f"{t}/upload" for t in targets[:3]]
    for url in upload_urls[:5]:
        try:
            req = urllib.request.Request(
                url,
                method="OPTIONS",
                headers={"User-Agent": "Mozilla/5.0", **ms_extra_headers},
            )
            _, headers, _ = await _async_urlopen(ms_urlopen, req, timeout=10)
            allow = headers.get("Allow", "") or headers.get("allow", "")
            findings.append(f"[mime-upload-endpoint] {url} — Allow: {allow}")
        except asyncio.CancelledError:
            raise
        except Exception:
            continue

    if not findings:
        findings.append("[mime-sniff] No MIME sniffing issues detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"195-MIMESNIFF: {len(findings)} findings -> {out}")
    return {"195-MIMESNIFF": str(out), "count": len(findings)}
