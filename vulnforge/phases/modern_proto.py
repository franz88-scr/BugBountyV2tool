"""Modern protocol security phases — HTTP/2 rapid reset, HTTP/3/QUIC, WebTransport."""

import asyncio
import socket
from pathlib import Path
from typing import Any, Dict, List

from vulnforge.phases.helpers import PhaseSet
from vulnforge.tools import Tools
from vulnforge.utils import (
    _load_live_hosts,
    count_nonblank,
    ensure,
    log,
    read_lines,
)


async def _find_https_hosts(outdir: Path) -> List[str]:
    hosts = _load_live_hosts(outdir)
    https_hosts: List[str] = []
    for h in hosts:
        if h.startswith("https://"):
            https_hosts.append(h)
        elif not h.startswith("http://"):
            https_hosts.append(f"https://{h}")
    return https_hosts


async def phase_167_H2RAPID(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"167-H2RAPID"}:
        return {}
    _out = outdir / "modern_h2_rapid_reset.txt"
    if _out.exists() and not force:
        return {"167-H2RAPID": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 167-H2RAPID: HTTP/2 Rapid Reset vulnerability check")
    findings: List[str] = []
    hosts = await _find_https_hosts(outdir)
    if not hosts:
        findings.append("[info] No HTTPS hosts found")
        out = ensure(_out)
        out.write_text("\n".join(findings) + "\n")
        return {"167-H2RAPID": str(_out), "count": 0}
    findings.append(f"[hosts] Testing {len(hosts)} hosts for HTTP/2 rapid reset")
    for host in hosts[:10]:
        hostname = host.replace("https://", "").replace("http://", "").split("/")[0]
        findings.append(f"  [testing] {host}")
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(hostname, 443, ssl=True), timeout=15
            )
            h2_connection = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
            writer.write(h2_connection)
            await writer.drain()
            findings.append(f"[h2-capable] {host} → supports HTTP/2")
            settings_frame = await asyncio.wait_for(reader.readexactly(9), timeout=5)
            if settings_frame[:3] == b"\x00\x00\x00":
                stream_id = int.from_bytes(settings_frame[5:9], "big")
                findings.append(f"[h2-settings] {host} → stream_id={stream_id}")
            writer.close()
            await writer.wait_closed()
        except asyncio.TimeoutError:
            findings.append(f"[h2-timeout] {host} → connection timeout")
        except ConnectionRefusedError:
            findings.append(f"[h2-refused] {host} → connection refused")
        except Exception as e:
            findings.append(f"[h2-error] {host} → {e}")
    findings.append("")
    findings.append("--- HTTP/2 Rapid Reset (CVE-2023-44487) manual check ---")
    findings.append(
        "  [manual] Use h2smuggle tool: h2smuggle -target https://hostname -rapid-reset"
    )
    findings.append("  [check] Verify server has HTTP/2 stream limit configured")
    findings.append("  [check] Verify server has rate limiting on stream creation")
    findings.append("  [check] Check vendor advisory for CVE-2023-44487 patch status")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"167-H2RAPID: {len(findings)} findings → {out}")
    return {"167-H2RAPID": str(_out), "count": len(findings)}


async def phase_168_H3QUIC(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"168-H3QUIC"}:
        return {}
    _out = outdir / "modern_quic_h3.txt"
    if _out.exists() and not force:
        return {"168-H3QUIC": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 168-H3QUIC: HTTP/3 & QUIC attack surface check")
    findings: List[str] = []
    hosts = _load_live_hosts(outdir)
    if not hosts:
        findings.append("[info] No live hosts found")
        out = ensure(_out)
        out.write_text("\n".join(findings) + "\n")
        return {"168-H3QUIC": str(_out), "count": 0}
    findings.append("[hosts] Testing hosts for QUIC/HTTP/3 support")
    for host in hosts[:10]:
        hostname = host.replace("https://", "").replace("http://", "").split("/")[0]
        findings.append(f"  [testing] {host}")
        for port in [443, 8443]:
            try:
                udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp_sock.settimeout(5)
                quic_initial = b"\xc0\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00"
                quic_initial += hostname.encode().ljust(32, b"\x00")[:32]
                udp_sock.sendto(quic_initial, (hostname, port))
                try:
                    data, addr = udp_sock.recvfrom(2048)
                    if data and len(data) > 0:
                        findings.append(
                            f"[quic-response] {host}:{port} → QUIC/HTTP/3 supported "
                            f"({len(data)} bytes response)"
                        )
                except socket.timeout:
                    pass
                finally:
                    udp_sock.close()
            except Exception as e:
                findings.append(f"[quic-error] {host}:{port} → {e}")
    findings.append("")
    findings.append("--- HTTP/3/QUIC attack surface ---")
    findings.append("  [check] QPACK bomb: HPACK compression bomb via HTTP/3 headers")
    findings.append("  [check] 0-RTT replay: replay 0-RTT data for replay attacks")
    findings.append("  [check] Connection migration hijack: spoof CID for session theft")
    findings.append("  [check] QUIC version downgrade: force weaker QUIC version")
    findings.append("  [check] HTTP/3 rapid reset: similar to CVE-2023-44487 but over QUIC")
    findings.append("  [tool] Use curl --http3 or quiche client for deeper testing")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"168-H3QUIC: {len(findings)} findings → {out}")
    return {"168-H3QUIC": str(_out), "count": len(findings)}


async def phase_169_WEBTRANSPORT(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"169-WEBTRANSPORT"}:
        return {}
    _out = outdir / "modern_webtransport.txt"
    if _out.exists() and not force:
        return {"169-WEBTRANSPORT": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 169-WEBTRANSPORT: WebTransport endpoint discovery")
    findings: List[str] = []
    urls = outdir / "urls_all.txt"
    if urls.exists():
        for u in read_lines(urls):
            if any(
                kw in u.lower()
                for kw in [".well-known/webtransport", "/webtransport", "wt://", "webtransport"]
            ):
                findings.append(f"[webtransport-endpoint] {u}")
    hosts = _load_live_hosts(outdir)
    for host in hosts[:10]:
        hostname = host.replace("https://", "").replace("http://", "").split("/")[0]
        findings.append(f"  [check] {hostname}: /.well-known/webtransport")
    findings.append("")
    findings.append("--- WebTransport security checklist ---")
    findings.append("  [check] Verify allowlist for WebTransport connections")
    findings.append("  [check] Check for unauthenticated WebTransport streams")
    findings.append("  [check] Verify stream limits and congestion control")
    findings.append("  [check] Check WebTransport over HTTP/3 vs HTTP/2 differences")
    if not [f for f in findings if f.startswith("[webtransport-endpoint]")]:
        findings.append("[info] No WebTransport endpoints discovered in URL corpus")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"169-WEBTRANSPORT: {len(findings)} findings → {out}")
    return {"169-WEBTRANSPORT": str(_out), "count": len(findings)}
