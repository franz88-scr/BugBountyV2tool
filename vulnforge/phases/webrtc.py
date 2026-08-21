"""WebRTC security: internal IP leak detection."""

import asyncio
import os
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict

from vulnforge.phases.harness import phase_begin, phase_targets
from vulnforge.phases.helpers import PhaseSet
from vulnforge.tools import Tools
from vulnforge.utils import (
    _async_urlopen,
    _extra_headers_dict,
    _get_urlopener,
    log,
    read_lines,
)

_WEBRTC_JS_PATTERNS = [
    "RTCPeerConnection",
    "createDataChannel",
    "createOffer",
    "createAnswer",
    "setLocalDescription",
    "setRemoteDescription",
    "onicecandidate",
    "getUserMedia",
    "getDisplayMedia",
    "enumerateDevices",
    "webrtc",
    "adapter.js",
    "peerjs",
    "simplewebrtc",
]
_STUN_PORTS = [3478, 3479, 19302, 19303, 49152]
_STUN_MAGIC_COOKIE = b"\x21\x12\xa4\x42"


def _stun_binding_request() -> bytes:
    return b"\x00\x01\x00\x00" + _STUN_MAGIC_COOKIE + os.urandom(12)


def _stun_binding_response_ok(data: bytes) -> bool:
    return len(data) >= 20 and data[:2] == b"\x01\x01" and data[4:8] == _STUN_MAGIC_COOKIE


def _stun_binding_ok(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(_stun_binding_request(), (host, port))
            data, _ = sock.recvfrom(2048)
            return _stun_binding_response_ok(data)
        finally:
            sock.close()
    except Exception:
        return False


async def phase_193_WEBRTC(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    run = phase_begin("193-WEBRTC", outdir, skip, force, "webrtc_leak.txt")
    if run is None:
        return {}
    webrtc_urlopen = _get_urlopener()
    webrtc_extra_headers = _extra_headers_dict()

    targets = phase_targets(outdir, "hosts")
    if not targets:
        return run.no_targets("no HTTP targets")

    # 1. Check if page loads WebRTC-related JS
    for host in targets[:20]:
        try:
            req = urllib.request.Request(
                host, method="GET", headers={"User-Agent": "Mozilla/5.0", **webrtc_extra_headers}
            )
            _, _, body = await _async_urlopen(webrtc_urlopen, req, timeout=10)
            if not body:
                continue
            body_text = body.decode("utf-8", errors="ignore")
            for pat in _WEBRTC_JS_PATTERNS:
                if pat.lower() in body_text.lower():
                    run.findings.append(
                        f"[webrtc-js-detected] {host} — found '{pat}' in page content (CWE-200)"
                    )
                    break
        except asyncio.CancelledError:
            raise
        except Exception:
            continue

    # 2. Check JS files for WebRTC references
    urls_file = outdir / "urls_js.txt"
    js_urls = read_lines(urls_file) if urls_file.exists() else []
    if not js_urls:
        urls_all = outdir / "urls_all.txt"
        if urls_all.exists():
            js_urls = [u for u in read_lines(urls_all) if u.lower().endswith(".js")]
    for js_url in js_urls[:30]:
        try:
            req = urllib.request.Request(
                js_url, method="GET", headers={"User-Agent": "Mozilla/5.0", **webrtc_extra_headers}
            )
            _, _, body = await _async_urlopen(webrtc_urlopen, req, timeout=10)
            if not body:
                continue
            js_text = body.decode("utf-8", errors="ignore")
            for pat in _WEBRTC_JS_PATTERNS:
                if pat.lower() in js_text.lower():
                    run.findings.append(
                        f"[webrtc-js-file] {js_url} — '{pat}' referenced in JS (CWE-200)"
                    )
                    break
            stun_matches = re.findall(r"(?:stun|turn)[s]?://[^\s\"']+", js_text)
            for sm in stun_matches[:5]:
                run.findings.append(f"[webrtc-stun-turn] {js_url} — STUN/TURN endpoint: {sm}")
        except asyncio.CancelledError:
            raise
        except Exception:
            continue

    # 3. Probe STUN endpoints via UDP STUN binding request
    stun_candidates = []
    for host in targets[:10]:
        parsed_host = urllib.parse.urlparse(host).netloc.split(":")[0]
        for port in _STUN_PORTS:
            stun_candidates.append((parsed_host, port))
    verified = 0
    for host, port in stun_candidates[:20]:
        try:
            ok = await asyncio.to_thread(_stun_binding_ok, host, port)
        except Exception:
            ok = False
        if ok:
            verified += 1
            run.findings.append(
                f"[webrtc-stun-candidate] stun:{host}:{port} — STUN binding response received"
            )
    if not verified:
        log("INFO", "193-WEBRTC: no reachable STUN endpoints on standard ports")

    return run.done()
