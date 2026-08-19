"""PWA security phases: Web Push API security testing."""

import asyncio
import base64
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Set

from vulnforge.phases.helpers import PhaseSet
from vulnforge.tools import Tools
from vulnforge.utils import (
    _async_urlopen,
    _extra_headers_dict,
    _get_urlopener,
    count_nonblank,
    ensure,
    log,
    read_lines,
)

_PUSH_ENDPOINT_PATTERNS = [
    "/push/subscribe",
    "/api/push/subscribe",
    "/api/push",
    "/push/register",
    "/subscribe",
    "/api/subscribe",
    "/push/subscription",
    "/api/notifications/subscribe",
    "/webpush/subscribe",
    "/api/webpush",
]
_PUSH_UNSUBSCRIBE_PATTERNS = [
    "/push/unsubscribe",
    "/api/push/unsubscribe",
    "/push/delete",
    "/api/push/delete",
]
_VAPID_PUBKEY_RE = re.compile(r"[BC][BC][A-Za-z0-9+/=]{40,}")


async def phase_196_PUSHAPI(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"196-PUSHAPI"}:
        return {}
    _out = outdir / "push_api.txt"
    if _out.exists() and not force:
        return {"196-PUSHAPI": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 196-PUSHAPI: Web Push API security testing")
    findings: List[str] = []
    push_urlopen = _get_urlopener()
    push_extra_headers = _extra_headers_dict()

    hosts_file = outdir / "host_targets.txt"
    if not hosts_file.exists():
        hosts_file = outdir / "hosts.txt"
    targets = [f"https://{h}" if not h.startswith("http") else h for h in read_lines(hosts_file)]
    if not targets:
        log("warn", "196-PUSHAPI: no HTTP targets; skipping")
        return {"196-PUSHAPI": str(_out), "count": 0}

    urls_file = outdir / "urls_all.txt"
    all_urls = read_lines(urls_file) if urls_file.exists() else []
    js_urls_file = outdir / "urls_js.txt"
    js_urls = read_lines(js_urls_file) if js_urls_file.exists() else []
    if not js_urls:
        js_urls = [u for u in all_urls if u.lower().endswith(".js")]

    # 1. Look for push subscription endpoints
    push_endpoints: Set[str] = set()
    for u in all_urls:
        low_u = u.lower()
        for pat in _PUSH_ENDPOINT_PATTERNS:
            if pat in low_u:
                push_endpoints.add(u.split("?")[0])
                break
    if not push_endpoints:
        for host in targets[:5]:
            for pat in _PUSH_ENDPOINT_PATTERNS:
                push_endpoints.add(host.rstrip("/") + pat)

    for ep in push_endpoints:
        try:
            req = urllib.request.Request(
                ep, method="GET", headers={"User-Agent": "Mozilla/5.0", **push_extra_headers}
            )
            status, headers, body = await _async_urlopen(push_urlopen, req, timeout=10)
            body_text = body.decode("utf-8", errors="ignore") if body else ""
            findings.append(f"[push-endpoint] {ep} — HTTP {status}")
            # Check if endpoint requires auth
            if status == 200:
                if "unauthorized" not in body_text.lower() and "login" not in body_text.lower():
                    findings.append(
                        f"[push-no-auth] {ep} — push subscription endpoint accessible without auth (CWE-200)"
                    )
        except urllib.error.HTTPError as e:
            if e.code == 401 or e.code == 403:
                findings.append(f"[push-auth-required] {ep} — HTTP {e.code} (auth enforced)")
            else:
                findings.append(f"[push-endpoint] {ep} — HTTP {e.code}")
        except asyncio.CancelledError:
            raise
        except Exception:
            continue

    # 2. Check JS files for VAPID public key exposure
    for js in js_urls[:30]:
        try:
            req = urllib.request.Request(
                js, method="GET", headers={"User-Agent": "Mozilla/5.0", **push_extra_headers}
            )
            _, _, body = await _async_urlopen(push_urlopen, req, timeout=10)
            if not body:
                continue
            js_text = body.decode("utf-8", errors="ignore")
            vapid_matches = _VAPID_PUBKEY_RE.findall(js_text)
            for vm in vapid_matches:
                try:
                    decoded = base64.urlsafe_b64decode(vm + "==")
                    if len(decoded) >= 32:
                        findings.append(
                            f"[vapid-key-exposed] {js} — VAPID public key found: {vm[:50]}... (CWE-200)"
                        )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue
            push_reg_patterns = re.findall(
                r'["\']([^"\']*(?:push|subscribe|notification)[^"\']*)["\']', js_text, re.IGNORECASE
            )
            for pp in push_reg_patterns[:5]:
                findings.append(f"[push-js-ref] {js} — push-related string: {pp}")
        except asyncio.CancelledError:
            raise
        except Exception:
            continue

    # 3. Check unsubscribe endpoints without auth
    unsub_endpoints: Set[str] = set()
    for u in all_urls:
        low_u = u.lower()
        for pat in _PUSH_UNSUBSCRIBE_PATTERNS:
            if pat in low_u:
                unsub_endpoints.add(u.split("?")[0])
                break
    if not unsub_endpoints:
        for host in targets[:3]:
            for pat in _PUSH_UNSUBSCRIBE_PATTERNS:
                unsub_endpoints.add(host.rstrip("/") + pat)

    for ep in unsub_endpoints:
        try:
            req = urllib.request.Request(
                ep,
                method="POST",
                data=b"",
                headers={"User-Agent": "Mozilla/5.0", **push_extra_headers},
            )
            status, _, _ = await _async_urlopen(push_urlopen, req, timeout=10)
            if status in (200, 204):
                findings.append(
                    f"[push-unsubscribe-no-auth] {ep} — unsubscribe works without auth (HTTP {status}) (CWE-200)"
                )
        except urllib.error.HTTPError as e:
            if e.code not in (401, 403):
                findings.append(f"[push-unsubscribe-accessible] {ep} — HTTP {e.code}")
        except asyncio.CancelledError:
            raise
        except Exception:
            continue

    if not findings:
        findings.append("[push-api] No Web Push API security issues detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"196-PUSHAPI: {len(findings)} findings -> {out}")
    return {"196-PUSHAPI": str(out), "count": len(findings)}
