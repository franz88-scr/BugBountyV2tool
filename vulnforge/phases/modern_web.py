"""Modern web vulnerability phases: Service Worker abuse, WASM security, JWT-to-Self XSS."""

import asyncio
import base64
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List

from vulnforge.phases.harness import phase_targets
from vulnforge.phases.helpers import PhaseSet
from vulnforge.process import _PIPELINE_CFG
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

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")

_SW_SECRET_ASSIGN_RE = re.compile(
    r"(?:api[_-]?key|secret|token|password|auth)[a-z0-9_]*\s*[:=]\s*['\"][^'\"]{4,}",
    re.I,
)


async def phase_173_SERVICEWORKER(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"173-SERVICEWORKER"}:
        return {}
    _out = outdir / "service_worker.txt"
    if _out.exists() and not force:
        return {"173-SERVICEWORKER": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 173-SERVICEWORKER: service worker abuse probes")
    findings: List[str] = []
    sw_urlopen = _get_urlopener()
    sw_extra_headers = _extra_headers_dict()
    targets = phase_targets(outdir, "hosts")[
        : _PIPELINE_CFG.sample_hosts_cached
        if hasattr(_PIPELINE_CFG, "sample_hosts_cached")
        else 100
    ]
    if not targets:
        log("WARNING", "173-SERVICEWORKER: no HTTP targets; skipping")
        return {"173-SERVICEWORKER": str(_out), "count": 0}

    async def _probe_sw(host: str) -> List[str]:
        results: List[str] = []
        sw_paths = ["/service-worker.js", "/sw.js"]
        for sp in sw_paths:
            try:
                url = host.rstrip("/") + sp
                req = urllib.request.Request(
                    url, method="GET", headers={"User-Agent": "Mozilla/5.0", **sw_extra_headers}
                )
                status, headers, body = await _async_urlopen(sw_urlopen, req, timeout=10)
                if status == 200 and body:
                    body_str = body.decode("utf-8", errors="ignore")
                    results.append(
                        f"[sw-found] {url} — service worker accessible ({len(body)} bytes)"
                    )
                    if (
                        "self.addEventListener('fetch'" in body_str
                        or 'self.addEventListener("fetch"' in body_str
                    ):
                        results.append(
                            f"[sw-cache-first] {url} — fetch event listener (cache-first opportunity)"
                        )
                    if "postMessage" in body_str or "onmessage" in body_str:
                        if "origin" not in body_str.lower() and "Origin" not in body_str:
                            results.append(
                                f"[sw-postmessage-no-origin] {url} — postMessage handler without origin validation (CWE-346)"
                            )
                    for m in _SW_SECRET_ASSIGN_RE.finditer(body_str):
                        results.append(
                            f"[sw-hardcoded-secret] {url} — assignment near: {m.group(0)[:80]}"
                        )
            except asyncio.CancelledError:
                raise
            except Exception:
                continue

        try:
            main_req = urllib.request.Request(
                host, method="GET", headers={"User-Agent": "Mozilla/5.0", **sw_extra_headers}
            )
            _, _, main_body = await _async_urlopen(sw_urlopen, main_req, timeout=10)
            if main_body:
                main_str = main_body.decode("utf-8", errors="ignore")
                sw_regs = re.finditer(
                    r'navigator\.serviceWorker\.register\s*\(\s*["\']([^"\']+)["\']',
                    main_str,
                )
                for m in sw_regs:
                    sw_url = m.group(1)
                    scope_match = re.search(
                        r'\{?\s*scope\s*:\s*["\']([^"\']+)["\']',
                        main_str[m.start() : m.end() + 100],
                    )
                    scope_info = f" scope={scope_match.group(1)}" if scope_match else ""
                    results.append(f"[sw-registration] {host} — register({sw_url}){scope_info}")
                if "onmessage" in main_str or re.search(
                    r"addEventListener\s*\(\s*['\"]message['\"]", main_str, re.I
                ):
                    if "event.origin" not in main_str and "event.source" not in main_str:
                        results.append(
                            f"[sw-page-message-no-origin] {host} — page has message handler without origin validation"
                        )
        except asyncio.CancelledError:
            raise
        except Exception:
            pass
        return results

    sw_results = await asyncio.gather(*[_probe_sw(t) for t in targets], return_exceptions=True)
    for r in sw_results:
        if isinstance(r, list):
            findings.extend(r)
    if not findings:
        findings.append("[service-worker] No service worker abuse vectors detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"173-SERVICEWORKER: {len(findings)} findings -> {out}")
    return {"173-SERVICEWORKER": str(out), "count": len(findings)}


async def phase_174_WASMSEC(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"174-WASMSEC"}:
        return {}
    _out = outdir / "wasm_findings.txt"
    if _out.exists() and not force:
        return {"174-WASMSEC": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 174-WASMSEC: WebAssembly security analysis")
    findings: List[str] = []
    wasm_urlopen = _get_urlopener()
    wasm_headers = _extra_headers_dict()

    wasm_urls: List[str] = []
    urls_file = outdir / "urls_all.txt"
    if urls_file.exists():
        for u in read_lines(urls_file):
            if ".wasm" in u:
                wasm_urls.append(u)
    js_file = outdir / "urls_js.txt" if (outdir / "urls_js.txt").exists() else None
    if js_file:
        for u in read_lines(js_file):
            if ".wasm" in u:
                wasm_urls.append(u)

    if not wasm_urls:
        log("INFO", "174-WASMSEC: no .wasm URLs found; skipping")
        findings.append("[wasm-info] No .wasm files discovered in harvested URLs")
        findings.append("[wasm-info] Manual hint: look for .wasm references in JS sources")
        out = ensure(_out)
        out.write_text("\n".join(findings) + "\n")
        return {"174-WASMSEC": str(_out), "count": 0}

    async def _analyze_wasm(wasm_url: str) -> List[str]:
        results: List[str] = []
        if not wasm_url.startswith("http"):
            wasm_url = "https://" + wasm_url
        if wasm_url.startswith("http://"):
            results.append(f"[wasm-insecure-origin] {wasm_url} — loaded over HTTP (CWE-829)")
        try:
            req = urllib.request.Request(
                wasm_url,
                method="GET",
                headers={"User-Agent": "Mozilla/5.0", **wasm_headers},
            )
            status, headers, body = await _async_urlopen(wasm_urlopen, req, timeout=15)
            if status != 200 or not body:
                return results
            if body[:4] != b"\0asm":
                results.append(f"[wasm-invalid] {wasm_url} — missing WASM magic bytes")
                return results
            results.append(f"[wasm-found] {wasm_url} — valid WASM binary ({len(body)} bytes)")

            printable_run: List[str] = []
            readable_strings: List[str] = []
            for b in body:
                if 32 <= b < 127:
                    printable_run.append(chr(b))
                else:
                    if len(printable_run) >= 4:
                        s = "".join(printable_run)
                        readable_strings.append(s)
                    printable_run = []
            if len(printable_run) >= 4:
                readable_strings.append("".join(printable_run))

            for s in readable_strings:
                low_s = s.lower()
                for kw in ["api_key", "api-key", "apikey", "secret", "token", "password", "auth"]:
                    if kw in low_s:
                        results.append(
                            f"[wasm-hardcoded-credential] {wasm_url} — '{kw}' in string: {s[:100]}"
                        )
                        break
                if s.startswith("http://") or s.startswith("https://"):
                    results.append(f"[wasm-url] {wasm_url} — embedded URL: {s[:120]}")
                if len(s) >= 32 and any(c.isdigit() for c in s) and any(c.isalpha() for c in s):
                    results.append(
                        f"[wasm-potential-key] {wasm_url} — potential crypto key/token: {s[:60]}"
                    )

            if readable_strings:
                results.append(
                    f"[wasm-strings] {wasm_url} — {len(readable_strings)} printable strings extracted"
                )

        except asyncio.CancelledError:
            raise
        except Exception as e:
            results.append(f"[wasm-error] {wasm_url} — {e}")
        return results

    wasm_results = await asyncio.gather(
        *[_analyze_wasm(u) for u in wasm_urls], return_exceptions=True
    )
    for r in wasm_results:
        if isinstance(r, list):
            findings.extend(r)
    if not findings:
        findings.append("[wasm] No WebAssembly security issues detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"174-WASMSEC: {len(findings)} findings -> {out}")
    return {"174-WASMSEC": str(out), "count": len(findings)}


async def phase_176_JWT2SELF(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"176-JWT2SELF"}:
        return {}
    _out = outdir / "jwt_xss.txt"
    if _out.exists() and not force:
        return {"176-JWT2SELF": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 176-JWT2SELF: JWT-to-self XSS detection")
    findings: List[str] = []
    jwt_urlopen = _get_urlopener()
    jwt_extra_headers = _extra_headers_dict()

    targets = phase_targets(outdir, "hosts")[
        : _PIPELINE_CFG.sample_hosts_cached
        if hasattr(_PIPELINE_CFG, "sample_hosts_cached")
        else 100
    ]
    if not targets:
        log("WARNING", "176-JWT2SELF: no HTTP targets; skipping")
        return {"176-JWT2SELF": str(_out), "count": 0}

    xss_payload = "<img src=x onerror=alert(1)>"
    forged_claims = {"name": xss_payload, "email": xss_payload, "preferred_username": xss_payload}
    forged_header = {"alg": "HS256", "typ": "JWT"}

    def _b64_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    def _forge_jwt(claims: Dict[str, Any]) -> str:
        header_b64 = _b64_encode(json.dumps(forged_header).encode())
        payload_b64 = _b64_encode(json.dumps(claims).encode())
        sig = _b64_encode(b"fakesignature")
        return f"{header_b64}.{payload_b64}.{sig}"

    async def _probe_jwt(host: str) -> List[str]:
        results: List[str] = []
        try:
            req = urllib.request.Request(
                host,
                method="GET",
                headers={"User-Agent": "Mozilla/5.0", **jwt_extra_headers},
            )
            _, _, body = await _async_urlopen(jwt_urlopen, req, timeout=10)
            if not body:
                return results
            body_str = body.decode("utf-8", errors="ignore")
            tokens = _JWT_RE.findall(body_str)
            for token in tokens:
                parts = token.split(".")
                if len(parts) != 3:
                    continue
                try:
                    payload_b64 = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
                    payload = json.loads(base64.urlsafe_b64decode(payload_b64))
                    results.append(
                        f"[jwt-found] {host} — token payload keys: {list(payload.keys())}"
                    )
                    interesting_claims = [
                        c
                        for c in ["name", "email", "preferred_username", "nickname"]
                        if c in payload
                    ]
                    if interesting_claims:
                        results.append(
                            f"[jwt-reflected-claims] {host} — JWT contains user-reflected claims: {interesting_claims}"
                        )
                        forged = _forge_jwt(forged_claims)
                        xss_req = urllib.request.Request(
                            host,
                            method="GET",
                            headers={
                                "User-Agent": "Mozilla/5.0",
                                **jwt_extra_headers,
                                "Authorization": f"Bearer {forged}",
                            },
                        )
                        _, _, xss_body = await _async_urlopen(jwt_urlopen, xss_req, timeout=10)
                        if xss_body:
                            xss_str = xss_body.decode("utf-8", errors="ignore")
                            if (
                                xss_payload in xss_str
                                or xss_payload.replace('"', "&quot;") in xss_str
                            ):
                                results.append(
                                    f"[jwt-xss-candidate] {host} — XSS payload from forged JWT reflected in response (CWE-79)"
                                )
                            if xss_payload.replace("<", "&lt;").replace(">", "&gt;") in xss_str:
                                results.append(
                                    f"[jwt-xss-encoded] {host} — payload reflected but HTML-encoded"
                                )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue
        except asyncio.CancelledError:
            raise
        except Exception:
            pass
        return results

    jwt_results = await asyncio.gather(*[_probe_jwt(t) for t in targets], return_exceptions=True)
    for r in jwt_results:
        if isinstance(r, list):
            findings.extend(r)
    if not findings:
        findings.append("[jwt-xss] No JWT-to-self XSS vectors detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"176-JWT2SELF: {len(findings)} findings -> {out}")
    return {"176-JWT2SELF": str(out), "count": len(findings)}
