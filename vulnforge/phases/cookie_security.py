"""Cookie security phases: cookie tossing and MIME sniffing detection."""

import asyncio
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List

from vulnforge.phases.harness import phase_begin, phase_targets
from vulnforge.phases.helpers import PhaseSet
from vulnforge.tools import Tools
from vulnforge.utils import (
    _async_urlopen,
    _async_urlopen_no_redirect,
    _extra_headers_dict,
    _get_urlopener,
    read_lines,
)


async def phase_194_COOKIETOSS(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    run = phase_begin("194-COOKIETOSS", outdir, skip, force, "cookie_toss.txt")
    if run is None:
        return {}
    ct_urlopen = _get_urlopener()
    ct_extra_headers = _extra_headers_dict()

    targets = phase_targets(outdir, "hosts")
    if not targets:
        return run.no_targets("no HTTP targets")

    async def _check_cookie_toss(host: str) -> List[str]:
        results: List[str] = []
        try:
            req = urllib.request.Request(
                host, method="GET", headers={"User-Agent": "Mozilla/5.0", **ct_extra_headers}
            )
            status, headers, body = await _async_urlopen_no_redirect(ct_urlopen, req, timeout=10)
            set_cookie_headers = (
                headers.get_all("Set-Cookie") if hasattr(headers, "get_all") else []
            )
            if not set_cookie_headers:
                set_cookie_val = headers.get("Set-Cookie", "")
                set_cookie_headers = [set_cookie_val] if set_cookie_val else []

            parsed_hostname = urllib.parse.urlparse(host).netloc.split(":")[0]
            parent_domain = (
                ".".join(parsed_hostname.split(".")[-2:])
                if parsed_hostname.count(".") >= 1
                else parsed_hostname
            )

            for sc in set_cookie_headers:
                if "__Host-" not in sc and "__Secure-" not in sc:
                    domain_match = re.search(r"domain=([^;]+)", sc, re.IGNORECASE)
                    if domain_match:
                        cookie_domain = domain_match.group(1).strip().lower()
                        if cookie_domain == f".{parent_domain}" or cookie_domain == parent_domain:
                            results.append(
                                f"[cookie-toss-candidate] {host} — cookie '{sc[:80]}' uses "
                                f"parent domain '{cookie_domain}' (CWE-614)"
                            )
                    else:
                        results.append(
                            f"[cookie-no-prefix] {host} — cookie '{sc[:80]}' lacks "
                            f"__Host-/__Secure- prefix (CWE-614)"
                        )

            # Test: craft a cookie for parent domain and observe effect
            test_req = urllib.request.Request(
                host,
                method="GET",
                headers={
                    "User-Agent": "Mozilla/5.0",
                    "Cookie": "session=attacker_overwrite",
                    **ct_extra_headers,
                },
            )
            _, test_headers, _ = await _async_urlopen_no_redirect(ct_urlopen, test_req, timeout=10)
            resp_cookies = (
                test_headers.get_all("Set-Cookie") if hasattr(test_headers, "get_all") else []
            )
            if not resp_cookies:
                resp_cookies_val = test_headers.get("Set-Cookie", "")
                resp_cookies = [resp_cookies_val] if resp_cookies_val else []
            for rc in resp_cookies:
                if "session" in rc.lower() and parent_domain in rc.lower():
                    results.append(
                        f"[cookie-toss-overwrite] {host} — subdomain cookie may overwrite "
                        f"parent domain session (CWE-614)"
                    )
        except asyncio.CancelledError:
            raise
        except Exception:
            pass
        return results

    ct_results = await asyncio.gather(
        *[_check_cookie_toss(t) for t in targets], return_exceptions=True
    )
    for r in ct_results:
        if isinstance(r, list):
            run.findings.extend(r)
    return run.done()


async def phase_195_MIMESNIFF(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    run = phase_begin("195-MIMESNIFF", outdir, skip, force, "mime_sniff.txt")
    if run is None:
        return {}
    ms_urlopen = _get_urlopener()
    ms_extra_headers = _extra_headers_dict()

    targets = phase_targets(outdir, "hosts")
    if not targets:
        return run.no_targets("no HTTP targets")

    urls_file = outdir / "urls_all.txt"
    all_urls = read_lines(urls_file) if urls_file.exists() else []

    # 1. Check for X-Content-Type-Options: nosniff header
    for host in targets[:20]:
        try:
            req = urllib.request.Request(
                host, method="GET", headers={"User-Agent": "Mozilla/5.0", **ms_extra_headers}
            )
            _, headers, body = await _async_urlopen(ms_urlopen, req, timeout=10)
            xcto = headers.get("X-Content-Type-Options", "")
            if "nosniff" not in xcto.lower():
                run.findings.append(
                    f"[mime-missing-nosniff] {host} — missing X-Content-Type-Options: nosniff (CWE-200)"
                )
            # Check Content-Type matches body content
            content_type = headers.get("Content-Type", "")
            if body and content_type:
                body_str = body.decode("utf-8", errors="ignore").lower()
                looks_html = "<html" in body_str or "<!doctype" in body_str or "<head" in body_str
                looks_json = body_str.lstrip().startswith(("{", "["))
                if "text/html" in content_type and looks_json:
                    run.findings.append(
                        f"[mime-conflicting-type] {host} — Content-Type '{content_type}' but body looks like JSON"
                    )
                elif "json" in content_type and looks_html:
                    run.findings.append(
                        f"[mime-conflicting-type] {host} — Content-Type '{content_type}' but body looks like HTML"
                    )
        except asyncio.CancelledError:
            raise
        except Exception:
            continue

    # 2. Test JSON endpoints with HTML content injection
    json_urls = [u for u in all_urls if ".json" in u.lower() or "/api/" in u.lower()] or targets[:5]
    for url in json_urls[:10]:
        try:
            req = urllib.request.Request(
                url,
                method="GET",
                headers={
                    "User-Agent": "Mozilla/5.0",
                    "Accept": "text/html,application/xhtml+xml",
                    **ms_extra_headers,
                },
            )
            _, headers, body = await _async_urlopen(ms_urlopen, req, timeout=10)
            content_type = headers.get("Content-Type", "")
            xcto = headers.get("X-Content-Type-Options", "")
            if "nosniff" not in xcto.lower():
                run.findings.append(
                    f"[mime-json-no-nosniff] {url} — JSON endpoint without nosniff (CWE-200)"
                )
            if body and ("application/json" in content_type or "text/javascript" in content_type):
                body_str = body.decode("utf-8", errors="ignore")
                if "<script>" in body_str.lower() or "<html" in body_str.lower():
                    run.findings.append(
                        f"[mime-html-injection] {url} — HTML-like content in JSON response (CWE-200)"
                    )
        except asyncio.CancelledError:
            raise
        except Exception:
            continue

    # 3. Check file upload endpoints for content-type manipulation
    upload_urls = [
        u for u in all_urls if any(m in u.lower() for m in ("/upload", "/import", "/api/upload"))
    ] or [f"{t}/upload" for t in targets[:3]]
    for url in upload_urls[:5]:
        try:
            req = urllib.request.Request(
                url,
                method="OPTIONS",
                headers={"User-Agent": "Mozilla/5.0", **ms_extra_headers},
            )
            _, headers, _ = await _async_urlopen(ms_urlopen, req, timeout=10)
            allow = headers.get("Allow", "") or headers.get("allow", "")
            run.findings.append(f"[mime-upload-endpoint] {url} — Allow: {allow}")
        except asyncio.CancelledError:
            raise
        except Exception:
            continue

    return run.done()
