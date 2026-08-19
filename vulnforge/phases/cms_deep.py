"""CMS deep-dive phases: Magento, SharePoint, Confluence, CI/CD deep, Tomcat deep."""

import base64
import socket
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List

from vulnforge.phases.helpers import PhaseSet
from vulnforge.tools import Tools
from vulnforge.utils import (
    _async_urlopen_no_redirect,
    _extra_headers_dict,
    _get_urlopener,
    _load_live_hosts,
    count_nonblank,
    ensure,
    log,
)


async def phase_185_MAGENTO(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"185-MAGENTO"}:
        return {}
    _out = outdir / "magento.txt"
    if _out.exists() and not force:
        return {"185-MAGENTO": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 185-MAGENTO: probing Magento/Adobe Commerce hosts")
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    hosts = _load_live_hosts(outdir)
    if not hosts:
        log("warn", "185-MAGENTO: no live hosts; skipping")
        return {"185-MAGENTO": str(_out), "count": 0}
    for h in hosts:
        h = h if h.startswith("http") else f"https://{h}"
        for path in ("/admin", "/index.php/admin"):
            try:
                req = urllib.request.Request(h.rstrip("/") + path, headers=_extra_h, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen_no_redirect(
                    _urlopen, req, timeout=10
                )
                if status == 200:
                    findings.append(f"[magento-admin] {h} path={path}")
            except Exception:
                pass
        try:
            req = urllib.request.Request(
                h.rstrip("/") + "/rest/V1/integration/admin/token",
                headers=_extra_h,
                method="POST",
                data=b'{"username":"test","password":"test"}',
            )
            status, resp_headers, body_bytes = await _async_urlopen_no_redirect(
                _urlopen, req, timeout=10
            )
            if status == 200 and body_bytes:
                findings.append(
                    f"[magento-api-unauthenticated] {h} /rest/V1/integration/admin/token"
                )
        except Exception:
            pass
        for path in ("/graphql",):
            try:
                gql_req = urllib.request.Request(
                    h.rstrip("/") + path,
                    headers={**_extra_h, "Content-Type": "application/json"},
                    method="POST",
                    data=b'{"query":"{__schema{types{name}}}"}',
                )
                g_status, g_headers, g_body = await _async_urlopen_no_redirect(
                    _urlopen, gql_req, timeout=10
                )
                if g_status == 200 and g_body:
                    g_str = g_body.decode("utf-8", errors="ignore")
                    if '"data"' in g_str or '"types"' in g_str:
                        findings.append(f"[magento-graphql-introspection] {h}{path}")
            except Exception:
                pass
    if not findings:
        findings.append("[magento] No Magento findings (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"185-MAGENTO: {len(findings)} findings → {out}")
    return {"185-MAGENTO": str(out), "count": len(findings)}


async def phase_186_SHAREPOINT(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"186-SHAREPOINT"}:
        return {}
    _out = outdir / "sharepoint.txt"
    if _out.exists() and not force:
        return {"186-SHAREPOINT": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 186-SHAREPOINT: probing SharePoint hosts")
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    hosts = _load_live_hosts(outdir)
    if not hosts:
        log("warn", "186-SHAREPOINT: no live hosts; skipping")
        return {"186-SHAREPOINT": str(_out), "count": 0}
    for h in hosts:
        h = h if h.startswith("http") else f"https://{h}"
        try:
            req = urllib.request.Request(
                h.rstrip("/") + "/_api/web/siteusers",
                headers=_extra_h,
                method="GET",
            )
            status, resp_headers, body_bytes = await _async_urlopen_no_redirect(
                _urlopen, req, timeout=10
            )
            if status == 200 and body_bytes:
                findings.append(f"[sharepoint-user-enum] {h} /_api/web/siteusers")
        except Exception:
            pass
        for path in (
            "/_layouts/15/",
            "/_layouts/15/start.aspx",
            "/_layouts/15/settings.aspx",
        ):
            try:
                req = urllib.request.Request(h.rstrip("/") + path, headers=_extra_h, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen_no_redirect(
                    _urlopen, req, timeout=10
                )
                if status == 200 and body_bytes:
                    findings.append(f"[sharepoint-layouts] {h} path={path}")
            except Exception:
                pass
        try:
            req = urllib.request.Request(
                h.rstrip("/") + "/_layouts/15/osssearchresults.aspx",
                headers=_extra_h,
                method="GET",
            )
            status, resp_headers, body_bytes = await _async_urlopen_no_redirect(
                _urlopen, req, timeout=10
            )
            if status == 200:
                findings.append(
                    f"[sharepoint-workflow-bypass] {h} /_layouts/15/osssearchresults.aspx"
                )
        except Exception:
            pass
    if not findings:
        findings.append("[sharepoint] No SharePoint findings (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"186-SHAREPOINT: {len(findings)} findings → {out}")
    return {"186-SHAREPOINT": str(out), "count": len(findings)}


async def phase_187_CONFLUENCE(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"187-CONFLUENCE"}:
        return {}
    _out = outdir / "confluence.txt"
    if _out.exists() and not force:
        return {"187-CONFLUENCE": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 187-CONFLUENCE: probing Confluence hosts")
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    hosts = _load_live_hosts(outdir)
    if not hosts:
        log("warn", "187-CONFLUENCE: no live hosts; skipping")
        return {"187-CONFLUENCE": str(_out), "count": 0}
    for h in hosts:
        h = h if h.startswith("http") else f"https://{h}"
        try:
            req = urllib.request.Request(
                h.rstrip("/") + "/rest/api/space",
                headers=_extra_h,
                method="GET",
            )
            status, resp_headers, body_bytes = await _async_urlopen_no_redirect(
                _urlopen, req, timeout=10
            )
            if status == 200 and body_bytes:
                body_str = body_bytes.decode("utf-8", errors="ignore")
                if '"results"' in body_str or '"key"' in body_str:
                    findings.append(f"[confluence-public-spaces] {h} /rest/api/space")
        except Exception:
            pass
        for path in ("/s/", "/s/backup", "/s/backups"):
            try:
                req = urllib.request.Request(h.rstrip("/") + path, headers=_extra_h, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen_no_redirect(
                    _urlopen, req, timeout=10
                )
                if status == 200 and body_bytes:
                    findings.append(f"[confluence-backup-exposure] {h} path={path}")
            except Exception:
                pass
        try:
            req = urllib.request.Request(
                h.rstrip("/") + "/rest/api/space?expand=settings",
                headers=_extra_h,
                method="GET",
            )
            status, resp_headers, body_bytes = await _async_urlopen_no_redirect(
                _urlopen, req, timeout=10
            )
            if status == 200 and body_bytes:
                findings.append(
                    f"[confluence-settings-exposure] {h} /rest/api/space?expand=settings"
                )
        except Exception:
            pass
    if not findings:
        findings.append("[confluence] No Confluence findings (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"187-CONFLUENCE: {len(findings)} findings → {out}")
    return {"187-CONFLUENCE": str(out), "count": len(findings)}


async def phase_188_CICD(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"188-CICD"}:
        return {}
    _out = outdir / "cicd_deep.txt"
    if _out.exists() and not force:
        return {"188-CICD": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 188-CICD: CI/CD / GitLab / Jenkins exposure deep")
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    hosts = _load_live_hosts(outdir)
    if not hosts:
        log("warn", "188-CICD: no live hosts; skipping")
        return {"188-CICD": str(_out), "count": 0}
    for h in hosts:
        h = h if h.startswith("http") else f"https://{h}"
        for path in ("/script", "/script/", "/scriptText"):
            try:
                req = urllib.request.Request(h.rstrip("/") + path, headers=_extra_h, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen_no_redirect(
                    _urlopen, req, timeout=10
                )
                if status == 200 and body_bytes:
                    body_str = body_bytes.decode("utf-8", errors="ignore")
                    if "jenkins" in body_str.lower() or "script" in body_str.lower():
                        findings.append(f"[jenkins-script-console] {h} path={path}")
            except Exception:
                pass
        for path in ("/api/v4/projects", "/api/v3/projects"):
            try:
                req = urllib.request.Request(h.rstrip("/") + path, headers=_extra_h, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen_no_redirect(
                    _urlopen, req, timeout=10
                )
                if status == 200 and body_bytes:
                    body_str = body_bytes.decode("utf-8", errors="ignore")
                    if '"id"' in body_str or '"name"' in body_str:
                        findings.append(f"[gitlab-anonymous] {h} {path}")
            except Exception:
                pass
        for path in ("/api/v4/projects/1/variables", "/api/v3/projects/1/variables"):
            try:
                req = urllib.request.Request(h.rstrip("/") + path, headers=_extra_h, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen_no_redirect(
                    _urlopen, req, timeout=10
                )
                if status == 200 and body_bytes:
                    findings.append(f"[gitlab-variable-leak] {h} {path}")
            except Exception:
                pass
        for path in ("/admin/runners", "/api/v4/runners"):
            try:
                req = urllib.request.Request(h.rstrip("/") + path, headers=_extra_h, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen_no_redirect(
                    _urlopen, req, timeout=10
                )
                if status == 200 and body_bytes:
                    findings.append(f"[cicd-runner-abuse] {h} path={path}")
            except Exception:
                pass
    if not findings:
        findings.append("[cicd] No CI/CD findings (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"188-CICD: {len(findings)} findings → {out}")
    return {"188-CICD": str(out), "count": len(findings)}


async def phase_189_TOMCAT(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"189-TOMCAT"}:
        return {}
    _out = outdir / "tomcat_deep.txt"
    if _out.exists() and not force:
        return {"189-TOMCAT": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 189-TOMCAT: Apache Tomcat in-depth probes")
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    hosts = _load_live_hosts(outdir)
    if not hosts:
        log("warn", "189-TOMCAT: no live hosts; skipping")
        return {"189-TOMCAT": str(_out), "count": 0}
    creds = [
        ("tomcat", "tomcat"),
        ("admin", "admin"),
        ("tomcat", "s3cret"),
        ("admin", "tomcat"),
    ]
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
                    status, resp_headers, body_bytes = await _async_urlopen_no_redirect(
                        _urlopen, req, timeout=10
                    )
                    if status == 200:
                        findings.append(
                            f"[tomcat-manager-deep] {h} creds={user}:{passwd} path={path}"
                        )
                except Exception:
                    pass
        for path in ("/examples/", "/examples/servlets/", "/examples/jsp/"):
            try:
                req = urllib.request.Request(h.rstrip("/") + path, headers=_extra_h, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen_no_redirect(
                    _urlopen, req, timeout=10
                )
                if status == 200 and body_bytes:
                    body_str = body_bytes.decode("utf-8", errors="ignore")
                    if "examples" in body_str.lower():
                        findings.append(f"[tomcat-examples] {h} path={path}")
            except Exception:
                pass
        hostname_part = urllib.parse.urlparse(h).hostname or h
        try:
            ajp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ajp_sock.settimeout(5)
            ajp_result = ajp_sock.connect_ex((hostname_part, 8009))
            ajp_sock.close()
            if ajp_result == 0:
                findings.append(
                    f"[tomcat-ajp-ghostcat] {h} port 8009 open — CVE-2020-1938 candidate"
                )
        except Exception:
            pass
    if not findings:
        findings.append("[tomcat-deep] No Tomcat findings (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"189-TOMCAT: {len(findings)} findings → {out}")
    return {"189-TOMCAT": str(out), "count": len(findings)}
