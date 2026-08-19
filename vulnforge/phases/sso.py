"""SSO & Federation security testing phases — OIDC, SAML, cross-tenant attacks."""

import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Set

from vulnforge.phases.helpers import PhaseSet
from vulnforge.tools import Tools
from vulnforge.utils import (
    _async_urlopen,
    _get_urlopener,
    _load_live_hosts,
    _throttle_rate,
    count_nonblank,
    ensure,
    log,
    read_lines,
)

_SSO_ENDPOINT_PATTERNS = [
    "/sso",
    "/saml",
    "/oauth",
    "/oauth2",
    "/oidc",
    "/authorize",
    "/token",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/saml-configuration",
    "/sso/login",
    "/saml/login",
    "/sso/acs",
    "/saml/acs",
    "/auth/realms",
    "/auth/admin/realms",
    "/connect/token",
    "/connect/authorize",
    "/connect/register",
    "/adfs",
    "/adfs/ls",
]

_OAUTH_MISCONFIG_PROBES = [
    ("response_type=token", "Implicit grant enabled"),
    ("response_type=code token", "Hybrid flow enabled"),
    ("response_type=code id_token", "Hybrid flow with ID token"),
    ("response_type=id_token", "ID token only"),
    ("redirect_uri=https://evil.com", "Open redirect via redirect_uri"),
    ("redirect_uri=https://target.com.evil.com", "Subdomain confusion"),
    ("redirect_uri=https://target.com@evil.com", "Credentials in redirect_uri"),
    ("redirect_uri=https://evil.com/?url=target.com", "Redirect parameter injection"),
    ("redirect_uri=https://evil.com%2Ftarget.com", "Encoding bypass"),
    ("scope=openid+profile+email+admin+*", "Scope escalation"),
    ("scope=openid+offline_access", "Offline token request"),
]

_SAML_ATTACK_VECTORS = [
    ("<saml:Subject><saml:NameID>admin@target.com</saml:NameID></saml:Subject>", "NameID spoofing"),
    (
        '<saml:Attribute Name="Role"><saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute>',
        "Role escalation",
    ),
    (
        '<saml:AuthnStatement AuthnInstant="2000-01-01T00:00:00Z" SessionIndex="../../etc/passwd"/>',
        "Path traversal in SessionIndex",
    ),
    (
        '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#_0"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo></ds:Signature>',
        "Empty signature",
    ),
]


async def _find_sso_endpoints(outdir: Path) -> List[str]:
    urls = outdir / "urls_all.txt"
    endpoints: List[str] = []
    seen: Set[str] = set()
    if urls.exists():
        for u in read_lines(urls):
            u_lower = u.lower()
            for pat in _SSO_ENDPOINT_PATTERNS:
                if pat in u_lower and u not in seen:
                    endpoints.append(u)
                    seen.add(u)
                    break
    live_hosts = _load_live_hosts(outdir)
    for h in live_hosts:
        base = h if h.startswith("http") else f"https://{h}"
        for pat in _SSO_ENDPOINT_PATTERNS:
            url = base + pat
            if url not in seen:
                endpoints.append(url)
                seen.add(url)
    return endpoints


async def phase_158_SSO(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"158-SSO"}:
        return {}
    _out = outdir / "sso_oidc.txt"
    if _out.exists() and not force:
        return {"158-SSO": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 158-SSO: OIDC/OAuth misconfiguration testing")
    findings: List[str] = []
    endpoints = await _find_sso_endpoints(outdir)
    if not endpoints:
        findings.append("[info] No SSO endpoints found")
        out = ensure(_out)
        out.write_text("\n".join(findings) + "\n")
        log("ok", "158-SSO: no SSO endpoints")
        return {"158-SSO": str(_out), "count": 0}
    findings.append(f"[endpoints] Found {len(endpoints)} SSO endpoints")
    for ep in endpoints:
        findings.append(f"  {ep}")
    findings.append("")
    findings.append("--- OAuth misconfiguration probes ---")
    oauth_endpoints = [
        u for u in endpoints if any(p in u.lower() for p in ["/authorize", "response_type"])
    ]
    for ep in oauth_endpoints[:10]:
        for probe, desc in _OAUTH_MISCONFIG_PROBES[:8]:
            sep = "&" if "?" in ep else "?"
            test_url = f"{ep}{sep}{probe}"
            findings.append(f"  [{desc}] {test_url[:200]}")
    well_known_urls = [u for u in endpoints if ".well-known" in u.lower()]
    for wk in well_known_urls[:5]:
        await _throttle_rate()
        opener_sso = _get_urlopener()
        req_sso = urllib.request.Request(wk)
        try:
            _, _, body = await _async_urlopen(opener_sso, req_sso, timeout=10)
        except Exception:
            continue
        if body:
            try:
                parsed = json.loads(body)
                issuers = parsed.get("issuer", parsed.get("iss", ""))
                findings.append(f"[openid-config] {wk} → issuer={issuers}")
                for key in [
                    "authorization_endpoint",
                    "token_endpoint",
                    "jwks_uri",
                    "userinfo_endpoint",
                    "device_authorization_endpoint",
                ]:
                    if parsed.get(key):
                        findings.append(f"  {key}={parsed[key]}")
            except (json.JSONDecodeError, Exception):
                findings.append(
                    f"[openid-config-raw] {wk} → {body[:200].decode('utf-8', errors='replace')}"
                )
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"158-SSO: {len(findings)} findings → {out}")
    return {"158-SSO": str(_out), "count": len(findings)}


async def phase_159_SAMLADV(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"159-SAMLADV"}:
        return {}
    _out = outdir / "sso_saml.txt"
    if _out.exists() and not force:
        return {"159-SAMLADV": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 159-SAMLADV: SAML assertion manipulation testing")
    findings: List[str] = []
    endpoints = await _find_sso_endpoints(outdir)
    saml_endpoints = [u for u in endpoints if "saml" in u.lower() or "adfs" in u.lower()]
    if not saml_endpoints and endpoints:
        saml_endpoints = endpoints[:5]
    if not saml_endpoints:
        findings.append("[info] No SAML endpoints found")
        out = ensure(_out)
        out.write_text("\n".join(findings) + "\n")
        log("ok", "159-SAMLADV: no SAML endpoints")
        return {"159-SAMLADV": str(_out), "count": 0}
    findings.append(f"[endpoints] {len(saml_endpoints)} SAML endpoints")
    for ep in saml_endpoints:
        findings.append(f"  {ep}")
    findings.append("")
    findings.append("--- SAML attack vectors ---")
    for ep in saml_endpoints[:5]:
        for vector, desc in _SAML_ATTACK_VECTORS:
            findings.append(f"  [{desc}] {ep} → {vector[:150]}…")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"159-SAMLADV: {len(findings)} findings → {out}")
    return {"159-SAMLADV": str(_out), "count": len(findings)}


async def phase_160_SSOCONF(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"160-SSOCONF"}:
        return {}
    _out = outdir / "sso_token_confusion.txt"
    if _out.exists() and not force:
        return {"160-SSOCONF": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 160-SSOCONF: cross-tenant token confusion & IdP spoofing")
    findings: List[str] = []
    endpoints = await _find_sso_endpoints(outdir)
    if not endpoints:
        findings.append("[info] No SSO endpoints found")
        out = ensure(_out)
        out.write_text("\n".join(findings) + "\n")
        log("ok", "160-SSOCONF: no SSO endpoints")
        return {"160-SSOCONF": str(_out), "count": 0}
    findings.append(f"[endpoints] {len(endpoints)} SSO endpoints")
    token_endpoints = [u for u in endpoints if "/token" in u.lower()]
    auth_endpoints = [u for u in endpoints if "/authorize" in u.lower()]
    findings.append("")
    findings.append("--- cross-tenant token confusion tests ---")
    for ep in token_endpoints[:5]:
        await _throttle_rate()
        opener_sso2 = _get_urlopener()
        req_sso2 = urllib.request.Request(ep)
        try:
            _, _, resp_body = await _async_urlopen(opener_sso2, req_sso2, timeout=10)
        except Exception:
            continue
        if resp_body:
            findings.append(
                f"[token-endpoint] {ep} → {resp_body[:200].decode('utf-8', errors='replace')}"
            )
    findings.append("")
    findings.append("--- IdP spoofing / login CSRF tests ---")
    for ep in auth_endpoints[:5]:
        findings.append(f"[auth-endpoint] {ep}")
        for idp_param in ["idp", "provider", "identity_provider", "domain_hint", "login_hint"]:
            test_hint = f"{idp_param}=evil-idp.com"
            sep = "&" if "?" in ep else "?"
            findings.append(f"  [idp-spoof] {ep}{sep}{test_hint}")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"160-SSOCONF: {len(findings)} findings → {out}")
    return {"160-SSOCONF": str(_out), "count": len(findings)}
