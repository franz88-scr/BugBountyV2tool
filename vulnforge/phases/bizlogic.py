"""Business logic deep testing phases — workflow, payment, coupon, multi-tenant, 2FA."""

import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from vulnforge.phases.helpers import PhaseSet
from vulnforge.tools import Tools
from vulnforge.utils import (
    _async_urlopen,
    _extra_headers_dict,
    _get_urlopener,
    _load_live_hosts,
    _throttle_rate,
    count_nonblank,
    ensure,
    log,
    read_lines,
)

_WORKFLOW_ENDPOINTS = [
    "/checkout",
    "/checkout/",
    "/cart",
    "/cart/",
    "/order",
    "/order/",
    "/api/checkout",
    "/api/cart",
    "/api/order",
    "/api/payment",
    "/payment",
    "/payment/",
    "/subscribe",
    "/subscription",
    "/api/subscribe",
    "/billing",
    "/api/billing",
    "/register",
    "/api/register",
    "/signup",
    "/api/signup",
    "/onboarding",
    "/api/onboarding",
    "/profile",
    "/api/profile",
    "/settings",
    "/api/settings",
]

_PAYMENT_ENDPOINTS = [
    "/api/payment",
    "/api/charge",
    "/api/create-payment",
    "/api/confirm-payment",
    "/stripe",
    "/api/stripe",
    "/checkout",
    "/api/checkout",
    "/order",
    "/api/order/",
    "/api/pay",
    "/payment/intent",
    "/api/payment/intent",
    "/charge",
    "/api/charge",
    "/webhook/stripe",
    "/api/webhook",
]

_COUPON_ENDPOINTS = [
    "/api/coupon",
    "/api/discount",
    "/api/promo",
    "/api/voucher",
    "/coupon",
    "/discount",
    "/promo",
    "/voucher",
    "/api/apply-coupon",
    "/apply-coupon",
    "/api/validate-coupon",
    "/validate-coupon",
]

_PAYMENT_ABUSE_PAYLOADS: List[Dict[str, Any]] = [
    {"amount": -1},
    {"amount": 0},
    {"quantity": -1},
    {"quantity": 999999},
    {"price": 0.01},
    {"price": -100},
    {"currency": "USD", "amount": 0},
    {"currency": "EUR", "amount": -50},
    {"coupon": "TEST123", "items": [{"id": 1, "qty": -1}]},
    {"items": [{"id": 1, "price": 0}]},
    {"discount": 100},
    {"discount": -50},
    {"total": 0},
    {"total": 1},
    {"subtotal": -1},
    {"tax": -100},
    {"shipping": -100},
]

_COUPON_ABUSE_STRATEGIES = [
    "TRYME123",
    "WELCOME10",
    "WELCOME20",
    "FIRSTORDER",
    "FREESHIPPING",
    "50OFF",
    "SAVE50",
    "DISCOUNT20",
    "PROMO2024",
    "PROMO2025",
    "NEWUSER",
    "REFERRAL",
    "FRIEND10",
    "VIP20",
    "BLACKFRIDAY",
    "CYBERMONDAY",
    "HOLIDAY30",
    "SUMMER20",
    "WINTER10",
    "SPRING15",
    "FALL25",
    "TESTCOUPON",
    "DEVELOPER",
    "DEBUG",
    "TESTMODE",
    "INTERNAL",
    "STAFF50",
    "EMPLOYEE20",
    "PARTNER",
    "BETAUSER",
]


async def _find_endpoints_by_patterns(outdir: Path, patterns: List[str]) -> List[str]:
    urls = outdir / "urls_all.txt"
    endpoints: List[str] = []
    seen: Set[str] = set()
    if urls.exists():
        for u in read_lines(urls):
            u_lower = u.lower()
            for pat in patterns:
                if pat in u_lower and u not in seen:
                    endpoints.append(u)
                    seen.add(u)
                    break
    live_hosts = _load_live_hosts(outdir)
    for h in live_hosts:
        base = h if h.startswith("http") else f"https://{h}"
        for pat in patterns:
            url = base + pat
            if url not in seen:
                endpoints.append(url)
                seen.add(url)
    return endpoints


async def _send_json(url: str, data: dict, timeout: int = 15) -> Optional[Dict[str, Any]]:
    opener = _get_urlopener()
    headers = {"Content-Type": "application/json"}
    headers.update(_extra_headers_dict())
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(data).encode(),
            headers=headers,
            method="POST",
        )
        status, _, body = await _async_urlopen(opener, req, timeout=timeout)
        return {"status": status, "body": body.decode("utf-8", errors="replace")}
    except Exception:
        return None


async def _send_get(url: str, timeout: int = 15) -> Optional[Dict[str, Any]]:
    opener = _get_urlopener()
    headers = _extra_headers_dict()
    try:
        req = urllib.request.Request(url, headers=headers)
        status, _, body = await _async_urlopen(opener, req, timeout=timeout)
        return {"status": status, "body": body.decode("utf-8", errors="replace")}
    except Exception:
        return None


async def _control_json(url: str) -> Optional[Dict[str, Any]]:
    return await _send_json(url, {"vulnforge_control": "benign", "action": "noop"}, timeout=10)


def _response_diff(attack: Optional[Dict[str, Any]], control: Optional[Dict[str, Any]]) -> bool:
    if not attack or attack["status"] not in (200, 201, 202, 204):
        return False
    if control is None:
        return False
    if attack["status"] != control["status"]:
        return True
    a_body = attack["body"][:200]
    c_body = control["body"][:200]
    if a_body != c_body:
        return True
    return False


async def phase_153_BIZLOGIC(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"153-BIZLOGIC"}:
        return {}
    _out = outdir / "bizlogic_workflow.txt"
    if _out.exists() and not force:
        return {"153-BIZLOGIC": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 153-BIZLOGIC: workflow logic bypass & state machine violation")
    findings: List[str] = []
    endpoints = await _find_endpoints_by_patterns(outdir, _WORKFLOW_ENDPOINTS)
    if not endpoints:
        findings.append("[info] No workflow endpoints found")
        out = ensure(_out)
        out.write_text("\n".join(findings) + "\n")
        log("OK", "153-BIZLOGIC: no workflow endpoints")
        return {"153-BIZLOGIC": str(_out), "count": 0}
    findings.append(f"[endpoints] Found {len(endpoints)} workflow endpoints")
    for ep in endpoints:
        findings.append(f"  {ep}")

    # State machine discovery: GET each endpoint and track status transitions
    findings.append("")
    findings.append("--- State Machine Discovery ---")
    state_transitions: Dict[str, int] = {}
    for ep in endpoints[:10]:
        resp = await _send_get(ep)
        if resp:
            state_transitions[ep] = resp["status"]
            findings.append(f"[state-transition] GET {ep} → HTTP {resp['status']}")

    # Skip/Coupon-Stacking: try multiple coupons in sequence
    coupon_stack_payloads: List[Dict[str, Any]] = [
        {"coupon": "TEST123", "coupon2": "TEST456"},
        {"coupon": "FREENOW", "extra_coupon": "EXTRA10"},
        {"coupons": ["TEST123", "TEST456", "EXTRA10"]},
        {"discount_code": "STACK1", "additional_discount": "STACK2"},
    ]
    for ep in endpoints[:5]:
        control = await _control_json(ep)
        for payload in coupon_stack_payloads:
            await _throttle_rate()
            resp = await _send_json(ep, payload)
            if _response_diff(resp, control):
                findings.append(
                    f"[coupon-stack] {ep} → payload={payload} -> {resp['status']}: {resp['body'][:100]}"
                )

    # Step-skipping: classic workflow bypass
    skipped_steps: List[Dict[str, Any]] = [
        {"step": "payment", "skip": True},
        {"step": "shipping", "skip": True},
        {"step": "review", "skip": True},
        {"step": "confirmation", "skip": True},
        {"completed": True},
        {"action": "complete", "validate": False},
        {"action": "skip"},
        {"status": "completed"},
        {"status": "confirmed"},
        {"force_complete": True},
        {"override": True},
        {"admin_approve": True},
    ]
    for ep in endpoints[:10]:
        control = await _control_json(ep)
        for attempt in skipped_steps:
            await _throttle_rate()
            resp = await _send_json(ep, attempt)
            if _response_diff(resp, control):
                findings.append(
                    f"[state-skip] {ep} → payload={attempt} -> {resp['status']}: {resp['body'][:100]}"
                )

    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"153-BIZLOGIC: {len(findings)} findings → {out}")
    return {"153-BIZLOGIC": str(_out), "count": len(findings)}


async def phase_154_PAYMENT(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"154-PAYMENT"}:
        return {}
    _out = outdir / "bizlogic_payment.txt"
    if _out.exists() and not force:
        return {"154-PAYMENT": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 154-PAYMENT: payment logic bypass testing")
    findings: List[str] = []
    endpoints = await _find_endpoints_by_patterns(outdir, _PAYMENT_ENDPOINTS)
    if not endpoints:
        findings.append("[info] No payment endpoints found")
        out = ensure(_out)
        out.write_text("\n".join(findings) + "\n")
        log("OK", "154-PAYMENT: no payment endpoints")
        return {"154-PAYMENT": str(_out), "count": 0}
    findings.append(f"[endpoints] Found {len(endpoints)} payment endpoints")
    for ep in endpoints:
        findings.append(f"  {ep}")

    # Extended price-manipulation payloads including integer overflow and negative quantity
    extended_payloads = _PAYMENT_ABUSE_PAYLOADS + [
        {"amount": 999999999999999},  # integer overflow
        {"quantity": 9999999},
        {"quantity": -999999},
        {"price": 999999999999999},
        {"price": "999999999999999999999999999999"},  # string overflow
        {"items": [{"id": 1, "price": 0, "qty": 1}, {"id": 2, "price": -100, "qty": 1}]},
        {"items": [{"id": 1, "qty": 1, "price": 100}], "discount": 101},  # negative total
        {"currency": "USD", "amount": 0, "items": [{"id": 1, "qty": 0}]},
        {"currency": "USD", "amount": 0.001},  # rounding attack
        {"currency": "USD", "amount": -0.01},
        {"currency": "XXX"},  # invalid currency
        {"currency": "USD", "amount": 100, "merchant": "self"},  # self-payment
        {"action": "refund", "amount": 100000},  # refund without purchase
        {"action": "credit", "amount": 10000},  # unauthorized credit
        {"amount": 100, "source": "attacker_account"},  # wrong source
    ]
    for ep in endpoints[:10]:
        control = await _control_json(ep)
        for payload in extended_payloads:
            await _throttle_rate()
            resp = await _send_json(ep, payload)
            if _response_diff(resp, control):
                findings.append(
                    f"[price-manipulation] {ep} → payload={payload} -> "
                    f"{resp['status']}: {resp['body'][:150]}"
                )

    # Race: send 5 identical payment requests simultaneously (only if the
    # endpoint accepts the payload in the first place, else it's a no-op)
    for ep in endpoints[:3]:
        try:
            import asyncio as _asyncio

            race_payload = {"amount": 1, "currency": "USD", "items": [{"id": 1, "qty": 1}]}
            probe = await _send_json(ep, race_payload, timeout=10)
            if not probe or probe["status"] not in (200, 201):
                continue
            race_tasks = []
            for _ in range(5):
                race_tasks.append(_send_json(ep, race_payload, timeout=10))
            race_results = await _asyncio.gather(*race_tasks, return_exceptions=True)
            success_count = sum(
                1 for r in race_results if isinstance(r, dict) and r["status"] in (200, 201)
            )
            if success_count > 1:
                findings.append(
                    f"[payment-race] {ep} — {success_count}/5 concurrent payment requests succeeded (potential race condition)"
                )
        except _asyncio.CancelledError:
            raise
        except Exception:
            pass

    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"154-PAYMENT: {len(findings)} findings → {out}")
    return {"154-PAYMENT": str(_out), "count": len(findings)}


async def phase_155_COUPON(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"155-COUPON"}:
        return {}
    _out = outdir / "bizlogic_coupon.txt"
    if _out.exists() and not force:
        return {"155-COUPON": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 155-COUPON: coupon/discount abuse testing")
    findings: List[str] = []
    endpoints = await _find_endpoints_by_patterns(outdir, _COUPON_ENDPOINTS)
    endpoints += await _find_endpoints_by_patterns(outdir, _PAYMENT_ENDPOINTS)
    if not endpoints:
        findings.append("[info] No coupon/payment endpoints found")
        out = ensure(_out)
        out.write_text("\n".join(findings) + "\n")
        log("OK", "155-COUPON: no coupon endpoints")
        return {"155-COUPON": str(_out), "count": 0}
    findings.append(f"[endpoints] Found {len(endpoints)} coupon endpoints")
    for ep in endpoints:
        findings.append(f"  {ep}")
    for ep in endpoints[:10]:
        control = await _control_json(ep)
        for coupon in _COUPON_ABUSE_STRATEGIES[:10]:
            await _throttle_rate()
            resp = await _send_json(ep, {"coupon": coupon, "code": coupon})
            if _response_diff(resp, control):
                rbody = resp["body"].lower()
                if "applied" in rbody or "valid" in rbody or "discount" in rbody:
                    findings.append(
                        f"[coupon-accepted] {ep} → coupon={coupon} -> "
                        f"{resp['status']}: {resp['body'][:150]}"
                    )
        resp = await _send_json(ep, {"coupon": "WELCOME10", "quantity": -1})
        if _response_diff(resp, control):
            findings.append(f"[coupon-negative-qty] {ep} -> {resp['status']}: {resp['body'][:150]}")
        resp = await _send_json(ep, {"coupon": "WELCOME10", "items": [{"id": 1, "qty": -1}]})
        if _response_diff(resp, control):
            findings.append(
                f"[coupon-negative-items] {ep} -> {resp['status']}: {resp['body'][:150]}"
            )
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"155-COUPON: {len(findings)} findings → {out}")
    return {"155-COUPON": str(_out), "count": len(findings)}


async def phase_156_MTENANT(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"156-MTENANT"}:
        return {}
    _out = outdir / "bizlogic_multitenant.txt"
    if _out.exists() and not force:
        return {"156-MTENANT": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 156-MTENANT: multi-tenant isolation testing")
    findings: List[str] = []
    urls = outdir / "urls_all.txt"
    api_endpoints: List[str] = []
    tenant_patterns = [
        "/api/",
        "/v1/",
        "/v2/",
        "/v3/",
        "/admin",
        "/organization",
        "/org/",
        "/team/",
        "/workspace/",
        "/project/",
        "/tenant/",
        "/account/",
        "/company/",
    ]
    tenant_id_headers = [
        "X-Tenant-ID",
        "X-Organization-ID",
        "X-Org-ID",
        "X-Account-ID",
        "X-Workspace-ID",
        "X-Project-ID",
        "X-Team-ID",
        "X-Company-ID",
        "X-Customer-ID",
    ]
    if urls.exists():
        for u in read_lines(urls):
            for pat in tenant_patterns:
                if pat in u.lower():
                    api_endpoints.append(u)
                    break
    findings.append(f"[endpoints] {len(api_endpoints)} potential tenant-aware endpoints")
    for ep in api_endpoints[:15]:
        findings.append(f"  {ep}")
    test_tenants = [
        "1",
        "0",
        "admin",
        "other",
        "00000000-0000-0000-0000-000000000000",
        "../",
        "../../",
        "*",
        "null",
        "undefined",
        "true",
        "false",
    ]
    findings.append("")
    findings.append("--- tenant ID switching tests ---")
    for ep in api_endpoints[:10]:
        opener = _get_urlopener()
        try:
            ctrl_req = urllib.request.Request(ep, headers=_extra_headers_dict())
            ctrl_status, _, ctrl_body_bytes = await _async_urlopen(opener, ctrl_req, timeout=10)
            ctrl_body = ctrl_body_bytes.decode("utf-8", errors="replace") if ctrl_body_bytes else ""
        except Exception:
            ctrl_status = None
            ctrl_body = ""
        for header in tenant_id_headers[:5]:
            for tid in test_tenants[:5]:
                await _throttle_rate()
                try:
                    req = urllib.request.Request(ep, headers={header: tid, **_extra_headers_dict()})
                    status, _, body_bytes = await _async_urlopen(opener, req, timeout=10)
                    body = body_bytes.decode("utf-8", errors="replace") if body_bytes else ""
                    if status in (200, 201) and (ctrl_status is None or status != ctrl_status or body != ctrl_body):
                        findings.append(
                            f"[tenant-switch] {ep} → {header}: {tid} -> {status}: {body[:100]}"
                        )
                except Exception:
                    pass
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"156-MTENANT: {len(findings)} findings → {out}")
    return {"156-MTENANT": str(_out), "count": len(findings)}


async def phase_157_2FA(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"157-2FA"}:
        return {}
    _out = outdir / "bizlogic_2fa.txt"
    if _out.exists() and not force:
        return {"157-2FA": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 157-2FA: 2FA/CAPTCHA bypass testing")
    findings: List[str] = []
    urls = outdir / "urls_all.txt"
    auth_endpoints: List[str] = []
    auth_patterns = [
        "/login",
        "/login/",
        "/2fa",
        "/verify",
        "/otp",
        "/mfa",
        "/auth",
        "/signin",
        "/api/login",
        "/api/2fa",
        "/api/verify",
        "/api/otp",
        "/api/mfa",
        "/captcha",
        "/recaptcha",
        "/api/captcha",
    ]
    if urls.exists():
        for u in read_lines(urls):
            for pat in auth_patterns:
                if pat in u.lower():
                    auth_endpoints.append(u)
                    break
    live_hosts = _load_live_hosts(outdir)
    for h in live_hosts:
        base = h if h.startswith("http") else f"https://{h}"
        for pat in auth_patterns:
            url = base + pat
            if url not in auth_endpoints:
                auth_endpoints.append(url)
    findings.append(f"[endpoints] {len(auth_endpoints)} potential 2FA/auth endpoints")
    for ep in auth_endpoints[:15]:
        findings.append(f"  {ep}")
    otp_bypass_payloads = [
        {"otp": "000000", "code": "000000", "token": "000000"},
        {"otp": "123456", "code": "123456", "token": "123456"},
        {"otp": "111111", "code": "111111", "token": "111111"},
        {"otp": "", "code": "", "token": ""},
        {"otp": "null", "code": "null", "token": "null"},
        {"otp": "undefined", "code": "undefined", "token": "undefined"},
        {"otp": "*", "code": "*", "token": "*"},
        {"otp": "true", "code": "true", "token": "true"},
        {"otp": "999999", "code": "999999"},
        {"otp": "-1", "code": "-1"},
    ]
    findings.append("")
    findings.append("--- 2FA bypass attempts ---")
    for ep in auth_endpoints[:10]:
        if any(p in ep.lower() for p in ["2fa", "otp", "mfa", "verify"]):
            control = await _send_json(ep, {"otp": "847291", "code": "847291"})
            for payload in otp_bypass_payloads:
                await _throttle_rate()
                resp = await _send_json(ep, payload)
                if _response_diff(resp, control):
                    findings.append(
                        f"[otp-bypass] {ep} → payload={payload} -> "
                        f"{resp['status']}: {resp['body'][:150]}"
                    )
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"157-2FA: {len(findings)} findings → {out}")
    return {"157-2FA": str(_out), "count": len(findings)}
