"""Account security phases: account takeover detection (ATO)."""

from vulnforge.phases.helpers import (
    Any,
    Dict,
    List,
    Path,
    PhaseSet,
    Tools,
    _async_urlopen,
    _extra_headers_dict,
    _get_urlopener,
    asyncio,
    count_nonblank,
    ensure,
    log,
    re,
    read_lines,
    urllib,
)

_PASSWORD_RESET_PATHS = [
    "/reset",
    "/reset-password",
    "/forgot-password",
    "/password-reset",
    "/api/reset",
    "/api/password-reset",
]
_EMAIL_CHANGE_PATHS = [
    "/account/email",
    "/profile/email",
    "/api/account/email",
    "/settings/email",
    "/user/email",
]
_OAUTH_LINK_PATHS = [
    "/account/link",
    "/auth/link",
    "/oauth/link",
    "/connect/account",
    "/api/oauth/link",
]
_LOGIN_PATHS = ["/login", "/signin", "/auth/login", "/api/login", "/api/auth"]
_DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("test", "test"),
    ("user", "user"),
    ("guest", "guest"),
    ("root", "root"),
    ("admin", "123456"),
    ("admin", "letmein"),
]
_TOKEN_PATTERNS = [
    r"token=[0-9]+",
    r"token=[a-f0-9]{8}",
    r"reset=[0-9]+",
    r"code=[0-9]{4,6}",
    r"key=[0-9a-f]{8,16}",
]


async def phase_191_ATO(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"191-ATO"}:
        return {}
    _out = outdir / "ato_findings.txt"
    if _out.exists() and not force:
        return {"191-ATO": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 191-ATO: account takeover detection")
    findings: List[str] = []
    ato_urlopen = _get_urlopener()
    ato_extra_headers = _extra_headers_dict()
    urls_file = outdir / "urls_all.txt"
    hosts_file = outdir / "host_targets.txt"
    if not hosts_file.exists():
        hosts_file = outdir / "hosts.txt"
    targets = [f"https://{h}" if not h.startswith("http") else h for h in read_lines(hosts_file)]
    all_urls = read_lines(urls_file) if urls_file.exists() else []

    # 1. Password reset token predictability
    reset_urls = [u for u in all_urls if any(p in u.lower() for p in _PASSWORD_RESET_PATHS)] or [
        f"{t}/reset" for t in targets[:3]
    ]
    for url in reset_urls[:5]:
        try:
            req = urllib.request.Request(
                url, method="GET", headers={"User-Agent": "Mozilla/5.0", **ato_extra_headers}
            )
            status, headers, body = await _async_urlopen(ato_urlopen, req, timeout=10)
            if not body:
                continue
            body_text = body.decode("utf-8", errors="ignore")
            findings.append(f"[reset-endpoint] {url} — HTTP {status} ({len(body)} bytes)")
            for pat in _TOKEN_PATTERNS:
                matches = re.findall(pat, body_text)
                for m in matches[:3]:
                    if m[-1:].isdigit() or len(m) < 12:
                        findings.append(
                            f"[reset-token-weak] {url} — predictable token pattern: {m} (CWE-287)"
                        )
        except asyncio.CancelledError:
            raise
        except Exception:
            continue

    # 2. Email change — check if old email confirmation is required
    email_urls = [u for u in all_urls if any(p in u.lower() for p in _EMAIL_CHANGE_PATHS)] or [
        f"{t}/account/email" for t in targets[:3]
    ]
    for url in email_urls[:5]:
        try:
            req = urllib.request.Request(
                url, method="GET", headers={"User-Agent": "Mozilla/5.0", **ato_extra_headers}
            )
            status, headers, body = await _async_urlopen(ato_urlopen, req, timeout=10)
            if not body:
                continue
            body_text = body.decode("utf-8", errors="ignore").lower()
            findings.append(f"[email-change-endpoint] {url} — HTTP {status}")
            if "current password" not in body_text and "confirm" not in body_text:
                findings.append(
                    f"[email-change-no-verify] {url} — no confirmation required (CWE-287)"
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            continue

    # 3. OAuth account linking
    oauth_urls = [u for u in all_urls if any(p in u.lower() for p in _OAUTH_LINK_PATHS)] or [
        f"{t}/account/link" for t in targets[:3]
    ]
    for url in oauth_urls[:5]:
        try:
            req = urllib.request.Request(
                url, method="GET", headers={"User-Agent": "Mozilla/5.0", **ato_extra_headers}
            )
            status, headers, body = await _async_urlopen(ato_urlopen, req, timeout=10)
            if not body:
                continue
            body_text = body.decode("utf-8", errors="ignore").lower()
            findings.append(f"[oauth-link-endpoint] {url} — HTTP {status}")
            if "current password" not in body_text and "confirm" not in body_text:
                findings.append(
                    f"[oauth-link-no-verify] {url} — no re-authentication for OAuth linking (CWE-287)"
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            continue

    # 4. Default credentials
    login_urls = [u for u in all_urls if any(p in u.lower() for p in _LOGIN_PATHS)] or [
        f"{t}/login" for t in targets[:3]
    ]
    for url in login_urls[:5]:
        for username, password in _DEFAULT_CREDS:
            try:
                data = urllib.parse.urlencode(
                    {"username": username, "password": password, "email": username}
                ).encode()
                req = urllib.request.Request(
                    url,
                    method="POST",
                    data=data,
                    headers={
                        "User-Agent": "Mozilla/5.0",
                        "Content-Type": "application/x-www-form-urlencoded",
                        **ato_extra_headers,
                    },
                )
                status, headers, body = await _async_urlopen(ato_urlopen, req, timeout=10)
                body_text = body.decode("utf-8", errors="ignore").lower() if body else ""
                if status == 200 and "invalid" not in body_text and "error" not in body_text:
                    findings.append(
                        f"[default-creds] {url} — {username}:{password} returned HTTP {status} (CWE-287)"
                    )
            except urllib.error.HTTPError as e:
                if e.code == 302:
                    location = e.headers.get("Location", "")
                    findings.append(
                        f"[default-creds-redirect] {url} — {username}:{password} -> {location} (CWE-287)"
                    )
            except asyncio.CancelledError:
                raise
            except Exception:
                continue

    if not findings:
        findings.append("[ato] No account takeover vectors detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"191-ATO: {len(findings)} findings -> {out}")
    return {"191-ATO": str(out), "count": len(findings)}
