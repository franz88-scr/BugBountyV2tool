"""Post-processing filter: removes false positives from phase output files."""
from __future__ import annotations
import re
from pathlib import Path
from typing import List

from reconchain.utils import ensure, log

_TOR_ERRORS = {
    "501 Tor is not an HTTP Proxy",
    "SOCKSHTTPSConnectionPool",
    "Max retries exceeded",
    "Tunnel connection failed",
    "Failed to establish a new connection",
    "Connection refused",
    "NewConnectionError",
    "ConnectionClosedError",
    "SOCKSHTTPSConnection",
}
_NOISE_PREFIXES = {
    "[error]",
    "[apikeyleak] 0 URLs scanned",
    "[depcheck] scanned 0",
}
_OBSOLETE_COUNT_PAT = re.compile(r'^target_(urls|hosts)=\d+$')
_DOMXSS_VUE_PAT = re.compile(r'Symbol\("evaluating"\)')


def _is_false_positive(line: str, fname: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False  # keep blank lines

    # Tor / network errors — never a real finding
    for tok in _TOR_ERRORS:
        if tok in stripped:
            return True

    # Error-prefixed log lines from phases
    for prefix in _NOISE_PREFIXES:
        if stripped.startswith(prefix):
            return True

    # Count-only lines like "target_urls=5" are meta, not findings
    if _OBSOLETE_COUNT_PAT.match(stripped):
        return True

    # File-specific filters
    if fname == "domxss_findings.txt":
        if _DOMXSS_VUE_PAT.search(stripped):
            return True

    if fname == "csp_analysis.txt":
        if stripped.startswith("[error]"):
            return True

    if fname == "account_enum.txt":
        if stripped.startswith("[error]"):
            return True

    if fname == "api_key_leaks.txt":
        if "0 URLs scanned" in stripped or "no API key leaks" in stripped:
            return True

    if fname == "depcheck.txt":
        if "scanned 0 JS files" in stripped:
            return True

    if fname == "mobile_api.txt":
        if stripped.startswith("[firebase-error]") and "→" in stripped:
            after = stripped.split("→", 1)[1].strip()
            if not after or "Tunnel" in after or "Connection" in after or "404" in after:
                return True

    if fname == "oauth_deep.txt":
        if "[403]" in stripped:
            parts = stripped.rsplit("[403]", 1)
            path = parts[1].strip() if len(parts) > 1 else ""
            if not path or "/" not in path:
                return True

    if fname == "cors_advanced.txt":
        if "No advanced CORS" in stripped:
            return True

    if fname == "csrf_findings.txt":
        if "0 URLs tested" in stripped:
            return True

    if fname == "ssrf_full.txt":
        if "No SSRF" in stripped:
            return True

    if fname == "ssti.txt":
        if "No SSTI" in stripped:
            return True

    if fname == "xxe.txt":
        if "No XXE" in stripped:
            return True

    if fname == "lfi.txt":
        if "No LFI" in stripped:
            return True

    if fname == "stored_xss_verified.txt":
        if "No stored XSS" in stripped:
            return True

    if fname == "stored_xss.txt":
        if "No stored XSS" in stripped:
            return True

    if fname in ("idor.txt", "idor_fuzz.txt"):
        if stripped.startswith("target_urls="):
            return True

    if fname in ("api_specs.txt",):
        if "[result] No API spec" in stripped:
            return True

    if fname in ("clickjacking.txt",):
        if "All targets have clickjacking protection" in stripped:
            return True

    return False


def filter_outputs(outdir: Path) -> int:
    total_removed = 0
    emptied = 0

    txt_files = sorted(outdir.rglob("*.txt"))
    if not txt_files:
        log("info", "no output files to filter")
        return 0

    for fp in txt_files:
        fname = fp.name
        try:
            raw = fp.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        if not raw.strip():
            continue

        # Split keeping line endings
        lines = raw.splitlines(keepends=True)
        kept: List[str] = []
        removed = 0
        for ln in lines:
            if _is_false_positive(ln, fname):
                removed += 1
            else:
                kept.append(ln)

        if removed == 0:
            continue

        total_removed += removed
        significant = [ln for ln in kept if ln.strip()]
        if not significant:
            fp.write_text("")
            emptied += 1
            log("info", f"filter {fname}: removed {removed}/{len(lines)} → emptied")
        else:
            fp.write_text("".join(kept))
            log("info", f"filter {fname}: removed {removed}/{len(lines)} lines")

    log("info", f"filter total: {total_removed} lines removed, {emptied} files emptied")
    return total_removed
