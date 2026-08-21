"""Protocol-level phases: HTTP/2 cache digestion, web cache poisoning extended."""

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
    _extra_headers_dict,
    _get_urlopener,
    count_nonblank,
    ensure,
    log,
    read_lines,
)


async def phase_183_CACHEDIG(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"183-CACHEDIG"}:
        return {}
    _out = outdir / "cache_dig.txt"
    if _out.exists() and not force:
        return {"183-CACHEDIG": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 183-CACHEDIG: HTTP/2 cache digestion / web cache poisoning extended")
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    cached_path = prev.get("28-CACHED", "")
    cached_hosts: List[str] = []
    if cached_path:
        cached_lines = read_lines(Path(cached_path))
        for ln in cached_lines:
            if ln.startswith("https://") or ln.startswith("http://"):
                cached_hosts.append(ln.split()[0])
            elif ln.startswith("[cache-detected]") or ln.startswith("[cache-poison"):
                parts = ln.split()
                for p in parts:
                    if p.startswith("http"):
                        cached_hosts.append(p)
                        break
    if not cached_hosts:
        hosts_file = outdir / "host_targets.txt"
        if not hosts_file.exists():
            hosts_file = outdir / "hosts.txt"
        cached_hosts = read_lines(hosts_file)
    cached_hosts = [h if h.startswith("http") else f"https://{h}" for h in cached_hosts][
        : _PIPELINE_CFG.sample_hosts_cached
    ]
    if not cached_hosts:
        log("WARNING", "183-CACHEDIG: no cached hosts; skipping")
        return {"183-CACHEDIG": str(_out), "count": 0}

    for h in cached_hosts:
        url = h.rstrip("/")
        base_req = urllib.request.Request(
            url, method="GET", headers={"User-Agent": "Mozilla/5.0", **_extra_h}
        )
        try:
            base_status, base_headers, base_body = await _async_urlopen(
                _urlopen, base_req, timeout=10
            )
        except Exception:
            continue
        base_str = str(base_headers).lower()
        base_is_cached = "x-cache" in base_str or "cf-cache" in base_str or "age:" in base_str
        if not base_is_cached:
            continue
        findings.append(f"[cache-digest] {url} — confirmed cache-enabled")
        for unkeyed_val in ("1", "2"):
            try:
                u_req = urllib.request.Request(
                    url + f"/?unkeyed={unkeyed_val}",
                    method="GET",
                    headers={"User-Agent": "Mozilla/5.0", **_extra_h},
                )
                u_status, u_headers, u_body = await _async_urlopen(_urlopen, u_req, timeout=10)
                if u_body == base_body:
                    findings.append(
                        f"[unkeyed-param] {url} — ?unkeyed={unkeyed_val} produced same response"
                    )
            except Exception:
                pass
        for hdr_name, hdr_val in (
            ("X-Forwarded-Host", "evil\nX-Forwarded-Host: evil.com"),
            ("X-Forwarded-Host", "evil\r\nX-Forwarded-Host: evil.com"),
        ):
            try:
                inj_req = urllib.request.Request(
                    url,
                    method="GET",
                    headers={
                        "User-Agent": "Mozilla/5.0",
                        hdr_name: hdr_val,
                        **_extra_h,
                    },
                )
                inj_status, inj_headers, inj_body = await _async_urlopen(
                    _urlopen, inj_req, timeout=10
                )
                inj_str = str(inj_headers).lower()
                if "evil" in inj_str:
                    findings.append(
                        f"[cache-key-injection] {url} via {hdr_name}: newline injection reflected"
                    )
            except Exception:
                pass
        try:
            push_req = urllib.request.Request(
                url,
                method="GET",
                headers={
                    "User-Agent": "Mozilla/5.0",
                    "X-HTTP2-Push": "1",
                    **_extra_h,
                },
            )
            push_status, push_headers, push_body = await _async_urlopen(
                _urlopen, push_req, timeout=10
            )
            push_str = str(push_headers).lower()
            if "push" in push_str or "promise" in push_str:
                findings.append(f"[http2-push] {url} — server appears to support PUSH_PROMISE")
        except Exception:
            pass
    if not findings:
        findings.append("[cache-digest] No cache digestion candidates detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"183-CACHEDIG: {len(findings)} findings → {out}")
    return {"183-CACHEDIG": str(out), "count": len(findings)}
