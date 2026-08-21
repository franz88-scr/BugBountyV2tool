"""Third-party and browser-related phases: SRI, mixed content, HSTS preload, third-party JS, browser storage."""

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict

from vulnforge.phases.harness import phase_begin
from vulnforge.phases.helpers import PhaseSet
from vulnforge.process import _PIPELINE_CFG
from vulnforge.tools import Tools
from vulnforge.utils import (
    _async_urlopen,
    _extra_headers_dict,
    _get_urlopener,
    _load_live_hosts,
    _throttle_rate,
    read_lines,
)


async def phase_107_SRI(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    run = phase_begin("107-SRI", outdir, skip, force, "sri_findings.txt")
    if run is None:
        return {}
    all_hosts = _load_live_hosts(outdir)
    if not all_hosts:
        return run.no_targets("no hosts")
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    _script_src_re = re.compile(r'<script[^>]*src=["\']([^"\']+)["\']', re.I)
    _link_stylesheet_re = re.compile(
        r'<link[^>]*rel=["\']stylesheet["\'][^>]*href=["\']([^"\']+)["\']', re.I
    )
    _integrity_re = re.compile(r"\bintegrity\s*=", re.I)
    for host_entry in all_hosts[: _PIPELINE_CFG.sample_hosts_sri]:
        host = host_entry.strip()
        if not host:
            continue
        if not host.startswith("http"):
            host = "https://" + host
        await _throttle_rate()
        try:
            req = urllib.request.Request(host, headers={"User-Agent": "Mozilla/5.0", **_extra_h})
            status, _, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
            if status != 200:
                continue
            body = body_bytes.decode("utf-8", errors="ignore")
            script_srcs = _script_src_re.findall(body)
            link_hrefs = _link_stylesheet_re.findall(body)
            parsed_host = urllib.parse.urlparse(host)
            host_domain = parsed_host.netloc.lower()
            for src in script_srcs:
                src_parsed = urllib.parse.urlparse(src)
                if not src_parsed.netloc:
                    continue
                src_domain = src_parsed.netloc.lower()
                if src_domain == host_domain or src_domain.endswith("." + host_domain):
                    continue
                start = body.find(f'src="{src}"')
                if start == -1:
                    start = body.find(f"src='{src}'")
                if start == -1:
                    continue
                snippet_start = max(0, start - 200)
                snippet = body[snippet_start : start + len(src) + 50]
                has_integrity = bool(_integrity_re.search(snippet))
                if has_integrity:
                    run.findings.append(f"[sri-present] {host} external_src={src}")
                else:
                    run.findings.append(f"[sri-missing] {host} external_src={src}")
            for href in link_hrefs:
                href_parsed = urllib.parse.urlparse(href)
                if not href_parsed.netloc:
                    continue
                href_domain = href_parsed.netloc.lower()
                if href_domain == host_domain or href_domain.endswith("." + host_domain):
                    continue
                start = body.find(f'href="{href}"')
                if start == -1:
                    start = body.find(f"href='{href}'")
                if start == -1:
                    continue
                snippet_start = max(0, start - 200)
                snippet = body[snippet_start : start + len(href) + 50]
                has_integrity = bool(_integrity_re.search(snippet))
                if has_integrity:
                    run.findings.append(f"[sri-present] {host} external_src={href}")
                else:
                    run.findings.append(f"[sri-missing] {host} external_src={href}")
        except Exception:
            continue
    return run.done()


async def phase_108_MIXEDCONTENT(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    run = phase_begin("108-MIXEDCONTENT", outdir, skip, force, "mixed_content.txt")
    if run is None:
        return {}
    _mc_urlopen = _get_urlopener()
    _mc_extra_headers = _extra_headers_dict()
    hosts = _load_live_hosts(outdir)
    if not hosts:
        return run.no_targets("no hosts")
    sample = getattr(_PIPELINE_CFG, "sample_hosts_mixedcontent", 20)
    for host in hosts[:sample]:
        if "://" in host:
            host_clean = urllib.parse.urlparse(host).hostname or host
        else:
            host_clean = host.split(":")[0].strip()
        if not host_clean:
            continue
        for scheme in ("https://",):
            url = f"{scheme}{host_clean}/"
            try:
                req = urllib.request.Request(
                    url, method="GET", headers={"User-Agent": "Mozilla/5.0", **_mc_extra_headers}
                )
                s, _, body_bytes = await _async_urlopen(_mc_urlopen, req, timeout=10)
                if s != 200:
                    continue
                body = body_bytes.decode("utf-8", errors="ignore")
                active_patterns = [
                    r'<script[^>]*src=["\']http://([^"\']+)["\']',
                    r'<iframe[^>]*src=["\']http://([^"\']+)["\']',
                    r'<link[^>]*href=["\']http://([^"\']+)["\'][^>]*stylesheet',
                    r'<object[^>]*data=["\']http://([^"\']+)["\']',
                    r'<embed[^>]*src=["\']http://([^"\']+)["\']',
                ]
                passive_patterns = [
                    r'<img[^>]*src=["\']http://([^"\']+)["\']',
                    r'background-image:\s*url\(["\']?http://([^)"\']+)',
                    r'<img[^>]*srcset=["\']http://([^"\']+)["\']',
                    r'<source[^>]*src=["\']http://([^"\']+)["\']',
                    r'<video[^>]*src=["\']http://([^"\']+)["\']',
                    r'<audio[^>]*src=["\']http://([^"\']+)["\']',
                ]
                for pat in active_patterns:
                    for m in re.finditer(pat, body, re.I):
                        run.findings.append(
                            f"[mixed-active] {host_clean} resource=http://{m.group(1)}"
                        )
                for pat in passive_patterns:
                    for m in re.finditer(pat, body, re.I):
                        run.findings.append(
                            f"[mixed-passive] {host_clean} resource=http://{m.group(1)}"
                        )
            except Exception:
                continue
    return run.done()


async def phase_109_HSTSPRELOAD(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    run = phase_begin("109-HSTSPRELOAD", outdir, skip, force, "hsts_preload.txt")
    if run is None:
        return {}
    _hp_urlopen = _get_urlopener()
    _hp_extra_headers = _extra_headers_dict()
    hosts = _load_live_hosts(outdir)
    if not hosts:
        return run.no_targets("no hosts")
    sample = getattr(_PIPELINE_CFG, "sample_hosts_hstspreload", 20)
    for host in hosts[:sample]:
        if "://" in host:
            host_clean = urllib.parse.urlparse(host).hostname or host
        else:
            host_clean = host.split(":")[0].strip()
        if not host_clean:
            continue
        for scheme in ("https://",):
            url = f"{scheme}{host_clean}/"
            try:
                req = urllib.request.Request(
                    url, method="GET", headers={"User-Agent": "Mozilla/5.0", **_hp_extra_headers}
                )
                s, headers, _ = await _async_urlopen(_hp_urlopen, req, timeout=10)
                if s not in (200, 301, 302, 307, 308):
                    continue
                hsts = headers.get("Strict-Transport-Security", "")
                if not hsts:
                    run.findings.append(f"[hsts-missing] {host_clean}")
                else:
                    max_age_m = re.search(r"max-age=(\d+)", hsts, re.I)
                    max_age = int(max_age_m.group(1)) if max_age_m else 0
                    has_include = "includesubdomains" in hsts.lower().replace(" ", "")
                    if max_age >= 31536000 and has_include:
                        try:
                            preload_req = urllib.request.Request(
                                f"https://hstspreload.org/api/v2/status?domain={host_clean}",
                                headers={"User-Agent": "Mozilla/5.0"},
                            )
                            ps, _, pb = await _async_urlopen(_hp_urlopen, preload_req, timeout=10)
                            if ps == 200:
                                preload_data = json.loads(pb.decode("utf-8", errors="ignore"))
                                if preload_data.get("status") == "preloaded":
                                    run.findings.append(f"[hsts-preloaded] {host_clean}")
                        except Exception:
                            pass
                    elif max_age < 31536000 or not has_include:
                        run.findings.append(
                            f"[hsts-insufficient] {host_clean} max-age={max_age} includeSubDomains={str(has_include).lower()}"
                        )
                break
            except Exception:
                continue
    return run.done()


async def phase_110_THIRDPARTYJS(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    run = phase_begin("110-THIRDPARTYJS", outdir, skip, force, "third_party_js.txt")
    if run is None:
        return {}
    _tj_urlopen = _get_urlopener()
    _tj_extra_headers = _extra_headers_dict()
    hosts = _load_live_hosts(outdir)
    if not hosts:
        return run.no_targets("no hosts")
    tracker_map = {
        "googletagmanager.com": "Google Tag Manager",
        "google-analytics.com": "Google Analytics",
        "googlesyndication.com": "Google Ads",
        "facebook.net": "Facebook Pixel",
        "connect.facebook.net": "Facebook Pixel",
        "hotjar.com": "Hotjar",
        "nr-data.net": "New Relic",
        "js-agent.newrelic.com": "New Relic",
        "cdn.ampproject.org": "AMP",
        "cdn.onesignal.com": "OneSignal",
        "cdn.segment.com": "Segment",
        "cdn.segment.io": "Segment",
        "cdn.jsdelivr.net": "jsDelivr CDN",
        "cdnjs.cloudflare.com": "Cloudflare CDN",
        "unpkg.com": "unpkg CDN",
    }
    sample = getattr(_PIPELINE_CFG, "sample_hosts_thirdpartyjs", 15)
    for host in hosts[:sample]:
        if "://" in host:
            host_clean = urllib.parse.urlparse(host).hostname or host
        else:
            host_clean = host.split(":")[0].strip()
        if not host_clean:
            continue
        for scheme in ("https://",):
            url = f"{scheme}{host_clean}/"
            try:
                req = urllib.request.Request(
                    url, method="GET", headers={"User-Agent": "Mozilla/5.0", **_tj_extra_headers}
                )
                s, _, body_bytes = await _async_urlopen(_tj_urlopen, req, timeout=10)
                if s != 200:
                    continue
                body = body_bytes.decode("utf-8", errors="ignore")
                script_tags = re.findall(r"(<script[^>]+>)", body, re.I)
                for stag in script_tags:
                    src_m = re.search(r'src=["\']([^"\']+)["\']', stag, re.I)
                    if not src_m:
                        continue
                    src = src_m.group(1).strip()
                    if not src.startswith("http"):
                        if src.startswith("//"):
                            src = "https:" + src
                        else:
                            src = urllib.parse.urljoin(url, src)
                    src_host = urllib.parse.urlparse(src).hostname or ""
                    if src_host != host_clean and not src_host.endswith("." + host_clean):
                        tracker_name = "unknown"
                        for tdom, tname in tracker_map.items():
                            if tdom in src_host:
                                tracker_name = tname
                                break
                        run.findings.append(
                            f"[third-party-js] {host_clean} src={src} tracker={tracker_name}"
                        )
                        has_sri = bool(re.search(r"\bintegrity\s*=", stag, re.I))
                        if not has_sri:
                            run.findings.append(f"[third-party-nosri] {host_clean} src={src}")
            except Exception:
                continue
    return run.done()


async def phase_111_BROWSERSTORAGE(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    run = phase_begin("111-BROWSERSTORAGE", outdir, skip, force, "browser_storage_audit.txt")
    if run is None:
        return {}
    _bs_urlopen = _get_urlopener()
    _bs_extra_headers = _extra_headers_dict()
    js_urls_file = outdir / "urls_js.txt"
    js_urls = read_lines(js_urls_file) if js_urls_file.exists() else []
    if not js_urls:
        return run.no_targets("no JS URLs")
    sensitive_patterns = [
        "token",
        "password",
        "secret",
        "api_key",
        "apikey",
        "session",
        "jwt",
        "access_token",
        "refresh_token",
        "auth",
        "credential",
        "private",
        "key",
        "passwd",
        "pwd",
        "secretkey",
    ]
    sample = getattr(_PIPELINE_CFG, "sample_hosts_browserstorage", 15)
    for js_url in js_urls[:sample]:
        js_url = js_url.strip()
        if not js_url:
            continue
        try:
            await _throttle_rate()
            req = urllib.request.Request(
                js_url, headers={"User-Agent": "Mozilla/5.0", **_bs_extra_headers}
            )
            s, _, body_bytes = await _async_urlopen(_bs_urlopen, req, timeout=10)
            if s != 200:
                continue
            body = body_bytes.decode("utf-8", errors="ignore")
            storage_calls = re.findall(
                r'(localStorage|sessionStorage)\.(?:setItem|getItem|removeItem)\s*\(\s*["\']([^"\']+)["\']',
                body,
                re.I,
            )
            for storage_type, key in storage_calls:
                key_lower = key.lower()
                for sp in sensitive_patterns:
                    if sp in key_lower:
                        run.findings.append(f"[browser-storage-sensitive] {js_url} pattern={sp}")
                        break
                run.findings.append(
                    f"[browser-storage] {js_url} storage_type={storage_type} key={key}"
                )
            indexeddb_matches = re.findall(
                r'indexedDB\.open\s*\(\s*["\']([^"\']+)["\']', body, re.I
            )
            for db_name in indexeddb_matches:
                db_lower = db_name.lower()
                for sp in sensitive_patterns:
                    if sp in db_lower:
                        run.findings.append(f"[browser-storage-sensitive] {js_url} pattern={sp}")
                        break
                run.findings.append(
                    f"[browser-storage] {js_url} storage_type=IndexedDB key={db_name}"
                )
        except Exception:
            continue
    return run.done()
