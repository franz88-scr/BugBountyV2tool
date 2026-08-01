"""ReDoS vulnerability detection phase."""

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
    os,
    read_lines,
    urllib,
)

_REDOS_PAYLOADS = [
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!@a.a",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa(a",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa[",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.",
]


async def phase_192_REDOS(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"192-REDOS"}:
        return {}
    _out = outdir / "redos_findings.txt"
    if _out.exists() and not force:
        return {"192-REDOS": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 192-REDOS: ReDoS detection via timing differential")
    findings: List[str] = []
    redos_urlopen = _get_urlopener()
    redos_extra_headers = _extra_headers_dict()

    param_urls: List[str] = []
    if "07-PARAMS" in prev:
        raw = prev["07-PARAMS"]
        if isinstance(raw, str) and os.path.isfile(raw):
            param_urls = read_lines(Path(raw))
        elif isinstance(raw, list):
            param_urls = raw
    if not param_urls:
        params_file = outdir / "params.txt"
        if params_file.exists():
            param_urls = read_lines(params_file)
    if not param_urls:
        urls_file = outdir / "urls_all.txt"
        if urls_file.exists():
            param_urls = [u for u in read_lines(urls_file) if "=" in u]
    if not param_urls:
        log("warn", "192-REDOS: no parameter URLs; skipping")
        return {"192-REDOS": str(_out), "count": 0}

    param_urls = param_urls[:50]

    async def _probe_redos(url: str) -> List[str]:
        results: List[str] = []
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            return results
        try:
            base_req = urllib.request.Request(
                url, method="GET", headers={"User-Agent": "Mozilla/5.0", **redos_extra_headers}
            )
            t0 = asyncio.get_event_loop().time()
            _, _, _ = await _async_urlopen(redos_urlopen, base_req, timeout=15)
            base_time = asyncio.get_event_loop().time() - t0
        except asyncio.CancelledError:
            raise
        except Exception:
            return results

        for param_name in qs:
            for payload in _REDOS_PAYLOADS:
                try:
                    encoded_payload = urllib.parse.quote(payload, safe="")
                    query_parts = []
                    for k, vals in qs.items():
                        for v in vals:
                            if k == param_name:
                                query_parts.append(
                                    f"{urllib.parse.quote_plus(k)}={encoded_payload}"
                                )
                            else:
                                query_parts.append(
                                    f"{urllib.parse.quote_plus(k)}={urllib.parse.quote_plus(v)}"
                                )
                    test_qs = "&".join(query_parts)
                    test_url = urllib.parse.urlunparse(parsed._replace(query=test_qs))

                    redos_req = urllib.request.Request(
                        test_url,
                        method="GET",
                        headers={"User-Agent": "Mozilla/5.0", **redos_extra_headers},
                    )
                    t1 = asyncio.get_event_loop().time()
                    p_status, _, _ = await _async_urlopen(redos_urlopen, redos_req, timeout=15)
                    elapsed = asyncio.get_event_loop().time() - t1

                    if base_time > 0 and elapsed > base_time * 5:
                        results.append(
                            f"[redos-potential] {test_url} — param={param_name} "
                            f"baseline={base_time:.3f}s payload={elapsed:.3f}s (CWE-1333)"
                        )
                except asyncio.TimeoutError:
                    results.append(
                        f"[redos-timeout] {url} — param={param_name} payload={payload[:40]}... timed out (CWE-1333)"
                    )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue
        return results

    probe_results = await asyncio.gather(
        *[_probe_redos(u) for u in param_urls], return_exceptions=True
    )
    for pr in probe_results:
        if isinstance(pr, list):
            findings.extend(pr)
    if not findings:
        findings.append("[redos] No ReDoS candidates detected (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"192-REDOS: {len(findings)} findings -> {out}")
    return {"192-REDOS": str(out), "count": len(findings)}
