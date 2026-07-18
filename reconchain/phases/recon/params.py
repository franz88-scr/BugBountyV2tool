"""Phase 07: parameter discovery."""
from reconchain.phases.helpers import *


async def phase_07_PARAMS(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"07-PARAMS"}:
        return {}
    if only and "07-PARAMS" not in only:
        return {}
    _d_out = outdir / "params.txt"
    if _d_out.exists() and not force:
        return {"07-PARAMS": str(_d_out), "count": count_nonblank(_d_out)}
    log("info", "Phase 07-PARAMS: parameter discovery")
    for old in outdir.glob("params_*.txt"):
        if old.name != "params.txt":
            old.unlink(missing_ok=True)
    if force:
        (outdir / "params_arjun.json").unlink(missing_ok=True)
    urls = outdir / "urls_all.txt"
    if not urls.exists() or not read_lines(urls):
        log("warn", "07-PARAMS: no URLs; skipping")
        return {"07-PARAMS": str(outdir / "params.txt"), "count": 0}
    _d_urls = _dedupe_by_host_path(read_lines(urls))
    jobs: List[Tuple[str, List[str], int]] = []
    arjun_had_input = False
    if t.has("arjun"):
        arjun_in = ensure(outdir / "urls_arjun_sample.txt")
        waf_detected = _PIPELINE_CFG.waf_detected
        sample_size = min(_PIPELINE_CFG.sample_urls_params, _PIPELINE_CFG.sample_urls_arjun_waf) if waf_detected else _PIPELINE_CFG.sample_urls_params
        arjun_urls = _d_urls[:sample_size]
        if arjun_urls:
            arjun_had_input = True
            arjun_in.write_text("\n".join(arjun_urls) + "\n")
            _arjun_parts = [
                "arjun", "-i", str(arjun_in), "-o", str(outdir / "params_arjun.json"),
                "-T", "60", "--rate-limit", "50",
                "--disable-redirects",
            ]
            _arjun_headers = _extra_headers_dict()
            if _arjun_headers:
                _arjun_parts += ["--headers", "\n".join(f"{k}: {v}" for k, v in _arjun_headers.items())]
            timeout = _maybe_timeout(600) if waf_detected else _maybe_timeout(1800)
            _arjun_broken = False
            try:
                _arjun_ver = subprocess.run(["arjun", "--version"], capture_output=True, text=True, timeout=10)
                if "2.2.7" in _arjun_ver.stdout:
                    log("warn", "arjun 2.2.7 has a known bug on Python 3.12 (AttributeError: 'dict' object has no attribute 'status_code'); consider pinning to 2.2.6 with: pip install arjun==2.2.6")
                    _arjun_broken = True
            except Exception:
                pass
            if not _arjun_broken:
                jobs.append(("arjun", _arjun_parts, timeout))
            else:
                log("warn", "07-PARAMS: skipping arjun due to known bug in installed version")
            if waf_detected and sample_size < _PIPELINE_CFG.sample_urls_params:
                log("info", f"07-PARAMS: WAF detected, reduced arjun sample to {sample_size} URLs with {timeout}s timeout")
    if jobs:
        await run_parallel(jobs, outdir)
    raw = outdir / "params_arjun.json"
    if raw.exists():
        norm = raw.with_suffix(".txt")
        urls_found: List[str] = []
        data = None
        try:
            data = json.loads(raw.read_text(encoding="utf-8", errors="ignore"))
        except json.JSONDecodeError:
            data = None
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(k, str) and (k.startswith("http://") or k.startswith("https://")):
                    urls_found.append(k)
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and isinstance(item.get("url"), str):
                    urls_found.append(item["url"])
        if not urls_found:
            for rec in read_jsonl(raw):
                if isinstance(rec, dict) and rec.get("url"):
                    urls_found.append(str(rec["url"]))
        if not urls_found:
            reason = "likely blocked by WAF" if _PIPELINE_CFG.waf_detected else "arjun produced no results"
            log("warn", f"07-PARAMS: {reason}")
        ensure(norm).write_text("\n".join(urls_found) + ("\n" if urls_found else ""))
    elif arjun_had_input:
        log("warn", "07-PARAMS: arjun produced no output file; retrying with smaller sample")
        retry_sample = arjun_urls[:3]
        if retry_sample:
            retry_in = ensure(outdir / "urls_arjun_retry.txt")
            retry_in.write_text("\n".join(retry_sample) + "\n")
            retry_parts = [
                "arjun", "-i", str(retry_in), "-o", str(outdir / "params_arjun.json"),
                "-T", "120", "--rate-limit", "50", "--disable-redirects",
            ]
            await run_parallel([("arjun-retry", retry_parts, _maybe_timeout(900))], outdir)
            if not (outdir / "params_arjun.json").exists():
                log("warn", "07-PARAMS: arjun retry also produced no output file")
    parts = sorted(p for p in outdir.glob("params_*.txt") if p.name != "params.txt")
    n = merge_unique(parts, outdir / "params.txt")
    return {"07-PARAMS": str(outdir / "params.txt"), "count": n}
