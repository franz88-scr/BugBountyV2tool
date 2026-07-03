"""Pipeline executor: runs phases stage-by-stage with state management."""
from __future__ import annotations
import argparse
import asyncio
import inspect
import json
import os
import sys
import shutil
import signal
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Set

from reconchain.config import PipelineConfig, FAST_PHASES
from reconchain.phases import (
    STAGES, _RECON_LEVELS, PIPELINE as _PIPELINE,
    _SCOPE_FILE, _SCOPE_PATTERNS, PhaseSet,
)
from reconchain.process import (
    _JOB_SEM, _PIPELINE_CFG, _TOOL_RC_REGISTRY,
    _USE_PROXYCHAINS, _cleanup_child_procs, _csv_from_phases,
    _domain_arg, _maybe_timeout, _atomic_write_json, _update_nuclei_templates,
    _run, _parse_phase_csv,
)
from reconchain.reporting import (
    _counts, write_summary, write_html, write_markdown, write_full_summary,
)
from reconchain.tools import Tools
from reconchain.utils import (
    Progress, ScanStatus, ensure, log, read_lines,
    _is_valid_hostname, _auto_detect_cookies, _auto_detect_proxy,
    _set_proxy_env, _downsample_file, _patch_socks, _socks_patched,
)
from reconchain.interactsh import Interactsh
from reconchain.dedup import DedupEngine
from reconchain.monitor import MonitorEngine


async def run_pipeline(args: argparse.Namespace) -> int:
    _TOOL_RC_REGISTRY.clear()
    import reconchain.process as _proc_mod
    _proc_mod._CLEANUP_DONE = False
    outdir = Path(args.out).resolve()
    if outdir.exists() and not outdir.is_dir():
        raise ValueError(f"output path exists and is not a directory: {outdir}")
    outdir.mkdir(parents=True, exist_ok=True)
    for tmp in outdir.glob("*.tmp"):
        tmp.unlink(missing_ok=True)
    for tmp in outdir.glob("*.ds_tmp"):
        tmp.unlink(missing_ok=True)
    import urllib.parse
    state_path = outdir / "state.json"
    state: Dict[str, Any] = {
        "domain": args.domain,
        "artifacts": {},
        "missing_tools": [],
        "tool_failures": {},
    }
    if args.resume and state_path.exists():
        try:
            with state_path.open() as f:
                saved = json.load(f)
            if saved.get("domain") and saved.get("domain") != args.domain:
                log("warn", f"state.json is for domain {saved.get('domain')!r}, not {args.domain!r}; ignoring and starting fresh")
            else:
                prev_outdir_s = saved.get("outdir")
                prev_outdir = Path(prev_outdir_s) if prev_outdir_s else None
                rebased: Dict[str, Any] = {}
                for k, v in (saved.get("artifacts") or {}).items():
                    if not isinstance(v, str):
                        continue
                    p = Path(v)
                    if p.is_absolute() and prev_outdir is not None:
                        try:
                            p = p.relative_to(prev_outdir)
                        except ValueError:
                            pass
                        rebased[k] = str(outdir / p)
                    elif p.is_absolute():
                        rebased[k] = v
                    else:
                        rebased[k] = str(outdir / p)
                saved["artifacts"] = rebased
                state = saved
                log("info", f"resuming from {state_path}")
        except json.JSONDecodeError:
            log("warn", f"{state_path} corrupt; ignoring and starting fresh")
    state["outdir"] = str(outdir)
    t = Tools()
    scan_status = ScanStatus(args.domain, outdir)
    only = _csv_from_phases(args.only)
    skip = _csv_from_phases(args.skip)
    if args.fast and not only:
        only = FAST_PHASES
    if only and skip:
        overlap = sorted(only & skip)
        if overlap:
            raise ValueError(f"phase(s) cannot be both --only and --skip: {', '.join(overlap)}")
    for m in list(state.get("missing_tools", [])):
        if shutil.which(m):
            state["missing_tools"].remove(m)
        else:
            t.seed_missing([m])
    global _JOB_SEM, _PIPELINE_CFG, _USE_PROXYCHAINS

    proxy = getattr(args, 'proxy', '')
    if not proxy:
        proxy = _auto_detect_proxy()
    if proxy:
        _set_proxy_env(proxy)
    _USE_PROXYCHAINS = bool(proxy and shutil.which("proxychains4") and proxy.startswith("socks"))
    if proxy and proxy.startswith(("socks4://", "socks5://", "socks5h://", "socks4a://")):
        _patch_socks(proxy)
    if proxy:
        import socket as _proxy_socket
        try:
            _parsed = urllib.parse.urlparse(proxy)
            _proxy_host = _parsed.hostname
            _proxy_port = _parsed.port
            if not _proxy_host:
                _proxy_url = proxy.split("://")[-1]
                _proxy_host = _proxy_url.split(":")[0]
                _proxy_port = int(_proxy_url.split(":")[1].split("/")[0])
            elif not _proxy_port:
                _default_ports = {"http": 80, "https": 443, "socks4": 1080, "socks5": 1080, "socks5h": 1080, "socks4a": 1080}
                _proxy_port = _default_ports.get(_parsed.scheme, 1080)
            _s = _proxy_socket.create_connection((_proxy_host, _proxy_port), timeout=3)
            _s.close()
        except Exception:
            log("warn", f"Proxy {proxy} unreachable — disabling proxy")
            proxy = ""
            _set_proxy_env("")
            _USE_PROXYCHAINS = False

    cookie = getattr(args, 'cookie', '')
    if not cookie:
        cookie = _auto_detect_cookies()

    rate_limit = getattr(args, 'rate_limit', 0)
    _PIPELINE_CFG = PipelineConfig(
        sqlmap_level=getattr(args, 'sqlmap_level', 1),
        sqlmap_risk=getattr(args, 'sqlmap_risk', 1),
        delay=getattr(args, 'delay', 0.0),
        rate_limit=rate_limit,
        sample_urls_fuzz=getattr(args, 'sample_urls_fuzz', 200),
        sample_urls_params=getattr(args, 'sample_urls_params', 50),
        sample_hosts_ssl=getattr(args, 'sample_hosts_ssl', 10),
        sample_hosts_origin=getattr(args, 'sample_hosts_origin', 10),
        sample_endpoints_l=getattr(args, 'sample_endpoints_l', 20),
        sample_urls_xss_blind=getattr(args, 'sample_urls_xss_blind', 20),
        sample_urls_ssti=getattr(args, 'sample_urls_ssti', 5),
        sample_endpoints_post=getattr(args, 'sample_endpoints_post', 5),
        sample_endpoints_cors=getattr(args, 'sample_endpoints_cors', 10),
        nuclei_exclude_tags=getattr(args, 'exclude_tags', ''),
        proxy=proxy,
        sample_urls_nosqli=getattr(args, 'sample_urls_nosqli', 30),
        sample_endpoints_race=getattr(args, 'sample_endpoints_race', 10),
        sample_hosts_jwt=getattr(args, 'sample_hosts_jwt', 20),
        sample_urls_xxe=getattr(args, 'sample_urls_xxe', 10),
        sample_urls_cmdi=getattr(args, 'sample_urls_cmdi', 30),
        sample_endpoints_sspp=getattr(args, 'sample_endpoints_sspp', 10),
        sample_hosts_cached=getattr(args, 'sample_hosts_cached', 10),
        sample_urls_depcheck=getattr(args, 'sample_urls_depcheck', 30),
    )
    jobs = max(1, args.jobs)
    _JOB_SEM = asyncio.Semaphore(jobs)
    oast = Interactsh(outdir)
    oast_started = False
    # Enhancement modules
    _dedup_engine = DedupEngine(outdir / "dedup_state.json")
    _monitor = MonitorEngine()
    _pipeline = getattr(sys.modules.get('reconchain'), 'PIPELINE', None) or _PIPELINE
    phase_map = {name: fn for name, fn, _ in _pipeline}

    def _selected(name: str) -> bool:
        return (not only or name in only) and name not in skip

    phases_to_run = [name for name, _, _ in _pipeline if _selected(name)]
    progress = Progress(phases_to_run, stages=STAGES)
    scan_status.set_total(len(phases_to_run))
    active_needs_oast = any(name in {"08-FUZZ", "09-VULNSCAN", "10-TLSCMS", "11-INJECT"} for name in phases_to_run)
    h_selected = _selected("13-OOB")
    if active_needs_oast and h_selected:
        oast_started = await oast.start()

    def _apply(name: str, result: Dict[str, Any]) -> None:
        prev.update(result or {})
        state["artifacts"].update({k: v for k, v in (result or {}).items() if not isinstance(v, str) or Path(v).exists()})
        for m in t.missing:
            if m not in state["missing_tools"]:
                state["missing_tools"].append(m)
        new_failures = (result or {}).get("failures") or {}
        if isinstance(new_failures, dict):
            state.setdefault("tool_failures", {}).update({k: int(v) for k, v in new_failures.items()})
        state.setdefault("tool_failures", {}).update(
            {k: int(v) for k, v in _TOOL_RC_REGISTRY.items() if k not in state.setdefault("tool_failures", {})}
        )

    if cookie:
        os.environ["COOKIE"] = cookie
    elif "COOKIE" in os.environ:
        del os.environ["COOKIE"]
    extra_hdrs = list(getattr(args, 'extra_headers', []))
    if extra_hdrs:
        os.environ["EXTRA_HEADERS"] = "\n".join(extra_hdrs)
    elif "EXTRA_HEADERS" in os.environ:
        del os.environ["EXTRA_HEADERS"]

    phase_timing: Dict[str, Dict[str, str]] = {}

    async def _run_phase(name: str) -> Dict[str, Any]:
        fn = phase_map[name]
        kwargs = {
            "domain": args.domain,
            "outdir": outdir,
            "t": t,
            "only": only,
            "skip": skip,
            "prev": prev,
            "oast_domain": oast.domain,
            "oast": oast,
            "resume": bool(args.resume),
            "force": bool(getattr(args, 'force', False)),
        }
        sig = inspect.signature(fn)
        call = {k: v for k, v in kwargs.items() if k in sig.parameters}
        scan_status.set_phase(name)
        scan_status.add_running(name)
        t0 = datetime.now()
        try:
            result = await fn(**call)
        except Exception as e:
            log("err", f"phase {name} crashed: {e}")
            scan_status.add_error(str(e))
            result = {}
        t1 = datetime.now()
        elapsed = (t1 - t0).total_seconds()
        phase_timing[name] = {
            "start": t0.isoformat(timespec="seconds"),
            "end": t1.isoformat(timespec="seconds"),
            "elapsed_seconds": round(elapsed, 1),
        }
        scan_status.add_completed(name)
        scan_status.set_missing(state.get("missing_tools", []))
        progress.next(name)
        return result or {}

    _shutdown_requested = False
    def _signal_handler(sig, frame):
        nonlocal _shutdown_requested
        if _shutdown_requested:
            os._exit(128 + sig)
        _shutdown_requested = True
        _cleanup_child_procs()
        raise SystemExit(128 + sig)
    _orig_sigint = signal.signal(signal.SIGINT, _signal_handler)
    _orig_sigterm = signal.signal(signal.SIGTERM, _signal_handler)

    try:
        _NUCLEI_PHASES = {"04-SCAN", "06-JSINTEL", "09-VULNSCAN", "10-TLSCMS"}
        if any(p in _NUCLEI_PHASES for p in phases_to_run):
            try:
                await _update_nuclei_templates(outdir)
            except Exception as _nuc_exc:
                log("warn", f"nuclei template update failed: {_nuc_exc}")

        prev: Dict[str, Any] = dict(state.get("artifacts", {}))
        waf_file = outdir / "waf_detection.txt"
        if waf_file.exists():
            waf_lines = read_lines(waf_file)
            _PIPELINE_CFG.waf_detected = any("detected" in l.lower() and "no waf" not in l.lower() for l in waf_lines)
            if _PIPELINE_CFG.waf_detected:
                _PIPELINE_CFG.waf_evasion_throttle = 1.0
        for stage in STAGES:
            run_now = [name for name in stage if _selected(name)]
            for name in stage:
                if name in skip:
                    log("skip", f"phase {name} (--skip)")
                elif only and name not in only:
                    log("skip", f"phase {name} (not in --only)")
            if not run_now:
                continue
            tasks = {n: asyncio.ensure_future(_run_phase(n)) for n in run_now}
            _stage_timeout = 7200 * 3 if _USE_PROXYCHAINS else 7200
            done, pending = await asyncio.wait(list(tasks.values()), timeout=_stage_timeout)
            if pending:
                log("warn", f"stage {stage}: {len(pending)} phase(s) timed out after {_stage_timeout}s; collecting partial results")
            results = {}
            for n, task in tasks.items():
                if task in done:
                    try:
                        results[n] = task.result()
                    except asyncio.CancelledError:
                        results[n] = {}
                    except Exception as e:
                        log("err", f"phase {n} crashed: {e}")
                        results[n] = {}
                else:
                    task.cancel()
                    results[n] = {}
            for name in run_now:
                _apply(name, results[name])
                if getattr(args, 'sample', False):
                    for k, v in (results[name] or {}).items():
                        if isinstance(v, str) and v.endswith(".txt"):
                            _downsample_file(Path(v), n=1)
            try:
                _atomic_write_json(state_path, state)
            except Exception as e:
                log("warn", f"state.json write failed: {e}")
    finally:
        _cleanup_child_procs()
        signal.signal(signal.SIGINT, _orig_sigint)
        signal.signal(signal.SIGTERM, _orig_sigterm)
        if oast_started:
            oast.stop()
        _JOB_SEM = None
        scan_status.close()
        _dedup_engine.save()
        _monitor.record_scan(args.domain)
        due = _monitor.due_scans()
        if due:
            log("info", f"Monitor: {len(due)} scan(s) due, starting...")
            await asyncio.to_thread(_monitor.run_due_scans)
        counts = _counts(outdir)
        if t.has("gowitness"):
            try:
                gowitness_targets = outdir / "host_targets.txt"
                if gowitness_targets.exists() and read_lines(gowitness_targets):
                    screenshots_dir = ensure(outdir / "screenshots")
                    _gw_proxy = []
                    if _PIPELINE_CFG.proxy:
                        _gw_proxy = ["--proxy", _PIPELINE_CFG.proxy]
                    await _run("gowitness", ["gowitness", "scan", "file", "-f", str(gowitness_targets), "-s", str(screenshots_dir), "--write-none"] + _gw_proxy, _maybe_timeout(600), outdir)
                    n_screenshots = len(list(screenshots_dir.glob("*.png"))) if screenshots_dir.exists() else 0
                    if n_screenshots:
                        log("ok", f"gowitness: {n_screenshots} screenshots → {screenshots_dir}")
            except Exception as _gw_exc:
                log("warn", f"gowitness failed: {_gw_exc}")
        try:
            sj = write_summary(outdir, args.domain, state, counts)
            if sj.exists():
                try:
                    with sj.open() as f:
                        summ = json.load(f)
                    summ["phase_timing"] = phase_timing
                    _atomic_write_json(sj, summ)
                except Exception:
                    pass
            hj = write_html(outdir, args.domain, counts, t.missing)
            mj = write_markdown(outdir, args.domain, counts, t.missing)
            tj = write_full_summary(outdir, args.domain, counts, t.missing)
            log("ok", f"summary → {sj}")
            log("ok", f"report  → {hj}")
            log("ok", f"report  → {mj}")
            log("ok", f"details → {tj}")
        except Exception as _rep_exc:
            log("warn", f"report generation failed: {_rep_exc}")
        progress.close()
    return 0
