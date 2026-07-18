"""Pipeline executor: runs phases stage-by-stage with state management."""
from __future__ import annotations

import argparse
import asyncio
import atexit
import contextlib
import inspect
import json
import os
import shutil
import signal
import socket
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Set

from reconchain.config import DOS_PHASES, FAST_PHASES, PipelineConfig
from reconchain.dedup import DedupEngine
from reconchain.events import bus
from reconchain.interactsh import Interactsh
from reconchain.monitor import MonitorEngine
from reconchain.phases import (
    PHASE_DEPS,
)
from reconchain.phases import (
    PIPELINE as _PIPELINE,
)
from reconchain.process import (
    _TOOL_RC_REGISTRY,
    MAX_OS_PROCS,
    _atomic_write_json,
    _cleanup_child_procs,
    _csv_from_phases,
    _maybe_timeout,
    _pop_phase_proxy,
    _push_phase_proxy,
    _run,
    _update_nuclei_templates,
)
from reconchain.reporting import (
    _counts,
    _coverage,
    write_faraday,
    write_full_summary,
    write_html,
    write_html_dashboard,
    write_markdown,
    write_sarif,
    write_summary,
)
from reconchain.resource_monitor import (
    AdaptiveSemaphore,
    AdaptiveThreadSemaphore,
    get_resource_monitor,
)
from reconchain.tools import Tools
from reconchain.utils import (
    Progress,
    ScanStatus,
    _auto_detect_cookies,
    _downsample_file,
    _validate_cookie,
    ensure,
    log,
    read_lines,
)
from reconchain.verify import filter_outputs


def _snapshot_findings(outdir: Path) -> Dict[str, Set[str]]:
    """Snapshot all .txt files in outdir for incremental diff comparison.

    Uses streaming reads to avoid loading entire files into memory.
    """
    snapshot: Dict[str, Set[str]] = {}
    for fp in outdir.glob("*.txt"):
        if fp.name.startswith("."):
            continue
        lines: Set[str] = set()
        try:
            with fp.open(encoding="utf-8", errors="ignore") as f:
                for ln in f:
                    ln = ln.strip()
                    if ln and not ln.startswith("#"):
                        lines.add(ln)
        except OSError:
            continue
        if lines:
            snapshot[fp.name] = lines
    return snapshot


def _diff_findings(before: Dict[str, Set[str]], after: Dict[str, Set[str]], outdir: Path) -> None:
    """Compare before/after snapshots and write diff files."""
    diff_dir = ensure(outdir / "diff")
    total_new = 0
    for fname, new_lines in sorted(after.items()):
        old_lines = before.get(fname, set())
        added = new_lines - old_lines
        if added:
            diff_path = diff_dir / f"new_{fname}"
            diff_path.write_text("\n".join(sorted(added)) + "\n")
            total_new += len(added)
            log("ok", f"diff: {len(added)} new entries in {fname}")
    if total_new:
        summary = diff_dir / "summary.txt"
        summary.write_text(f"New findings: {total_new}\n")
        log("ok", f"diff summary: {total_new} total new findings → {diff_dir}")
    else:
        log("info", "diff: no new findings since last scan")


def _preflight_memory_check(safe_mode: bool = False) -> None:
    """Abort early if system has too little RAM/swap for a scan."""
    try:
        import psutil
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        avail_gb = mem.available / (1024 ** 3)
        total_ram_gb = mem.total / (1024 ** 3)
        swap_total_gb = swap.total / (1024 ** 3)
        swap_free_gb = (swap.total - swap.used) / (1024 ** 3)

        log("info", f"Preflight: RAM {total_ram_gb:.1f} GB total, {avail_gb:.1f} GB free | "
            f"Swap {swap_total_gb:.1f} GB total, {swap_free_gb:.1f} GB free")

        min_ram = 1.0 if safe_mode else 2.0
        min_total = 4.0 if safe_mode else 8.0
        min_swap = 0.5

        if total_ram_gb < min_total:
            from reconchain.exceptions import InsufficientResourcesError
            msg = (f"System has only {total_ram_gb:.1f} GB RAM (minimum {min_total:.0f} GB). "
                   f"A full scan will likely freeze the VM. Aborting.")
            log("err", msg)
            raise InsufficientResourcesError(msg)

        if avail_gb < min_ram:
            msg = (f"Only {avail_gb:.1f} GB RAM available (minimum {min_ram:.0f} GB). "
                   f"Close other applications and retry.")
            log("err", msg)
            raise SystemExit(1)

        if swap_total_gb > 0 and swap_free_gb < min_swap:
            log("warn", f"Swap is nearly full ({swap_free_gb:.1f} GB free). "
                "Heavy swapping can cause the VM to freeze.")

        if avail_gb < 3.0 and not safe_mode:
            log("warn", f"Low available RAM ({avail_gb:.1f} GB). "
                "Consider running with --safe for a lighter scan.")
    except ImportError:
        log("warn", "psutil not installed; skipping preflight memory check")


async def run_pipeline(args: argparse.Namespace) -> int:
    from reconchain.process import reset_globals
    reset_globals()
    _TOOL_RC_REGISTRY.clear()

    # Load plugins if enabled
    if not getattr(args, 'no_plugins', False):
        try:
            from pathlib import Path as _P

            from reconchain.plugin import discover_plugins, register_plugin_to_pipeline
            dirs = []
            plugins_dir = getattr(args, 'plugins_dir', '')
            if plugins_dir:
                dirs.append(_P(plugins_dir))
            plugins = discover_plugins(dirs) if dirs else []
            if plugins:
                register_plugin_to_pipeline(plugins)
                log("info", f"Loaded {len(plugins)} plugin(s)")
        except Exception as _plug_exc:
            log("warn", f"plugin loading failed: {_plug_exc}")
    import reconchain.process as _proc_mod
    with _proc_mod._SPAWNED_PIDS_LOCK:
        _proc_mod._SPAWNED_PIDS.clear()
    _safe_mode = getattr(args, 'safe', False)
    _preflight_memory_check(safe_mode=_safe_mode)
    _t_pipeline_start = time.monotonic()
    def _debug_ts(msg: str) -> None:
        elapsed = time.monotonic() - _t_pipeline_start
        log("debug", f"[+{elapsed:.1f}s] {msg}")
    _debug_ts("pipeline starting")
    outdir = Path(args.out).resolve()
    if outdir.exists() and not outdir.is_dir():
        from reconchain.exceptions import OutputPathError
        raise OutputPathError(f"output path exists and is not a directory: {outdir}")
    outdir.mkdir(parents=True, exist_ok=True)
    # Audit logging: record scan initiation
    try:
        from reconchain.audit import init_audit_log, log_event as _audit
        init_audit_log(outdir)
        _audit("scan_start", domain=args.domain, detail={
            "out": str(outdir),
            "safe_mode": getattr(args, 'safe', False),
            "only": sorted(getattr(args, 'only', set())),
            "skip": sorted(getattr(args, 'skip', set())),
        })
    except Exception:
        pass  # best-effort
    for tmp in outdir.glob("*.tmp"):
        tmp.unlink(missing_ok=True)
    for tmp in outdir.glob("*.ds_tmp"):
        tmp.unlink(missing_ok=True)
    # Incremental mode: snapshot before scan
    incremental = getattr(args, 'incremental', False)
    _pre_scan_snapshot: Dict[str, Set[str]] = {}
    if incremental and any(outdir.glob("*.txt")):
        _pre_scan_snapshot = _snapshot_findings(outdir)
        log("info", f"Incremental mode: captured {len(_pre_scan_snapshot)} files for diff")
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
                    # Validate rebased path stays within outdir
                    resolved = Path(rebased[k]).resolve()
                    outdir_resolved = outdir.resolve()
                    if not resolved.is_relative_to(outdir_resolved):
                        log("warn", f"state.json artifact path escapes outdir, skipping: {rebased[k]}")
                        rebased[k] = str(outdir / Path(v).name)
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
    profile = getattr(args, 'profile', '')
    if profile == "quick":
        from reconchain.config import QUICK_SKIP_PHASES
        skip = skip | QUICK_SKIP_PHASES
        log("info", f"Profile 'quick': skipping {len(QUICK_SKIP_PHASES)} redundant/low-signal phases")
    dos_mode = getattr(args, 'dos_mode', False)
    if not dos_mode:
        skip = skip | DOS_PHASES
    # If --only is set, remove any profile/DOS skips that conflict (--only takes priority)
    if only:
        skip = skip - only
    for m in list(state.get("missing_tools", [])):
        if shutil.which(m):
            state["missing_tools"].remove(m)
        else:
            t.seed_missing([m])
    global _JOB_SEM

    # --- Concurrency setup: adaptive (ramp-up) or static ---
    jobs = max(1, args.jobs)
    # Sequential mode: force jobs=1 when --no-parallel is set
    if os.environ.get("RECONCHAIN_SEQUENTIAL") == "1":
        jobs = 1
        log("info", "Sequential mode: phases run one at a time")
    _adaptive_enabled = getattr(args, 'adaptive', True)
    _adaptive_start = getattr(args, 'adaptive_start', 2)
    _adaptive_max = getattr(args, 'adaptive_max', 0)
    _adaptive_interval = getattr(args, 'adaptive_interval', 5.0)
    _adaptive_cpu_high = getattr(args, 'adaptive_cpu_high', 80)
    _adaptive_ram_crit = getattr(args, 'adaptive_ram_crit', 1)

    _adaptive_max_procs = getattr(args, 'adaptive_max_procs', 0)

    # --safe mode: very conservative defaults for VMs / low-resource systems
    _safe_mode = getattr(args, 'safe', False)
    if _safe_mode:
        jobs = 1
        _adaptive_start = max(_adaptive_start, 1)
        _adaptive_max = min(_adaptive_max if _adaptive_max > 0 else 999, 4)
        _adaptive_max_procs = min(_adaptive_max_procs if _adaptive_max_procs > 0 else 999, 2)
        _adaptive_cpu_high = min(_adaptive_cpu_high, 60)
        _adaptive_ram_crit = max(_adaptive_ram_crit, 2.0)
        log("info", f"Safe mode: phases={jobs}, start={_adaptive_start}, max={_adaptive_max}, max_procs={_adaptive_max_procs}")

    if _adaptive_enabled:
        _adaptive_sem = AdaptiveSemaphore(initial=_adaptive_start)
        _JOB_SEM = _adaptive_sem
        _proc_mod._JOB_SEM = _adaptive_sem
        _PHASE_SEM = asyncio.Semaphore(jobs)

        _resmon = get_resource_monitor(
            initial=_adaptive_start,
            max_limit=_adaptive_max if _adaptive_max > 0 else None,
            interval=_adaptive_interval,
            cpu_high=float(_adaptive_cpu_high),
            ram_crit_bytes=int(_adaptive_ram_crit * 1024 * 1024 * 1024),
            max_os_procs=_adaptive_max_procs if _adaptive_max_procs > 0 else None,
        )
        _resmon.bind(_adaptive_sem, os_sem=_proc_mod._OS_PROC_SEM)
        _resmon.start()
        log("info", f"ResourceMonitor started: initial={_adaptive_start}, max={_resmon._max_limit}, os_procs={MAX_OS_PROCS}, interval={_adaptive_interval}s")
        # Safe mode: immediately cap OS process semaphore to safe limit
        if _safe_mode:
            _proc_mod._OS_PROC_SEM.resize(_adaptive_max_procs)
    else:
        max_procs = getattr(args, 'max_procs', 0) or 0
        if max_procs <= 0:
            max_procs = MAX_OS_PROCS
        _JOB_SEM = asyncio.Semaphore(max_procs)
        _proc_mod._JOB_SEM = _JOB_SEM
        _PHASE_SEM = asyncio.Semaphore(jobs)
        _proc_mod._OS_PROC_SEM = AdaptiveThreadSemaphore(max_procs)
        _resmon = None
        log("info", f"Static concurrency: {max_procs} procs, {jobs} phases")

    cookie = getattr(args, 'cookie', '')
    if not cookie:
        _outdir_hint = Path(args.out).resolve() if getattr(args, 'out', '') else None
        cookie = _auto_detect_cookies(_outdir_hint, fix_permissions=not getattr(args, 'no_fix_permissions', False))
    if cookie:
        # Sanitize: strip newlines, null bytes, and leading '--' fragments that
        # could inject CLI arguments when cookies are passed via --cookie.
        cookie = _validate_cookie(cookie)
        cookie = cookie.replace("\n", " ").replace("\r", "").replace("\x00", "")

    # Proxy configuration
    proxy = getattr(args, 'proxy', '')
    vuln_proxy = getattr(args, 'vuln_proxy', '') or proxy
    if not vuln_proxy and shutil.which("proxychains4"):
        try:
            _tor_sock = socket.create_connection(("127.0.0.1", 9050), timeout=2)
            _tor_sock.close()
            vuln_proxy = "socks5://127.0.0.1:9050"
            log("info", "Tor detected on 127.0.0.1:9050 — auto-enabling --vuln-proxy for vulnerability probing phases")
        except Exception:
            pass
    proxy_timeout_mult = getattr(args, 'proxy_timeout_multiplier', 1.5)

    rate_limit = getattr(args, 'rate_limit', 0)

    # Safe mode: inject defaults for delay/rate_limit if user didn't set them
    if _safe_mode:
        if not getattr(args, 'delay', None):
            args.delay = 0.3
        if not rate_limit:
            rate_limit = 10

    # Update the EXISTING _PIPELINE_CFG in process module (not replace it)
    # so that reconchain/phases/ (which did `from process import _PIPELINE_CFG`) sees the changes.
    import dataclasses

    def _ss(val: int) -> int:
        """Apply sample size mode: minimal=1, normal=default, all=sys.maxsize, safe_mode halves."""
        mode = getattr(args, 'sample_mode', 'normal')
        if mode == 'minimal':
            return 1
        if mode == 'all':
            return sys.maxsize
        return max(1, val // 2) if _safe_mode else val

    _new_cfg = PipelineConfig(
        safe_mode=_safe_mode,
        dos_mode=dos_mode,
        sqlmap_level=getattr(args, 'sqlmap_level', 1),
        sqlmap_risk=getattr(args, 'sqlmap_risk', 1),
        delay=getattr(args, 'delay', 0.0),
        rate_limit=rate_limit,
        sample_urls_fuzz=_ss(getattr(args, 'sample_urls_fuzz', 200)),
        sample_urls_params=_ss(getattr(args, 'sample_urls_params', 50)),
        sample_hosts_ssl=_ss(getattr(args, 'sample_hosts_ssl', 10)),
        sample_hosts_origin=_ss(getattr(args, 'sample_hosts_origin', 10)),
        sample_endpoints_l=_ss(getattr(args, 'sample_endpoints_l', 20)),
        sample_urls_xss_blind=_ss(getattr(args, 'sample_urls_xss_blind', 20)),
        sample_urls_ssti=_ss(getattr(args, 'sample_urls_ssti', 5)),
        sample_endpoints_post=_ss(getattr(args, 'sample_endpoints_post', 5)),
        sample_endpoints_cors=_ss(getattr(args, 'sample_endpoints_cors', 10)),
        nuclei_exclude_tags=(
            (getattr(args, 'exclude_tags', '') + ',dos,brute-force,deep').strip(',')
            if _safe_mode and not getattr(args, 'exclude_tags', '')
            else getattr(args, 'exclude_tags', '')
        ),
        proxy=proxy,
        vuln_proxy=vuln_proxy,
        proxy_timeout_multiplier=proxy_timeout_mult,
        sample_urls_nosqli=_ss(getattr(args, 'sample_urls_nosqli', 30)),
        sample_endpoints_race=_ss(getattr(args, 'sample_endpoints_race', 10)),
        sample_hosts_jwt=_ss(getattr(args, 'sample_hosts_jwt', 20)),
        sample_urls_xxe=_ss(getattr(args, 'sample_urls_xxe', 10)),
        sample_urls_cmdi=_ss(getattr(args, 'sample_urls_cmdi', 30)),
        sample_endpoints_sspp=_ss(getattr(args, 'sample_endpoints_sspp', 10)),
        sample_hosts_cached=_ss(getattr(args, 'sample_hosts_cached', 10)),
        sample_urls_depcheck=_ss(getattr(args, 'sample_urls_depcheck', 30)),
        sample_urls_redirect=_ss(getattr(args, 'sample_urls_redirect', 30)),
        sample_hosts_clickjack=_ss(getattr(args, 'sample_hosts_clickjack', 20)),
        sample_urls_crlf=_ss(getattr(args, 'sample_urls_crlf', 20)),
        sample_hosts_ratelimit=_ss(getattr(args, 'sample_hosts_ratelimit', 10)),
        sample_endpoints_corsadv=_ss(getattr(args, 'sample_endpoints_corsadv', 10)),
        sample_hosts_jwtadv=_ss(getattr(args, 'sample_hosts_jwtadv', 20)),
        sample_urls_upload=_ss(getattr(args, 'sample_urls_upload', 10)),
        sample_hosts_smuggle=_ss(getattr(args, 'sample_hosts_smuggle', 10)),
        sample_hosts_h2smuggle=_ss(getattr(args, 'sample_hosts_h2smuggle', 10)),
        sample_hosts_frameworks=_ss(getattr(args, 'sample_hosts_frameworks', 20)),
        sample_urls_domxss=_ss(getattr(args, 'sample_urls_domxss', 30)),
        sample_urls_ldap=_ss(getattr(args, 'sample_urls_ldap', 20)),
        sample_endpoints_deserial=_ss(getattr(args, 'sample_endpoints_deserial', 10)),
        sample_endpoints_oauth=_ss(getattr(args, 'sample_endpoints_oauth', 10)),
        sample_endpoints_pwreset=_ss(getattr(args, 'sample_endpoints_pwreset', 10)),
        sample_hosts_websocket=_ss(getattr(args, 'sample_hosts_websocket', 10)),
        sample_urls_lfi=_ss(getattr(args, 'sample_urls_lfi', 30)),
        sample_urls_idor=_ss(getattr(args, 'sample_urls_idor', 50)),
        sample_urls_apisec=_ss(getattr(args, 'sample_urls_apisec', 50)),
        sample_hosts_cloud=_ss(getattr(args, 'sample_hosts_cloud', 5)),
        sample_hosts_git=_ss(getattr(args, 'sample_hosts_git', 5)),
        sample_hosts_graphql=_ss(getattr(args, 'sample_hosts_graphql', 5)),
        sample_hosts_waf=_ss(getattr(args, 'sample_hosts_waf', 5)),
        sample_urls_arjun_waf=_ss(getattr(args, 'sample_urls_arjun_waf', 5)),
        sample_urls_csrf=_ss(getattr(args, 'sample_urls_csrf', 20)),
        sample_hosts_sessionfix=_ss(getattr(args, 'sample_hosts_sessionfix', 10)),
        sample_endpoints_saml=_ss(getattr(args, 'sample_endpoints_saml', 10)),
        sample_users_spray=_ss(getattr(args, 'sample_users_spray', 20)),
        sample_hosts_cookie=_ss(getattr(args, 'sample_hosts_cookie', 20)),
        sample_urls_posttest=_ss(getattr(args, 'sample_urls_posttest', 30)),
        sample_urls_methodoverride=_ss(getattr(args, 'sample_urls_methodoverride', 20)),
        sample_hosts_forcedbrowse=_ss(getattr(args, 'sample_hosts_forcedbrowse', 20)),
        sample_urls_casebypass=_ss(getattr(args, 'sample_urls_casebypass', 20)),
        sample_urls_apipage=_ss(getattr(args, 'sample_urls_apipage', 20)),
        sample_urls_tabnab=_ss(getattr(args, 'sample_urls_tabnab', 30)),
        sample_urls_apikeyleak=_ss(getattr(args, 'sample_urls_apikeyleak', 30)),
        sample_urls_redirabuse=_ss(getattr(args, 'sample_urls_redirabuse', 20)),
        sample_urls_logtrigger=_ss(getattr(args, 'sample_urls_logtrigger', 20)),
        sample_urls_xssstored=_ss(getattr(args, 'sample_urls_xssstored', 10)),
        sample_hosts_hostabuse=_ss(getattr(args, 'sample_hosts_hostabuse', 10)),
        sample_urls_authbypassadv=_ss(getattr(args, 'sample_urls_authbypassadv', 20)),
        sample_urls_ssi=_ss(getattr(args, 'sample_urls_ssi', 20)),
        sample_urls_jsoninject=_ss(getattr(args, 'sample_urls_jsoninject', 20)),
        sample_urls_nullbyte=_ss(getattr(args, 'sample_urls_nullbyte', 20)),
        sample_urls_doubleencod=_ss(getattr(args, 'sample_urls_doubleencod', 20)),
        sample_urls_unicode=_ss(getattr(args, 'sample_urls_unicode', 20)),
        sample_hosts_postmsg=_ss(getattr(args, 'sample_hosts_postmsg', 15)),
        sample_hosts_jsonp=_ss(getattr(args, 'sample_hosts_jsonp', 20)),
        sample_hosts_sri=_ss(getattr(args, 'sample_hosts_sri', 20)),
        sample_hosts_mixedcontent=_ss(getattr(args, 'sample_hosts_mixedcontent', 20)),
        sample_hosts_hstspreload=_ss(getattr(args, 'sample_hosts_hstspreload', 20)),
        sample_hosts_thirdpartyjs=_ss(getattr(args, 'sample_hosts_thirdpartyjs', 15)),
        sample_hosts_browserstorage=_ss(getattr(args, 'sample_hosts_browserstorage', 15)),
        sample_urls_rfi=_ss(getattr(args, 'sample_urls_rfi', 20)),
        sample_hosts_webdav=_ss(getattr(args, 'sample_hosts_webdav', 10)),
        sample_hosts_snmp=_ss(getattr(args, 'sample_hosts_snmp', 10)),
        sample_hosts_banner=_ss(getattr(args, 'sample_hosts_banner', 15)),
        sample_hosts_phpinfo=_ss(getattr(args, 'sample_hosts_phpinfo', 15)),
        sample_hosts_srvstatus=_ss(getattr(args, 'sample_hosts_srvstatus', 15)),
        sample_urls_errorleak=_ss(getattr(args, 'sample_urls_errorleak', 20)),
        sample_hosts_wildcarddns=_ss(getattr(args, 'sample_hosts_wildcarddns', 10)),
        sample_hosts_dnsrebind=_ss(getattr(args, 'sample_hosts_dnsrebind', 10)),
        sample_hosts_iisaspnet=_ss(getattr(args, 'sample_hosts_iisaspnet', 10)),
        sample_hosts_tomcat=_ss(getattr(args, 'sample_hosts_tomcat', 10)),
        sample_hosts_nodejs=_ss(getattr(args, 'sample_hosts_nodejs', 10)),
        sample_hosts_laravel=_ss(getattr(args, 'sample_hosts_laravel', 10)),
        sample_hosts_django=_ss(getattr(args, 'sample_hosts_django', 10)),
        sample_hosts_symfony=_ss(getattr(args, 'sample_hosts_symfony', 10)),
        sample_hosts_cicd=_ss(getattr(args, 'sample_hosts_cicd', 10)),
        sample_hosts_docker=_ss(getattr(args, 'sample_hosts_docker', 10)),
        sample_hosts_k8s=_ss(getattr(args, 'sample_hosts_k8s', 10)),
        sample_hosts_terraform=_ss(getattr(args, 'sample_hosts_terraform', 10)),
        sample_hosts_envdeep=_ss(getattr(args, 'sample_hosts_envdeep', 10)),
        sample_hosts_gqlabuse=_ss(getattr(args, 'sample_hosts_gqlabuse', 10)),
        sample_urls_apiversion=_ss(getattr(args, 'sample_urls_apiversion', 20)),
        sample_hosts_lbdetect=_ss(getattr(args, 'sample_hosts_lbdetect', 15)),
        sample_hosts_vhost=_ss(getattr(args, 'sample_hosts_vhost', 10)),
        sample_urls_ratelimitbypass=_ss(getattr(args, 'sample_urls_ratelimitbypass', 20)),
        cookie_b=getattr(args, 'cookie_b', ''),
        idor_session_a=getattr(args, 'cookie_a', ''),
        idor_session_b=getattr(args, 'cookie_b', ''),
    )
    # Copy every attribute to the existing object so all importers see the update
    for _f in dataclasses.fields(_new_cfg):
        setattr(_proc_mod._PIPELINE_CFG, _f.name, getattr(_new_cfg, _f.name))
    if _safe_mode:
        log("info", "Safe mode: sample sizes halved, delay=0.3s, rate_limit=10, "
            "nmap reduced (-T3), serial tool execution, memory limits reduced")
    oast = Interactsh(outdir)
    oast_started = False
    # Enhancement modules
    _dedup_engine = DedupEngine(outdir / "dedup_state.json")
    _monitor = MonitorEngine()

    # v3.0: Tool health monitor
    _tool_health = None
    try:
        from reconchain.tool_health import get_tool_health_monitor
        _tool_health = get_tool_health_monitor(outdir / "tool_health.json")
    except Exception:
        pass

    # v3.0: Target profiling (after initial recon phases run)
    _target_profile = None

    # v3.0: Learning engine for FP filtering
    _learning = None
    try:
        from reconchain.learning import LearningEngine
        _learning = LearningEngine(outdir / "fp_patterns.json")
    except Exception:
        pass

    _pipeline = getattr(sys.modules.get('reconchain'), 'PIPELINE', None) or _PIPELINE
    phase_map = {name: fn for name, fn, _ in _pipeline}

    def _selected(name: str) -> bool:
        return (not only or name in only) and name not in skip

    phases_to_run = [name for name, _, _ in _pipeline if _selected(name)]
    progress = Progress(phases_to_run)
    scan_status.set_total(len(phases_to_run))
    active_needs_oast = any(name in {"08-FUZZ", "09-VULNSCAN", "10-TLSCMS", "11-INJECT"} for name in phases_to_run)
    h_selected = _selected("13-OOB")
    if active_needs_oast and h_selected:
        _debug_ts("starting interactsh OOB server...")
        oast_started = await oast.start()
        _debug_ts(f"interactsh started={oast_started}")

    def _apply(name: str, result: Dict[str, Any]) -> None:
        prev.update(result or {})
        state["artifacts"].update({k: v for k, v in (result or {}).items() if not isinstance(v, str) or Path(v).exists()})
        # Emit finding events for new artifact files — read only tail (last 3 lines)
        for k, v in (result or {}).items():
            if isinstance(v, str) and v.endswith(".txt"):
                try:
                    _fpath = Path(v)
                    if _fpath.exists() and _fpath.stat().st_size > 0:
                        import collections
                        with _fpath.open("rb") as _f:
                            _tail = collections.deque(_f, maxlen=3)
                        for _raw in _tail:
                            _line = _raw.decode(errors="replace").strip()
                            if _line:
                                bus.emit("finding.new", {
                                    "text": _line,
                                    "phase": name,
                                    "source": k,
                                    "domain": args.domain,
                                })
                except Exception:
                    pass
        for m in t.missing:
            if m not in state["missing_tools"]:
                state["missing_tools"].append(m)
        new_failures = (result or {}).get("failures") or {}
        if isinstance(new_failures, dict):
            state.setdefault("tool_failures", {}).update({k: int(v) for k, v in new_failures.items()})
        state.setdefault("tool_failures", {}).update(
            {k: int(v) for k, v in _TOOL_RC_REGISTRY.items() if k not in state.setdefault("tool_failures", {})}
        )

    _cookie_file: Optional[Path] = None
    _cookie_atexit_token = None
    _cleanup_cookie_fn = None
    if cookie:
        import tempfile
        _fd, _cookie_path = tempfile.mkstemp(prefix=".reconchain_cookie_", suffix=".txt", dir=str(outdir))
        with os.fdopen(_fd, "w") as _cf:
            _cf.write(cookie)
        os.chmod(_cookie_path, 0o600)
        os.environ["COOKIE"] = cookie
        _cookie_file = Path(_cookie_path)
        _cookie_atexit_token = _cookie_file
        def _cleanup_cookie(p: Path = _cookie_atexit_token) -> None:
            p.unlink(missing_ok=True)
        _cleanup_cookie_fn = _cleanup_cookie
        atexit.register(_cleanup_cookie)
    elif "COOKIE" in os.environ:
        del os.environ["COOKIE"]
    # IDOR cross-session cookies
    _idor_a = getattr(args, 'cookie_a', '')
    _idor_b = getattr(args, 'cookie_b', '')
    if _idor_a:
        os.environ["COOKIE_A"] = _idor_a
    elif "COOKIE_A" in os.environ:
        del os.environ["COOKIE_A"]
    if _idor_b:
        os.environ["COOKIE_B"] = _idor_b
    elif "COOKIE_B" in os.environ:
        del os.environ["COOKIE_B"]
    extra_hdrs = list(getattr(args, 'extra_headers', []))
    if extra_hdrs:
        os.environ["EXTRA_HEADERS"] = "\n".join(extra_hdrs)
    elif "EXTRA_HEADERS" in os.environ:
        del os.environ["EXTRA_HEADERS"]

    phase_timing: Dict[str, Dict[str, str]] = {}
    _debug_ts(f"pipeline init complete, {len(phases_to_run)} phases selected")

    async def _run_phase(name: str) -> Dict[str, Any]:
        async with _PHASE_SEM:
            # BUG 9 FIX: Always call wait_if_paused() — removes TOCTOU race
            # where pause could be set between the check and the wait.
            if _resmon is not None:
                await _resmon.wait_if_paused()
            # v3.0: Smart gating — skip phases deemed unnecessary by target profile
            if _target_profile is not None and not _target_profile.should_run(name):
                _debug_ts(f"phase {name} skipped by target profile")
                progress.next(name)
                bus.emit("phase.skip", {"phase": name, "reason": "target_profile"})
                return {}
            # v3.0: Tool health — skip if tool has been auto-disabled
            if _tool_health is not None:
                _tool_name = name.split("-", 1)[-1].lower() if "-" in name else name.lower()
                if _tool_health.is_disabled(_tool_name):
                    _debug_ts(f"phase {name} skipped — tool {_tool_name} auto-disabled by health monitor")
                    progress.next(name)
                    return {}
            _debug_ts(f"phase {name} acquired semaphore, starting")
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
                "cfg": _proc_mod._PIPELINE_CFG,
            }
            sig = inspect.signature(fn)
            call = {k: v for k, v in kwargs.items() if k in sig.parameters}
            scan_status.set_phase(name)
            scan_status.add_running(name)
            t0 = datetime.now()
            bus.emit("phase.start", {"phase": name, "ts": time.time()})
            result: Dict[str, Any] = {}
            await _push_phase_proxy(name, proxy, vuln_proxy)
            try:
                result = await fn(**call)
            except asyncio.CancelledError:
                log("warn", f"phase {name} cancelled")
                raise
            except Exception as e:
                log("err", f"phase {name} crashed: {e}")
                scan_status.add_error(str(e))
                bus.emit("phase.fail", {"phase": name, "error": str(e)})
                result = {}
            finally:
                try:
                    await asyncio.shield(_pop_phase_proxy())
                except (asyncio.CancelledError, Exception):
                    pass
                t1 = datetime.now()
                elapsed = (t1 - t0).total_seconds()
                phase_timing[name] = {
                    "start": t0.isoformat(timespec="seconds"),
                    "end": t1.isoformat(timespec="seconds"),
                    "elapsed_seconds": round(elapsed, 1),
                }
                # v3.0: Record tool health (success/failure per tool)
                if _tool_health is not None:
                    try:
                        for _tk, _tv in _TOOL_RC_REGISTRY.items():
                            if isinstance(_tv, int):
                                if _tv == 0:
                                    _tool_health.record_success(_tk, elapsed)
                                else:
                                    _tool_health.record_failure(_tk, f"rc={_tv}")
                    except Exception:
                        pass
                scan_status.add_completed(name)
                scan_status.set_missing(state.get("missing_tools", []))
                progress.next(name)
                bus.emit("phase.complete", {
                    "phase": name,
                    "elapsed": elapsed,
                    "count": sum(1 for v in (result or {}).values() if isinstance(v, str) and v.endswith(".txt")),
                })
            return result

    _shutdown_event = threading.Event()
    def _signal_handler(sig, frame):
        if _shutdown_event.is_set():
            # Run critical cleanup before hard exit — use forceful kill
            # to avoid deadlock on _SPAWNED_PIDS_LOCK
            try:
                import psutil
                parent = psutil.Process()
                for child in parent.children(recursive=True):
                    with contextlib.suppress(Exception):
                        child.kill()
            except Exception:
                pass
            try:
                if scan_status is not None:
                    scan_status.close()
            except Exception:
                pass
            os._exit(128 + sig)
        _shutdown_event.set()
        try:
            loop = asyncio.get_running_loop()
            loop.call_soon_threadsafe(_cleanup_child_procs)
            loop.call_soon_threadsafe(loop.stop)
        except RuntimeError:
            raise SystemExit(128 + sig)
    _orig_sigint = signal.signal(signal.SIGINT, _signal_handler)
    _orig_sigterm = signal.signal(signal.SIGTERM, _signal_handler)

    try:
        _NUCLEI_PHASES = {"04-SCAN", "06-JSINTEL", "09-VULNSCAN", "10-TLSCMS"}
        if any(p in _NUCLEI_PHASES for p in phases_to_run):
            if _safe_mode:
                log("info", "Safe mode: skipping nuclei template update (memory-intensive)")
            else:
                try:
                    await _update_nuclei_templates(outdir, proxy=vuln_proxy)
                except Exception as _nuc_exc:
                    log("warn", f"nuclei template update failed: {_nuc_exc}")

        prev: Dict[str, Any] = dict(state.get("artifacts", {}))
        waf_file = outdir / "waf_detection.txt"
        if waf_file.exists():
            waf_lines = read_lines(waf_file)
            _proc_mod._PIPELINE_CFG.waf_detected = any("detected" in wl.lower() and "no waf" not in wl.lower() for wl in waf_lines)
            if _proc_mod._PIPELINE_CFG.waf_detected:
                _proc_mod._PIPELINE_CFG.waf_evasion_throttle = 1.0
        # Log skipped phases for user visibility
        for name, _, _ in _pipeline:
            if name in skip:
                log("skip", f"phase {name} (--skip)")
            elif only and name not in only:
                log("skip", f"phase {name} (not in --only)")

        completed_phases: Set[str] = set()
        pending_tasks: Dict[str, asyncio.Task] = {}
        phase_started: Dict[str, datetime] = {}
        selected_set = set(phases_to_run)
        phase_timeout = int(7200 * proxy_timeout_mult) if vuln_proxy else 7200
        if _safe_mode:
            phase_timeout = min(phase_timeout, 1800)
            log("info", f"Safe mode: phase timeout reduced to {phase_timeout}s")

        def _check_memory() -> None:
            """Warn if resource monitor reports critically low memory."""
            if _resmon is None:
                return
            ram_gb = _resmon.ram_available_gb
            cpu = _resmon.cpu_percent
            conc = _resmon.current_concurrency
            # Emit resource update to event bus (for dashboard/bot)
            try:
                bus.emit("resource.update", {
                    "cpu": cpu,
                    "ram_gb": ram_gb,
                    "concurrency": conc,
                })
            except Exception:
                pass
            if ram_gb < 1.0:
                log("warn", f"LOW MEMORY: {ram_gb:.1f} GB available — concurrency={conc}, CPU={cpu:.0f}%")
            elif cpu > 90:
                log("warn", f"HIGH CPU: {cpu:.0f}% — concurrency={conc}, RAM={ram_gb:.1f}GB")

        _memory_check_counter = 0
        # Build initial ready set (phases whose deps are all satisfied)
        ready: Set[str] = set()
        for name in phases_to_run:
            deps = PHASE_DEPS.get(name, set()) & selected_set
            if not deps:
                ready.add(name)
        _debug_ts(f"pipeline loop starting: {len(ready)} root phases ready, "
                  f"{len(phases_to_run) - len(ready)} waiting on deps")
        while len(completed_phases) < len(phases_to_run):
            for name in list(ready):
                if name not in pending_tasks:
                    pending_tasks[name] = asyncio.ensure_future(_run_phase(name))
                    phase_started[name] = datetime.now()
            ready.clear()
            if not pending_tasks:
                break
            _memory_check_counter += 1
            if _memory_check_counter % 5 == 0:
                _check_memory()
            done_set, _ = await asyncio.wait(
                list(pending_tasks.values()),
                return_when=asyncio.FIRST_COMPLETED,
                timeout=phase_timeout,
            )
            if not done_set:
                longest = max(phase_started, key=lambda n: phase_started[n])
                _debug_ts(f"phase {longest} TIMED OUT after {phase_timeout}s")
                log("warn", f"phase {longest} timed out after {phase_timeout}s; cancelling")
                # Kill all running subprocesses so the thread pool thread unblocks
                with _proc_mod._SPAWNED_PIDS_LOCK:
                    for _pid in list(_proc_mod._SPAWNED_PIDS):
                        try:
                            os.killpg(_pid, signal.SIGTERM)
                        except (ProcessLookupError, PermissionError, OSError):
                            pass
                pending_tasks[longest].cancel()
                pending_tasks.pop(longest, None)
                phase_started.pop(longest, None)
                _apply(longest, {})
                completed_phases.add(longest)
                # Discover phases that are now ready after the timed-out phase
                for _candidate in phases_to_run:
                    if _candidate not in completed_phases and _candidate not in pending_tasks:
                        _deps = PHASE_DEPS.get(_candidate, set()) & selected_set
                        if _deps.issubset(completed_phases):
                            ready.add(_candidate)
                continue
            for name, task in list(pending_tasks.items()):
                if task in done_set:
                    pending_tasks.pop(name, None)
                    phase_started.pop(name, None)
                    try:
                        result = task.result()
                    except asyncio.CancelledError:
                        result = {}
                    except Exception as e:
                        log("err", f"phase {name} crashed: {e}")
                        result = {}
                    _apply(name, result)
                    completed_phases.add(name)
                    _debug_ts(f"phase {name} completed ({len(completed_phases)}/{len(phases_to_run)})")
                    try:
                        from reconchain.audit import log_event as _audit_phase
                        _audit_phase("phase_complete", domain=args.domain, detail={
                            "phase": name,
                            "progress": f"{len(completed_phases)}/{len(phases_to_run)}",
                        })
                    except Exception:
                        pass
                    # Add phases that are now ready (all deps satisfied)
                    for _candidate in phases_to_run:
                        if _candidate not in completed_phases and _candidate not in pending_tasks:
                            _deps = PHASE_DEPS.get(_candidate, set()) & selected_set
                            if _deps.issubset(completed_phases):
                                ready.add(_candidate)
                    if getattr(args, 'sample', False):
                        for k, v in (result or {}).items():
                            if isinstance(v, str) and v.endswith(".txt"):
                                _downsample_file(Path(v), n=1)
                    try:
                        _SENSITIVE_KEYWORDS = {"cookie", "session", "credential", "secret", "token", "password", "auth", "extra_headers"}
                        _SENSITIVE_KEYS = {"cookie", "COOKIE", "COOKIE_A", "COOKIE_B", "extra_headers", "EXTRA_HEADERS", "credentials", "credentials_queue"}
                        _SAFE_STATE_KEYS = {
                            "domain", "outdir", "started_at", "updated_at", "completed_phases",
                            "running_phases", "total_phases", "phase", "phase_progress",
                            "missing_tools", "tool_failures", "artifacts", "counts",
                            "coverage", "oast_urls", "oast_triggered", "errors",
                        }
                        # Filter first, then serialize once (avoids json.loads(json.dumps()) round-trip)
                        _filtered_state = {}
                        for _sk, _sv in state.items():
                            if _sk in _SAFE_STATE_KEYS and _sk not in _SENSITIVE_KEYS:
                                if _sk == "artifacts" and isinstance(_sv, dict):
                                    _filtered_state[_sk] = {
                                        ak: av for ak, av in _sv.items()
                                        if not any(s in ak.lower() for s in _SENSITIVE_KEYWORDS)
                                    }
                                else:
                                    _filtered_state[_sk] = _sv
                        _atomic_write_json(state_path, _filtered_state)
                    except Exception as e:
                        log("warn", f"state.json write failed: {e}")
    finally:
        if _resmon is not None:
            _resmon.stop()
        if _cookie_file and _cookie_file.exists():
            with contextlib.suppress(Exception):
                _cookie_file.unlink()
        if _cookie_atexit_token is not None and _cleanup_cookie_fn is not None:
            with contextlib.suppress(Exception):
                atexit.unregister(_cleanup_cookie_fn)
        for _env_k in ("COOKIE_A", "COOKIE_B"):
            os.environ.pop(_env_k, None)
        _cleanup_child_procs()
        signal.signal(signal.SIGINT, _orig_sigint)
        signal.signal(signal.SIGTERM, _orig_sigterm)
        if oast_started:
            oast.stop()
        _JOB_SEM = None
        scan_status.close()
        _dedup_engine.save()
        _monitor.record_scan(args.domain)
        try:
            due = _monitor.due_scans()
            if due:
                log("info", f"Monitor: {len(due)} scan(s) due, starting...")
                await asyncio.to_thread(_monitor.run_due_scans)
        except Exception:
            pass
        filter_outputs(outdir)
        # v3.0: Write tool health report
        if _tool_health is not None:
            try:
                _tool_health.write_report(outdir)
            except Exception:
                pass
        # Remove empty output files to reduce noise
        _empty_removed = 0
        for _fp in outdir.glob("*.txt"):
            try:
                if _fp.stat().st_size == 0:
                    _fp.unlink()
                    _empty_removed += 1
            except Exception:
                pass
        if _empty_removed:
            log("info", f"Removed {_empty_removed} empty output files")
        counts = _counts(outdir)

        # v3.0: Build target profile from early recon data (used for smart gating on future scans)
        try:
            from reconchain.target_profile import build_target_profile, save_profile
            _target_profile = build_target_profile(outdir, args.domain)
            save_profile(_target_profile, outdir)
            log("ok", f"target profile: {_target_profile.cloud_provider or 'unknown'} cloud, "
                f"{len(_target_profile.technologies)} techs, "
                f"{_target_profile.httpx_confidence:.0%} confidence")
        except Exception as _tp_exc:
            log("warn", f"target profiling failed: {_tp_exc}")

        # v3.0: Risk scoring
        try:
            from reconchain.severity import calculate_risk_score, write_risk_score
            _risk = calculate_risk_score(outdir)
            write_risk_score(outdir, _risk)
            log("ok", f"risk score: {_risk.grade} ({_risk.total_score:.0f}/100)")
        except Exception as _risk_exc:
            log("warn", f"risk scoring failed: {_risk_exc}")

        # v3.0: Confidence scoring
        try:
            from reconchain.confidence import score_all_findings, write_confidence_report
            _conf_scores = score_all_findings(outdir)
            if _conf_scores:
                write_confidence_report(outdir, _conf_scores)
                _confirmed = sum(1 for s in _conf_scores if s.confidence.value == "confirmed")
                _likely = sum(1 for s in _conf_scores if s.confidence.value == "likely")
                log("ok", f"confidence: {_confirmed} confirmed, {_likely} likely, {len(_conf_scores)} total")
        except Exception as _conf_exc:
            log("warn", f"confidence scoring failed: {_conf_exc}")

        # v3.0: Auto-PoC generation
        try:
            from reconchain.poc import generate_all_pocs
            _poc_path = generate_all_pocs(outdir)
            if _poc_path and _poc_path.exists():
                log("ok", f"auto-pocs → {_poc_path}")
        except Exception as _poc_exc:
            log("warn", f"auto-PoC generation failed: {_poc_exc}")
        if t.has("gowitness"):
            try:
                gowitness_targets = outdir / "host_targets.txt"
                if gowitness_targets.exists() and read_lines(gowitness_targets):
                    screenshots_dir = ensure(outdir / "screenshots")
                    _gw_proxy = []
                    if _proc_mod._PIPELINE_CFG.proxy and not _proc_mod._USE_PROXYCHAINS:
                        _gw_proxy = ["--chrome-proxy", _proc_mod._PIPELINE_CFG.proxy]
                    await _run("gowitness", ["gowitness", "scan", "file", "-f", str(gowitness_targets), "-s", str(screenshots_dir), "--screenshot-format", "png", "--write-none", "--headless"] + _gw_proxy, _maybe_timeout(600), outdir)
                    n_screenshots = len(list(screenshots_dir.glob("*.png"))) if screenshots_dir.exists() else 0
                    if n_screenshots:
                        log("ok", f"gowitness: {n_screenshots} screenshots → {screenshots_dir}")
            except Exception as _gw_exc:
                log("warn", f"gowitness failed: {_gw_exc}")
        try:
            state["coverage"] = _coverage(outdir, phases_to_run)
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
            report_format = getattr(args, 'format', 'html')
            if report_format == "sarif":
                sj_path = write_sarif(outdir, args.domain, counts, state)
                log("ok", f"sarif   → {sj_path}")
            # Generate Faraday report
            fj_path = write_faraday(outdir, args.domain, counts, state)
            log("ok", f"faraday → {fj_path}")
            # Generate interactive dashboard
            dj_path = write_html_dashboard(outdir, args.domain, counts, t.missing)
            log("ok", f"dashboard → {dj_path}")
        except Exception as _rep_exc:
            log("warn", f"report generation failed: {_rep_exc}")

        # --- Post-scan: Exploit chain analysis (heuristic) ---
        _exploit_chains_enabled = getattr(args, 'exploit_chains', True)
        if _exploit_chains_enabled:
            try:
                from reconchain.exploit_chain import analyze_exploit_chains
                _chains = analyze_exploit_chains(outdir)
                if _chains:
                    log("ok", f"exploit chains: {len(_chains)} chains identified")
            except Exception as _chain_exc:
                log("warn", f"exploit chain analysis failed: {_chain_exc}")

        # --- Post-scan: Attack surface graph ---
        _attack_graph = getattr(args, 'attack_graph', False)
        if _attack_graph or counts.get("subdomains", 0) > 0:
            try:
                from reconchain.attack_surface import (
                    build_graph,
                    write_attack_surface_html,
                    write_attack_surface_json,
                )
                _graph = build_graph(outdir)
                if _graph["nodes"]:
                    write_attack_surface_json(outdir, args.domain, _graph)
                    write_attack_surface_html(outdir, args.domain, _graph)
            except Exception as _graph_exc:
                log("warn", f"attack surface generation failed: {_graph_exc}")

        # --- Post-scan: AI-powered analysis ---
        _ai_enabled = getattr(args, 'ai_provider', 'none') != 'none'
        if _ai_enabled:
            try:
                from reconchain.ai import configure as ai_configure
                from reconchain.ai_exploit import suggest_exploit_chains
                from reconchain.ai_triage import run_triage

                _ai_cache = outdir / "ai_cache"
                _ai_cache.mkdir(exist_ok=True)
                ai_configure(
                    provider_name=getattr(args, 'ai_provider', 'dry-run'),
                    model=getattr(args, 'ai_model', ''),
                    cache_dir=_ai_cache,
                )

                _scan_duration = sum(v.get("elapsed_seconds", 0) for v in phase_timing.values())
                _duration_str = f"{int(_scan_duration // 60)}m {int(_scan_duration % 60)}s"

                # AI triage
                log("AI: running vulnerability triage...")
                _triage_results = await run_triage(outdir, args.domain, _duration_str)

                # AI exploit chain suggestions
                log("AI: generating exploit chain suggestions...")
                await suggest_exploit_chains(outdir, args.domain)

            except Exception as _ai_exc:
                log("warn", f"AI analysis failed: {_ai_exc}")

        # --- Start live dashboard if configured ---
        _dashboard_port = getattr(args, 'dashboard_port', 0)
        if _dashboard_port:
            try:
                from reconchain.dashboard_server import start_dashboard
                _dashboard_host = getattr(args, 'dashboard_host', '127.0.0.1')
                start_dashboard(
                    host=_dashboard_host,
                    port=_dashboard_port,
                    open_browser=getattr(args, 'dashboard_browser', True),
                )
            except Exception as _dash_exc:
                log("warn", f"dashboard server failed: {_dash_exc}")

        # --- Start companion bot if configured ---
        _bot_platform = getattr(args, 'bot', '')
        if _bot_platform:
            try:
                from reconchain.bot import start_bot_thread
                start_bot_thread(
                    platform=_bot_platform,
                    token=getattr(args, 'bot_token', ''),
                    channel_id=getattr(args, 'bot_channel', ''),
                    mention_on_critical=getattr(args, 'bot_mention', True),
                )
            except Exception as _bot_exc:
                log("warn", f"companion bot failed: {_bot_exc}")

        _scan_duration_val = sum(v.get("elapsed_seconds", 0) for v in phase_timing.values())
        _duration_str = f"{int(_scan_duration_val // 60)}m {int(_scan_duration_val % 60)}s"

        # --- Emit scan complete event ---
        bus.emit("scan.complete", {
            "domain": args.domain,
            "total_findings": sum(counts.values()),
            "duration": _duration_str,
            "stats": counts,
        })

        # Incremental mode: compute diff
        if incremental and _pre_scan_snapshot:
            try:
                _post_scan_snapshot = _snapshot_findings(outdir)
                _diff_findings(_pre_scan_snapshot, _post_scan_snapshot, outdir)
            except Exception as _diff_exc:
                log("warn", f"incremental diff failed: {_diff_exc}")
        # Send notification if configured
        try:
            from reconchain.notify import send_scan_summary
            _scan_duration = sum(v.get("elapsed_seconds", 0) for v in phase_timing.values())
            _notify_url = getattr(args, 'notify', '')
            send_scan_summary(
                args.domain, counts, _scan_duration, t.missing,
                notify_url=_notify_url,
            )
        except Exception as _notify_exc:
            log("warn", f"notification failed: {_notify_exc}")
        progress.close()
    return 0
