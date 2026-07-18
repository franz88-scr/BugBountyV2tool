"""CLI helper functions and main entry point."""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

from reconchain.config import __version__
from reconchain.pipeline import run_pipeline
from reconchain.process import MAX_PARALLEL_JOBS, _parse_phase_csv
from reconchain.utils import (
    ScanStatus,
    _is_valid_hostname,
    disable_color,
    log,
)


def _pid_alive(pid: int) -> bool:
    """Check if a process is still running."""
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError, OSError):
        return False


def _run_single(domain: str, args: argparse.Namespace) -> int:
    """Run a scan pipeline for a single domain.

    Creates a shallow copy of *args* with the domain and output directory
    set, then executes :func:`run_pipeline` in a new event loop.

    Returns:
        Exit code: 0 = success, 2 = configuration error,
        130 = interrupted.
    """
    import copy
    a = copy.copy(args)
    a.domain = domain.rstrip(".").lower()
    if not a.out or a.out == f"./out/{args.domain}":
        a.out = f"./out/{a.domain}"
    a.out = str(Path(a.out).resolve())
    try:
        return asyncio.run(run_pipeline(a))
    except KeyboardInterrupt:
        log("warn", "interrupted")
        return 130
    except ValueError as e:
        log("err", str(e))
        return 2
    except RuntimeError as e:
        _msg = str(e).lower()
        if "event loop" in _msg or "loop is closed" in _msg or "loop is running" in _msg:
            log("warn", "event loop shutdown race (non-fatal)")
            return 0
        log("err", f"runtime error: {e}")
        return 1
    except Exception as e:
        log("err", f"scan failed: {e}")
        return 1


def main() -> int:
    """Main entry point for reconchain CLI.

    Dispatches to the appropriate handler based on parsed arguments.
    Execution modes (in priority order):

    1. **Meta commands** -- ``--gen-config``, ``--list-plugins``: run and exit.
    2. **Status** -- ``--status``: show live progress of a running scan.
    3. **Compare** -- ``--compare OLD NEW``: diff two scan outputs.
    4. **Review** -- ``--review``: interactive triage of findings.
    5. **Batch** -- ``--batch FILE``: scan multiple domains from a file.
    6. **Daemon** -- ``--daemon``: fork to background, write PID file.
    7. **Interactive** -- ``-i``: launch the setup wizard.
    8. **Single/domain** -- ``-d DOMAIN``: run the full pipeline for one or
       more comma-separated domains.

    Returns:
        Exit code: 0 = success, 1 = scan errors, 2 = config error,
        130 = interrupted (SIGINT).
    """
    from reconchain.cli.parser import build_parser
    parser = build_parser()
    args = parser.parse_args()

    # Handle --gen-config: generate example config and exit
    if getattr(args, 'gen_config', False):
        from reconchain.conf import generate_example_config
        print(generate_example_config())
        return 0

    # Handle --list-plugins: discover and list plugins, then exit
    if getattr(args, 'list_plugins', False):
        from pathlib import Path as _P
        from reconchain.plugin import discover_plugins, list_plugins_cli
        dirs = []
        if getattr(args, 'plugins_dir', ''):
            dirs.append(_P(args.plugins_dir))
        discover_plugins(dirs)
        list_plugins_cli()
        return 0

    # Handle --dashboard: auto-set dashboard port
    if getattr(args, 'dashboard', False) and not getattr(args, 'dashboard_port', 0):
        args.dashboard_port = 8765

    # Handle --no-ai: override ai_provider
    if getattr(args, 'no_ai', False):
        args.ai_provider = "none"

    # Load external config file and apply to args (CLI flags take precedence)
    from reconchain.conf import apply_config_to_args, find_config, load_config
    args._defaults = {a.dest: a.default for a in parser._actions}
    config_path = find_config(getattr(args, 'config', '') or None)
    if config_path:
        cfg = load_config(config_path)
        apply_config_to_args(cfg, args)
        log("info", f"Loaded config from {config_path}")

    # Dry-run mode: set a global flag that process.py checks
    if getattr(args, 'dry_run', False):
        os.environ["RECONCHAIN_DRY_RUN"] = "1"
        log("info", "Dry-run mode: commands will be printed but not executed")

    # Parallel mode
    if not getattr(args, 'parallel', True):
        os.environ["RECONCHAIN_SEQUENTIAL"] = "1"
        log("info", "Sequential mode: phases will run one at a time")

    # v3.0: Handle --compare mode
    if getattr(args, 'compare', None):
        from pathlib import Path as _P
        from reconchain.compare import compare_scans
        old_dir, new_dir = args.compare
        output_dir = _P(getattr(args, 'out', './out/compare')).resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        result = compare_scans(_P(old_dir), _P(new_dir), output_dir)
        print(f"Comparison complete: {result.get('summary', {}).get('total_changes', 0)} changes")
        return 0

    # v3.0: Handle --review mode
    if getattr(args, 'review', False):
        if not args.domain:
            parser.error("--review requires -d/--domain")
        outdir = Path(getattr(args, 'out', f"./out/{args.domain}")).resolve()
        if not outdir.exists():
            log("err", f"Output directory not found: {outdir}")
            return 1
        from reconchain.review import run_interactive_review
        run_interactive_review(outdir)
        return 0

    # v3.0: Handle --batch mode
    if getattr(args, 'batch', ''):
        from pathlib import Path as _P
        batch_file = _P(args.batch)
        if not batch_file.exists():
            log("err", f"Batch file not found: {batch_file}")
            return 1
        from reconchain.batch import BatchScan
        batch_outdir = Path(getattr(args, 'out', './out/batch')).resolve()
        batch_outdir.mkdir(parents=True, exist_ok=True)
        scan = BatchScan(outdir=batch_outdir)
        raw_domains = [line.strip() for line in batch_file.read_text().splitlines() if line.strip() and not line.startswith('#')]
        domains = []
        for line_num, raw in enumerate(raw_domains, 1):
            d = raw.rstrip(".").lower()
            if not _is_valid_hostname(d):
                log("warn", f"batch line {line_num}: invalid domain '{raw}', skipping")
                continue
            domains.append(d)
        log("info", f"Batch mode: {len(domains)} valid domains out of {len(raw_domains)} entries")
        for i, domain in enumerate(domains, 1):
            log("info", f"[{i}/{len(domains)}] Scanning {domain}...")
            scan.add_target(domain)
            import copy
            a = copy.copy(args)
            a.domain = domain
            a.out = str(Path(f"./out/{a.domain}").resolve())
            if not Path(a.out).resolve().is_relative_to(batch_outdir.resolve()) and not Path(a.out).resolve().is_relative_to(Path("./out").resolve()):
                log("warn", f"batch: output path escapes expected directory for '{domain}', skipping")
                continue
            try:
                asyncio.run(run_pipeline(a))
                scan.record_result(a.domain, {"status": "completed"})
            except Exception as exc:
                log("warn", f"Failed to scan {domain}: {exc}")
                scan.record_result(a.domain, {"status": "failed", "error": str(exc)})
                continue
        scan.write_batch_summary()
        scan.write_batch_markdown()
        log("ok", f"Batch scan complete: {len(domains)} targets")
        return 0

    if args.status:
        if args.status.lower() == "list":
            active = ScanStatus.list_active()
            if not active:
                print("No active scans found.")
                return 0
            for s in active:
                print(f"  {s.get('domain')} — phase={s.get('phase')} completed={len(s.get('completed_phases', []))}/{s.get('total_phases')} errors={len(s.get('errors', []))}")
            return 0
        data = ScanStatus.load(args.status)
        if not data:
            print(f"No status found for domain '{args.status}'.")
            print("Active scans:")
            for s in ScanStatus.list_active():
                print(f"  {s.get('domain')}")
            return 1
        print(f"Domain:   {data.get('domain')}")
        print(f"Output:   {data.get('outdir')}")
        print(f"Phase:    {data.get('phase')} — {data.get('phase_progress', '')}")
        print(f"Started:  {data.get('started_at')}")
        print(f"Updated:  {data.get('updated_at')}")
        print(f"Progress: {len(data.get('completed_phases', []))}/{data.get('total_phases', '?')} phases completed")
        if data.get("completed_phases"):
            print(f"Done:     {', '.join(data['completed_phases'])}")
        if data.get("running_phases"):
            print(f"Running:  {', '.join(data['running_phases'])}")
        if data.get("errors"):
            print(f"Errors:   {len(data['errors'])}")
            for e in data["errors"][-3:]:
                print(f"  - {e}")
        if data.get("missing_tools"):
            print(f"Missing:  {', '.join(data['missing_tools'])}")
        return 0

    if args.interactive:
        from reconchain.cli.wizard import InteractiveWizard
        args = InteractiveWizard().run()
    else:
        if not args.domain:
            parser.error("the following arguments are required: -d/--domain (or use -i for interactive)")
        args.domain = args.domain.rstrip(".").lower()

    if args.no_color:
        disable_color()

    if hasattr(args, 'proxy') and args.proxy:
        if not args.proxy.startswith(("http://", "https://", "socks4://", "socks5://", "socks5h://", "socks4a://")):
            parser.error(f"invalid proxy URL scheme: {args.proxy!r} (must start with http://, https://, socks4://, socks5://, socks5h://, or socks4a://)")

    if hasattr(args, 'vuln_proxy') and args.vuln_proxy:
        if not args.vuln_proxy.startswith(("http://", "https://", "socks4://", "socks5://", "socks5h://", "socks4a://")):
            parser.error(f"invalid vuln-proxy URL scheme: {args.vuln_proxy!r}")

    if args.only and args.skip and (args.only & args.skip):
        parser.error("phase(s) cannot be both --only and --skip: " + ", ".join(sorted(args.only & args.skip)))

    if args.quiet:
        from reconchain.utils import log as _quiet_log
        def _quiet_log_impl(lvl, msg):
            if lvl in ("ok", "err", "warn"):
                _quiet_log(lvl, msg)
        import reconchain.utils as _utils
        _utils.log = _quiet_log_impl
        import reconchain.phases as _phases
        _phases.log = _quiet_log_impl
        import reconchain.reporting as _rep
        _rep.log = _quiet_log_impl
        import reconchain.pipeline as _pl
        _pl.log = _quiet_log_impl

    domains = [d.strip() for d in args.domain.split(",") if d.strip()]
    if not domains:
        parser.error("the following arguments are required: -d/--domain (or use -i for interactive)")

    for domain in domains:
        if not _is_valid_hostname(domain):
            parser.error(f"invalid domain: {domain}")

    try:
        if args.daemon:
            daemon_args = [a for a in sys.argv if a != "--daemon"]
            for domain in domains:
                fd, pidfile_path = tempfile.mkstemp(prefix=f"reconchain_{domain.replace('.', '_')}_", suffix=".pid")
                try:
                    os.write(fd, b"")
                    os.close(fd)
                    proc = subprocess.Popen([sys.executable] + daemon_args + ["-d", domain], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
                    with open(pidfile_path, "w") as pf:
                        pf.write(str(proc.pid))
                    import atexit
                    def _cleanup_pidfile(path=pidfile_path):
                        try:
                            with open(path) as f:
                                pid = int(f.read().strip())
                            if not _pid_alive(pid):
                                os.unlink(path)
                        except Exception:
                            pass
                    atexit.register(_cleanup_pidfile)
                except Exception:
                    with contextlib.suppress(Exception):
                        os.unlink(pidfile_path)
                    raise
                log("info", f"daemon started for {domain} (PID {proc.pid}); check status with: --status {domain}")
            return 0

        results = []
        for domain in domains:
            log("info", f"{'='*60}")
            log("info", f"Starting scan for domain: {domain}")
            log("info", f"{'='*60}")
            rc = _run_single(domain, args)
            results.append((domain, rc))
            if rc != 0:
                log("warn", f"Scan for {domain} exited with code {rc}")

        failed = [(d, c) for d, c in results if c != 0]
        if failed:
            log("warn", f"{len(failed)} domain(s) had errors: {', '.join(d for d, _ in failed)}")
            return 1
        return 0
    except KeyboardInterrupt:
        log("warn", "interrupted")
        return 130
