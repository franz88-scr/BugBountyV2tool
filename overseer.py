#!/usr/bin/env python3
"""Overseer — unified scan orchestrator for VulnForge.

Combines monitoring, restart logic, stuck detection, auto-tool-install,
and pre-flight checks into a single script.  Replaces the old sentinel.py,
guardian.sh, and overseer.py scripts.

Features:
  - Restart loop with --resume from state.json
  - Stuck detection (output dir activity, log writes, child tool processes, CPU)
  - Browser-tab detection (kills scan if a browser accidentally opens)
  - Auto-installs missing Go tools (subfinder, httpx, nuclei, etc.)
  - Pre-flight checks: proxy env cleanup, Tor reachability, nuclei templates
  - Configurable timeout per attempt and max restart count
  - Reads ScanStatus files for real-time phase progress

Usage:
    python3 overseer.py -d example.com
    python3 overseer.py -d example.com --proxy socks5://127.0.0.1:9050
    python3 overseer.py -d example.com --timeout 7200 --max-restarts 50
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

CHECK_INTERVAL = 120
MAX_IDLE = 3

GO_TOOLS = {
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "dnsx": "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    "naabu": "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    "ffuf": "github.com/ffuf/ffuf/v2@latest",
    "gau": "github.com/lc/gau/v2/cmd/gau@latest",
    "katana": "github.com/projectdiscovery/katana/cmd/katana@latest",
}


def signal_sleep(seconds: float) -> None:
    """Sleep that responds to SIGINT/SIGTERM immediately."""
    deadline = time.monotonic() + seconds
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            time.sleep(min(remaining, 1.0))
        except InterruptedError:
            break


def log(msg: str, logfile: Optional[Path] = None) -> None:
    line = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    if logfile:
        try:
            if logfile.exists() and logfile.stat().st_size > 10_000_000:
                logfile.unlink()
            with open(logfile, "a") as f:
                f.write(line + "\n")
        except OSError:
            pass


# ── Pre-flight checks (from guardian.sh) ──────────────────────────────


def clean_proxy_env() -> None:
    """Unset stray proxy env vars that force traffic through Tor when it's not running."""
    if any(os.environ.get(v) for v in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "PROXY")):
        return
    for var in ("ALL_PROXY", "all_proxy", "HTTPS_PROXY", "https_proxy",
                "HTTP_PROXY", "http_proxy", "PROXY"):
        os.environ.pop(var, None)


def check_tor() -> bool:
    """Return True if Tor is reachable on 127.0.0.1:9050."""
    try:
        with socket.create_connection(("127.0.0.1", 9050), timeout=2):
            return True
    except (OSError, TimeoutError):
        return False


def update_nuclei_templates(logfile: Optional[Path] = None) -> None:
    """Update nuclei templates if nuclei is installed."""
    if not shutil.which("nuclei"):
        return
    try:
        subprocess.run(
            ["nuclei", "-update-templates", "-silent"],
            capture_output=True, timeout=60,
        )
    except subprocess.TimeoutExpired:
        log("WARN: nuclei template update timed out", logfile)
    except Exception as exc:
        log(f"WARN: nuclei template update failed: {exc}", logfile)


# ── Tool auto-install (from overseer.py) ──────────────────────────────


def fix_missing_tools(missing: list[str]) -> None:
    if not shutil.which("go"):
        return
    for tool in missing:
        if shutil.which(tool):
            continue
        if tool in GO_TOOLS:
            log(f"Auto-installing {tool}...")
            try:
                r = subprocess.run(
                    ["go", "install", GO_TOOLS[tool]],
                    capture_output=True, timeout=180,
                )
                if r.returncode == 0:
                    log(f"Installed {tool}")
                else:
                    log(f"Failed to install {tool}: {r.stderr.decode(errors='replace')[:200]}")
            except Exception as exc:
                log(f"Failed to install {tool}: {exc}")


# ── Process management ────────────────────────────────────────────────


def kill_process_group(proc: Optional[subprocess.Popen]) -> None:
    """Kill a process and its entire process group."""
    if proc is None:
        return
    pgid = None
    try:
        pgid = os.getpgid(proc.pid)
    except (ProcessLookupError, OSError, OverflowError):
        pass
    if pgid is not None:
        try:
            os.killpg(pgid, signal.SIGTERM)
        except (ProcessLookupError, OSError):
            pass
    try:
        proc.wait(timeout=10)
    except Exception:
        if pgid is not None:
            try:
                os.killpg(pgid, signal.SIGKILL)
            except (ProcessLookupError, OSError):
                pass
        try:
            proc.wait(timeout=5)
        except Exception:
            pass


def check_browser_tabs() -> list[str]:
    """Detect accidentally opened browser tabs (only if psutil is available)."""
    if not HAS_PSUTIL:
        return []
    browsers = []
    browser_names = ("firefox", "chrome", "chromium", "brave", "opera", "edge")
    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            name = proc.info["name"] or ""
            cmdline = " ".join(proc.info["cmdline"] or [])
            lower = name.lower() + " " + cmdline.lower()
            if any(b in lower for b in browser_names):
                browsers.append(f"{name} (pid {proc.info['pid']})")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return browsers


# ── Status readers ────────────────────────────────────────────────────


def read_status(scan_status_file: Path) -> Optional[dict]:
    try:
        if scan_status_file.exists():
            return json.loads(scan_status_file.read_text())
    except Exception:
        return None
    return None


def read_state(state_file: Path) -> Optional[dict]:
    try:
        if state_file.exists():
            return json.loads(state_file.read_text())
    except Exception:
        return None
    return None


# ── Log scanning ──────────────────────────────────────────────────────

ERROR_KEYWORDS = (
    "traceback", "exception", "killed", "segfault", "panic",
    "refused", "reset by peer", "no route", "dns lookup failed",
    "timeout", "cannot assign", "address in use",
)


def check_logs(log_dir: Path, max_age: float) -> list[str]:
    """Scan recent log files for error keywords. Returns list of issues."""
    issues: list[str] = []
    if not log_dir.exists():
        return issues
    recent = sorted(log_dir.glob("*.log"), key=lambda f: f.stat().st_mtime, reverse=True)[:5]
    for lf in recent:
        age = time.time() - lf.stat().st_mtime
        if age > max_age:
            continue
        try:
            lines = lf.read_text(errors="replace").splitlines()
        except Exception:
            continue
        for line in lines[-40:]:
            if any(kw in line.lower() for kw in ERROR_KEYWORDS):
                issues.append(f"  {lf.name}: {line.strip()[:180]}")
                if len(issues) >= 6:
                    return issues
    return issues


# ── Activity detection (from overseer.py) ─────────────────────────────


def detect_activity(outdir: Path, proc: subprocess.Popen) -> tuple[bool, str]:
    """Check if the scan is still active. Returns (is_active, reason)."""
    if proc.poll() is not None:
        return False, "process exited"
    # Output dir file changes
    if outdir.exists():
        try:
            latest = max(f.stat().st_mtime for f in outdir.rglob("*") if f.is_file())
            if time.time() - latest < CHECK_INTERVAL:
                return True, "output dir active"
        except (ValueError, OSError):
            pass

    # Log file writes
    log_dir = outdir / "logs"
    if log_dir.exists():
        try:
            latest = max(f.stat().st_mtime for f in log_dir.glob("*.log") if f.is_file())
            if time.time() - latest < CHECK_INTERVAL:
                return True, "logs active"
        except (ValueError, OSError):
            pass

    # Child processes still running
    try:
        out = subprocess.check_output(
            ["pgrep", "-af", "nuclei|httpx|ffuf|sqlmap|naabu|katana|waymore|commix"],
            text=True, stderr=subprocess.DEVNULL,
        ).strip()
        if out:
            names = [l.split()[-1].split("/")[-1] for l in out.splitlines()[:3]]
            return True, f"child tools: {', '.join(names)}"
    except (subprocess.CalledProcessError, Exception):
        pass

    return False, "no activity"


# ── Main loop ─────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Overseer — VulnForge scan orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Monitors vulnforge.py, restarts on failure/stuck, auto-installs tools.",
    )
    p.add_argument("-d", "--domain", required=True, help="Target domain")
    p.add_argument("-o", "--outdir", default="", help="Output directory (default: out_<domain>)")
    p.add_argument("--proxy", default="", help="Proxy URL (e.g. socks5://127.0.0.1:9050)")
    p.add_argument("--timeout", type=int, default=14400, help="Seconds per attempt (default: 14400 = 4h)")
    p.add_argument("--max-restarts", type=int, default=20, help="Max restart attempts (default: 20)")
    p.add_argument("--check-interval", type=int, default=120, help="Seconds between checks (default: 120)")
    p.add_argument("--max-idle", type=int, default=3, help="Idle cycles before restart (default: 3)")
    p.add_argument("--no-preflight", action="store_true", help="Skip pre-flight checks")
    p.add_argument("--no-browser-check", action="store_true", help="Skip browser-tab detection")
    return p


def main() -> int:
    args = build_parser().parse_args()

    domain = args.domain
    if not re.match(r"^[A-Za-z0-9]([A-Za-z0-9.\-]*[A-Za-z0-9])?$", domain):
        sys.exit(f"error: invalid domain {domain!r}")

    workdir = Path(__file__).resolve().parent
    outdir = Path(args.outdir) if args.outdir else workdir / f"out_{domain}"
    logfile = outdir / "overseer.log"
    state_file = outdir / "state.json"

    xdg = os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
    scan_status_file = Path(xdg) / "vulnforge_status" / f"{domain.replace('.', '_')}.json"

    check_interval = args.check_interval
    max_idle = args.max_idle

    outdir.mkdir(parents=True, exist_ok=True)

    # ── Banner ────────────────────────────────────────────────────
    log("=" * 60, logfile)
    log(f"Overseer — {domain}", logfile)
    log(f"Output:    {outdir}", logfile)
    log(f"Status:    {scan_status_file}", logfile)
    log(f"Timeout:   {args.timeout}s per attempt", logfile)
    log(f"Restart:   max {args.max_restarts}, stuck after {max_idle} idle cycles", logfile)
    log(f"Interval:  {check_interval}s", logfile)
    log("=" * 60, logfile)

    # ── Pre-flight checks (from guardian.sh) ──────────────────────
    if not args.no_preflight:
        clean_proxy_env()

        if shutil.which("proxychains4") and not check_tor():
            log("WARN: proxychains4 installed but Tor (127.0.0.1:9050) unreachable", logfile)
            log("WARN: tools using bash runners may hang — unset PROXY or start Tor", logfile)

        update_nuclei_templates(logfile)

    # ── Build command ─────────────────────────────────────────────
    base_args = ["-d", domain, "-o", str(outdir)]
    if args.proxy:
        base_args += ["--proxy", args.proxy]
    base_args += ["--sample-urls-fuzz", "10", "--sample-urls-params", "10"]

    # ── Restart loop ──────────────────────────────────────────────
    proc: Optional[subprocess.Popen] = None
    restart_count = 0

    while restart_count < args.max_restarts:
        restart_count += 1
        log(f"\n{'─' * 50}", logfile)
        log(f"Attempt {restart_count}/{args.max_restarts}", logfile)

        # Decide resume vs fresh
        has_state = state_file.exists()
        run_args = base_args + (["--resume"] if has_state else ["--force"])
        if has_state:
            log("Resuming from state.json", logfile)
        else:
            log("Fresh start", logfile)

        # Launch
        cmd = ["python3", str(workdir / "vulnforge.py")] + run_args
        log(f"CMD: {' '.join(cmd)}", logfile)
        proc = subprocess.Popen(
            cmd, cwd=str(workdir),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, start_new_session=True,
        )

        idle = 0
        last_activity = time.time()
        reason = ""

        while True:
            signal_sleep(check_interval)

            alive = proc.poll() is None
            now = time.time()

            # ── Status from ScanStatus or state.json ──
            status = read_status(scan_status_file)
            state = read_state(state_file)

            if status:
                done = set(status.get("completed_phases", []))
                running = set(status.get("running_phases", []))
                errors = status.get("errors", [])
                total = status.get("total_phases", "?")
                phase = status.get("phase", "")
                log(f"Alive={alive} | Phase={phase} | {len(done)}/{total} done, "
                    f"{len(running)} running, {len(errors)} errors", logfile)

                if errors:
                    for e in errors[-3:]:
                        log(f"  Error: {e}", logfile)

                missing = status.get("missing_tools", [])
                if missing:
                    fix_missing_tools(missing)

                if not running and len(done) > 0 and total != "?" and len(done) >= total:
                    log("=== SCAN COMPLETE ===", logfile)
                    return 0

            elif state:
                artifacts = state.get("artifacts", {})
                n = len([k for k in artifacts
                         if k not in ("count", "failures") and not isinstance(artifacts[k], dict)])
                failures = state.get("tool_failures", {})
                log(f"Alive={alive} | state.json: {n} artifacts, {len(failures)} failures", logfile)
            else:
                log("No status yet — initializing", logfile)

            # ── Activity / stuck detection ──
            if alive:
                is_active, reason = detect_activity(outdir, proc)

                # Browser tab check (from sentinel.py)
                if not is_active and not args.no_browser_check:
                    browsers = check_browser_tabs()
                    if browsers:
                        log(f"BROWSER TAB OPENED: {browsers}", logfile)
                        kill_process_group(proc)
                        proc = None
                        time.sleep(5)
                        break

                if is_active:
                    idle = 0
                    last_activity = now
                    log(f"  Active: {reason}", logfile)
                else:
                    idle += 1
                    log(f"No activity {idle}/{max_idle}", logfile)

                    # CPU check (from sentinel.py)
                    if idle == 1 and HAS_PSUTIL and proc and proc.poll() is None:
                        try:
                            p = psutil.Process(proc.pid)
                            cpu = p.cpu_percent(interval=0.5)
                            if cpu < 0.5 and (now - last_activity) > 600:
                                log(f"  STUCK — no output for 10min, CPU={cpu}%", logfile)
                                idle = max_idle  # force restart
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass

                    if idle >= max_idle:
                        log("Stuck — killing and restarting", logfile)
                        kill_process_group(proc)
                        proc = None
                        time.sleep(30)
                        break

            # ── Log error scanning ──
            issues = check_logs(outdir / "logs", max_age=check_interval * 3)
            for issue in issues:
                log(issue, logfile)

            # ── Process died ──
            if not alive:
                rc = proc.poll()
                log(f"Process died rc={rc}", logfile)
                if state:
                    log(f"Last state: {len(state.get('artifacts', {}))} artifacts", logfile)
                break

        # After inner loop: decide whether to restart
        if proc is not None:
            # Process exited normally
            rc = proc.poll()
            if rc == 0 and not state_file.exists():
                log("Scan completed successfully", logfile)
                return 0
            log(f"Process exited rc={rc}, state.json {'exists' if state_file.exists() else 'missing'}", logfile)

        log(f"Restarting in 5s...", logfile)
        time.sleep(5)

    log(f"Exceeded max restarts ({args.max_restarts})", logfile)
    return 1


if __name__ == "__main__":
    proc: Optional[subprocess.Popen] = None
    try:
        rc = main()
    except KeyboardInterrupt:
        print("\nInterrupted", flush=True)
        rc = 130
    finally:
        if proc is not None and proc.poll() is None:
            kill_process_group(proc)
    sys.exit(rc)
