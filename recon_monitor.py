#!/usr/bin/env python3
"""
ReconChain Monitor v4
- Runs reconchain.py against brandenburg.cloud via Tor proxy
- Checks every 2 min (sleep 120) for errors/warnings/stuck
- Fixes missing tools, restarts failed phases via --resume
- Reads ScanStatus from /run/user/1000/reconchain_status/ for real progress
- Loops until scan is complete
"""
from __future__ import annotations
import json, os, re, shutil, signal, subprocess, sys, time
from datetime import datetime
from pathlib import Path

DOMAIN = os.environ.get("RECON_DOMAIN", "brandenburg.cloud")
if not re.match(r'^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$', DOMAIN):
    sys.exit(f"error: invalid domain {DOMAIN!r} (path traversal check)")
WORKDIR = Path(os.environ.get("RECON_WORKDIR", str(Path(__file__).resolve().parent)))
OUTDIR = WORKDIR / "out" / DOMAIN
STATE_FILE = OUTDIR / "state.json"
SCAN_STATUS_DIR = Path(os.environ.get('XDG_RUNTIME_DIR', f'/run/user/{os.getuid()}')) / 'reconchain_status'
SCAN_STATUS_FILE = SCAN_STATUS_DIR / f"{DOMAIN.replace('.', '_')}.json"
CHECK_INTERVAL = 120
MAX_IDLE = 3

os.chdir(str(WORKDIR))

def log(msg: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)

def read_status() -> dict | None:
    try:
        if SCAN_STATUS_FILE.exists():
            return json.loads(SCAN_STATUS_FILE.read_text())
    except Exception:
        return None
    return None

def read_state() -> dict | None:
    try:
        if STATE_FILE.exists():
            return json.loads(STATE_FILE.read_text())
    except Exception:
        return None
    return None

def run_scan(args: list[str]) -> subprocess.Popen:
    cmd = ["python3", "reconchain.py"] + args
    log(f"Starting: {' '.join(cmd)}")
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, start_new_session=True)

def fix_missing_tools(missing: list[str]) -> None:
    go_install = {
        "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "dnsx": "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        "naabu": "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
        "ffuf": "github.com/ffuf/ffuf/v2@latest",
        "gau": "github.com/lc/gau/v2/cmd/gau@latest",
        "katana": "github.com/projectdiscovery/katana/cmd/katana@latest",
    }
    for tool in missing:
        if shutil.which(tool):
            continue
        if tool in go_install and shutil.which("go"):
            log(f"Auto-installing {tool}...")
            r = subprocess.run(["go", "install", go_install[tool]], capture_output=True, timeout=180)
            if r.returncode == 0:
                log(f"Installed {tool}")
            else:
                err = r.stderr.decode(errors="replace")[:200]
                log(f"Failed to install {tool}: {err}")

def check_logs() -> None:
    log_dir = OUTDIR / "logs"
    if not log_dir.exists():
        return
    recent = sorted(log_dir.glob("*.log"), key=lambda f: f.stat().st_mtime, reverse=True)[:5]
    for lf in recent:
        age = time.time() - lf.stat().st_mtime
        if age > CHECK_INTERVAL * 3:
            continue
        try:
            lines = lf.read_text(errors="replace").splitlines()
        except Exception:
            continue
        tail = lines[-40:]
        bad = [l for l in tail if any(kw in l.lower() for kw in
               ["traceback", "exception", "killed", "segfault", "panic",
                "refused", "reset by peer", "no route", "dns lookup failed",
                "timeout", "cannot assign", "address in use"])]
        if bad:
            log(f"Issues in {lf.name}:")
            for b in bad[:3]:
                log(f"  {b.strip()[:180]}")

def main() -> int:
    log("=" * 60)
    log(f"ReconChain Monitor — {DOMAIN}")
    log(f"Output: {OUTDIR}")
    log(f"Status: {SCAN_STATUS_FILE}")
    log(f"Check every {CHECK_INTERVAL}s, max {MAX_IDLE} idle cycles before restart")
    log("=" * 60)

    OUTDIR.mkdir(parents=True, exist_ok=True)
    attempt = 0
    max_attempts = 200
    proc: subprocess.Popen | None = None

    base_args = [
        "-d", DOMAIN, "-o", str(OUTDIR),
        "--proxy", "socks5://127.0.0.1:9050",
        "--proxy-timeout-multiplier", "2.0",
        "--dos",
        "--sample-mode", "minimal",
    ]

    while attempt < max_attempts:
        attempt += 1
        log(f"\n{'─'*50}")
        log(f"Attempt {attempt}/{max_attempts}")

        status = read_status()
        has_resume = status is not None and bool(status.get("completed_phases"))
        args_run = base_args + (["--resume"] if has_resume else ["--force"])

        if proc is None or proc.poll() is not None:
            proc = run_scan(args_run)

        idle = 0
        prev_artifacts = 0
        prev_failures: dict = {}
        prev_state_mtime = 0.0

        while True:
            time.sleep(CHECK_INTERVAL)

            alive = proc.poll() is None
            status = read_status()
            state = read_state()

            # --- Status from ScanStatus or state.json ---
            if status:
                done = set(status.get("completed_phases", []))
                running = set(status.get("running_phases", []))
                errors = status.get("errors", [])
                total = status.get("total_phases", "?")
                phase = status.get("phase", "")
                log(f"Alive={alive} | Phase={phase} | {len(done)}/{total} done, {len(running)} running, {len(errors)} errors")

                if errors:
                    for e in errors[-3:]:
                        log(f"  Error: {e}")

                missing = status.get("missing_tools", [])
                if missing:
                    fix_missing_tools(missing)

                if not running and len(done) > 0:
                    if total != "?" and len(done) >= total:
                        log("=== SCAN COMPLETE ===")
                        return 0
            elif state:
                # Fallback: track progress via state.json artifact count
                artifacts = state.get("artifacts", {})
                n_artifacts = len([k for k in artifacts if k != "count" and k != "failures" and not isinstance(artifacts[k], dict)])
                failures = state.get("tool_failures", {})
                mtime = STATE_FILE.stat().st_mtime if STATE_FILE.exists() else 0
                log(f"Alive={alive} | state.json: {n_artifacts} artifacts, {len(failures)} tool failures, mtime={datetime.fromtimestamp(mtime).strftime('%H:%M:%S')}")

                if failures:
                    new_fails = {k: v for k, v in failures.items() if prev_failures.get(k, 0) < v}
                    if new_fails:
                        log(f"  New tool failures: {new_fails}")

                prev_state_mtime = mtime
                prev_artifacts = n_artifacts
                prev_failures = failures
            else:
                log("No ScanStatus or state.json yet — scan initializing")

            # --- Stuck detection: check output dir mtime, logs, and process ---
            if alive:
                # Check if any file in output dir was recently modified (within CHECK_INTERVAL)
                outdir_changed = False
                if OUTDIR.exists():
                    try:
                        latest_mtime = max(f.stat().st_mtime for f in OUTDIR.rglob("*") if f.is_file())
                        outdir_changed = (time.time() - latest_mtime) < CHECK_INTERVAL
                    except (ValueError, OSError):
                        pass

                # Check if any log file was recently written
                logs_changed = False
                log_dir = OUTDIR / "logs"
                if log_dir.exists():
                    try:
                        latest_log = max(f.stat().st_mtime for f in log_dir.glob("*.log") if f.is_file())
                        logs_changed = (time.time() - latest_log) < CHECK_INTERVAL
                    except (ValueError, OSError):
                        pass

                if outdir_changed or logs_changed:
                    idle = 0
                    if outdir_changed:
                        log("  Output dir active (files changing)")
                    if logs_changed:
                        log("  Logs active (recent writes)")
                else:
                    idle += 1
                    log(f"No activity detected {idle}/{MAX_IDLE} (outdir_changed={outdir_changed}, logs_changed={logs_changed})")
                    if idle >= MAX_IDLE:
                        log("Stuck — killing and restarting")
                        try:
                            os.killpg(proc.pid, signal.SIGTERM)
                        except (ProcessLookupError, OSError):
                            pass
                        try:
                            proc.wait(timeout=10)
                        except Exception:
                            try:
                                os.killpg(proc.pid, signal.SIGKILL)
                            except (ProcessLookupError, OSError):
                                pass
                            try:
                                proc.wait(timeout=5)
                            except Exception:
                                pass
                        proc = None
                        time.sleep(30)
                        break

            # --- Log scan output (tail of process stdout) ---
            check_logs()

            # --- Process died ---
            if not alive:
                rc = proc.poll()
                log(f"Process died rc={rc}")
                if state:
                    log(f"Last state: {len(state.get('artifacts', {}))} artifacts")
                break

    log(f"Giving up after {max_attempts}")
    return 1

if __name__ == "__main__":
    try:
        rc = main()
    except KeyboardInterrupt:
        print("\nInterrupted", flush=True)
        rc = 130
    log(f"Exited with rc={rc}")
    sys.exit(rc)
