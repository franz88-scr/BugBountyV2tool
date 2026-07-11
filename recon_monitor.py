#!/usr/bin/env python3
"""
ReconChain Monitor v3
- Runs reconchain.py against brandenburg.cloud via Tor/proxychains4
- Checks every 5 min (sleep 300) for errors/warnings/stuck
- Fixes missing tools, restarts failed phases via --resume
- Reads ScanStatus from /run/user/1000/reconchain_status/ for real progress
- Loops until scan is complete
"""
from __future__ import annotations
import json, os, shutil, signal, subprocess, sys, time
from datetime import datetime
from pathlib import Path

DOMAIN = os.environ.get("RECON_DOMAIN", "brandenburg.cloud")
WORKDIR = Path(os.environ.get("RECON_WORKDIR", str(Path(__file__).resolve().parent)))
OUTDIR = WORKDIR / f"out_{DOMAIN}"
STATE_FILE = OUTDIR / "state.json"
SCAN_STATUS_DIR = Path("/run/user/1000/reconchain_status")
SCAN_STATUS_FILE = SCAN_STATUS_DIR / f"{DOMAIN.replace('.', '_')}.json"
CHECK_INTERVAL = 300
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
        "--sample-urls-fuzz", "3",
        "--sample-urls-params", "3",
        "--sample-urls-cmdi", "2",
        "--sample-hosts-ssl", "1",
        "--sample-hosts-origin", "2",
        "--sample-hosts-cloud", "1",
        "--sample-hosts-git", "1",
        "--sample-hosts-graphql", "1",
        "--sample-hosts-waf", "1",
        "--sample-urls-xss-blind", "3",
        "--sample-urls-domxss", "3",
        "--sample-urls-ssti", "2",
        "--sample-urls-nosqli", "3",
        "--sample-endpoints-race", "2",
        "--sample-hosts-jwt", "3",
        "--sample-urls-xxe", "2",
        "--sample-urls-redirect", "3",
        "--sample-hosts-ratelimit", "2",
        "--sample-urls-ldap", "2",
        "--sample-urls-crlf", "3",
        "--sample-urls-upload", "2",
        "--sample-hosts-smuggle", "2",
        "--sample-hosts-h2smuggle", "2",
        "--sample-hosts-frameworks", "3",
        "--sample-hosts-cached", "2",
        "--sample-urls-depcheck", "3",
        "--sample-hosts-clickjack", "3",
        "--sample-endpoints-corsadv", "2",
        "--sample-hosts-jwtadv", "3",
        "--sample-endpoints-oauth", "2",
        "--sample-endpoints-pwreset", "2",
        "--sample-hosts-websocket", "2",
        "--sample-endpoints-deserial", "2",
        "--sample-endpoints-l", "3",
        "--sample-endpoints-post", "2",
        "--sample-endpoints-cors", "2",
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
        prev_done: set = set()

        while attempt < max_attempts:
            time.sleep(CHECK_INTERVAL)

            alive = proc.poll() is None
            status = read_status()

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

                # Fix missing tools
                missing = status.get("missing_tools", [])
                if missing:
                    fix_missing_tools(missing)

                # Completion check
                if not running and len(done) > 0:
                    if total != "?" and len(done) >= total:
                        log("=== SCAN COMPLETE ===")
                        return 0
                    # If no running phases but not all done, might be between phases or stuck
                    if not phase and attempt < 2:
                        log("Initial setup phase, waiting...")
                    else:
                        log("No running phases — waiting for next phase to start")

                # Stuck detection: no progress across multiple checks
                if alive:
                    if done == prev_done and not running:
                        idle += 1
                        log(f"No progress {idle}/{MAX_IDLE}")
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
                            time.sleep(30)  # Minimum delay before restart
                            break
                    else:
                        idle = 0
                    prev_done = done
            else:
                log("Waiting for ScanStatus file...")
                # Also check if state.json exists
                if STATE_FILE.exists():
                    log("state.json exists but no ScanStatus yet")
                idle = 0

            check_logs()

            if not alive:
                rc = proc.poll()
                log(f"Process died rc={rc}")
                # Check if it actually completed
                if status:
                    done = set(status.get("completed_phases", []))
                    total = status.get("total_phases", "?")
                    if total != "?" and len(done) >= total:
                        log("=== SCAN COMPLETE ===")
                        return 0
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
