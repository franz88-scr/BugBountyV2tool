#!/usr/bin/env python3
"""Monitor reconchain.py run, restarting on failure/stuck/browser opens."""
from __future__ import annotations
import argparse, subprocess, time, sys, os, psutil
from pathlib import Path


def log(msg: str, logfile: Path):
    ts = time.strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    with open(logfile, "a") as f:
        f.write(line + "\n")


def check_browser_tabs() -> list[str]:
    browsers = []
    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            name = proc.info["name"] or ""
            cmdline = " ".join(proc.info["cmdline"] or [])
            if any(b in name.lower() or b in cmdline.lower() for b in
                   ["firefox", "chrome", "chromium", "brave", "opera", "edge"]):
                browsers.append(f"{name} (pid {proc.info['pid']})")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return browsers


def kill_proc_tree(proc):
    try:
        parent = psutil.Process(proc.pid)
        children = parent.children(recursive=True)
        for child in children:
            try:
                child.kill()
            except psutil.NoSuchProcess:
                pass
        parent.kill()
    except psutil.NoSuchProcess:
        pass


def main():
    parser = argparse.ArgumentParser(description="Monitor reconchain.py run")
    parser.add_argument("-d", "--domain", required=True, help="target domain")
    parser.add_argument("-o", "--outdir", default="", help="output directory")
    parser.add_argument("--proxy", default="", help="proxy URL")
    args = parser.parse_args()

    DOMAIN = args.domain
    WORKDIR = Path(__file__).resolve().parent
    OUTDIR = Path(args.outdir) if args.outdir else WORKDIR / f"out_{DOMAIN}"
    LOGFILE = OUTDIR / "monitor.log"
    CHECK_INTERVAL = 120
    MAX_RESTARTS = 20

    OUTDIR.mkdir(parents=True, exist_ok=True)

    cmd = ["python3", str(WORKDIR / "reconchain.py"),
        "-d", DOMAIN, "-o", str(OUTDIR),
        "--sample-urls-fuzz", "10", "--sample-urls-params", "10",
    ]
    if args.proxy:
        cmd += ["--proxy", args.proxy]

    if (OUTDIR / "state.json").exists():
        cmd += ["--resume"]
    else:
        cmd += ["--force"]

    restarts = 0
    while restarts < MAX_RESTARTS:
        restarts += 1
        log(f"Launch: {' '.join(cmd)}", LOGFILE)
        proc = subprocess.Popen(cmd, cwd=WORKDIR, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        last_output = time.time()
        broken = False
        stuck = False
        browser_opened = False

        while True:
            try:
                line = proc.stdout.readline()
                if line:
                    last_output = time.time()
                    print(line, end="", flush=True)
                    time.sleep(0.05)
                    continue
            except (ValueError, OSError):
                pass

            time.sleep(CHECK_INTERVAL)
            now = time.time()

            browsers = check_browser_tabs()
            if browsers:
                log(f"BROWSER TAB OPENED: {browsers}", LOGFILE)
                browser_opened = True
                break

            rc = proc.poll()
            if rc is not None:
                log(f"Process exited with rc={rc}", LOGFILE)
                if rc != 0:
                    broken = True
                break

            try:
                p = psutil.Process(proc.pid)
                if now - last_output > 600:
                    cpu = p.cpu_percent(interval=0.5)
                    if cpu < 0.5:
                        log(f"STUCK — no output for 10min, CPU={cpu}%", LOGFILE)
                        stuck = True
                        break
            except psutil.NoSuchProcess:
                log("Process disappeared unexpectedly", LOGFILE)
                broken = True
                break

        if browser_opened or broken or stuck:
            log(f"Killing process (browser={browser_opened}, broken={broken}, stuck={stuck})", LOGFILE)
            kill_proc_tree(proc)
            time.sleep(5)
            log(f"Restart #{restarts} in 5s", LOGFILE)
            time.sleep(5)
        else:
            log("Scan completed successfully", LOGFILE)
            sys.exit(0)

    log(f"Exceeded max restarts ({MAX_RESTARTS})", LOGFILE)
    sys.exit(1)


if __name__ == "__main__":
    main()
