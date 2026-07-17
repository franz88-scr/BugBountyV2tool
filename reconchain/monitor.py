"""Monitor engine — periodic re-scan scheduling with persistence and status tracking."""
import fcntl
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional


class MonitorEngine:
    def __init__(self, state_dir: Optional[Path] = None) -> None:
        self._state_dir = state_dir or Path.home() / ".config" / "reconchain" / "monitor"
        self._state_dir.mkdir(parents=True, exist_ok=True)
        self._state_file = self._state_dir / "watches.json"
        self._watches: Dict[str, Dict[str, Any]] = {}
        self._lock_file = self._state_dir / ".watches.lock"
        self._load()

    def _load(self) -> None:
        if self._state_file.exists():
            try:
                with self._state_file.open() as f:
                    self._watches = json.load(f)
            except (json.JSONDecodeError, OSError):
                self._watches = {}

    def _acquire_lock(self) -> int:
        """Acquire an exclusive file lock for cross-process safety."""
        fd = os.open(str(self._lock_file), os.O_CREAT | os.O_RDWR, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fd

    def _release_lock(self, fd: int) -> None:
        """Release the file lock."""
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def _save(self) -> None:
        import tempfile
        fd, tmp_path = tempfile.mkstemp(dir=self._state_dir, suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(self._watches, f, indent=2, default=str)
            os.replace(tmp_path, self._state_file)
        except Exception:
            import contextlib as _ctx
            with _ctx.suppress(Exception):
                os.unlink(tmp_path)
            raise

    def watch(self, domain: str, interval_hours: int = 24, args: Optional[List[str]] = None) -> None:
        if interval_hours < 1:
            raise ValueError(f"interval_hours must be at least 1, got {interval_hours}")
        self._watches[domain] = {
            "domain": domain,
            "interval_hours": interval_hours,
            "last_scan": None,
            "next_scan": datetime.now().isoformat(),
            "args": args or [],
            "created": datetime.now().isoformat(),
        }
        self._save()

    def unwatch(self, domain: str) -> bool:
        if domain in self._watches:
            del self._watches[domain]
            self._save()
            return True
        return False

    def get_watches(self) -> List[Dict[str, Any]]:
        return list(self._watches.values())

    def record_scan(self, domain: str, interval_hours: int = 24, args: Optional[List[str]] = None) -> None:
        fd = self._acquire_lock()
        try:
            self._load()  # re-read to get latest state
            if domain not in self._watches:
                self._watches[domain] = {
                    "domain": domain,
                    "interval_hours": interval_hours,
                    "last_scan": None,
                    "next_scan": datetime.now().isoformat(),
                    "args": args or [],
                    "created": datetime.now().isoformat(),
                }
            now = datetime.now()
            interval = self._watches[domain].get("interval_hours", interval_hours)
            self._watches[domain]["last_scan"] = now.isoformat()
            self._watches[domain]["next_scan"] = (now + timedelta(hours=interval)).isoformat()
            self._save()
        finally:
            self._release_lock(fd)

    def due_scans(self) -> List[Dict[str, Any]]:
        fd = self._acquire_lock()
        try:
            self._load()  # re-read to get latest state
            now = datetime.now()
            due = []
            for domain, info in self._watches.items():
                next_str = info.get("next_scan", "")
                if next_str:
                    try:
                        next_dt = datetime.fromisoformat(next_str)
                        if next_dt <= now:
                            due.append(info)
                    except ValueError:
                        due.append(info)
                else:
                    due.append(info)
            return due
        finally:
            self._release_lock(fd)

    def run_due_scans(self, reconchain_cmd: str = "") -> List[str]:
        started = []
        if not reconchain_cmd:
            reconchain_cmd = os.path.abspath(sys.argv[0]) if sys.argv and sys.argv[0] else "reconchain"
        for scan in self.due_scans():
            domain = scan["domain"]
            args = scan.get("args", [])
            cmd = [reconchain_cmd, "-d", domain] + args
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                # Reap zombie: detach the process so init reaps it
                # We don't wait because these are daemon scans
                import threading as _threading
                def _reap(p: subprocess.Popen) -> None:
                    try:
                        p.wait()
                    except Exception:
                        pass
                _threading.Thread(target=_reap, args=(proc,), daemon=True).start()
                self.record_scan(domain)
                started.append(domain)
            except Exception as e:
                print(f"Monitor: failed to start scan for {domain}: {e}", file=sys.stderr)
        return started
