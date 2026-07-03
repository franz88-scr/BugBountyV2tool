"""Monitor engine — periodic re-scan scheduling with persistence and status tracking."""
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional


class MonitorEngine:
    def __init__(self, state_dir: Optional[Path] = None) -> None:
        self._state_dir = state_dir or Path.home() / ".config" / "reconchain" / "monitor"
        self._state_dir.mkdir(parents=True, exist_ok=True)
        self._state_file = self._state_dir / "watches.json"
        self._watches: Dict[str, Dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        if self._state_file.exists():
            try:
                with self._state_file.open() as f:
                    self._watches = json.load(f)
            except (json.JSONDecodeError, OSError):
                self._watches = {}

    def _save(self) -> None:
        with self._state_file.open("w") as f:
            json.dump(self._watches, f, indent=2, default=str)

    def watch(self, domain: str, interval_hours: int = 24, args: Optional[List[str]] = None) -> None:
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
        if domain not in self._watches:
            self.watch(domain, interval_hours, args)
        now = datetime.now()
        interval = self._watches[domain].get("interval_hours", interval_hours)
        self._watches[domain]["last_scan"] = now.isoformat()
        self._watches[domain]["next_scan"] = (now + timedelta(hours=interval)).isoformat()
        self._save()

    def due_scans(self) -> List[Dict[str, Any]]:
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

    def run_due_scans(self, reconchain_cmd: str = "reconchain") -> List[str]:
        started = []
        for scan in self.due_scans():
            domain = scan["domain"]
            args = scan.get("args", [])
            cmd = [reconchain_cmd, "-d", domain] + args
            try:
                subprocess.Popen(
                    cmd,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                self.record_scan(domain)
                started.append(domain)
            except Exception as e:
                print(f"Monitor: failed to start scan for {domain}: {e}", file=sys.stderr)
        return started
