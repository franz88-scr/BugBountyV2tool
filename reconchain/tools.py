"""Tool binary detection and verification."""
from __future__ import annotations
import shutil
import subprocess
import time
from typing import Dict, List, Optional, Set

from reconchain.utils import log


class Tools:
    """Cached presence check for external binaries."""

    _RECHECK_INTERVAL = 60.0

    def __init__(self) -> None:
        self._cache: Dict[str, bool] = {}
        self._cache_ts: Dict[str, float] = {}
        self.missing_set: Set[str] = set()
        self.missing: List[str] = []
        self._broken: Dict[str, bool] = {}

    def have(self, *names: str) -> List[str]:
        out: List[str] = []
        for n in names:
            now = time.monotonic()
            if n not in self._cache or (not self._cache[n] and now - self._cache_ts.get(n, 0) > self._RECHECK_INTERVAL):
                ok = shutil.which(n) is not None
                self._cache[n] = ok
                self._cache_ts[n] = now
                if not ok and n not in self.missing_set:
                    self.missing_set.add(n)
                    self.missing.append(n)
            if self._cache[n] and not self._broken.get(n):
                out.append(n)
        return out

    def has(self, name: str) -> bool:
        return bool(self.have(name))

    def seed_missing(self, names: List[str]) -> None:
        for n in names:
            if n not in self.missing_set:
                self.missing_set.add(n)
                self.missing.append(n)

    def verify(self, name: str, args: Optional[List[str]] = None) -> bool:
        if not shutil.which(name):
            self._broken[name] = True
            return False
        try:
            result = subprocess.run(
                [name] + (args or ["--help"]),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
            ok = result.returncode == 0
            self._broken[name] = not ok
            if not ok:
                log("warn", f"tool {name} binary exists but failed verification (rc={result.returncode})")
            return ok
        except Exception as e:
            self._broken[name] = True
            log("warn", f"tool {name} verification failed: {e}")
            return False
