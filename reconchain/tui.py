"""Terminal UI dashboard — real-time ANSI-based scan monitoring."""
from __future__ import annotations

import os
import sys
import threading
import time
from typing import Any, Dict, List, Optional

from reconchain.utils import C, log


class TUIDashboard:
    """Real-time terminal dashboard for scan monitoring."""

    def __init__(self) -> None:
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._data: Dict[str, Any] = {
            "phase": "",
            "phases_completed": 0,
            "phases_total": 0,
            "findings": 0,
            "cpu": 0.0,
            "ram_gb": 0.0,
            "concurrency": 0,
            "elapsed": 0.0,
            "findings_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "recent_findings": [],
            "phase_timing": {},
        }
        self._lock = threading.Lock()
        self._start_time = 0.0

    def update(self, **kwargs: Any) -> None:
        with self._lock:
            self._data.update(kwargs)

    def add_finding(self, text: str, severity: str = "info") -> None:
        with self._lock:
            self._data["findings"] += 1
            sev = self._data["findings_by_severity"]
            sev[severity] = sev.get(severity, 0) + 1
            self._data["recent_findings"].append((text[:80], severity))
            if len(self._data["recent_findings"]) > 5:
                self._data["recent_findings"].pop(0)

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._start_time = time.time()
        self._thread = threading.Thread(target=self._render_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)

    def _render_loop(self) -> None:
        while self._running:
            try:
                self._render()
            except Exception:
                pass
            time.sleep(1.0)

    def _render(self) -> None:
        with self._lock:
            d = dict(self._data)

        elapsed = time.time() - self._start_time if self._start_time else 0
        elapsed_str = f"{int(elapsed // 60):02d}:{int(elapsed % 60):02d}"
        total = d.get("phases_total", 0)
        done = d.get("phases_completed", 0)
        progress = f"{done}/{total}" if total else "?/?"

        # Progress bar
        if total > 0:
            bar_width = 30
            filled = int(bar_width * done / total)
            bar = "█" * filled + "░" * (bar_width - filled)
        else:
            bar = "░" * 30

        sev = d.get("findings_by_severity", {})
        cpu = d.get("cpu", 0)
        ram = d.get("ram_gb", 0)
        conc = d.get("concurrency", 0)

        # Build output
        lines = [
            f"\033[2J\033[H",  # Clear screen
            f"{C['c']}╔══════════════════════════════════════════════════════════╗{C['r']}",
            f"{C['c']}║{C['r']} {C['b']}ReconChain v3.0 — Live Dashboard{C['r']}",
            f"{C['c']}╠══════════════════════════════════════════════════════════╣{C['r']}",
            f"{C['c']}║{C['r']} Phase: {C['y']}{d.get('phase', 'starting'):<40}{C['r']}",
            f"{C['c']}║{C['r']} Progress: [{C['g']}{bar}{C['r']}] {progress}",
            f"{C['c']}║{C['r']} Elapsed: {elapsed_str}  |  Findings: {C['b']}{d.get('findings', 0)}{C['r']}",
            f"{C['c']}╠══════════════════════════════════════════════════════════╣{C['r']}",
            f"{C['c']}║{C['r']} Resources: CPU {cpu:.0f}% | RAM {ram:.1f}GB | Concurrency {conc}",
            f"{C['c']}║{C['r']} Severity: {C['err']}C:{sev.get('critical',0)}{C['r']} {C['warn']}H:{sev.get('high',0)}{C['r']} {C['y']}M:{sev.get('medium',0)}{C['r']} {C['ok']}L:{sev.get('low',0)}{C['r']} I:{sev.get('info',0)}",
            f"{C['c']}╠══════════════════════════════════════════════════════════╣{C['r']}",
        ]

        recent = d.get("recent_findings", [])
        for text, sev_level in recent[-4:]:
            color = {"critical": "err", "high": "warn", "medium": "y", "low": "ok"}.get(sev_level, "d")
            lines.append(f"{C['c']}║{C['r']} {C[color]}●{C['r']} {text}")

        if not recent:
            lines.append(f"{C['c']}║{C['r']} {C['d']}Waiting for findings...{C['r']}")

        lines.append(f"{C['c']}╚══════════════════════════════════════════════════════════╝{C['r']}")

        sys.stderr.write("\n".join(lines) + "\n")
        sys.stderr.flush()


# Global instance
_tui: Optional[TUIDashboard] = None


def get_tui() -> TUIDashboard:
    global _tui
    if _tui is None:
        _tui = TUIDashboard()
    return _tui
