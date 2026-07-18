"""Tool health monitoring — track per-tool metrics and auto-disable failing tools."""
from __future__ import annotations

import json
import os
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from reconchain.utils import ensure, log


@dataclass
class ToolMetrics:
    """Metrics for a single external tool."""
    name: str
    total_runs: int = 0
    successes: int = 0
    failures: int = 0
    consecutive_failures: int = 0
    total_runtime: float = 0.0
    avg_runtime: float = 0.0
    last_run: float = 0.0
    last_failure_reason: str = ""
    disabled: bool = False
    disabled_reason: str = ""

    @property
    def success_rate(self) -> float:
        return self.successes / max(self.total_runs, 1)

    def record_success(self, runtime: float) -> None:
        self.total_runs += 1
        self.successes += 1
        self.consecutive_failures = 0
        self.total_runtime += runtime
        self.avg_runtime = self.total_runtime / self.total_runs
        self.last_run = time.time()

    def record_failure(self, reason: str = "") -> None:
        self.total_runs += 1
        self.failures += 1
        self.consecutive_failures += 1
        self.last_failure_reason = reason
        self.last_run = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "total_runs": self.total_runs,
            "successes": self.successes,
            "failures": self.failures,
            "consecutive_failures": self.consecutive_failures,
            "success_rate": round(self.success_rate, 3),
            "avg_runtime": round(self.avg_runtime, 2),
            "disabled": self.disabled,
            "disabled_reason": self.disabled_reason,
            "last_failure_reason": self.last_failure_reason,
        }


class ToolHealthMonitor:
    """Track health metrics for all external tools."""

    FAILURE_THRESHOLD = 3  # Consecutive failures before disabling
    SLOW_THRESHOLD = 600  # Seconds — tool considered hung

    def __init__(self, state_path: Optional[Path] = None) -> None:
        self._tools: Dict[str, ToolMetrics] = {}
        self._state_path = state_path
        self._disabled_tools: set = set()
        if state_path and state_path.exists():
            self._load()

    def _load(self) -> None:
        if not self._state_path:
            return
        try:
            data = json.loads(self._state_path.read_text())
            for name, metrics in data.get("tools", {}).items():
                tm = ToolMetrics(name=name, **{k: v for k, v in metrics.items() if hasattr(ToolMetrics, k)})
                if tm.disabled:
                    self._disabled_tools.add(name)
                self._tools[name] = tm
        except Exception:
            pass

    def _save(self) -> None:
        if not self._state_path:
            return
        data = {
            "tools": {name: tm.to_dict() for name, tm in self._tools.items()},
            "disabled": list(self._disabled_tools),
        }
        import tempfile
        fd, tmp_path = tempfile.mkstemp(dir=str(self._state_path.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, str(self._state_path))
        except Exception:
            import contextlib
            with contextlib.suppress(Exception):
                os.unlink(tmp_path)
            raise

    def is_disabled(self, tool_name: str) -> bool:
        """Check if a tool has been auto-disabled."""
        return tool_name in self._disabled_tools

    def record_success(self, tool_name: str, runtime: float) -> None:
        """Record a successful tool execution."""
        if tool_name not in self._tools:
            self._tools[tool_name] = ToolMetrics(name=tool_name)
        self._tools[tool_name].record_success(runtime)
        self._tools[tool_name].disabled = False
        self._tools[tool_name].disabled_reason = ""
        self._disabled_tools.discard(tool_name)
        self._save()

    def record_failure(self, tool_name: str, reason: str = "") -> None:
        """Record a failed tool execution. Auto-disables after threshold."""
        if tool_name not in self._tools:
            self._tools[tool_name] = ToolMetrics(name=tool_name)
        tm = self._tools[tool_name]
        tm.record_failure(reason)

        if tm.consecutive_failures >= self.FAILURE_THRESHOLD:
            tm.disabled = True
            tm.disabled_reason = f"Auto-disabled after {tm.consecutive_failures} consecutive failures: {reason}"
            self._disabled_tools.add(tool_name)
            log("warn", f"Tool health: {tool_name} auto-disabled ({tm.consecutive_failures} failures)")

        self._save()

    def get_metrics(self, tool_name: str) -> Optional[ToolMetrics]:
        return self._tools.get(tool_name)

    def get_all_metrics(self) -> Dict[str, ToolMetrics]:
        return dict(self._tools)

    def get_summary(self) -> Dict[str, Any]:
        """Get summary of all tool health metrics."""
        total_tools = len(self._tools)
        healthy = sum(1 for tm in self._tools.values() if tm.success_rate >= 0.5 and not tm.disabled)
        degraded = sum(1 for tm in self._tools.values() if 0.2 <= tm.success_rate < 0.5 and not tm.disabled)
        failed = sum(1 for tm in self._tools.values() if tm.disabled)

        return {
            "total_tools": total_tools,
            "healthy": healthy,
            "degraded": degraded,
            "failed": failed,
            "disabled_tools": list(self._disabled_tools),
        }

    def write_report(self, outdir: Path) -> Path:
        """Write tool health report."""
        report = {
            "summary": self.get_summary(),
            "tools": {name: tm.to_dict() for name, tm in sorted(self._tools.items())},
        }
        out = ensure(outdir / "tool_health.json")
        out.write_text(json.dumps(report, indent=2, default=str))
        return out


# Global instance
_monitor: Optional[ToolHealthMonitor] = None


def get_tool_health_monitor(state_path: Optional[Path] = None) -> ToolHealthMonitor:
    """Get or create the global tool health monitor."""
    global _monitor
    if _monitor is None:
        _monitor = ToolHealthMonitor(state_path)
    return _monitor
