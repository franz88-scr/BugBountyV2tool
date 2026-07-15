"""Adaptive resource monitor: dynamically adjusts concurrency based on CPU/RAM."""
from __future__ import annotations

import asyncio
import logging
import os
import signal
import threading
import time
from typing import Callable, Optional

_log = logging.getLogger("resmon")


class AdaptiveSemaphore:
    """asyncio.Semaphore replacement with dynamic resize capability.

    Thread-safe: resize() can be called from the monitor thread while
    coroutines await acquire() on the event loop thread.

    Uses asyncio.Condition for full control over permit count.
    """

    def __init__(self, value: int = 1, initial: Optional[int] = None) -> None:
        init_val = initial if initial is not None else value
        self._limit = init_val
        self._permits = init_val
        self._cond: Optional[asyncio.Condition] = None
        self._lock = threading.Lock()

    def _get_cond(self) -> asyncio.Condition:
        if self._cond is None:
            self._cond = asyncio.Condition()
        return self._cond

    @property
    def limit(self) -> int:
        with self._lock:
            return self._limit

    def resize(self, new_limit: int) -> int:
        """Adjust the semaphore capacity. Returns the actual new limit.

        Increases are immediate (release extra permits).
        Decreases are deferred — excess permits drain naturally as tasks
        release them, so we never block or steal held permits.

        new_limit=0 is special: it *pauses* the semaphore (all acquire()
        calls block) until resize(>=1) is called.
        """
        with self._lock:
            old = self._limit
            self._limit = new_limit
            if new_limit > old:
                diff = new_limit - old
                self._permits += diff
                cond = self._cond
                if cond is not None:
                    try:
                        loop = asyncio.get_running_loop()
                    except RuntimeError:
                        loop = None
                    if loop is not None:
                        async def _notify():
                            async with cond:
                                cond.notify_all()
                        loop.create_task(_notify())
            elif new_limit < old:
                self._permits = min(self._permits, max(new_limit, 0))
            return self._limit

    async def acquire(self) -> None:
        cond = self._get_cond()
        async with cond:
            while self._permits <= 0:
                await cond.wait()
            self._permits -= 1

    def release(self) -> None:
        with self._lock:
            if self._permits < self._limit:
                self._permits += 1
        cond = self._cond
        if cond is None:
            return
        loop = None
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            pass
        if loop is not None:
            async def _notify():
                async with cond:
                    cond.notify_all()
            loop.create_task(_notify())

    def locked(self) -> bool:
        with self._lock:
            return self._permits <= 0

    def __repr__(self) -> str:
        return f"AdaptiveSemaphore(limit={self._limit}, permits={self._permits})"

    async def __aenter__(self) -> AdaptiveSemaphore:
        await self.acquire()
        return self

    async def __aexit__(self, *args: object) -> None:
        self.release()


class AdaptiveThreadSemaphore:
    """threading.Semaphore replacement with dynamic resize capability.

    Unlike replacing the entire semaphore object (which orphans blocked
    threads), this adjusts permits in-place by releasing/acquiring extras.
    """

    def __init__(self, value: int = 1) -> None:
        self._sem = threading.Semaphore(value)
        self._limit = value
        self._lock = threading.Lock()

    @property
    def limit(self) -> int:
        with self._lock:
            return self._limit

    def resize(self, new_limit: int) -> int:
        """Adjust capacity without orphaning blocked threads."""
        with self._lock:
            if new_limit <= 0:
                new_limit = 0
            old = self._limit
            self._limit = new_limit
            diff = new_limit - old
        if diff > 0:
            for _ in range(diff):
                self._sem.release()
        elif diff < 0:
            for _ in range(-diff):
                try:
                    self._sem.acquire(blocking=False)
                except RuntimeError:
                    break
        return self._limit

    def acquire(self, blocking: bool = True, timeout: float = -1) -> bool:
        return self._sem.acquire(blocking=blocking, timeout=timeout)

    def release(self, n: int = 1) -> None:
        self._sem.release(n)

    def __repr__(self) -> str:
        return f"AdaptiveThreadSemaphore(limit={self._limit})"


class ResourceMonitor:
    """Background thread that monitors CPU/RAM and resizes semaphores.

    Starts conservatively and ramps up when the system has headroom.
    Includes an emergency circuit breaker that pauses all new process
    spawning when RAM drops critically low.
    """

    def __init__(
        self,
        initial: int = 2,
        max_limit: Optional[int] = None,
        interval: float = 5.0,
        cpu_low: float = 50.0,
        cpu_high: float = 80.0,
        ram_low_bytes: int = 2 * 1024 * 1024 * 1024,   # 2 GB free to scale up
        ram_crit_bytes: int = 1 * 1024 * 1024 * 1024,    # 1 GB free to scale down
        ram_emergency_bytes: int = 500 * 1024 * 1024,     # 500 MB = PAUSE everything
        ram_resume_bytes: int = 1500 * 1024 * 1024,       # 1.5 GB free to unpause
        max_os_procs: Optional[int] = None,
    ) -> None:
        if max_limit is None:
            max_limit = min((os.cpu_count() or 4) * 2, 8)
        if max_os_procs is None:
            max_os_procs = min(max(1, (os.cpu_count() or 4)), 4)
        self._initial = max(1, initial)
        self._max_limit = max(1, max_limit)
        self._max_os_procs = max(1, max_os_procs)
        self._interval = max(1.0, interval)
        self._cpu_low = cpu_low
        self._cpu_high = cpu_high
        self._ram_low = ram_low_bytes
        self._ram_crit = ram_crit_bytes
        self._ram_emergency = ram_emergency_bytes
        self._ram_resume = ram_resume_bytes

        self._sem: Optional[AdaptiveSemaphore] = None
        self._os_sem: Optional[AdaptiveThreadSemaphore] = None
        self._on_resize: Optional[Callable[[int], None]] = None

        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._started = False

        # Emergency state
        self._paused = False
        self._pause_event = asyncio.Event()
        self._pause_event.set()  # not paused initially

        # Stats
        self.current_concurrency = self._initial
        self.cpu_percent = 0.0
        self.ram_available_gb = 0.0

    @property
    def paused(self) -> bool:
        return self._paused

    def bind(
        self,
        sem: AdaptiveSemaphore,
        os_sem: Optional[AdaptiveThreadSemaphore] = None,
        on_resize: Optional[Callable[[int], None]] = None,
    ) -> None:
        self._sem = sem
        self._os_sem = os_sem
        self._on_resize = on_resize
        self.current_concurrency = sem.limit

    @property
    def paused(self) -> bool:
        return self._paused

    def start(self) -> None:
        if self._started:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="resmon")
        self._thread.start()
        self._started = True

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=self._interval + 2)
        self._started = False

    async def wait_if_paused(self) -> None:
        """Called by pipeline before starting a new phase. Blocks while paused."""
        if self._paused:
            await self._pause_event.wait()

    # -- resource reading ---------------------------------------------------

    @staticmethod
    def _read_cpu_percent() -> float:
        """Read CPU usage. Returns 0.0-100.0 average across all cores."""
        try:
            import psutil
            return psutil.cpu_percent(interval=1)
        except ImportError:
            pass
        # Fallback: /proc/stat (Linux)
        try:
            with open("/proc/stat") as f:
                line = f.readline()
            parts = line.split()
            vals = [int(parts[i]) for i in range(1, min(9, len(parts)))]
            idle = vals[3] + vals[4]
            total = sum(vals)
            time.sleep(1)
            with open("/proc/stat") as f:
                line2 = f.readline()
            parts2 = line2.split()
            vals2 = [int(parts2[i]) for i in range(1, min(9, len(parts2)))]
            idle2 = vals2[3] + vals2[4]
            total2 = sum(vals2)
            d_idle = idle2 - idle
            d_total = total2 - total
            if d_total <= 0:
                return 0.0
            return max(0.0, min(100.0, (1.0 - d_idle / d_total) * 100.0))
        except (OSError, IndexError, ValueError):
            return 0.0

    @staticmethod
    def _read_ram_available() -> int:
        """Read available RAM in bytes (Linux /proc/meminfo)."""
        try:
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemAvailable:"):
                        return int(line.split()[1]) * 1024
        except (OSError, ValueError):
            pass
        return 4 * 1024 * 1024 * 1024

    @staticmethod
    def _count_child_procs() -> int:
        """Count total descendant processes of this process (Linux /proc)."""
        try:
            import psutil
            return len(psutil.Process().children(recursive=True))
        except (ImportError, psutil.NoSuchProcess):
            pass
        try:
            my_pid = os.getpid()
            count = 0
            for entry in os.listdir("/proc"):
                if not entry.isdigit():
                    continue
                try:
                    ppid = int(open(f"/proc/{entry}/stat").read().split(")")[1].split()[1])
                    if ppid == my_pid:
                        count += 1
                except (OSError, IndexError, ValueError):
                    pass
            return count
        except OSError:
            return 0

    def _emergency_kill_children(self) -> None:
        """Kill all descendant processes to free RAM in emergency."""
        _log.warning(
            f"EMERGENCY PAUSE: RAM={self.ram_available_gb:.1f}GB "
            f"(<{self._ram_emergency / (1024**3):.1f}GB). "
            f"Killing child processes to free memory."
        )
        my_pid = os.getpid()
        killed = 0
        try:
            for entry in os.listdir("/proc"):
                if not entry.isdigit():
                    continue
                try:
                    pid = int(entry)
                    if pid == my_pid:
                        continue
                    ppid = int(open(f"/proc/{entry}/stat").read().split(")")[1].split()[1])
                    if ppid == my_pid:
                        os.kill(pid, signal.SIGTERM)
                        killed += 1
                except (OSError, IndexError, ValueError, ProcessLookupError, PermissionError):
                    pass
        except OSError:
            pass
        # Also kill grandchildren
        try:
            for entry in os.listdir("/proc"):
                if not entry.isdigit():
                    continue
                try:
                    pid = int(entry)
                    ppid = int(open(f"/proc/{entry}/stat").read().split(")")[1].split()[1])
                    # Check if ppid is a direct child we're about to kill
                    if ppid != my_pid:
                        # Check grandparent
                        pppid = int(open(f"/proc/{ppid}/stat").read().split(")")[1].split()[1])
                        if pppid == my_pid:
                            os.kill(pid, signal.SIGTERM)
                            killed += 1
                except (OSError, IndexError, ValueError, ProcessLookupError, PermissionError):
                    pass
        except OSError:
            pass
        if killed:
            _log.warning(f"Sent SIGTERM to {killed} child/grandchild processes")
        # Force SIGKILL after 3s for stubborn processes
        time.sleep(3)
        try:
            for entry in os.listdir("/proc"):
                if not entry.isdigit():
                    continue
                try:
                    pid = int(entry)
                    if pid == my_pid:
                        continue
                    ppid = int(open(f"/proc/{entry}/stat").read().split(")")[1].split()[1])
                    if ppid == my_pid:
                        os.kill(pid, signal.SIGKILL)
                except (OSError, IndexError, ValueError, ProcessLookupError, PermissionError):
                    pass
        except OSError:
            pass

    # -- main loop ----------------------------------------------------------

    def _run(self) -> None:
        self.cpu_percent = self._read_cpu_percent()
        self.ram_available_gb = self._read_ram_available() / (1024 ** 3)

        while not self._stop.is_set():
            self._stop.wait(timeout=self._interval)
            if self._stop.is_set():
                break
            self._measure_and_adjust()

    def _measure_and_adjust(self) -> None:
        self.cpu_percent = self._read_cpu_percent()
        ram_bytes = self._read_ram_available()
        self.ram_available_gb = ram_bytes / (1024 ** 3)
        cur = self.current_concurrency
        child_procs = self._count_child_procs()

        # --- EMERGENCY: RAM critically low → pause + kill excess children ---
        if ram_bytes < self._ram_emergency:
            if not self._paused:
                self._paused = True
                self._pause_event.clear()
                if self._sem is not None:
                    self._sem.resize(0)
                self.current_concurrency = 0
                if self._os_sem is not None:
                    self._os_sem.resize(1)
                self._emergency_kill_children()
            return

        # --- RESUME: RAM recovered enough → unpause ---
        if self._paused and ram_bytes >= self._ram_resume:
            self._paused = False
            self._pause_event.set()
            # Restore OS semaphore to hard cap
            if self._os_sem is not None:
                self._os_sem.resize(self._max_os_procs)
            # Will fall through to normal scaling below

        # --- Normal adaptive scaling ---
        if self._paused:
            return

        # Scale up only if CPU low, RAM headroom, AND child process count is reasonable
        if (self.cpu_percent < self._cpu_low
                and ram_bytes > self._ram_low
                and child_procs < self._max_os_procs * 3):
            new = min(cur + 1, self._max_limit)
        # Scale down if ANY pressure signal: high CPU, low RAM, or too many child procs
        elif (self.cpu_percent > self._cpu_high
              or ram_bytes < self._ram_crit
              or child_procs >= self._max_os_procs * 5):
            new = max(cur - 1, 2)
        else:
            new = cur

        if new != cur and self._sem is not None:
            actual = self._sem.resize(new)
            self.current_concurrency = actual
            if self._on_resize:
                try:
                    os_n = min(actual, self._max_os_procs)
                    self._on_resize(os_n)
                except Exception:
                    pass


# --- Singleton accessor ---------------------------------------------------

_resource_monitor_instance: Optional[ResourceMonitor] = None


def get_resource_monitor(**kwargs) -> ResourceMonitor:
    """Return the global ResourceMonitor singleton, creating it if needed."""
    global _resource_monitor_instance
    if _resource_monitor_instance is None:
        _resource_monitor_instance = ResourceMonitor(**kwargs)
    return _resource_monitor_instance


def reset_resource_monitor() -> None:
    """Reset the singleton (for tests / pipeline restart)."""
    global _resource_monitor_instance
    if _resource_monitor_instance is not None:
        _resource_monitor_instance.stop()
    _resource_monitor_instance = None
