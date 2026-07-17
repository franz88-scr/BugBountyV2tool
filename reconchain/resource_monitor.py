"""Adaptive resource monitor: dynamically adjusts concurrency based on CPU/RAM."""
from __future__ import annotations

import asyncio
import logging
import os
import signal
import threading
import time
from pathlib import Path
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

    def resize(self, new_limit: int, *, main_loop: Optional[asyncio.AbstractEventLoop] = None) -> int:
        """Adjust the semaphore capacity. Returns the actual new limit.

        Increases are immediate (release extra permits).
        Decreases cap free permits immediately; held permits drain naturally.
        new_limit=0 pauses the semaphore (all acquire() calls block).
        """
        new_limit = max(0, new_limit)
        with self._lock:
            old = self._limit
            self._limit = new_limit
            if new_limit > old:
                diff = new_limit - old
                self._permits += diff
                cond = self._cond
                if cond is not None:
                    loop = main_loop
                    if loop is None:
                        try:
                            loop = asyncio.get_running_loop()
                        except RuntimeError:
                            loop = None
                    if loop is not None and loop.is_running():
                        async def _notify():
                            async with cond:
                                cond.notify_all()
                        def _schedule_notify():
                            task = loop.create_task(_notify())
                            task.add_done_callback(lambda t: t.exception() if not t.cancelled() else None)
                        loop.call_soon_threadsafe(_schedule_notify)
            elif new_limit < old:
                # BUG 3 FIX: Account for held permits to prevent over-commit
                held = old - self._permits
                self._permits = max(0, new_limit - held)
            return self._limit

    async def acquire(self) -> None:
        """Acquire a permit. Blocks until one is available.

        Uses the standard condition-variable predicate loop to prevent
        lost-wakeup races: cond.notify_all() from resize() is always
        received because we hold cond's lock for the entire wait.
        """
        cond = self._get_cond()
        async with cond:
            while True:
                with self._lock:
                    if self._permits > 0:
                        self._permits -= 1
                        return
                await cond.wait()

    def release(self) -> None:
        """Release a permit back to the pool."""
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
        if loop is not None and loop.is_running():
            async def _notify():
                async with cond:
                    cond.notify_all()
            loop.create_task(_notify())

    def locked(self) -> bool:
        with self._lock:
            return self._permits <= 0

    def __repr__(self) -> str:
        with self._lock:
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
        self._count = 0

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
            # Reclaim permits from the underlying semaphore.
            # Use a loop with short timeout to avoid giving up too early.
            reclaimed = 0
            for _ in range(-diff):
                acquired = self._sem.acquire(blocking=True, timeout=0.1)
                if acquired:
                    reclaimed += 1
                else:
                    # Can't reclaim more permits right now (all held by workers)
                    # Update _count to reflect what we actually reclaimed
                    break
        return self._limit

    def acquire(self, blocking: bool = True, timeout: float = -1) -> bool:
        result = self._sem.acquire(blocking=blocking, timeout=timeout)
        if result:
            with self._lock:
                self._count += 1
        return result

    def release(self, n: int = 1) -> None:
        with self._lock:
            current_count = self._count
            allowed = max(0, self._limit - current_count)
            n = min(n, allowed)
            if n > 0:
                self._count -= n
        if n > 0:
            self._sem.release(n)

    def __repr__(self) -> str:
        with self._lock:
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
        ram_emergency_bytes: int = 2 * 1024 * 1024 * 1024,  # 2 GB = PAUSE everything
        ram_resume_bytes: int = 2 * 1024 * 1024 * 1024,    # 2 GB free to unpause
        max_os_procs: Optional[int] = None,
    ) -> None:
        if max_limit is None:
            max_limit = min((os.cpu_count() or 4) * 2, 8)
        if max_os_procs is None:
            max_os_procs = min(max(8, (os.cpu_count() or 4) * 2), 12)
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

        # Emergency state — use threading.Event for thread-safe pause/resume
        self._paused = False
        self._pause_event: Optional[asyncio.Event] = None
        self._paused_lock = threading.Lock()
        self._main_loop: Optional[asyncio.AbstractEventLoop] = None

        # Stats
        self.current_concurrency = self._initial
        self.cpu_percent = 0.0
        self.ram_available_gb = 0.0

        # BUG 11 FIX: Prime psutil CPU measurement (non-blocking after first call)
        try:
            import psutil
            psutil.cpu_percent(interval=None)
        except ImportError:
            pass

    @property
    def paused(self) -> bool:
        with self._paused_lock:
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

    def start(self) -> None:
        if self._started:
            return
        # Capture the event loop reference from the calling (main) thread
        try:
            self._main_loop = asyncio.get_running_loop()
        except RuntimeError:
            self._main_loop = None
        # Lazily create the asyncio.Event bound to the running loop
        if self._pause_event is None and self._main_loop is not None:
            self._pause_event = asyncio.Event()
            self._pause_event.set()  # not paused initially
        self._stop.clear()
        self.ram_available_gb = self._read_ram_available() / (1024 ** 3)
        self.cpu_percent = self._read_cpu_percent()
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
        # BUG 9 FIX: Always check the event (remove TOCTOU race)
        if self._pause_event is not None:
            await self._pause_event.wait()

    # -- resource reading ---------------------------------------------------

    def _update_config(self, **kwargs: Any) -> None:
        """Update config kwargs for existing singleton (called from get_resource_monitor)."""
        for k, v in kwargs.items():
            attr = f"_{k}"
            if hasattr(self, attr):
                setattr(self, attr, v)
            elif k in ("initial",):
                pass

    @staticmethod
    def _read_cpu_percent() -> float:
        """Read CPU usage. Returns 0.0-100.0 average across all cores."""
        try:
            import psutil
            # BUG 11 FIX: Use non-blocking call after priming in __init__
            return psutil.cpu_percent(interval=None)
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
            time.sleep(0.1)
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
            pid_set = set()
            for entry in os.listdir("/proc"):
                if not entry.isdigit():
                    continue
                try:
                    pid = int(entry)
                    stat = Path(f"/proc/{entry}/stat").read_text()
                    ppid = int(stat.split(")")[1].split()[1])
                    pid_set.add((pid, ppid))
                except (OSError, IndexError, ValueError):
                    pass
            # Build adjacency and walk recursively
            children_map: Dict[int, List[int]] = {}
            for pid, ppid in pid_set:
                if pid == my_pid:
                    continue
                children_map.setdefault(ppid, []).append(pid)
            count = 0
            stack = list(children_map.get(my_pid, []))
            while stack:
                pid = stack.pop()
                count += 1
                stack.extend(children_map.get(pid, []))
            return count
        except OSError:
            return 0

    def _emergency_kill_children(self) -> None:
        """Kill all descendant processes to free RAM in emergency.

        BUG 7+8 FIX: Use psutil recursive children if available (handles
        arbitrary depth). Fallback: snapshot PIDs first, then kill to avoid
        PID recycling hitting wrong processes.
        """
        _log.warning(
            f"EMERGENCY PAUSE: RAM={self.ram_available_gb:.1f}GB "
            f"(<{self._ram_emergency / (1024**3):.1f}GB). "
            f"Killing child processes to free memory."
        )
        # Try psutil first — handles arbitrary process tree depth
        try:
            import psutil
            parent = psutil.Process()
            for child in parent.children(recursive=True):
                try:
                    child.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                    pass
            return
        except (ImportError, psutil.NoSuchProcess):
            pass

        # Fallback: manual /proc walk with PID snapshot (recursive kill)
        my_pid = os.getpid()
        pid_set = set()
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            try:
                pid = int(entry)
                if pid == my_pid:
                    continue
                stat = Path(f"/proc/{entry}/stat").read_text()
                ppid = int(stat.split(")")[1].split()[1])
                pid_set.add((pid, ppid))
            except (OSError, IndexError, ValueError):
                pass
        children_map: Dict[int, List[int]] = {}
        for pid, ppid in pid_set:
            children_map.setdefault(ppid, []).append(pid)
        to_kill = set()
        stack = list(children_map.get(my_pid, []))
        while stack:
            pid = stack.pop()
            to_kill.add(pid)
            stack.extend(children_map.get(pid, []))

        if to_kill:
            for pid in to_kill:
                try:
                    os.kill(pid, signal.SIGTERM)
                except (OSError, ProcessLookupError, PermissionError):
                    pass
            _log.warning(f"Sent SIGTERM to {len(to_kill)} child processes")

        # Force SIGKILL after 3s for stubborn processes — use same snapshot
        time.sleep(3)
        for pid in to_kill:
            try:
                os.kill(pid, signal.SIGKILL)
            except (OSError, ProcessLookupError, PermissionError):
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
            with self._paused_lock:
                if not self._paused:
                    self._paused = True
                    if self._pause_event is not None and self._main_loop is not None:
                        self._main_loop.call_soon_threadsafe(self._pause_event.clear)
                    if self._sem is not None:
                        self._sem.resize(0, main_loop=self._main_loop)
                    self.current_concurrency = 0
                    # BUG 15 FIX: Resize to 0, not 1 — no OS process should start during emergency
                    if self._os_sem is not None:
                        self._os_sem.resize(0)
            self._emergency_kill_children()
            return

        # --- RESUME: RAM recovered enough → unpause ---
        # BUG 17 FIX: Also handle partial recovery (RAM above emergency but below full resume)
        if self._paused:
            if ram_bytes >= self._ram_resume:
                # Full resume
                with self._paused_lock:
                    self._paused = False
                if self._pause_event is not None and self._main_loop is not None:
                    self._main_loop.call_soon_threadsafe(self._pause_event.set)
                if self._os_sem is not None:
                    self._os_sem.resize(self._max_os_procs)
            elif ram_bytes >= self._ram_emergency * 2:
                # Partial recovery — resume with reduced concurrency
                with self._paused_lock:
                    self._paused = False
                if self._pause_event is not None and self._main_loop is not None:
                    self._main_loop.call_soon_threadsafe(self._pause_event.set)
                if self._os_sem is not None:
                    self._os_sem.resize(max(2, self._max_os_procs // 2))
                # Start conservatively after emergency
                if self._sem is not None:
                    actual = self._sem.resize(self._initial, main_loop=self._main_loop)
                    self.current_concurrency = actual
            # else: still paused, RAM between emergency and 2× emergency — wait

        # --- Normal adaptive scaling ---
        if self._paused:
            return

        # Scale up only if CPU low, RAM headroom, AND child process count is reasonable
        if (self.cpu_percent < self._cpu_low
                and ram_bytes > self._ram_low
                and child_procs < self._max_os_procs * 3):
            new = min(cur + 2, self._max_limit)
        # Scale down if ANY pressure signal: high CPU, low RAM, or too many child procs
        elif (self.cpu_percent > self._cpu_high
              or ram_bytes < self._ram_crit
              or child_procs >= self._max_os_procs * 5):
            new = max(cur - 1, 2)
        else:
            new = cur

        if new != cur and self._sem is not None:
            actual = self._sem.resize(new, main_loop=self._main_loop)
            self.current_concurrency = actual
            # Also scale OS process semaphore proportionally to async concurrency
            if self._os_sem is not None:
                os_new = min(actual * 2, self._max_os_procs)
                os_new = max(os_new, 2)  # never go below 2
                self._os_sem.resize(os_new)
            # BUG 10 FIX: Use same value for callback as for os_sem.resize()
            if self._on_resize:
                try:
                    os_new_cb = min(actual * 2, self._max_os_procs)
                    os_new_cb = max(os_new_cb, 2)
                    self._on_resize(os_new_cb)
                except Exception:
                    pass


# --- Singleton accessor ---------------------------------------------------

_resource_monitor_instance: Optional[ResourceMonitor] = None
_resource_monitor_lock = threading.Lock()


def get_resource_monitor(**kwargs) -> ResourceMonitor:
    """Return the global ResourceMonitor singleton, creating it if needed."""
    global _resource_monitor_instance
    with _resource_monitor_lock:
        if _resource_monitor_instance is None:
            _resource_monitor_instance = ResourceMonitor(**kwargs)
        elif kwargs:
            _resource_monitor_instance._update_config(**kwargs)
    return _resource_monitor_instance


def reset_resource_monitor() -> None:
    """Reset the singleton (for tests / pipeline restart)."""
    global _resource_monitor_instance
    with _resource_monitor_lock:
        if _resource_monitor_instance is not None:
            _resource_monitor_instance.stop()
            _resource_monitor_instance = None
