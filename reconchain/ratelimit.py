"""Rate limiter for outbound HTTP requests with per-domain tracking and adaptive backoff."""
import asyncio
import random
import time
from collections import defaultdict
from typing import Dict, Optional


class RateLimiter:
    def __init__(self, max_per_second: float = 0) -> None:
        self.max_per_second = max_per_second
        self._global_last = 0.0
        self._domain_last: Dict[str, float] = defaultdict(float)
        self._domain_failures: Dict[str, int] = defaultdict(int)
        self._backoff_factor = 2.0
        self._max_backoff = 60.0
        self._jitter = 0.1

    def _min_interval(self) -> float:
        return 1.0 / self.max_per_second if self.max_per_second > 0 else 0.0

    def acquire(self, domain: str = "") -> None:
        if self.max_per_second <= 0:
            return
        now = time.monotonic()
        global_interval = self._min_interval()
        since_global = now - self._global_last
        if since_global < global_interval:
            time.sleep(global_interval - since_global)
        self._global_last = time.monotonic()
        if domain:
            failures = self._domain_failures.get(domain, 0)
            backoff = min(self._backoff_factor ** failures, self._max_backoff) if failures > 0 else 0.0
            since_domain = time.monotonic() - self._domain_last[domain]
            wait = max(0.0, backoff - since_domain)
            if wait > 0:
                time.sleep(wait + random.uniform(0, self._jitter))
        self._domain_last[domain] = time.monotonic()

    async def acquire_async(self, domain: str = "") -> None:
        if self.max_per_second <= 0:
            return
        now = time.monotonic()
        global_interval = self._min_interval()
        since_global = now - self._global_last
        if since_global < global_interval:
            await asyncio.sleep(global_interval - since_global)
        self._global_last = time.monotonic()
        if domain:
            failures = self._domain_failures.get(domain, 0)
            backoff = min(self._backoff_factor ** failures, self._max_backoff) if failures > 0 else 0.0
            since_domain = time.monotonic() - self._domain_last[domain]
            wait = max(0.0, backoff - since_domain)
            if wait > 0:
                await asyncio.sleep(wait + random.uniform(0, self._jitter))
        self._domain_last[domain] = time.monotonic()

    def record_failure(self, domain: str = "") -> None:
        if domain:
            self._domain_failures[domain] += 1

    def record_success(self, domain: str = "") -> None:
        if domain and domain in self._domain_failures:
            self._domain_failures[domain] = max(0, self._domain_failures[domain] - 1)

    def reset(self) -> None:
        self._global_last = 0.0
        self._domain_last.clear()
        self._domain_failures.clear()
