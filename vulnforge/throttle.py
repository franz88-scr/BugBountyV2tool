"""Throttle — unified rate limiting for outbound requests.

Combines token-bucket (burst-aware) and adaptive-backoff (per-domain) rate
limiting into a single module.  Provides both sync and async APIs, thread-safe
domain eviction, and a configurable global + per-domain limiter.

Usage::

    from vulnforge.throttle import GlobalRateLimiter, RateLimiter, TokenBucket

    # Quick global limiter
    limiter = GlobalRateLimiter(rate=10, burst=20, per_domain_rate=5)
    async with limiter:
        await make_request(url)

    # Simple per-domain limiter with backoff
    rl = RateLimiter(max_per_second=5)
    rl.acquire(domain="example.com")
"""

from __future__ import annotations

import asyncio
import random
import threading
import time
from collections import defaultdict
from typing import Dict, Optional

# ── Token Bucket ────────────────────────────────────────────────────────


class TokenBucket:
    """Thread-safe token bucket rate limiter."""

    def __init__(self, rate: float, burst: int = 1):
        self.rate = rate
        self.burst = burst
        self._tokens = float(burst)
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
        self._last_refill = now

    def acquire(self, tokens: int = 1) -> bool:
        with self._lock:
            self._refill()
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False

    def wait_time(self, tokens: int = 1) -> float:
        with self._lock:
            self._refill()
            if self._tokens >= tokens:
                return 0.0
            return (tokens - self._tokens) / self.rate

    @property
    def available(self) -> float:
        with self._lock:
            self._refill()
            return self._tokens


class AsyncTokenBucket:
    """Async wrapper around TokenBucket for use in async phase functions."""

    def __init__(self, rate: float, burst: int = 1):
        self._bucket = TokenBucket(rate, burst)
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: int = 1) -> None:
        while True:
            if self._bucket.acquire(tokens):
                return
            wait = self._bucket.wait_time(tokens)
            await asyncio.sleep(min(wait, 0.1))

    async def try_acquire(self, tokens: int = 1) -> bool:
        return self._bucket.acquire(tokens)


# ── Global Rate Limiter (burst-aware) ──────────────────────────────────


class GlobalRateLimiter:
    """Coordinated rate limiter with per-domain and global limits.

    Usage:
        limiter = GlobalRateLimiter(rate=10, burst=20, per_domain_rate=5, per_domain_burst=10)
        async with limiter:
            await make_request(url)
    """

    def __init__(
        self,
        rate: float = 0,
        burst: int = 0,
        per_domain_rate: float = 0,
        per_domain_burst: int = 0,
    ):
        self.rate = rate
        self.burst = burst
        self.per_domain_rate = per_domain_rate
        self.per_domain_burst = per_domain_burst

        self._global_bucket: Optional[AsyncTokenBucket] = None
        self._domain_buckets: dict[str, AsyncTokenBucket] = {}
        self._domain_lock = asyncio.Lock()

        if rate > 0:
            self._global_bucket = AsyncTokenBucket(rate, burst or max(1, int(rate)))

    async def _get_domain_bucket(self, domain: str) -> AsyncTokenBucket:
        async with self._domain_lock:
            if domain not in self._domain_buckets:
                self._domain_buckets[domain] = AsyncTokenBucket(
                    self.per_domain_rate,
                    self.per_domain_burst or max(1, int(self.per_domain_rate)),
                )
            return self._domain_buckets[domain]

    async def acquire(self, domain: str = "") -> None:
        if self._global_bucket:
            await self._global_bucket.acquire()
        if self.per_domain_rate > 0 and domain:
            bucket = await self._get_domain_bucket(domain)
            await bucket.acquire()
        if len(self._domain_buckets) > 1000:
            async with self._domain_lock:
                if len(self._domain_buckets) > 1000:
                    await self._cleanup_domains()

    async def try_acquire(self, domain: str = "") -> bool:
        if self._global_bucket and not await self._global_bucket.try_acquire():
            return False
        if self.per_domain_rate > 0 and domain:
            bucket = await self._get_domain_bucket(domain)
            if not await bucket.try_acquire():
                return False
        return True

    async def __aenter__(self):
        await self.acquire()
        return self

    async def __aexit__(self, *args):
        pass

    async def _cleanup_domains(self) -> int:
        """Remove stale domain buckets (caller must hold _domain_lock)."""
        removed = 0
        stale = [
            d
            for d, b in self._domain_buckets.items()
            if b._bucket.available >= b._bucket.burst * 0.9
        ]
        for d in stale[: max(0, len(stale) - 50)]:
            self._domain_buckets.pop(d, None)
            removed += 1
        return removed

    async def cleanup_domains(self) -> int:
        """Remove stale domain buckets. Returns number removed."""
        async with self._domain_lock:
            return await self._cleanup_domains()


# ── Per-Domain Adaptive Rate Limiter ────────────────────────────────────


class RateLimiter:
    """Per-domain rate limiter with adaptive backoff on failures.

    Tracks global and per-domain request timing, automatically backs off
    when a domain returns errors, and evicts stale entries to bound memory.
    """

    _MAX_DOMAINS = 10000

    def __init__(self, max_per_second: float = 0) -> None:
        self.max_per_second = max_per_second
        self._global_last = 0.0
        self._domain_last: Dict[str, float] = defaultdict(float)
        self._domain_failures: Dict[str, int] = defaultdict(int)
        self._backoff_factor = 2.0
        self._max_backoff = 60.0
        self._jitter = 0.1
        self._sync_lock = threading.Lock()

    def _evict_old_domains(self) -> None:
        if len(self._domain_last) <= self._MAX_DOMAINS:
            return
        now = time.monotonic()
        stale = [d for d, t in self._domain_last.items() if now - t > 300]
        for d in stale:
            self._domain_last.pop(d, None)
            self._domain_failures.pop(d, None)
        if len(self._domain_last) > self._MAX_DOMAINS:
            all_domains = sorted(self._domain_last.items(), key=lambda x: x[1])
            for d, _ in all_domains[: len(all_domains) - self._MAX_DOMAINS]:
                self._domain_last.pop(d, None)
                self._domain_failures.pop(d, None)

    def _min_interval(self) -> float:
        return 1.0 / self.max_per_second if self.max_per_second > 0 else 0.0

    def _compute_wait(self, now: float, domain: str) -> float:
        global_interval = self._min_interval()
        since_global = now - self._global_last
        wait = max(0.0, global_interval - since_global)
        if domain:
            failures = self._domain_failures.get(domain, 0)
            backoff = (
                min(self._backoff_factor**failures, self._max_backoff) if failures > 0 else 0.0
            )
            since_domain = now - self._domain_last[domain]
            wait = max(wait, backoff - since_domain)
        return wait

    def acquire(self, domain: str = "") -> None:
        if self.max_per_second <= 0:
            return
        wait = 0.0
        jitter = 0.0
        with self._sync_lock:
            self._evict_old_domains()
            now = time.monotonic()
            wait = self._compute_wait(now, domain)
            if wait > 0:
                jitter = random.uniform(0, self._jitter)
                total_wait = wait + jitter
                self._global_last = now + total_wait
                self._domain_last[domain] = now
            else:
                self._global_last = now
                self._domain_last[domain] = now
        if wait > 0:
            time.sleep(wait + jitter)

    async def acquire_async(self, domain: str = "") -> None:
        if self.max_per_second <= 0:
            return
        wait = 0.0
        jitter = 0.0
        with self._sync_lock:
            self._evict_old_domains()
            now = time.monotonic()
            wait = self._compute_wait(now, domain)
            if wait > 0:
                jitter = random.uniform(0, self._jitter)
                total_wait = wait + jitter
                self._global_last = now + total_wait
                self._domain_last[domain] = now
            else:
                self._global_last = now
                self._domain_last[domain] = now
        if wait > 0:
            await asyncio.sleep(wait + jitter)

    def record_failure(self, domain: str = "") -> None:
        if domain:
            with self._sync_lock:
                self._domain_failures[domain] += 1

    def record_success(self, domain: str = "") -> None:
        if domain:
            with self._sync_lock:
                if domain in self._domain_failures:
                    self._domain_failures[domain] = max(0, self._domain_failures[domain] - 1)

    def reset(self) -> None:
        with self._sync_lock:
            self._global_last = 0.0
            self._domain_last.clear()
            self._domain_failures.clear()


# ── Singleton helpers ───────────────────────────────────────────────────

_default_limiter: Optional[GlobalRateLimiter] = None
_init_lock = threading.Lock()


def get_rate_limiter() -> GlobalRateLimiter:
    global _default_limiter
    if _default_limiter is None:
        with _init_lock:
            if _default_limiter is None:
                _default_limiter = GlobalRateLimiter()
    return _default_limiter


def configure_rate_limiter(
    rate: float = 0,
    burst: int = 0,
    per_domain_rate: float = 0,
    per_domain_burst: int = 0,
) -> GlobalRateLimiter:
    global _default_limiter
    with _init_lock:
        _default_limiter = GlobalRateLimiter(
            rate=rate,
            burst=burst,
            per_domain_rate=per_domain_rate,
            per_domain_burst=per_domain_burst,
        )
    return _default_limiter


def reset_rate_limiter() -> None:
    global _default_limiter
    with _init_lock:
        _default_limiter = None
