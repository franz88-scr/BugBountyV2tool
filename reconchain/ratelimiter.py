"""Global rate limiter — coordinated token-bucket rate limiting across all phases.

Provides per-IP, per-domain, and global rate limiting with thread-safe async support.
"""
from __future__ import annotations

import asyncio
import threading
import time
from collections import defaultdict
from typing import Optional


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
        # Periodic cleanup of stale domain buckets
        if len(self._domain_buckets) > 1000:
            self.cleanup_domains()

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

    def cleanup_domains(self, max_age: float = 300.0) -> int:
        """Remove stale domain buckets. Returns number removed."""
        removed = 0
        stale = [
            d for d, b in self._domain_buckets.items()
            if b._bucket.available >= b._bucket.burst * 0.9
        ]
        for d in stale[:max(0, len(stale) - 50)]:
            self._domain_buckets.pop(d, None)
            removed += 1
        return removed


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
    rate: float = 0, burst: int = 0,
    per_domain_rate: float = 0, per_domain_burst: int = 0,
) -> GlobalRateLimiter:
    global _default_limiter
    with _init_lock:
        _default_limiter = GlobalRateLimiter(
            rate=rate, burst=burst,
            per_domain_rate=per_domain_rate,
            per_domain_burst=per_domain_burst,
        )
    return _default_limiter


def reset_rate_limiter() -> None:
    global _default_limiter
    with _init_lock:
        _default_limiter = None
