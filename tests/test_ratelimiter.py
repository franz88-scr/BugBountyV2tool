"""Tests for the rate limiter module."""
import asyncio
import time
import threading

import pytest

from reconchain.ratelimiter import (
    TokenBucket,
    AsyncTokenBucket,
    GlobalRateLimiter,
    configure_rate_limiter,
    reset_rate_limiter,
)


def _run_async(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


class TestTokenBucket:
    def test_allows_burst(self):
        b = TokenBucket(rate=1, burst=5)
        for _ in range(5):
            assert b.acquire()
        assert not b.acquire()

    def test_refills_over_time(self):
        b = TokenBucket(rate=100, burst=1)
        b.acquire()
        time.sleep(0.05)
        assert b.acquire()

    def test_available_property(self):
        b = TokenBucket(rate=1, burst=5)
        avail = b.available
        assert avail == 5.0

    def test_wait_time(self):
        b = TokenBucket(rate=10, burst=1)
        b.acquire()
        wt = b.wait_time(1)
        assert 0.0 < wt <= 0.15

    def test_thread_safety(self):
        b = TokenBucket(rate=1000, burst=100)
        results = []
        def acquire_many():
            count = 0
            for _ in range(50):
                if b.acquire():
                    count += 1
            results.append(count)
        threads = [threading.Thread(target=acquire_many) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        total = sum(results)
        # Allow small race condition margin due to refill
        assert 100 <= total <= 110


class TestAsyncTokenBucket:
    def test_acquire(self):
        b = AsyncTokenBucket(rate=100, burst=10)
        _run_async(b.acquire())
        assert b._bucket.available < 10

    def test_try_acquire(self):
        b = AsyncTokenBucket(rate=1, burst=1)
        assert _run_async(b.try_acquire())
        assert not _run_async(b.try_acquire())

    def test_acquire_waits(self):
        b = AsyncTokenBucket(rate=200, burst=1)
        _run_async(b.try_acquire())
        start = time.monotonic()
        _run_async(b.acquire())
        elapsed = time.monotonic() - start
        assert elapsed < 1.0


class TestGlobalRateLimiter:
    def test_no_limit(self):
        limiter = GlobalRateLimiter()
        for _ in range(10):
            _run_async(limiter.acquire())

    def test_global_limit(self):
        limiter = GlobalRateLimiter(rate=100, burst=5)
        for _ in range(5):
            _run_async(limiter.acquire())

    def test_per_domain_limit(self):
        limiter = GlobalRateLimiter(per_domain_rate=100, per_domain_burst=3)
        for _ in range(3):
            _run_async(limiter.acquire("example.com"))

    def test_context_manager(self):
        limiter = GlobalRateLimiter()
        _run_async(limiter.__aenter__())
        _run_async(limiter.__aexit__(None, None, None))

    def test_try_acquire(self):
        limiter = GlobalRateLimiter(rate=1, burst=1)
        assert _run_async(limiter.try_acquire())
        assert not _run_async(limiter.try_acquire())

    def test_domain_isolation(self):
        limiter = GlobalRateLimiter(per_domain_rate=100, per_domain_burst=2)
        _run_async(limiter.acquire("a.com"))
        _run_async(limiter.acquire("a.com"))
        _run_async(limiter.acquire("b.com"))

    def test_cleanup_domains(self):
        limiter = GlobalRateLimiter(per_domain_rate=100, per_domain_burst=10)
        limiter._domain_buckets["old.com"] = AsyncTokenBucket(100, 10)
        limiter._domain_buckets["new.com"] = AsyncTokenBucket(100, 10)
        removed = limiter.cleanup_domains()
        assert isinstance(removed, int)


class TestConfigureRateLimiter:
    def test_configure_and_reset(self):
        reset_rate_limiter()
        limiter = configure_rate_limiter(rate=10, burst=5, per_domain_rate=5, per_domain_burst=3)
        assert limiter.rate == 10
        assert limiter.burst == 5
        assert limiter.per_domain_rate == 5
        reset_rate_limiter()
