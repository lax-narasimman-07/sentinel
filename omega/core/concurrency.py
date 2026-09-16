"""Async concurrency controls — token buckets and a global worker pool.

Phase 1.5: rate limiting with exponential backoff is provided at the tool
adapter boundary. Every subprocess launch waits on a per-tool token bucket
before spawning, and a process-wide :class:`WorkerPool` bounds how many scans
run concurrently. Both honor :class:`omega.config.RateLimitConfig`.
"""

from __future__ import annotations

import asyncio
import contextlib
import threading
import time
from typing import Any

# ── Token bucket ────────────────────────────────────────────────────────────

class AsyncTokenBucket:
    """Awaitable token bucket for rate-limited sections.

    A bucket starts full at ``burst`` tokens so the first ``burst`` waits pass
    immediately; tokens refill continuously at ``rps`` tokens/second. ``acquire``
    sleeps until a token is available (backoff capped by ``timeout``) and returns
    ``False`` if the wait would exceed ``timeout``.
    """

    __slots__ = ("rps", "burst", "_tokens", "_updated")

    def __init__(self, rps: float, burst: int) -> None:
        self.rps = float(rps)
        self.burst = int(max(1, burst))
        self._tokens = float(self.burst)
        self._updated = time.monotonic()

    def _refill(self) -> None:
        now = time.monotonic()
        self._tokens = min(self.burst, self._tokens + (now - self._updated) * self.rps)
        self._updated = now

    async def acquire(self, timeout: float = 30.0) -> bool:
        """Consume one token, waiting up to ``timeout`` seconds; False on timeout."""
        if self.rps <= 0 or self._tokens < 1.0:
            self._refill()
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            self._refill()
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            now = time.monotonic()
            remaining = deadline - now
            if remaining <= 0:
                return False
            deficit = 1.0 - self._tokens
            wait = deficit / self.rps if self.rps > 0 else remaining
            await asyncio.sleep(max(0.01, min(wait, remaining)))


# ── Global worker pool ──────────────────────────────────────────────────────

class WorkerPool:
    """Bounds how many sections run concurrently with a shared semaphore."""

    def __init__(self, max_concurrent: int) -> None:
        self._sem = asyncio.Semaphore(max(1, int(max_concurrent)))

    @contextlib.asynccontextmanager
    async def run(self) -> Any:
        """Async context manager: acquire a slot for the duration of the block."""
        async with self._sem:
            yield

    @property
    def max_concurrent(self) -> int:
        return self._sem._value  # type: ignore[attr-defined]


# ── Module-level singletons ─────────────────────────────────────────────────

_pool: WorkerPool | None = None
_buckets: dict[str, AsyncTokenBucket] = {}
_pool_lock = threading.Lock()


def get_worker_pool() -> WorkerPool:
    """Return the process-wide pool sized from ``RateLimitConfig.max_concurrent``."""
    global _pool
    if _pool is None:
        from omega.config import get_config
        with _pool_lock:
            if _pool is None:
                _pool = WorkerPool(get_config().rate_limits.max_concurrent)
    return _pool


def tool_bucket(tool_name: str) -> AsyncTokenBucket:
    """Return the (shared, per-tool) token bucket honoring ``RateLimitConfig``."""
    from omega.config import get_config
    cfg = get_config().rate_limits
    with _pool_lock:
        bucket = _buckets.get(tool_name)
        if bucket is None:
            bucket = AsyncTokenBucket(rps=cfg.per_tool_rps, burst=cfg.burst_size)
            _buckets[tool_name] = bucket
        return bucket


def reset_concurrency() -> None:
    """Reset the singleton pool and buckets (used by tests)."""
    global _pool
    with _pool_lock:
        _pool = None
        _buckets.clear()
