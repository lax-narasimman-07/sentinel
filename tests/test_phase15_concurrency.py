"""Phase 1.5 — concurrency enforcement: token-bucket throttling + global worker pool.

Covers the async token bucket, the process-wide worker pool, config gating,
and the per-tool rate limiting wired into the shared subprocess runners.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from sentinel.config import SentinelConfig, RateLimitConfig, set_config
from sentinel.core import concurrency
from sentinel.core.concurrency import AsyncTokenBucket, WorkerPool, get_worker_pool, reset_concurrency, tool_bucket
from sentinel.tools import ToolAdapter, ToolExecutionRequest, ToolResult

# ── AsyncTokenBucket ─────────────────────────────────────────────────────────

class TestAsyncTokenBucket:
    async def test_first_requests_pass_up_to_burst(self) -> None:
        bucket = AsyncTokenBucket(rps=1.0, burst=3)
        for _ in range(3):
            assert await bucket.acquire(timeout=0.1) is True

    async def test_blocks_after_burst(self) -> None:
        bucket = AsyncTokenBucket(rps=1.0, burst=2)
        assert await bucket.acquire(timeout=0.1) is True
        assert await bucket.acquire(timeout=0.1) is True
        started = time.monotonic()
        assert await bucket.acquire(timeout=0.05) is False
        assert time.monotonic() - started < 0.5

    async def test_refills_over_time(self) -> None:
        bucket = AsyncTokenBucket(rps=1.0, burst=1)
        assert await bucket.acquire(timeout=0.1) is True
        assert await bucket.acquire(timeout=0.05) is False
        await asyncio.sleep(1.1)
        assert await bucket.acquire(timeout=0.3) is True

    async def test_zero_rps_never_granted(self) -> None:
        bucket = AsyncTokenBucket(rps=0.0, burst=1)
        await bucket.acquire(timeout=0.1)
        assert await bucket.acquire(timeout=0.05) is False

    async def test_acquire_waits_until_token_available(self) -> None:
        bucket = AsyncTokenBucket(rps=2.0, burst=1)
        assert await bucket.acquire(timeout=1.0) is True
        started = time.monotonic()
        assert await bucket.acquire(timeout=2.0) is True
        assert time.monotonic() - started >= 0.4


# ── WorkerPool ───────────────────────────────────────────────────────────────

class TestWorkerPool:
    async def test_bounds_concurrency(self) -> None:
        pool = WorkerPool(max_concurrent=3)
        active = 0
        peak = 0

        async def worker() -> None:
            nonlocal active, peak
            async with pool.run():
                active += 1
                peak = max(peak, active)
                await asyncio.sleep(0.05)
                active -= 1

        await asyncio.gather(*(worker() for _ in range(12)))
        assert peak <= 3

    async def test_max_concurrent_at_least_one(self) -> None:
        pool = WorkerPool(max_concurrent=0)
        async with pool.run():
            pass
        assert pool.max_concurrent >= 1


# ── Singletons ───────────────────────────────────────────────────────────────

class TestSingletons:
    async def test_get_worker_pool_shared_and_config_sized(self, monkeypatch) -> None:
        monkeypatch.setattr(concurrency, "_pool", None)
        cfg = SentinelConfig(rate_limits=RateLimitConfig(max_concurrent=7))
        monkeypatch.setattr("sentinel.config._config", cfg)
        pool = get_worker_pool()
        assert pool.max_concurrent == 7
        assert get_worker_pool() is pool

    def test_tool_bucket_is_per_tool(self, monkeypatch) -> None:
        reset_concurrency()
        a = tool_bucket("alpha")
        b = tool_bucket("alpha")
        c = tool_bucket("beta")
        assert a is b
        assert a is not c

    def test_tool_bucket_honors_config(self, monkeypatch) -> None:
        reset_concurrency()
        cfg = SentinelConfig(rate_limits=RateLimitConfig(per_tool_rps=0.25, burst_size=4))
        monkeypatch.setattr("sentinel.config._config", cfg)
        bucket = tool_bucket("gamma")
        assert bucket.rps == 0.25
        assert bucket.burst == 4


# ── Adapter integration ──────────────────────────────────────────────────────

class EchoAdapter(ToolAdapter):
    def name(self) -> str:
        return "echo_adapter"

    def version(self) -> str:
        return "1.0"

    def capabilities(self) -> object:
        from sentinel.core.schemas import ToolCapability, ToolRiskLevel, new_id, now_utc
        return ToolCapability(
            id=new_id(), name=self.name(), version=self.version(), description="",
            risk_level=ToolRiskLevel.READ_ONLY, is_available=True,
            created_at=now_utc(), updated_at=now_utc(),
        )

    async def execute(self, request: ToolExecutionRequest) -> ToolResult:
        return await self._run_subprocess(["/bin/echo", "hi"])


@pytest.mark.asyncio
async def test_adapter_run_throttled_when_bucket_depleted(monkeypatch) -> None:
    reset_concurrency()
    cfg = SentinelConfig(rate_limits=RateLimitConfig(
        enabled=True, per_tool_rps=0.0, burst_size=1, wait_seconds=0.1,
    ))
    monkeypatch.setattr("sentinel.config._config", cfg)
    adapter = EchoAdapter()
    bucket = tool_bucket("echo_adapter")
    assert await bucket.acquire(timeout=0.1) is True
    stdout, stderr, rc, duration = await adapter._run_subprocess(["/bin/echo", "hi"])
    assert rc == -1
    assert "Rate limit exceeded" in stderr
    assert stdout == ""


@pytest.mark.asyncio
async def test_adapter_run_proceeds_with_tokens(monkeypatch) -> None:
    reset_concurrency()
    cfg = SentinelConfig(rate_limits=RateLimitConfig(
        enabled=True, per_tool_rps=3.0, burst_size=5, wait_seconds=0.5,
    ))
    monkeypatch.setattr("sentinel.config._config", cfg)
    adapter = EchoAdapter()
    stdout, stderr, rc, duration = await adapter._run_subprocess(["/bin/echo", "hi"])
    assert rc == 0
    assert stdout.strip() == "hi"
    assert stderr == ""


@pytest.mark.asyncio
async def test_run_failure_maps_rate_limited(monkeypatch) -> None:
    adapter = EchoAdapter()
    result = adapter._run_failure("", "Rate limit exceeded for tool 'echo_adapter' (waited 30s). Retry later.", -1, 0.0)
    assert result is not None
    assert not result.success
    assert result.error.startswith("RATE_LIMITED:")


@pytest.mark.asyncio
async def test_disabled_rate_limit_skips_throttling(monkeypatch) -> None:
    reset_concurrency()
    cfg = SentinelConfig(rate_limits=RateLimitConfig(enabled=False))
    monkeypatch.setattr("sentinel.config._config", cfg)
    adapter = EchoAdapter()
    stdout, stderr, rc, duration = await adapter._run_subprocess(["/bin/echo", "hi"])
    assert rc == 0
    assert stdout.strip() == "hi"


def test_reset_concurrency_clears_singletons(monkeypatch) -> None:
    reset_concurrency()
    get_worker_pool()
    tool_bucket("x")
    reset_concurrency()
    assert concurrency._pool is None
    assert concurrency._buckets == {}


# sanity: `set_config` import is available (used by harness/CLI)
def test_set_config_importable() -> None:
    assert callable(set_config)
