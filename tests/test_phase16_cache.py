"""Phase 1.6 — read-through recon cache (SQLite) wired into the subprocess runners.

Caching is opt-in per tool via ``ToolConfig.cache_ttl_seconds`` (0 = off). Only
successful runs are stored; the key covers tool + command + input hash.
"""

from __future__ import annotations

import asyncio

import pytest

from sentinel.config import SentinelConfig, RateLimitConfig, ToolConfig
from sentinel.core import cache as cache_mod
from sentinel.core.cache import ReconCache, cache_key, ttl_for
from sentinel.tools import ToolAdapter, ToolExecutionRequest, ToolResult

# ── Key derivation ───────────────────────────────────────────────────────────

class TestCacheKey:
    def test_key_is_deterministic_and_input_sensitive(self) -> None:
        a = cache_key("httpx", ["httpx", "-u", "http://x", "-json"])
        b = cache_key("httpx", ["httpx", "-u", "http://x", "-json"])
        c = cache_key("httpx", ["httpx", "-u", "http://y", "-json"])
        assert a == b
        assert a != c

    def test_key_includes_input_data(self) -> None:
        assert cache_key("sqlmap", ["sqlmap", "-u", "http://x?id=1"], b"rockyou") != \
            cache_key("sqlmap", ["sqlmap", "-u", "http://x?id=1"], b"other")


# ── TTL resolution ───────────────────────────────────────────────────────────

class TestTtlFor:
    def test_zero_by_default(self, monkeypatch) -> None:
        monkeypatch.setattr("sentinel.config._config", SentinelConfig())
        assert ttl_for("http") == 0.0

    def test_honors_per_tool_config(self, monkeypatch) -> None:
        cfg = SentinelConfig(tools={"nmap": ToolConfig(name="nmap", cache_ttl_seconds=3600)})
        monkeypatch.setattr("sentinel.config._config", cfg)
        assert ttl_for("nmap") == 3600.0
        assert ttl_for("other") == 0.0


# ── ReconCache store ─────────────────────────────────────────────────────────

class TestReconCache:
    async def _cache(self, tmp_path) -> ReconCache:
        path = str(tmp_path / "recon_cache.db")
        cache_mod.set_cache_path(path)
        return ReconCache(path)

    async def test_put_get_roundtrip(self, tmp_path) -> None:
        c = await self._cache(tmp_path)
        await c.put("k1", "nmap", ["nmap", "-sV"], None, "out-a", "err", 0)
        hit = await c.get("k1", max_age=3600)
        assert hit is not None
        stdout, stderr, rc, duration = hit
        assert stdout == "out-a"
        assert stderr == "err"
        assert rc == 0
        assert duration == 0.0

    async def test_stale_entry_returns_none(self, tmp_path) -> None:
        c = await self._cache(tmp_path)
        await c.put("k1", "nmap", ["nmap"], None, "out", "", 0)
        await asyncio.sleep(0.05)
        assert await c.get("k1", max_age=0.01) is None
        assert await c.get("k1", max_age=3600) is not None

    async def test_failing_runs_not_stored(self, tmp_path) -> None:
        c = await self._cache(tmp_path)
        await c.put("k1", "nmap", ["nmap"], None, "out", "boom", 3)
        assert await c.get("k1", 3600) is None
        assert await c.count() == 0

    async def test_zero_ttl_never_reads(self, tmp_path) -> None:
        c = await self._cache(tmp_path)
        await c.put("k1", "nmap", ["nmap"], None, "out", "", 0)
        assert await c.get("k1", max_age=0) is None

    async def test_clear_by_tool(self, tmp_path) -> None:
        c = await self._cache(tmp_path)
        await c.put("k1", "nmap", ["nmap"], None, "out", "", 0)
        await c.put("k2", "httpx", ["httpx"], None, "out", "", 0)
        removed = await c.clear(tool="nmap")
        assert removed == 1
        assert await c.count() == 1
        assert await c.clear() == 1
        assert await c.count() == 0


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


def _config(ttl: float) -> SentinelConfig:
    return SentinelConfig(
        tools={"echo_adapter": ToolConfig(name="echo_adapter", cache_ttl_seconds=ttl)},
        rate_limits=RateLimitConfig(enabled=False),
    )


def _counting_spawn(monkeypatch, counter: list[int], outcome: tuple[str, str, int, float]):
    async def fake_spawn(self, cmd, input_data, timeout, max_output_bytes, env):
        counter[0] += 1
        return outcome
    monkeypatch.setattr(EchoAdapter, "_spawn", fake_spawn)


@pytest.mark.asyncio
async def test_second_call_hits_cache(monkeypatch, tmp_path) -> None:
    cache_mod.set_cache_path(str(tmp_path / "rc.db"))
    monkeypatch.setattr("sentinel.config._config", _config(ttl=60))
    adapter = EchoAdapter()
    counter: list[int] = [0]
    _counting_spawn(monkeypatch, counter, ("fresh-out", "", 0, 5.0))
    r1 = await adapter._run_subprocess(["/bin/echo", "hi"])
    r2 = await adapter._run_subprocess(["/bin/echo", "hi"])
    assert r1[0] == "fresh-out"
    assert r2[0] == "fresh-out"
    assert counter[0] == 1

@pytest.mark.asyncio
async def test_failure_not_cached(monkeypatch, tmp_path) -> None:
    cache_mod.set_cache_path(str(tmp_path / "rc.db"))
    monkeypatch.setattr("sentinel.config._config", _config(ttl=60))
    adapter = EchoAdapter()
    counter: list[int] = [0]
    _counting_spawn(monkeypatch, counter, ("out", "boom", 3, 5.0))
    await adapter._run_subprocess(["/bin/echo", "hi"])
    await adapter._run_subprocess(["/bin/echo", "hi"])
    assert counter[0] == 2

@pytest.mark.asyncio
async def test_caching_disabled_by_default(monkeypatch, tmp_path) -> None:
    cache_mod.set_cache_path(str(tmp_path / "rc.db"))
    monkeypatch.setattr("sentinel.config._config", SentinelConfig(rate_limits=RateLimitConfig(enabled=False)))
    adapter = EchoAdapter()
    counter: list[int] = [0]
    _counting_spawn(monkeypatch, counter, ("out", "", 0, 5.0))
    await adapter._run_subprocess(["/bin/echo", "hi"])
    await adapter._run_subprocess(["/bin/echo", "hi"])
    assert counter[0] == 2

@pytest.mark.asyncio
async def test_expired_ttl_spawns_again(monkeypatch, tmp_path) -> None:
    cache_mod.set_cache_path(str(tmp_path / "rc.db"))
    monkeypatch.setattr("sentinel.config._config", _config(ttl=0.05))
    adapter = EchoAdapter()
    counter: list[int] = [0]
    _counting_spawn(monkeypatch, counter, ("out", "", 0, 5.0))
    await adapter._run_subprocess(["/bin/echo", "hi"])
    await asyncio.sleep(0.1)
    await adapter._run_subprocess(["/bin/echo", "hi"])
    assert counter[0] == 2

@pytest.mark.asyncio
async def test_input_data_distinguishes_cache_entries(monkeypatch, tmp_path) -> None:
    cache_mod.set_cache_path(str(tmp_path / "rc.db"))
    monkeypatch.setattr("sentinel.config._config", SentinelConfig(
        tools={"echo_adapter": ToolConfig(name="echo_adapter", cache_ttl_seconds=60)},
        rate_limits=RateLimitConfig(enabled=False),
    ))
    adapter = EchoAdapter()
    counter: list[int] = [0]
    _counting_spawn(monkeypatch, counter, ("out", "", 0, 5.0))
    await adapter._run_subprocess_with_input(["/bin/echo"], input_data=b"aaaa")
    await adapter._run_subprocess_with_input(["/bin/echo"], input_data=b"bbbb")
    assert counter[0] == 2
    await adapter._run_subprocess_with_input(["/bin/echo"], input_data=b"aaaa")
    assert counter[0] == 2
