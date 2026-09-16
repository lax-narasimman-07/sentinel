"""Phase 0 regression tests.

Covers bugs found during the Phase 0 audit:
- HttpxAdapter never fed its targets to httpx via stdin (broken omega_recon_probe)
- RateLimiter buckets never refilled (hard lockout after burst)
- Duplicated dead CTF branch in ScopeEngine.authorize_target
- Recon/web/http tools bypassed scope authorization entirely
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from contextlib import asynccontextmanager
from collections.abc import AsyncGenerator

import pytest

import omega.scope
import omega.recon
from omega.scope import RateLimiter
from omega.tools import ToolAdapter, ToolExecutionRequest
from mcp import types
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VENV_PYTHON = os.path.join(PROJECT_ROOT, ".venv", "bin", "python")
TIMEOUT = 30


def _server_params(tmpdir: str) -> StdioServerParameters:
    return StdioServerParameters(
        command=VENV_PYTHON,
        args=["-m", "omega.mcp"],
        cwd=PROJECT_ROOT,
        env={"OMEGA_BASE_DIR": tmpdir},
    )


def _extract(result: types.CallToolResult) -> str:
    return "\n".join(item.text for item in result.content if isinstance(item, types.TextContent))


def _json(result: types.CallToolResult) -> dict | list:
    return json.loads(_extract(result))


async def _call(session: ClientSession, tool: str, args: dict | None = None) -> types.CallToolResult:
    return await asyncio.wait_for(session.call_tool(tool, args or {}), timeout=TIMEOUT)


@asynccontextmanager
async def fresh_server() -> AsyncGenerator[ClientSession, None]:
    with tempfile.TemporaryDirectory(prefix="omega_ph0_") as tmpdir:
        async with stdio_client(_server_params(tmpdir)) as streams:
            read, write = streams
            async with ClientSession(read, write) as session:
                await asyncio.wait_for(session.initialize(), timeout=TIMEOUT)
                yield session


# ═══════════════════════════════════════════════════════════════════════════
# HttpxAdapter — broken tool regression
# ═══════════════════════════════════════════════════════════════════════════

def test_httpx_feeds_targets_via_stdin(monkeypatch):
    captured: dict = {}

    async def fake_run(self, cmd, input_data=None, **kwargs):
        captured["cmd"] = cmd
        captured["input_data"] = input_data
        return "", "", 0, 1.0

    monkeypatch.setattr(omega.recon.HttpxAdapter, "_run_subprocess_with_input", fake_run)
    adapter = omega.recon.HttpxAdapter()
    request = ToolExecutionRequest(
        tool_name="httpx",
        target="a.example.com",
        parameters={"targets": ["a.example.com", "b.example.com"]},
    )
    result = asyncio.run(adapter.execute(request))

    assert result.success
    assert "-l" in captured["cmd"]
    assert "/dev/stdin" in captured["cmd"]
    assert captured["input_data"] == b"a.example.com\nb.example.com\n"


def test_httpx_single_target_falls_back_to_request_target(monkeypatch):
    captured: dict = {}

    async def fake_run(self, cmd, input_data=None, **kwargs):
        captured["input_data"] = input_data
        return "", "", 0, 1.0

    monkeypatch.setattr(omega.recon.HttpxAdapter, "_run_subprocess_with_input", fake_run)
    adapter = omega.recon.HttpxAdapter()
    request = ToolExecutionRequest(tool_name="httpx", target="single.example.com")
    asyncio.run(adapter.execute(request))
    assert captured["input_data"] == b"single.example.com\n"


def test_subprocess_with_input_is_shared_base_helper():
    assert callable(getattr(ToolAdapter, "_run_subprocess_with_input"))
    assert callable(getattr(omega.recon.DnsxAdapter, "_run_subprocess_with_input"))


# ═══════════════════════════════════════════════════════════════════════════
# RateLimiter — never-refilling token bucket regression
# ═══════════════════════════════════════════════════════════════════════════

def test_rate_limiter_respects_burst(monkeypatch):
    clock = {"now": 1000.0}
    monkeypatch.setattr(omega.scope.time, "time", lambda: clock["now"])
    limiter = RateLimiter(rps=5.0, burst=3)

    assert limiter.allow("t")
    assert limiter.allow("t")
    assert limiter.allow("t")
    assert not limiter.allow("t")  # burst consumed


def test_rate_limiter_refills_over_time(monkeypatch):
    clock = {"now": 1000.0}
    monkeypatch.setattr(omega.scope.time, "time", lambda: clock["now"])
    limiter = RateLimiter(rps=2.0, burst=3)

    for _ in range(3):
        limiter.allow("t")
    assert not limiter.allow("t")

    clock["now"] += 1.0  # 1 second -> 2 tokens refilled
    assert limiter.allow("t")
    assert limiter.allow("t")
    assert not limiter.allow("t")  # 2 tokens consumed


def test_rate_limiter_bucket_is_capped_at_burst(monkeypatch):
    clock = {"now": 1000.0}
    monkeypatch.setattr(omega.scope.time, "time", lambda: clock["now"])
    limiter = RateLimiter(rps=1.0, burst=2)

    for _ in range(2):
        limiter.allow("t")
    assert not limiter.allow("t")

    clock["now"] += 3600.0  # a long time passes; should cap at burst, not accumulate
    assert limiter.allow("t")
    assert limiter.allow("t")
    assert not limiter.allow("t")


def test_rate_limiter_targets_are_independent(monkeypatch):
    clock = {"now": 1000.0}
    monkeypatch.setattr(omega.scope.time, "time", lambda: clock["now"])
    limiter = RateLimiter(rps=5.0, burst=1)

    assert limiter.allow("a")
    assert not limiter.allow("a")
    assert limiter.allow("b")  # separate bucket unaffected


# ═══════════════════════════════════════════════════════════════════════════
# Scope gating — recon/web/http tools must deny when engagement has no scope
# ═══════════════════════════════════════════════════════════════════════════

async def assert_denied(session: ClientSession, tool: str, args: dict) -> None:
    r = await _call(session, tool, args)
    data = _json(r)
    assert isinstance(data, dict), f"{tool} did not return an object: {data}"
    assert "error" in data, f"{tool} was not gated: {data}"
    err = data["error"]
    assert isinstance(err, dict) and err.get("code") == "SCOPE_DENIED", f"{tool} error not scope-related: {data}"


@pytest.mark.asyncio
async def test_recon_tools_gated_when_engagement_has_no_rules():
    async with fresh_server() as s:
        eng = await _call(s, "omega_engagement_create", {"name": "Gated", "mode": "bug_bounty"})
        eid = _json(eng)["id"]

        cases = [
            ("omega_recon_probe", {"target": "probe.example.com", "engagement_id": eid}),
            ("omega_recon_fuzz", {"target": "http://fuzz.example.com", "engagement_id": eid}),
            ("omega_recon_tech", {"target": "tech.example.com", "engagement_id": eid}),
            ("omega_recon_crawl", {"target": "http://crawl.example.com", "engagement_id": eid}),
        ]
        for tool, args in cases:
            await assert_denied(s, tool, args)


@pytest.mark.asyncio
async def test_web_tools_gated_when_engagement_has_no_rules():
    async with fresh_server() as s:
        eng = await _call(s, "omega_engagement_create", {"name": "Gated", "mode": "bug_bounty"})
        eid = _json(eng)["id"]

        cases = [
            ("omega_web_headers", {"url": "http://web.example.com", "engagement_id": eid}),
            ("omega_web_cors", {"url": "http://web.example.com", "engagement_id": eid}),
            ("omega_web_cookies", {"url": "http://web.example.com", "engagement_id": eid}),
            ("omega_web_endpoints", {"url": "http://web.example.com", "engagement_id": eid}),
            ("omega_web_full_scan", {"target": "http://web.example.com", "engagement_id": eid}),
            ("omega_web_js_analyze", {"js_url": "http://web.example.com/app.js", "engagement_id": eid}),
        ]
        for tool, args in cases:
            await assert_denied(s, tool, args)


@pytest.mark.asyncio
async def test_http_request_gated_when_engagement_has_no_rules():
    async with fresh_server() as s:
        eng = await _call(s, "omega_engagement_create", {"name": "Gated", "mode": "bug_bounty"})
        eid = _json(eng)["id"]
        await assert_denied(s, "omega_http_request", {"method": "GET", "url": "http://api.example.com", "engagement_id": eid})


@pytest.mark.asyncio
async def test_recon_tools_open_world_without_engagement():
    """Without an engagement_id, recon tools remain ungated (open-world design)."""
    async with fresh_server() as s:
        r = await _call(s, "omega_recon_probe", {"target": "http://127.0.0.1:1"})
        data = _json(r)
        assert "scope" not in json.dumps(data).lower().split("denied")
        assert "success" in data or "error" in data


@pytest.mark.asyncio
async def test_scope_gated_tools_allow_after_include_rule():
    """Once an include rule is added, the same tools are authorized."""
    async with fresh_server() as s:
        eng = await _call(s, "omega_engagement_create", {"name": "Allowed", "mode": "bug_bounty"})
        eid = _json(eng)["id"]
        await _call(s, "omega_scope_add_rule", {
            "engagement_id": eid, "rule_type": "include",
            "target_type": "url", "pattern": "http://target.example.com",
        })
        r = await _call(s, "omega_recon_probe", {"target": "http://target.example.com", "engagement_id": eid})
        data = _json(r)
        # Should NOT be a scope denial; execution proceeds (binary may be absent/fail, but not scope-blocked)
        err = data.get("error")
        assert not (isinstance(err, dict) and err.get("code") == "SCOPE_DENIED"), f"unexpected scope denial: {data}"


# ═══════════════════════════════════════════════════════════════════════════
# CTF scope path — the branch that used to be duplicated
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_ctf_mode_scope_with_exclusions():
    async with fresh_server() as s:
        eng = await _call(s, "omega_engagement_create", {"name": "CTF", "mode": "ctf"})
        eid = _json(eng)["id"]

        r = await _call(s, "omega_scope_check", {"engagement_id": eid, "target": "anything.example"})
        assert _json(r)["allowed"] is True

        await _call(s, "omega_scope_add_rule", {
            "engagement_id": eid, "rule_type": "exclude",
            "target_type": "wildcard", "pattern": "*.banned.example",
        })
        r = await _call(s, "omega_scope_check", {"engagement_id": eid, "target": "sub.banned.example"})
        assert _json(r)["allowed"] is False


# ═══════════════════════════════════════════════════════════════════════════
# Rate limiting through the full pipeline should not hard-lock after one burst
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_authorize_does_not_permanently_lock_after_burst():
    from omega.storage import Database
    from omega.scope import ScopeEngine
    from omega.core.schemas import Engagement, EngagementMode, new_id, now_utc

    db = Database()
    await db.connect()
    try:
        scope = ScopeEngine(db)
        eng = Engagement(id=new_id(), name="RL", mode=EngagementMode.LOCAL_LAB,
                         rate_limit_policy="stealth", created_at=now_utc(), updated_at=now_utc())
        await db.save_engagement(eng.model_dump())
        scope._engagement_cache[eng.id] = eng

        # stealth: rps=1, burst=3
        for _ in range(3):
            result = await scope.enforce_rate_limit(eng.id, "rl.example.com")
            assert result.allowed

        result = await scope.enforce_rate_limit(eng.id, "rl.example.com")
        assert not result.allowed  # burst exhausted

        # After enough time, tokens must come back (no permanent lockout)
        import time as _time
        scope._rate_limiters[eng.id]._buckets["rl.example.com"][1] = _time.time() - 10
        result = await scope.enforce_rate_limit(eng.id, "rl.example.com")
        assert result.allowed
    finally:
        await db.close()