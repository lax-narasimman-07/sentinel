"""Phase 0 per-tool MCP harness.

Boots the real MCP server over stdio and calls every registered tool with
benign, fast-failing inputs. For each call it captures:
  - subprocess boot (server initialized without crash)
  - MCP protocol result (is_error, content blocks)
  - raw response text
  - round-trip duration

Assertions are robustness-oriented: every tool must return a non-empty
TextContent response and must never leave the server wedged. Tools whose
external binary/network is unavailable still satisfy this contract by
returning a structured error string instead of crashing.
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
import time
from contextlib import asynccontextmanager
from collections.abc import AsyncGenerator

import pytest

from mcp import types
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VENV_PYTHON = os.path.join(PROJECT_ROOT, ".venv", "bin", "python")
TIMEOUT = 30
SCAN_TIMEOUT = 90
TOTAL_HARNESS_TIMEOUT = 300  # overall ceiling for the full 41-tool sweep

# Fast-failing targets keep the harness offline-safe and quick.
STEALTH = "http://127.0.0.1:1"
STEALTH_DOMAIN = "invalid.invalid"

# tool name -> (args, per-call timeout). "EID" is replaced with a real
# engagement id created at session start.
HARNESS_CASES: list[tuple[str, dict, int]] = [
    # System / doctor
    ("omega_doctor", {}, TIMEOUT),
    ("omega_tools_list", {}, TIMEOUT),
    ("omega_audit_log", {"engagement_id": "EID"}, TIMEOUT),
    # Engagement management
    ("omega_engagement_create", {"name": "Harness E", "mode": "local_lab"}, TIMEOUT),
    ("omega_engagement_list", {}, TIMEOUT),
    ("omega_engagement_get", {"engagement_id": "EID"}, TIMEOUT),
    # Scope
    ("omega_scope_add_rule", {"engagement_id": "EID", "rule_type": "include", "target_type": "domain", "pattern": "example.com"}, TIMEOUT),
    ("omega_scope_check", {"engagement_id": "EID", "target": "example.com"}, TIMEOUT),
    ("omega_scope_list_rules", {"engagement_id": "EID"}, TIMEOUT),
    # Recon
    ("omega_recon_subdomains", {"target": STEALTH_DOMAIN, "timeout": 15}, TIMEOUT),
    ("omega_recon_probe", {"target": STEALTH, "timeout": 15}, TIMEOUT),
    ("omega_recon_portscan", {"target": "127.0.0.1", "ports": "22", "timeout": 20}, TIMEOUT),
    ("omega_recon_fuzz", {"target": STEALTH, "wordlist": "/nonexistent-wordlist.txt", "timeout": 15}, TIMEOUT),
    ("omega_recon_tech", {"target": STEALTH, "timeout": 20}, TIMEOUT),
    ("omega_recon_crawl", {"target": STEALTH, "depth": 1, "timeout": 20}, TIMEOUT),
    # Web security
    ("omega_web_headers", {"url": STEALTH}, TIMEOUT),
    ("omega_web_cors", {"url": STEALTH}, TIMEOUT),
    ("omega_web_cookies", {"url": STEALTH}, TIMEOUT),
    ("omega_web_endpoints", {"url": STEALTH}, TIMEOUT),
    ("omega_web_full_scan", {"target": STEALTH}, SCAN_TIMEOUT),
    ("omega_web_js_analyze", {"js_url": STEALTH + "/app.js"}, TIMEOUT),
    # HTTP client
    ("omega_http_request", {"method": "GET", "url": STEALTH}, TIMEOUT),
    # Orchestrated scan
    ("omega_scan", {"target": STEALTH, "scan_type": "recon"}, SCAN_TIMEOUT),
    # Graph
    ("omega_graph_add_node", {"engagement_id": "EID", "node_type": "domain", "label": "example.com"}, TIMEOUT),
    ("omega_graph_add_edge", {"engagement_id": "EID", "source_id": "s", "target_id": "t", "edge_type": "hosts"}, TIMEOUT),
    ("omega_graph_query", {"engagement_id": "EID"}, TIMEOUT),
    # Findings & hypotheses
    ("omega_hypothesis_create", {"engagement_id": "EID", "category": "web", "target": "x", "hypothesis": "probe"}, TIMEOUT),
    ("omega_hypothesis_update", {"hypothesis_id": "nonexistent"}, TIMEOUT),
    ("omega_finding_create", {"engagement_id": "EID", "title": "Harness finding"}, TIMEOUT),
    ("omega_finding_list", {"engagement_id": "EID"}, TIMEOUT),
    ("omega_finding_validate", {"finding_id": "nonexistent"}, TIMEOUT),
    ("omega_finding_reject", {"finding_id": "nonexistent"}, TIMEOUT),
    ("omega_finding_summary", {"engagement_id": "EID"}, TIMEOUT),
    ("omega_evidence_list", {"engagement_id": "EID"}, TIMEOUT),
    # CTF
    ("omega_ctf_challenge_create", {"engagement_id": "EID", "name": "Harness C", "category": "crypto"}, TIMEOUT),
    ("omega_ctf_challenge_list", {"engagement_id": "EID"}, TIMEOUT),
    # Reporting
    ("omega_report_generate", {"engagement_id": "EID", "format": "json"}, TIMEOUT),
]


def _server_params(tmpdir: str) -> StdioServerParameters:
    return StdioServerParameters(
        command=VENV_PYTHON,
        args=["-m", "omega.mcp"],
        cwd=PROJECT_ROOT,
        env={"OMEGA_BASE_DIR": tmpdir, "OMEGA_LOG_LEVEL": "WARNING"},
    )


def _extract(result: types.CallToolResult) -> str:
    return "\n".join(item.text for item in result.content if isinstance(item, types.TextContent))


@asynccontextmanager
async def fresh_session() -> AsyncGenerator[ClientSession, None]:
    with tempfile.TemporaryDirectory(prefix="omega_harness_") as tmpdir:
        async with stdio_client(_server_params(tmpdir)) as streams:
            read, write = streams
            async with ClientSession(read, write) as session:
                await asyncio.wait_for(session.initialize(), timeout=TIMEOUT)
                yield session


@pytest.mark.asyncio
async def test_all_registered_tools_have_structured_responses():
    """Every registered tool returns valid structured text and never wedges the server."""

    async def _inner():
        async with fresh_session() as s:
            eng = await s.call_tool("omega_engagement_create", {"name": "Harness Root", "mode": "local_lab"})
            eid = json.loads(_extract(eng))["id"]

            for i, (name, args, timeout) in enumerate(HARNESS_CASES):
                resolved = {k: (v if v != "EID" else eid) for k, v in args.items()}
                started = time.monotonic()
                try:
                    r = await asyncio.wait_for(s.call_tool(name, resolved), timeout=timeout)
                    duration_ms = (time.monotonic() - started) * 1000
                except asyncio.TimeoutError:
                    duration_ms = (time.monotonic() - started) * 1000
                    raise AssertionError(
                        f"{name} timed out after {duration_ms:.0f}ms "
                        f"(per-call limit: {timeout}s) — check adapter timeout handling"
                    )

                text_items = [item.text for item in r.content if isinstance(item, types.TextContent)]
                assert text_items, f"{name}: returned no TextContent blocks -> {r.content!r}"

                raw = _extract(r)
                assert raw.strip(), f"{name}: empty response after {duration_ms:.0f}ms"
                try:
                    parsed = json.loads(raw)
                    assert isinstance(parsed, (dict, list)), f"{name}: JSON not object/list"
                    if r.is_error:
                        assert "error" in parsed or isinstance(parsed, list), f"{name}: MCP error without structured payload"
                except json.JSONDecodeError:
                    assert not r.is_error, f"{name}: error response is not structured JSON: {raw[:200]}"

            after = await s.call_tool("omega_doctor")
            assert not after.is_error

    await asyncio.wait_for(_inner(), timeout=TOTAL_HARNESS_TIMEOUT)


@pytest.mark.asyncio
async def test_server_survives_unknown_tool_then_healthy_tool():
    async with fresh_session() as s:
        r = await s.call_tool("totally_bogus_tool", {"x": "y"})
        assert r.is_error
        r2 = await s.call_tool("omega_doctor")
        assert not r2.is_error