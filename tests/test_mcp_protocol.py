"""MCP protocol integration tests for SENTINEL.

Starts the server as a subprocess, connects via the MCP client SDK,
and exercises real tool calls over the wire.

Each test launches its own server subprocess and tears it down on exit,
keeping tests fully independent.  asyncio.timeout guards against hangs.
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from contextlib import asynccontextmanager
from collections.abc import AsyncGenerator

import pytest

from mcp import types
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

# ── Constants ───────────────────────────────────────────────────────────────

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VENV_PYTHON = os.path.join(PROJECT_ROOT, ".venv", "bin", "python")
STARTUP_TIMEOUT = 30
TOOL_CALL_TIMEOUT = 30

EXPECTED_TOOLS: list[str] = [
    "sentinel_doctor",
    "sentinel_engagement_create",
    "sentinel_engagement_list",
    "sentinel_engagement_get",
    "sentinel_scope_add_rule",
    "sentinel_scope_check",
    "sentinel_scope_list_rules",
    "sentinel_recon_subdomains",
    "sentinel_recon_probe",
    "sentinel_recon_portscan",
    "sentinel_recon_fuzz",
    "sentinel_recon_tech",
    "sentinel_recon_crawl",
    "sentinel_web_headers",
    "sentinel_web_cors",
    "sentinel_web_cookies",
    "sentinel_web_endpoints",
    "sentinel_web_full_scan",
    "sentinel_web_js_analyze",
    "sentinel_http_request",
    "sentinel_scan",
    "sentinel_graph_add_node",
    "sentinel_graph_add_edge",
    "sentinel_graph_query",
    "sentinel_hypothesis_create",
    "sentinel_hypothesis_update",
    "sentinel_finding_create",
    "sentinel_finding_list",
    "sentinel_finding_validate",
    "sentinel_finding_reject",
    "sentinel_finding_summary",
    "sentinel_evidence_list",
    "sentinel_ctf_challenge_create",
    "sentinel_ctf_challenge_list",
    "sentinel_ctf_hypothesis",
    "sentinel_ctf_submit_flag",
    "sentinel_ctf_confirm_flag",
    "sentinel_ctf_ledger",
    "sentinel_report_generate",
    "sentinel_tools_list",
    "sentinel_audit_log",
]


# ── Helpers ─────────────────────────────────────────────────────────────────

def _server_params(tmpdir: str, **overrides) -> StdioServerParameters:
    """Build StdioServerParameters with a fresh temp-dir database."""
    defaults: dict = {
        "command": VENV_PYTHON,
        "args": ["-m", "sentinel.mcp"],
        "cwd": PROJECT_ROOT,
        "env": {"SENTINEL_BASE_DIR": tmpdir},
    }
    defaults.update(overrides)
    return StdioServerParameters(**defaults)


def _extract_text(result: types.CallToolResult) -> str:
    parts: list[str] = []
    for item in result.content:
        if isinstance(item, types.TextContent):
            parts.append(item.text)
    return "\n".join(parts)


def _parse_json(text: str) -> dict | list:
    return json.loads(text)


async def _call(session: ClientSession, tool: str, args: dict | None = None) -> types.CallToolResult:
    """Call a tool with a safety timeout."""
    return await asyncio.wait_for(
        session.call_tool(tool, args or {}),
        timeout=TOOL_CALL_TIMEOUT,
    )


@asynccontextmanager
async def connected_server() -> AsyncGenerator[ClientSession, None]:
    """Spin up a fresh MCP server subprocess and yield a connected session.

    Each server gets its own temporary directory so the database schema is
    always created from scratch — no stale-schema conflicts.
    """
    with tempfile.TemporaryDirectory(prefix="sentinel_test_") as tmpdir:
        async with stdio_client(_server_params(tmpdir)) as streams:
            read_stream, write_stream = streams
            async with ClientSession(read_stream, write_stream) as session:
                await asyncio.wait_for(session.initialize(), timeout=STARTUP_TIMEOUT)
                yield session


# ── Tests ───────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_initialize_handshake():
    async with connected_server() as session:
        result = await asyncio.wait_for(
            session.send_ping(), timeout=STARTUP_TIMEOUT
        )
        assert result is not None, "Ping after init failed"


@pytest.mark.asyncio
async def test_list_tools_returns_expected():
    async with connected_server() as session:
        result = await asyncio.wait_for(
            session.list_tools(), timeout=TOOL_CALL_TIMEOUT
        )
        tool_names = {t.name for t in result.tools}
        for expected in EXPECTED_TOOLS:
            assert expected in tool_names, (
                f"Expected tool '{expected}' not found. "
                f"Available: {sorted(tool_names)}"
            )


@pytest.mark.asyncio
async def test_list_tools_not_empty():
    async with connected_server() as session:
        result = await asyncio.wait_for(
            session.list_tools(), timeout=TOOL_CALL_TIMEOUT
        )
        assert len(result.tools) > 0, "Server reported zero tools"


@pytest.mark.asyncio
async def test_sentinel_doctor_returns_structured_output():
    async with connected_server() as session:
        result = await _call(session, "sentinel_doctor")
        assert not result.is_error, f"sentinel_doctor returned error: {result.content}"
        data = _parse_json(_extract_text(result))
        assert "python_version" in data
        assert "platform" in data
        assert "tools" in data
        assert isinstance(data["tools"], dict)


@pytest.mark.asyncio
async def test_sentinel_engagement_create():
    async with connected_server() as session:
        result = await _call(session, "sentinel_engagement_create", {
            "name": "MCP Test Engagement",
            "mode": "local_lab",
            "description": "Created by test_mcp_protocol",
        })
        assert not result.is_error, f"engagement_create error: {result.content}"
        data = _parse_json(_extract_text(result))
        assert data["name"] == "MCP Test Engagement"
        assert data["mode"] == "local_lab"
        assert "id" in data


@pytest.mark.asyncio
async def test_sentinel_engagement_list():
    async with connected_server() as session:
        await _call(session, "sentinel_engagement_create", {
            "name": "List Test", "mode": "local_lab",
        })
        result = await _call(session, "sentinel_engagement_list")
        assert not result.is_error
        data = _parse_json(_extract_text(result))
        assert isinstance(data, list)
        assert len(data) >= 1


@pytest.mark.asyncio
async def test_sentinel_scope_check_in_and_out_of_scope():
    async with connected_server() as session:
        create_result = await _call(session, "sentinel_engagement_create", {
            "name": "Scope Test", "mode": "ctf",
        })
        eng_id = _parse_json(_extract_text(create_result))["id"]

        in_scope = await _call(session, "sentinel_scope_check", {
            "engagement_id": eng_id, "target": "challenge.ctf.local",
        })
        assert not in_scope.is_error
        in_data = _parse_json(_extract_text(in_scope))
        assert in_data["allowed"] is True

        oos = await _call(session, "sentinel_scope_check", {
            "engagement_id": "nonexistent_id", "target": "evil.com",
        })
        assert not oos.is_error
        oos_data = _parse_json(_extract_text(oos))
        assert oos_data["allowed"] is False


@pytest.mark.asyncio
async def test_sentinel_scope_add_rule_and_list():
    async with connected_server() as session:
        create_result = await _call(session, "sentinel_engagement_create", {
            "name": "Scope Rule Test", "mode": "bug_bounty",
            "description": "testing scope rules via MCP",
        })
        eng_id = _parse_json(_extract_text(create_result))["id"]

        add_result = await _call(session, "sentinel_scope_add_rule", {
            "engagement_id": eng_id,
            "rule_type": "include",
            "target_type": "wildcard",
            "pattern": "*.target.example.com",
            "description": "wildcard include",
        })
        assert not add_result.is_error
        add_data = _parse_json(_extract_text(add_result))
        assert add_data["success"] is True

        list_result = await _call(session, "sentinel_scope_list_rules", {
            "engagement_id": eng_id,
        })
        assert not list_result.is_error
        rules = _parse_json(_extract_text(list_result))
        assert isinstance(rules, list)
        patterns = [r.get("pattern") for r in rules]
        assert "*.target.example.com" in patterns


@pytest.mark.asyncio
async def test_sentinel_tools_list():
    async with connected_server() as session:
        result = await _call(session, "sentinel_tools_list")
        assert not result.is_error
        data = _parse_json(_extract_text(result))
        assert isinstance(data, dict)
        for tool_name, info in data.items():
            assert "available" in info
            assert "binary" in info
            assert "risk_level" in info


@pytest.mark.asyncio
async def test_sentinel_hypothesis_create():
    async with connected_server() as session:
        eng_result = await _call(session, "sentinel_engagement_create", {
            "name": "Hypothesis Test", "mode": "local_lab",
        })
        eng_id = _parse_json(_extract_text(eng_result))["id"]

        result = await _call(session, "sentinel_hypothesis_create", {
            "engagement_id": eng_id,
            "category": "xss",
            "target": "app.local",
            "hypothesis": "Reflected XSS on search parameter",
            "endpoint": "/search",
        })
        assert not result.is_error
        data = _parse_json(_extract_text(result))
        assert data["hypothesis"] == "Reflected XSS on search parameter"
        assert data["status"] == "hypothesis"
        assert "id" in data


@pytest.mark.asyncio
async def test_sentinel_finding_create_and_list():
    async with connected_server() as session:
        eng_result = await _call(session, "sentinel_engagement_create", {
            "name": "Finding Test", "mode": "local_lab",
        })
        eng_id = _parse_json(_extract_text(eng_result))["id"]

        create_result = await _call(session, "sentinel_finding_create", {
            "engagement_id": eng_id,
            "title": "SQL Injection in login form",
            "severity": "high",
            "confidence": "medium",
            "affected_asset": "app.local",
            "affected_endpoint": "/login",
            "description": "Unparameterised SQL query in login handler.",
        })
        assert not create_result.is_error
        finding = _parse_json(_extract_text(create_result))
        assert finding["title"] == "SQL Injection in login form"
        assert finding["severity"] == "high"

        list_result = await _call(session, "sentinel_finding_list", {
            "engagement_id": eng_id,
        })
        assert not list_result.is_error
        findings = _parse_json(_extract_text(list_result))
        assert isinstance(findings, list)
        titles = [f["title"] for f in findings]
        assert "SQL Injection in login form" in titles


@pytest.mark.asyncio
async def test_sentinel_finding_summary():
    async with connected_server() as session:
        eng_result = await _call(session, "sentinel_engagement_create", {
            "name": "Summary Test", "mode": "local_lab",
        })
        eng_id = _parse_json(_extract_text(eng_result))["id"]

        for severity in ("high", "medium", "low"):
            await _call(session, "sentinel_finding_create", {
                "engagement_id": eng_id,
                "title": f"Finding [{severity}]",
                "severity": severity,
            })

        summary_result = await _call(session, "sentinel_finding_summary", {
            "engagement_id": eng_id,
        })
        assert not summary_result.is_error
        summary = _parse_json(_extract_text(summary_result))
        assert summary["total"] == 3
        assert summary["by_severity"]["high"] == 1
        assert summary["by_severity"]["medium"] == 1
        assert summary["by_severity"]["low"] == 1


@pytest.mark.asyncio
async def test_sentinel_graph_workflow():
    async with connected_server() as session:
        eng_result = await _call(session, "sentinel_engagement_create", {
            "name": "Graph Test", "mode": "local_lab",
        })
        eng_id = _parse_json(_extract_text(eng_result))["id"]

        n1_result = await _call(session, "sentinel_graph_add_node", {
            "engagement_id": eng_id, "node_type": "domain", "label": "example.com",
        })
        assert not n1_result.is_error
        n1 = _parse_json(_extract_text(n1_result))

        n2_result = await _call(session, "sentinel_graph_add_node", {
            "engagement_id": eng_id, "node_type": "ip", "label": "1.2.3.4",
        })
        assert not n2_result.is_error
        n2 = _parse_json(_extract_text(n2_result))

        edge_result = await _call(session, "sentinel_graph_add_edge", {
            "engagement_id": eng_id,
            "source_id": n1["id"],
            "target_id": n2["id"],
            "edge_type": "resolves_to",
        })
        assert not edge_result.is_error
        edge = _parse_json(_extract_text(edge_result))
        assert edge["type"] == "resolves_to"

        query_result = await _call(session, "sentinel_graph_query", {
            "engagement_id": eng_id, "node_type": "domain",
        })
        assert not query_result.is_error
        graph = _parse_json(_extract_text(query_result))
        assert graph["count"] == 1
        assert graph["nodes"][0]["label"] == "example.com"


@pytest.mark.asyncio
async def test_sentinel_ctf_challenge_workflow():
    async with connected_server() as session:
        eng_result = await _call(session, "sentinel_engagement_create", {
            "name": "CTF Workflow", "mode": "ctf",
        })
        eng_id = _parse_json(_extract_text(eng_result))["id"]

        ch_result = await _call(session, "sentinel_ctf_challenge_create", {
            "engagement_id": eng_id,
            "name": "Buffer Overflow 101",
            "category": "pwn",
            "target": "pwn.challenge.local",
            "port": 9999,
        })
        assert not ch_result.is_error
        ch = _parse_json(_extract_text(ch_result))
        assert ch["name"] == "Buffer Overflow 101"
        assert ch["category"] == "pwn"
        ch_id = ch["id"]

        hyp_result = await _call(session, "sentinel_ctf_hypothesis", {
            "challenge_id": ch_id,
            "hypothesis": "Stack buffer overflow via gets()",
            "test_plan": "Send 200 bytes of padding + addr",
            "category": "exploitation",
        })
        assert not hyp_result.is_error
        hyp = _parse_json(_extract_text(hyp_result))
        assert hyp["status"] == "active"

        submit_result = await _call(session, "sentinel_ctf_submit_flag", {
            "challenge_id": ch_id, "flag": "flag{pwn3d_y0u}",
        })
        assert not submit_result.is_error
        sub = _parse_json(_extract_text(submit_result))
        assert sub["submitted"] is True

        confirm_result = await _call(session, "sentinel_ctf_confirm_flag", {
            "challenge_id": ch_id, "flag": "flag{pwn3d_y0u}",
        })
        assert not confirm_result.is_error
        conf = _parse_json(_extract_text(confirm_result))
        assert conf["confirmed"] is True

        ledger_result = await _call(session, "sentinel_ctf_ledger", {
            "challenge_id": ch_id,
        })
        assert not ledger_result.is_error
        ledger = _parse_json(_extract_text(ledger_result))
        all_hyps = (
            ledger.get("active", [])
            + ledger.get("succeeded", [])
            + ledger.get("failed", [])
        )
        assert len(all_hyps) >= 1


@pytest.mark.asyncio
async def test_sentinel_audit_log():
    async with connected_server() as session:
        eng_result = await _call(session, "sentinel_engagement_create", {
            "name": "Audit Log Test", "mode": "local_lab",
        })
        eng_id = _parse_json(_extract_text(eng_result))["id"]

        result = await _call(session, "sentinel_audit_log", {
            "engagement_id": eng_id,
        })
        assert not result.is_error
        log = _parse_json(_extract_text(result))
        assert isinstance(log, list)


@pytest.mark.asyncio
async def test_sentinel_report_generate():
    async with connected_server() as session:
        eng_result = await _call(session, "sentinel_engagement_create", {
            "name": "Report Test", "mode": "local_lab",
        })
        eng_id = _parse_json(_extract_text(eng_result))["id"]

        result = await _call(session, "sentinel_report_generate", {
            "engagement_id": eng_id,
            "format": "markdown",
            "title": "Integration Test Report",
        })
        assert not result.is_error
        report = _parse_json(_extract_text(result))
        assert report["format"] == "markdown"
        assert report["title"] == "Integration Test Report"
        assert "content" in report
        assert isinstance(report["content"], str)


@pytest.mark.asyncio
async def test_server_rejects_bad_tool_name():
    """Calling a non-existent tool should return an error result."""
    async with connected_server() as session:
        result = await asyncio.wait_for(
            session.call_tool("nonexistent_tool_xyz", {}),
            timeout=TOOL_CALL_TIMEOUT,
        )
        assert result.is_error, (
            f"Expected error for unknown tool, got: {result.content}"
        )


def _declared_tool_names() -> list[str]:
    """Derive the intended MCP tool inventory from the registration source.

    This is the authoritative expectation: every ``@mcp.tool`` decorated handler
    declared inside ``SentinelServer._register_tools`` must be exposed by the
    server. Nothing is hard-coded here — the expectation follows the code.
    """
    import inspect
    import re

    from sentinel.mcp import SentinelServer
    source = inspect.getsource(SentinelServer._register_tools)
    return sorted(set(re.findall(r'name="(sentinel_[a-z_]+)"', source)))


@pytest.mark.asyncio
async def test_list_tools_returns_complete_declared_inventory():
    """tools/list must expose EVERY declared @mcp.tool handler — nothing dropped."""
    declared = _declared_tool_names()
    assert len(declared) >= len(EXPECTED_TOOLS), (
        "Declared source inventory smaller than the curated expectation list"
    )

    async with connected_server() as session:
        result = await asyncio.wait_for(
            session.list_tools(), timeout=TOOL_CALL_TIMEOUT
        )
        served = sorted(t.name for t in result.tools)
        assert served == declared, (
            f"MCP tools/list ≠ declared registration. "
            f"Missing from server: {set(declared) - set(served)}. "
            f"Extra on server: {set(served) - set(declared)}."
        )

    # Representative coverage — every tool category must be present.
    category_reps = {
        "engagement": "sentinel_engagement_create",
        "scope": "sentinel_scope_add_rule",
        "recon": "sentinel_recon_subdomains",
        "web": "sentinel_web_headers",
        "api": "sentinel_api_openapi",
        "http": "sentinel_http_request",
        "scan": "sentinel_scan",
        "graph": "sentinel_graph_add_node",
        "hypothesis": "sentinel_hypothesis_create",
        "finding": "sentinel_finding_create",
        "evidence": "sentinel_evidence_list",
        "ctf": "sentinel_ctf_challenge_create",
        "reporting": "sentinel_report_generate",
        "discovery": "sentinel_tools_list",
        "audit": "sentinel_audit_log",
        "diagnostics": "sentinel_health_check",
    }
    for category, tool in category_reps.items():
        assert tool in declared, f"Missing representative tool for category '{category}': {tool}"


@pytest.mark.asyncio
async def test_health_check_mcp_count_matches_tools_list():
    """Health check must report the MCP tool count dynamically — not a stale constant.

    The invariant: ``mcp_tools.registered`` reported by sentinel_health_check must
    equal the actual tools/list exposure, and must be distinct from the external
    security-binary adapter count (which previously masqueraded as "tools registered").
    """
    async with connected_server() as session:
        listed = await asyncio.wait_for(
            session.list_tools(), timeout=TOOL_CALL_TIMEOUT
        )
        served_count = len(listed.tools)

        result = await asyncio.wait_for(
            session.call_tool("sentinel_health_check", {}),
            timeout=TOOL_CALL_TIMEOUT,
        )
        assert not result.is_error, f"health_check error: {result.content}"
        data = _parse_json(_extract_text(result))

        mcp = data.get("mcp_tools", {})
        assert mcp.get("registered") == served_count, (
            f"health_check mcp_tools.registered={mcp.get('registered')} != "
            f"tools/list count={served_count}"
        )
        assert set(mcp.get("names", [])) == {t.name for t in listed.tools}

        # External security-binary adapter count is a DIFFERENT number and must be
        # reported under its own field, never as the MCP tool count.
        adapter_size = data.get("adapter_registry_size")
        assert isinstance(adapter_size, int) and adapter_size > 0
        assert adapter_size != served_count, (
            "adapter_registry_size must not be conflated with the MCP tool count"
        )

        # Security binaries are reported separately.
        security = data.get("security_tools", {})
        assert isinstance(security.get("installed"), list)
        assert security.get("installed_count") == len(security.get("installed", []))

        assert data.get("database") in ("connected", "unavailable")
        assert data.get("status") in ("ready", "degraded")
