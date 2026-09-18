"""Phase 2 guardrails — scope-gating hardening and authorization metadata.

Tests:
  1. sentinel_recon_probe: multi-target list with out-of-scope entry → SCOPE_DENIED.
  2. sentinel_scan: analysis_only + active scan type → SCOPE_DENIED (mode guard).
  3. sentinel_scan: engagement with no scope rules + active scan → SCOPE_DENIED (target guard).
  4. ToolExecutor: multi-target scope enforcement at the adapter level.
  5. FindingEngine.create_finding: authorization_status stamped when scope provided.
  6. FindingEngine.create_finding: defaults to 'unverified' when no scope.
  7. ReportEngine: authorization summary present in markdown output.
  8. ReportEngine: authorization_summary present in JSON output.
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

import pytest
import pytest_asyncio
from mcp import types
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from sentinel.core.schemas import (
    Finding,
    ToolCapability,
    ToolExecutionRequest,
    ToolResult,
    ToolRiskLevel,
    new_id,
    now_utc,
)
from sentinel.findings import FindingEngine
from sentinel.reporting import ReportEngine
from sentinel.scope import ScopeEngine
from sentinel.storage import Database
from sentinel.tools import ToolAdapter, ToolExecutor, ToolRegistry

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

# ── Re-usable helpers (mirrors test_phase0_regressions) ────────────────────

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VENV_PYTHON = os.path.join(PROJECT_ROOT, ".venv", "bin", "python")
TIMEOUT = 30


def _server_params(tmpdir: str) -> StdioServerParameters:
    return StdioServerParameters(
        command=VENV_PYTHON,
        args=["-m", "sentinel.mcp"],
        cwd=PROJECT_ROOT,
        env={"SENTINEL_BASE_DIR": tmpdir},
    )


def _extract(result: types.CallToolResult) -> str:
    return "\n".join(item.text for item in result.content if isinstance(item, types.TextContent))


def _json(result: types.CallToolResult) -> dict | list:
    return json.loads(_extract(result))


async def _call(session: ClientSession, tool: str, args: dict | None = None) -> types.CallToolResult:
    return await asyncio.wait_for(session.call_tool(tool, args or {}), timeout=TIMEOUT)


@asynccontextmanager
async def fresh_server() -> AsyncGenerator[ClientSession, None]:
    with tempfile.TemporaryDirectory(prefix="sentinel_ph2_") as tmpdir:
        async with stdio_client(_server_params(tmpdir)) as streams:
            read, write = streams
            async with ClientSession(read, write) as session:
                await asyncio.wait_for(session.initialize(), timeout=TIMEOUT)
                yield session


async def assert_scope_denied(session: ClientSession, tool: str, args: dict) -> None:
    """Assert that an MCP tool call returns a SCOPE_DENIED error object."""
    r = await _call(session, tool, args)
    data = _json(r)
    assert isinstance(data, dict), f"{tool} did not return a dict: {data}"
    err = data.get("error", {})
    assert isinstance(err, dict), f"{tool} error is not a dict: {data}"
    assert err.get("code") == "SCOPE_DENIED", f"{tool} error not SCOPE_DENIED: {data}"


# ═══════════════════════════════════════════════════════════════════════════
# Test 1 — recon_probe multi-target deny
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_recon_probe_multi_target_denies_out_of_scope():
    """When the targets list contains an out-of-scope host, the tool must
    deny before the adapter runs, even though the primary target is in scope."""
    async with fresh_server() as s:
        eng = await _call(s, "sentinel_engagement_create", {"name": "T2", "mode": "bug_bounty"})
        eid = _json(eng)["id"]
        await _call(s, "sentinel_scope_add_rule", {
            "engagement_id": eid, "rule_type": "include",
            "target_type": "domain", "pattern": "in-scope.com",
        })
        await assert_scope_denied(s, "sentinel_recon_probe", {
            "target": "in-scope.com",
            "targets": "in-scope.com\nattacker.com",
            "engagement_id": eid,
        })


# ═══════════════════════════════════════════════════════════════════════════
# Test 2 — sentinel_scan: analysis_only mode blocks active scans
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_scan_denied_analysis_only_blocks_active():
    """An active scan (scan_type='full') in analysis_only mode must be denied
    before any agents run, regardless of scope rules."""
    async with fresh_server() as s:
        eng = await _call(s, "sentinel_engagement_create", {"name": "A1", "mode": "analysis_only"})
        eid = _json(eng)["id"]
        await _call(s, "sentinel_scope_add_rule", {
            "engagement_id": eid, "rule_type": "include",
            "target_type": "domain", "pattern": "allowed.com",
        })
        await assert_scope_denied(s, "sentinel_scan", {
            "target": "allowed.com", "scan_type": "full", "engagement_id": eid,
        })


# ═══════════════════════════════════════════════════════════════════════════
# Test 3 — sentinel_scan: no scope rules → deny
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_scan_denied_no_rules_blocks_active():
    """Active scan with an engagement but no scope rules must be denied
    (deny-by-default policy)."""
    async with fresh_server() as s:
        eng = await _call(s, "sentinel_engagement_create", {"name": "A2", "mode": "pentest"})
        eid = _json(eng)["id"]
        await assert_scope_denied(s, "sentinel_scan", {
            "target": "example.com", "scan_type": "full", "engagement_id": eid,
        })


# ═══════════════════════════════════════════════════════════════════════════
# Helpers for unit-level executor / finding / report tests
# ═══════════════════════════════════════════════════════════════════════════

@pytest_asyncio.fixture
async def db():
    with tempfile.TemporaryDirectory(prefix="sentinel_ph2_db_") as td:
        d = Database(os.path.join(td, "test.db"))
        await d.connect()
        yield d
        await d.close()


@pytest.fixture
def scope(db):
    return ScopeEngine(db)


class _FakeActiveAdapter(ToolAdapter):
    """Minimal adapter whose risk level is ACTIVE (triggers executor gating)."""

    def name(self) -> str:
        return "fake_active"

    def id(self) -> str:
        return "fake_active"

    def version(self) -> str:
        return "0.0.1"

    def capabilities(self) -> ToolCapability:
        return ToolCapability(
            id=new_id(),
            name="fake_active",
            version="0.0.1",
            description="fake active adapter",
            risk_level=ToolRiskLevel.ACTIVE,
            is_available=True,
            created_at=now_utc(),
            updated_at=now_utc(),
        )

    async def execute(self, request: ToolExecutionRequest):  # type: ignore[override]
        return ToolResult(
            id=new_id(),
            tool_name=request.tool_name,
            success=True,
            raw_output="ok",
            parsed_output={"ok": True},
            duration_ms=1.0,
            created_at=now_utc(),
            updated_at=now_utc(),
        )


# ═══════════════════════════════════════════════════════════════════════════
# Test 4 — executor multi-target scope enforcement
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_executor_denies_unauthorized_extra_target(db, scope):
    """Executor must deny when a `targets` list contains a host not in scope."""
    eid = new_id()
    await db.save_engagement({
        "id": eid, "name": "ExecTest", "mode": "pentest",
        "rate_limit_policy": "normal",
        "created_at": now_utc().isoformat(), "updated_at": now_utc().isoformat(),
    })
    await db.save_scope_rule({
        "id": new_id(), "engagement_id": eid, "rule_type": "include",
        "target_type": "domain", "pattern": "in-scope.com",
        "ports": "[]", "protocols": "[]", "methods": "[]", "paths": "[]",
        "created_at": now_utc().isoformat(), "updated_at": now_utc().isoformat(),
    })

    registry = ToolRegistry()
    registry.register(_FakeActiveAdapter())
    executor = ToolExecutor(db, scope, registry)

    # Extra target out of scope → must be denied.
    request = ToolExecutionRequest(
        tool_name="fake_active",
        target="in-scope.com",
        parameters={"targets": ["in-scope.com", "rogue.example.com"]},
    )
    result = await executor.execute(request, engagement_id=eid)
    assert not result.success
    assert "rogue.example.com" in (result.error or "")
    assert "Scope authorization denied" in (result.error or "")


@pytest.mark.asyncio
async def test_executor_allows_authorized_targets(db, scope):
    """Executor passes when every target in the list is in scope."""
    eid = new_id()
    await db.save_engagement({
        "id": eid, "name": "ExecTest2", "mode": "pentest",
        "rate_limit_policy": "normal",
        "created_at": now_utc().isoformat(), "updated_at": now_utc().isoformat(),
    })
    for pat in ["a.in-scope.com", "b.in-scope.com"]:
        await db.save_scope_rule({
            "id": new_id(), "engagement_id": eid, "rule_type": "include",
            "target_type": "domain", "pattern": pat,
            "ports": "[]", "protocols": "[]", "methods": "[]", "paths": "[]",
            "created_at": now_utc().isoformat(), "updated_at": now_utc().isoformat(),
        })

    registry = ToolRegistry()
    registry.register(_FakeActiveAdapter())
    executor = ToolExecutor(db, scope, registry)

    request = ToolExecutionRequest(
        tool_name="fake_active",
        target="a.in-scope.com",
        parameters={"targets": ["a.in-scope.com", "b.in-scope.com"]},
    )
    result = await executor.execute(request, engagement_id=eid)
    assert result.success


# ═══════════════════════════════════════════════════════════════════════════
# Test 5 & 6 — Finding authorization metadata
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_finding_authorized_asset_stamped(db, scope):
    """When scope engine is provided and affected_asset is in scope, the
    finding must have authorization_status='authorized'."""
    eid = new_id()
    await db.save_engagement({
        "id": eid, "name": "FindTest", "mode": "pentest",
        "created_at": now_utc().isoformat(), "updated_at": now_utc().isoformat(),
    })
    await db.save_scope_rule({
        "id": new_id(), "engagement_id": eid, "rule_type": "include",
        "target_type": "domain", "pattern": "safe.example.com",
        "ports": "[]", "protocols": "[]", "methods": "[]", "paths": "[]",
        "created_at": now_utc().isoformat(), "updated_at": now_utc().isoformat(),
    })

    engine = FindingEngine(db, scope=scope)
    finding = Finding(
        id=new_id(), engagement_id=eid, title="Test auth",
        affected_asset="safe.example.com",
        created_at=now_utc(), updated_at=now_utc(),
    )
    saved = await engine.create_finding(finding)
    assert saved.authorization_status == "authorized"
    assert saved.authorization_basis == "safe.example.com"
    assert saved.authorization_mode == "pentest"
    assert saved.authorization_id != ""


@pytest.mark.asyncio
async def test_finding_out_of_scope_asset_stamped(db, scope):
    """When affected_asset is NOT in scope, authorization_status must be
    'not_in_scope'."""
    eid = new_id()
    await db.save_engagement({
        "id": eid, "name": "FindTest2", "mode": "bug_bounty",
        "created_at": now_utc().isoformat(), "updated_at": now_utc().isoformat(),
    })
    await db.save_scope_rule({
        "id": new_id(), "engagement_id": eid, "rule_type": "include",
        "target_type": "domain", "pattern": "safe.example.com",
        "ports": "[]", "protocols": "[]", "methods": "[]", "paths": "[]",
        "created_at": now_utc().isoformat(), "updated_at": now_utc().isoformat(),
    })

    engine = FindingEngine(db, scope=scope)
    finding = Finding(
        id=new_id(), engagement_id=eid, title="Out of scope",
        affected_asset="evil.example.com",
        created_at=now_utc(), updated_at=now_utc(),
    )
    saved = await engine.create_finding(finding)
    assert saved.authorization_status == "not_in_scope"


@pytest.mark.asyncio
async def test_finding_unverified_without_scope(db):
    """When FindingEngine has no scope, authorization defaults to 'unverified'."""
    engine = FindingEngine(db, scope=None)
    finding = Finding(
        id=new_id(), engagement_id="e1", title="No scope test",
        affected_asset="example.com",
        created_at=now_utc(), updated_at=now_utc(),
    )
    saved = await engine.create_finding(finding)
    assert saved.authorization_status == "unverified"
    assert saved.authorization_basis == ""
    assert saved.authorization_id == ""


# ═══════════════════════════════════════════════════════════════════════════
# Test 7 & 8 — Report contains authorization content
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_report_markdown_includes_authorization_section(db):
    eid = new_id()
    await db.save_engagement({
        "id": eid, "name": "RptTest", "mode": "pentest",
        "created_at": now_utc().isoformat(), "updated_at": now_utc().isoformat(),
    })
    await db.save_finding({
        "id": new_id(), "engagement_id": eid, "title": "Auth Test",
        "severity": "high", "confidence": "medium",
        "affected_asset": "web.example.com",
        "description": "desc", "impact": "impact",
        "authorization_status": "authorized",
        "authorization_basis": "web.example.com",
        "steps_to_reproduce": "[]", "evidence_ids": "[]",
        "references": "[]", "validation_status": "candidate",
        "created_at": now_utc().isoformat(), "updated_at": now_utc().isoformat(),
    })
    engine = ReportEngine(db)
    report = await engine.generate(eid, title="Auth Report", fmt="markdown")
    assert "Scope & Authorization" in report.content
    assert "Authorization:** authorized" in report.content
    assert "Authorization Basis:** web.example.com" in report.content


@pytest.mark.asyncio
async def test_report_json_includes_authorization_summary(db):
    eid = new_id()
    await db.save_engagement({
        "id": eid, "name": "RptJSON", "mode": "local_lab",
        "created_at": now_utc().isoformat(), "updated_at": now_utc().isoformat(),
    })
    # Two findings: one authorized, one not
    for asset, status in [("a.com", "authorized"), ("b.com", "not_in_scope")]:
        await db.save_finding({
            "id": new_id(), "engagement_id": eid, "title": f"Find-{asset}",
            "severity": "medium", "confidence": "none",
            "affected_asset": asset, "authorization_status": status,
            "steps_to_reproduce": "[]", "evidence_ids": "[]",
            "references": "[]", "validation_status": "candidate",
            "created_at": now_utc().isoformat(), "updated_at": now_utc().isoformat(),
        })

    engine = ReportEngine(db)
    report = await engine.generate(eid, fmt="json")
    data = json.loads(report.content)
    summary = data.get("authorization_summary", {})
    assert summary["authorized"] == 1
    assert summary["not_in_scope"] == 1
    assert summary["total"] == 2
