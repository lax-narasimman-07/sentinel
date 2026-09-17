"""Phase 3 feature modules — new MCP tool surface and reporting polish.

Covers the newly exposed tool families:
  - Recon adapters: nuclei/nikto/vuln, gobuster, gospider, masscan, naabu, dnsx, wafw00f
  - Web engine:           omega_web_jwt, omega_web_tech
  - API security engine:  omega_api_openapi/graphql/auth/idor/introspection/full_scan
  - CTF toolkit:          resolve_hypothesis, add_note, add_artifact, hypothesis_ledger
  - Reporting:            hypotheses present in markdown and JSON reports

Vuln triage (phase 3 second increment):
  - nuclei parsed_output findings → Finding records via _triage_nuclei_findings
  - nikto parsed_output vulnerabilities → Finding records via _triage_nikto_findings
  - _run_recon auto-triages when engagement_id is present

Assertions are scope-gating-first: active tools must deny under engagements
without scope rules; passive tools must be permitted (never SCOPE_DENIED) in
analysis_only mode. Execution paths are exercised against STEALTH targets or
engines in-process so the suite stays offline-safe and fast.
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

import pytest
from mcp import types
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from omega.agents import Orchestrator
from omega.mcp import OmegaServer
from omega.core.schemas import Severity, new_id, now_utc
from omega.storage import Database

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

from tests.fixtures import TestServer

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VENV_PYTHON = os.path.join(PROJECT_ROOT, ".venv", "bin", "python")
TIMEOUT = 40

# Targets that fast-fail so no real network traffic occurs.
STEALTH = "http://127.0.0.1:1"

NEW_TOOLS = [
    "omega_health_check",
    "omega_web_jwt",
    "omega_web_tech",
    "omega_api_openapi",
    "omega_api_graphql",
    "omega_api_auth",
    "omega_api_idor",
    "omega_api_introspection",
    "omega_api_full_scan",
    "omega_recon_vuln_scan",
    "omega_recon_server_audit",
    "omega_recon_dirbrute",
    "omega_recon_webcrawl",
    "omega_recon_port_rapid",
    "omega_recon_fastportscan",
    "omega_recon_dns_lookup",
    "omega_recon_waf_detect",
    "omega_ctf_resolve_hypothesis",
    "omega_ctf_add_note",
    "omega_ctf_add_artifact",
    "omega_ctf_hypothesis_ledger",
]

# Active tools: deny by default when an engagement has no scope rules.
ACTIVE_TOOLS = [
    ("omega_recon_vuln_scan", {"target": "http://active.example.com"}),
    ("omega_recon_server_audit", {"target": "http://active.example.com"}),
    ("omega_recon_dirbrute", {"target": "http://active.example.com"}),
    ("omega_recon_port_rapid", {"target": "127.0.0.1"}),
    ("omega_recon_fastportscan", {"target": "127.0.0.1"}),
    ("omega_api_idor", {"url_pattern": "http://api.example.com/users/{id}", "id_values": "1,2"}),
    ("omega_api_full_scan", {"target": "http://api.example.com"}),
]

# Passive tools: permitted under analysis_only (observation-only).
PASSIVE_TOOLS = [
    ("omega_recon_webcrawl", {"target": STEALTH}),
    ("omega_recon_dns_lookup", {"target": "example.com"}),
    ("omega_recon_waf_detect", {"target": "http://example.com"}),
    ("omega_web_jwt", {"url": STEALTH}),
    ("omega_web_tech", {"url": STEALTH}),
    ("omega_api_openapi", {"base_url": STEALTH}),
    ("omega_api_graphql", {"base_url": STEALTH}),
    ("omega_api_auth", {"url": STEALTH}),
    ("omega_api_introspection", {"graphql_url": STEALTH + "/graphql"}),
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


def _json(result: types.CallToolResult) -> dict | list:
    return json.loads(_extract(result))


async def _call(session: ClientSession, tool: str, args: dict | None = None) -> types.CallToolResult:
    return await asyncio.wait_for(session.call_tool(tool, args or {}), timeout=TIMEOUT)


async def _error_code(result: types.CallToolResult) -> str | None:
    data = _json(result)
    if isinstance(data, dict):
        err = data.get("error")
        if isinstance(err, dict):
            return err.get("code")
    return None


@asynccontextmanager
async def fresh_server() -> AsyncGenerator[ClientSession, None]:
    with tempfile.TemporaryDirectory(prefix="omega_ph3_") as tmpdir:
        async with stdio_client(_server_params(tmpdir)) as streams:
            read, write = streams
            async with ClientSession(read, write) as session:
                await asyncio.wait_for(session.initialize(), timeout=TIMEOUT)
                yield session


# ═══════════════════════════════════════════════════════════════════════════
# Registration
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_new_tools_registered():
    async with fresh_server() as s:
        listed = await s.list_tools()
        names = {t.name for t in listed.tools}
        for tool in NEW_TOOLS:
            assert tool in names, f"{tool} not registered in MCP tool list"


# ═══════════════════════════════════════════════════════════════════════════
# Active tools — deny-by-default gating
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_active_tools_deny_without_scope_rules():
    """Active tools must deny (SCOPE_DENIED) under an engagement with no scope rules."""
    async with fresh_server() as s:
        eng = await _call(s, "omega_engagement_create", {"name": "P3-A", "mode": "pentest"})
        eid = _json(eng)["id"]
        for name, args in ACTIVE_TOOLS:
            r = await _call(s, name, {**args, "engagement_id": eid})
            code = await _error_code(r)
            assert code == "SCOPE_DENIED", f"{name} expected SCOPE_DENIED, got {code}: {_extract(r)[:200]}"


@pytest.mark.asyncio
async def test_active_tools_deny_analysis_only():
    """Active tools are also blocked in analysis_only mode (no autonomous testing)."""
    async with fresh_server() as s:
        eng = await _call(s, "omega_engagement_create", {"name": "P3-AO", "mode": "analysis_only"})
        eid = _json(eng)["id"]
        for name, args in ACTIVE_TOOLS:
            r = await _call(s, name, {**args, "engagement_id": eid})
            assert await _error_code(r) == "SCOPE_DENIED", f"{name} must deny in analysis_only"


# ═══════════════════════════════════════════════════════════════════════════
# Passive tools — permitted in analysis_only
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_passive_tools_allowed_analysis_only():
    """Passive/observation-only tools must proceed (never SCOPE_DENIED)."""
    async with fresh_server() as s:
        eng = await _call(s, "omega_engagement_create", {"name": "P3-P", "mode": "analysis_only"})
        eid = _json(eng)["id"]
        for name, args in PASSIVE_TOOLS:
            r = await _call(s, name, {**args, "engagement_id": eid})
            code = await _error_code(r)
            assert code != "SCOPE_DENIED", (
                f"{name} passive tool must be permitted in analysis_only: {_extract(r)[:200]}"
            )
            parsed = _json(r)
            assert isinstance(parsed, (dict, list)), f"{name} should return structured JSON: {_extract(r)[:200]}"


@pytest.mark.asyncio
async def test_missing_binary_tools_return_structured_error():
    """Missing optional binaries surface as BINARY_MISSING, not a crash."""
    async with fresh_server() as s:
        r = await _call(s, "omega_recon_dns_lookup", {"target": "example.com"})
        assert await _error_code(r) in ("BINARY_MISSING", None)


# ═══════════════════════════════════════════════════════════════════════════
# CTF toolkit happy path
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_ctf_toolkit_hypothesis_lifecycle():
    async with fresh_server() as s:
        eng = await _call(s, "omega_engagement_create", {"name": "P3-CTF", "mode": "ctf"})
        eid = _json(eng)["id"]
        ch = await _call(s, "omega_ctf_challenge_create", {"engagement_id": eid, "name": "Rev Me", "category": "rev"})
        challenge = _json(ch)
        assert isinstance(challenge, dict)
        cid = challenge["id"]

        hyp = await _call(s, "omega_ctf_hypothesis", {"challenge_id": cid, "hypothesis": "flag in constant pool"})
        hyp_data = _json(hyp)
        hyp_id = hyp_data["id"]

        r = await _call(s, "omega_ctf_resolve_hypothesis", {
            "challenge_id": cid, "hypothesis_id": hyp_id,
            "result": "binary strings", "successful": True,
        })
        assert _json(r).get("resolved") is True

        r = await _call(s, "omega_ctf_add_note", {"challenge_id": cid, "note": "check .rodata"})
        assert _json(r).get("added") is True

        r = await _call(s, "omega_ctf_add_artifact", {"challenge_id": cid, "artifact": "/bin/ls"})
        assert _json(r).get("added") is True

        ledger = await _call(s, "omega_ctf_hypothesis_ledger", {"challenge_id": cid})
        data = _json(ledger)
        assert data["total_hypotheses"] == 1
        assert len(data["succeeded"]) == 1
        assert "binary strings" in data["succeeded"][0]["result"]


# ═══════════════════════════════════════════════════════════════════════════
# Reporting — hypotheses included
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_report_includes_hypotheses():
    async with fresh_server() as s:
        eng = await _call(s, "omega_engagement_create", {"name": "P3-RPT", "mode": "ctf"})
        eid = _json(eng)["id"]
        await _call(s, "omega_hypothesis_create", {
            "engagement_id": eid, "category": "web", "target": "http://t.example.com",
            "hypothesis": "IDOR on items endpoint", "endpoint": "/items",
        })
        md = await _call(s, "omega_report_generate", {"engagement_id": eid, "format": "markdown"})
        assert "## Hypotheses" in _extract(md)

        js = await _call(s, "omega_report_generate", {"engagement_id": eid, "format": "json"})
        data = _json(js)
        report = json.loads(data["content"])
        assert "hypotheses" in report
        assert len(report["hypotheses"]) >= 1


# ═══════════════════════════════════════════════════════════════════════════
# orch.api lazy wiring — in-process against a live local server
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_orchestrator_api_engine_wired():
    with tempfile.TemporaryDirectory(prefix="omega_ph3_db_") as td:
        db = Database(os.path.join(td, "test.db"))
        await db.connect()
        try:
            orch = Orchestrator(db)
            assert orch.api is orch.api  # lazy singleton
            server = TestServer()
            port = server.start()
            base = f"http://127.0.0.1:{port}"
            try:
                openapi = await orch.api.discover_openapi(base)
                assert isinstance(openapi, dict)
                assert "found" in openapi

                graphql = await orch.api.discover_graphql(base)
                assert isinstance(graphql, dict) and "found" in graphql

                auth = await orch.api.analyze_authentication(base)
                assert isinstance(auth, dict) and "url" in auth
            finally:
                server.stop()
        finally:
            await db.close()


# ═══════════════════════════════════════════════════════════════════════════
# Vuln triage — nuclei/nikto → Finding records
# ═══════════════════════════════════════════════════════════════════════════

SAMPLE_NUCLEI_PARSED = {
    "findings": [
        {
            "template_id": "cves/2021/CVE-2021-44228",
            "name": "Log4j RCE",
            "severity": "critical",
            "matched_at": "http://target.example.com:8080/api",
            "type": "http",
            "matcher_name": "log4j",
            "curl_command": "curl -X GET http://target.example.com/api",
        },
        {
            "template_id": "misconfiguration/directory-listing",
            "name": "Directory Listing Enabled",
            "severity": "medium",
            "matched_at": "http://target.example.com/files/",
            "type": "http",
            "matcher_name": "",
            "curl_command": "",
        },
        {
            "template_id": "technologies/wordpress",
            "name": "WordPress Detected",
            "severity": "info",
            "matched_at": "http://target.example.com/",
            "type": "http",
            "matcher_name": "",
            "curl_command": "",
        },
    ],
    "severity_counts": {"critical": 1, "medium": 1, "info": 1},
}

SAMPLE_NIKTO_PARSED = {
    "vulnerabilities": [
        {"finding": "OSVDB-3092: /admin/: This might be interesting...", "source": "nikto"},
        {"finding": "CVE-2021-41773: Path traversal in Apache", "source": "nikto"},
        {"info": "+ Server: Apache/2.4.41"},
        {"finding": "Retrieved x-powered-by header: PHP/7.4.3", "source": "nikto"},
    ],
    "server_info": {"server": "Apache/2.4.41"},
}


@pytest.mark.asyncio
async def test_triage_nuclei_findings_creates_records():
    """_triage_nuclei_findings maps parsed findings to Finding records with correct severity."""
    with tempfile.TemporaryDirectory(prefix="omega_triage_") as td:
        db = Database(os.path.join(td, "test.db"))
        await db.connect()
        try:
            orch = Orchestrator(db)
            # Create engagement
            eng = await orch.create_engagement("Triage Test", "pentest", "triage test")

            server = OmegaServer()
            server.db = db
            server.orchestrator = orch
            server._initialized = True

            ids = await server._triage_nuclei_findings(
                eng.id, "http://target.example.com", SAMPLE_NUCLEI_PARSED,
            )
            assert len(ids) == 3

            findings = await orch.findings.list_findings(eng.id)
            assert len(findings) == 3
            titles = {f.title for f in findings}
            assert "[nuclei] Log4j RCE" in titles
            assert "[nuclei] Directory Listing Enabled" in titles
            assert "[nuclei] WordPress Detected" in titles

            # Severity mapping
            by_title = {f.title: f for f in findings}
            assert by_title["[nuclei] Log4j RCE"].severity == Severity.CRITICAL
            assert by_title["[nuclei] Directory Listing Enabled"].severity == Severity.MEDIUM
            assert by_title["[nuclei] WordPress Detected"].severity == Severity.INFORMATIONAL

            # Authorization stamping
            for f in findings:
                assert f.authorization_status in ("authorized", "not_in_scope", "unverified")

            # References include nuclei template links
            log4j = by_title["[nuclei] Log4j RCE"]
            assert any("CVE-2021-44228" in r for r in log4j.references)

            # Technical details
            assert log4j.technical_details["template_id"] == "cves/2021/CVE-2021-44228"
            assert log4j.tool_sources == ["nuclei"]
        finally:
            await db.close()


@pytest.mark.asyncio
async def test_triage_nikto_findings_creates_records():
    """_triage_nikto_findings maps OSVDB/CVE vulns to Finding records."""
    with tempfile.TemporaryDirectory(prefix="omega_triage_") as td:
        db = Database(os.path.join(td, "test.db"))
        await db.connect()
        try:
            orch = Orchestrator(db)
            eng = await orch.create_engagement("Nikto Triage", "pentest", "triage test")

            server = OmegaServer()
            server.db = db
            server.orchestrator = orch
            server._initialized = True

            ids = await server._triage_nikto_findings(
                eng.id, "http://target.example.com", SAMPLE_NIKTO_PARSED,
            )
            # Only vulns with source="nikto" should be triaged; info line without nikto source is skipped
            assert len(ids) == 3

            findings = await orch.findings.list_findings(eng.id)
            assert len(findings) == 3

            # OSVDB reference
            osvdb_finding = [f for f in findings if "OSVDB-3092" in f.title][0]
            assert any("osvdb.org" in r for r in osvdb_finding.references)

            # CVE reference
            cve_finding = [f for f in findings if "CVE-2021-41773" in f.title][0]
            assert "CVE-2021-41773" in cve_finding.references

            # Tool source
            for f in findings:
                assert f.tool_sources == ["nikto"]
        finally:
            await db.close()


@pytest.mark.asyncio
async def test_triage_skipped_without_engagement_id():
    """_triage methods return empty list when no engagement_id is provided."""
    with tempfile.TemporaryDirectory(prefix="omega_triage_") as td:
        db = Database(os.path.join(td, "test.db"))
        await db.connect()
        try:
            orch = Orchestrator(db)
            server = OmegaServer()
            server.db = db
            server.orchestrator = orch
            server._initialized = True

            ids = await server._triage_nuclei_findings("", "http://x.com", SAMPLE_NUCLEI_PARSED)
            assert ids == []
        finally:
            await db.close()


@pytest.mark.asyncio
async def test_run_recon_includes_triaged_findings():
    """_run_recon auto-triages nuclei findings when engagement_id is present."""
    with tempfile.TemporaryDirectory(prefix="omega_triage_") as td:
        db = Database(os.path.join(td, "test.db"))
        await db.connect()
        try:
            orch = Orchestrator(db)
            eng = await orch.create_engagement("RunRecon Triage", "ctf", "")

            server = OmegaServer()
            server.db = db
            server.orchestrator = orch
            server._initialized = True

            # Create a fake adapter that returns nuclei-like parsed_output
            class FakeNucleiAdapter:
                def name(self) -> str: return "nuclei"
                def version(self) -> str: return "test"
                async def execute(self, request):
                    from omega.core.schemas import ToolResult
                    return ToolResult(
                        id=new_id(), tool_name="nuclei", success=True,
                        raw_output="test", parsed_output=SAMPLE_NUCLEI_PARSED,
                        normalized_output={"assets": []},
                        target=request.target,
                        created_at=now_utc(), updated_at=now_utc(),
                    )

            result_json = await server._run_recon(
                FakeNucleiAdapter(), "nuclei", "http://target.example.com",
                eng.id, "active",
            )
            result = json.loads(result_json)
            assert result["success"] is True
            assert len(result["triaged_findings"]) == 3

            # Findings actually in the DB
            findings = await orch.findings.list_findings(eng.id)
            assert len(findings) == 3
        finally:
            await db.close()


@pytest.mark.asyncio
async def test_run_recon_no_triage_without_engagement():
    """_run_recon does NOT triage when engagement_id is empty."""
    with tempfile.TemporaryDirectory(prefix="omega_triage_") as td:
        db = Database(os.path.join(td, "test.db"))
        await db.connect()
        try:
            orch = Orchestrator(db)
            server = OmegaServer()
            server.db = db
            server.orchestrator = orch
            server._initialized = True

            class FakeNucleiAdapter:
                def name(self) -> str: return "nuclei"
                def version(self) -> str: return "test"
                async def execute(self, request):
                    from omega.core.schemas import ToolResult
                    return ToolResult(
                        id=new_id(), tool_name="nuclei", success=True,
                        raw_output="test", parsed_output=SAMPLE_NUCLEI_PARSED,
                        normalized_output={"assets": []},
                        target=request.target,
                        created_at=now_utc(), updated_at=now_utc(),
                    )

            result_json = await server._run_recon(
                FakeNucleiAdapter(), "nuclei", "http://target.example.com",
                "", "active",
            )
            result = json.loads(result_json)
            assert result["triaged_findings"] == []
        finally:
            await db.close()


@pytest.mark.asyncio
async def test_triage_deduplicates():
    """Duplicate findings (same title + endpoint) get marked as DUPLICATE."""
    with tempfile.TemporaryDirectory(prefix="omega_triage_") as td:
        db = Database(os.path.join(td, "test.db"))
        await db.connect()
        try:
            orch = Orchestrator(db)
            eng = await orch.create_engagement("Dedup Triage", "pentest", "")

            server = OmegaServer()
            server.db = db
            server.orchestrator = orch
            server._initialized = True

            dup_parsed = {
                "findings": [
                    {
                        "template_id": "misconfig/x",
                        "name": "Test Finding",
                        "severity": "low",
                        "matched_at": "http://t.com/a",
                        "type": "http",
                        "matcher_name": "",
                        "curl_command": "",
                    },
                    {
                        "template_id": "misconfig/x",
                        "name": "Test Finding",
                        "severity": "low",
                        "matched_at": "http://t.com/a",
                        "type": "http",
                        "matcher_name": "",
                        "curl_command": "",
                    },
                ],
                "severity_counts": {"low": 2},
            }
            ids = await server._triage_nuclei_findings(eng.id, "http://t.com", dup_parsed)
            assert len(ids) == 2

            findings = await orch.findings.list_findings(eng.id)
            from omega.core.schemas import ValidationStatus
            statuses = [f.validation_status for f in findings]
            assert ValidationStatus.DUPLICATE in statuses
            assert ValidationStatus.CANDIDATE in statuses
        finally:
            await db.close()


# ═══════════════════════════════════════════════════════════════════════════
# Phase 4 — omega_health_check
# ═══════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_health_check_reports_status():
    """omega_health_check returns structured health with DB + tool registrations."""
    async with fresh_server() as s:
        r = await _call(s, "omega_health_check", {})
        data = _json(r)
        assert data["status"] in ("ready", "degraded")
        assert data["database"] == "connected"
        assert data["registry_size"] > 0
        assert isinstance(data["tools"]["installed"], list)
        assert isinstance(data["tools"]["missing"], list)
        # Core tool set is always reported
        all_tools = set(data["tools"]["installed"]) | set(data["tools"]["missing"])
        assert "nmap" in all_tools
        assert "nuclei" in all_tools
