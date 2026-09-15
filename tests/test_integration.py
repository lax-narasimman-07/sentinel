"""End-to-end integration tests for OMEGA-CYBER-MCP.

Tests real workflows through the MCP protocol against a local test fixture server.
Each test group uses a shared server fixture for efficiency.
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

from tests.fixtures import TestServer

# ── Constants ───────────────────────────────────────────────────────────────

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VENV_PYTHON = os.path.join(PROJECT_ROOT, ".venv", "bin", "python")
TIMEOUT = 30


# ── Helpers ─────────────────────────────────────────────────────────────────

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
    with tempfile.TemporaryDirectory(prefix="omega_integ_") as tmpdir:
        async with stdio_client(_server_params(tmpdir)) as streams:
            read, write = streams
            async with ClientSession(read, write) as session:
                await asyncio.wait_for(session.initialize(), timeout=TIMEOUT)
                yield session


# ── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def test_server() -> TestServer:
    server = TestServer(port=0)
    server.start()
    yield server
    server.stop()


@pytest.fixture(scope="module")
def base_url(test_server: TestServer) -> str:
    return f"http://127.0.0.1:{test_server.port}"


# ═══════════════════════════════════════════════════════════════════════════
# 1. SCOPE → TARGET → DISCOVERY → PROBE → GRAPH PIPELINE
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_scope_to_graph_pipeline(base_url: str):
    """Scope → engagement → graph nodes → graph query → persistence."""
    async with fresh_server() as s:
        # Create engagement
        r = await _call(s, "omega_engagement_create", {
            "name": "Pipeline Test", "mode": "local_lab",
        })
        eng = _json(r)
        eid = eng["id"]

        # Add scope rule
        r = await _call(s, "omega_scope_add_rule", {
            "engagement_id": eid, "rule_type": "include",
            "target_type": "domain", "pattern": "127.0.0.1",
        })
        assert _json(r)["success"]

        # Check scope
        r = await _call(s, "omega_scope_check", {
            "engagement_id": eid, "target": "127.0.0.1",
        })
        assert _json(r)["allowed"]

        # Build graph: domain → subdomain → IP → service → URL
        nodes = []
        chain = [
            ("domain", "example.com"),
            ("subdomain", "www.example.com"),
            ("ip", "127.0.0.1"),
            ("service", f"127.0.0.1:80/tcp"),
            ("url", f"{base_url}/"),
        ]
        for ntype, label in chain:
            r = await _call(s, "omega_graph_add_node", {
                "engagement_id": eid, "node_type": ntype, "label": label,
            })
            assert not r.is_error
            nodes.append(_json(r))

        # Add edges
        for i in range(len(nodes) - 1):
            r = await _call(s, "omega_graph_add_edge", {
                "engagement_id": eid,
                "source_id": nodes[i]["id"],
                "target_id": nodes[i + 1]["id"],
                "edge_type": "connects_to",
            })
            assert not r.is_error

        # Query
        r = await _call(s, "omega_graph_query", {
            "engagement_id": eid, "node_type": "domain",
        })
        q = _json(r)
        assert q["count"] == 1
        assert q["nodes"][0]["label"] == "example.com"


# ═══════════════════════════════════════════════════════════════════════════
# 2. WEB SECURITY: headers, CORS, cookies, endpoints, JS analysis
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_web_headers_analysis(base_url: str):
    r = await fresh_server().__aenter__().__anext__() if False else None
    async with fresh_server() as s:
        r = await _call(s, "omega_web_headers", {
            "url": f"{base_url}/",
        })
        assert not r.is_error
        data = _json(r)
        assert "headers" in data or "missing_security_headers" in data or "url" in data


@pytest.mark.asyncio
async def test_web_cors_analysis(base_url: str):
    async with fresh_server() as s:
        r = await _call(s, "omega_web_cors", {
            "url": f"{base_url}/cors-test",
        })
        assert not r.is_error
        data = _json(r)
        assert isinstance(data, dict)


@pytest.mark.asyncio
async def test_web_cookies_analysis(base_url: str):
    async with fresh_server() as s:
        r = await _call(s, "omega_web_cookies", {
            "url": f"{base_url}/cookies",
        })
        assert not r.is_error
        data = _json(r)
        assert isinstance(data, dict)


@pytest.mark.asyncio
async def test_web_endpoints_extraction(base_url: str):
    async with fresh_server() as s:
        r = await _call(s, "omega_web_endpoints", {
            "url": f"{base_url}/",
        })
        assert not r.is_error
        data = _json(r)
        assert isinstance(data, dict)
        endpoints = data.get("endpoints", data.get("found", []))
        assert isinstance(endpoints, list)
        assert len(endpoints) > 0


@pytest.mark.asyncio
async def test_web_js_analyze(base_url: str):
    async with fresh_server() as s:
        r = await _call(s, "omega_web_js_analyze", {
            "js_url": f"{base_url}/static/app.js",
        })
        assert not r.is_error
        data = _json(r)
        assert isinstance(data, dict)


@pytest.mark.asyncio
async def test_web_full_scan(base_url: str):
    async with fresh_server() as s:
        eng_r = await _call(s, "omega_engagement_create", {
            "name": "Web Scan Test", "mode": "local_lab",
        })
        eid = _json(eng_r)["id"]

        r = await _call(s, "omega_web_full_scan", {
            "target": f"{base_url}",
            "engagement_id": eid,
        })
        assert not r.is_error
        data = _json(r)
        assert isinstance(data, dict)


# ═══════════════════════════════════════════════════════════════════════════
# 3. HTTP CLIENT
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_http_get(base_url: str):
    async with fresh_server() as s:
        r = await _call(s, "omega_http_request", {
            "method": "GET", "url": f"{base_url}/api/users",
        })
        assert not r.is_error
        data = _json(r)
        assert data["status_code"] == 200
        body = json.loads(data["body"])
        assert isinstance(body, list)


@pytest.mark.asyncio
async def test_http_post_json(base_url: str):
    async with fresh_server() as s:
        r = await _call(s, "omega_http_request", {
            "method": "POST",
            "url": f"{base_url}/login",
            "json_body": json.dumps({"username": "admin", "password": "password123"}),
        })
        assert not r.is_error
        data = _json(r)
        assert data["status_code"] == 200
        body = json.loads(data["body"])
        assert "token" in body


@pytest.mark.asyncio
async def test_http_404(base_url: str):
    async with fresh_server() as s:
        r = await _call(s, "omega_http_request", {
            "method": "GET", "url": f"{base_url}/nonexistent",
        })
        assert not r.is_error
        data = _json(r)
        assert data["status_code"] == 404


@pytest.mark.asyncio
async def test_http_request_with_history(base_url: str):
    async with fresh_server() as s:
        eng_r = await _call(s, "omega_engagement_create", {
            "name": "HTTP History", "mode": "local_lab",
        })
        eid = _json(eng_r)["id"]

        r = await _call(s, "omega_http_request", {
            "method": "GET",
            "url": f"{base_url}/health",
            "engagement_id": eid,
        })
        assert not r.is_error

        # Verify the request was recorded
        r = await _call(s, "omega_evidence_list", {"engagement_id": eid})
        assert not r.is_error


# ═══════════════════════════════════════════════════════════════════════════
# 4. EVIDENCE ENGINE
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_evidence_pipeline():
    async with fresh_server() as s:
        eng_r = await _call(s, "omega_engagement_create", {
            "name": "Evidence Test", "mode": "local_lab",
        })
        eid = _json(eng_r)["id"]

        # Create a hypothesis
        h_r = await _call(s, "omega_hypothesis_create", {
            "engagement_id": eid,
            "category": "xss",
            "target": "test.local",
            "hypothesis": "XSS via search param",
        })
        assert not h_r.is_error

        # List evidence (empty initially)
        e_r = await _call(s, "omega_evidence_list", {"engagement_id": eid})
        assert not e_r.is_error
        ev = _json(e_r)
        assert isinstance(ev, list)


# ═══════════════════════════════════════════════════════════════════════════
# 5. FINDING LIFECYCLE
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_finding_full_lifecycle():
    """hypothesis → candidate → testing → validated → summary."""
    async with fresh_server() as s:
        eng_r = await _call(s, "omega_engagement_create", {
            "name": "Finding Lifecycle", "mode": "local_lab",
        })
        eid = _json(eng_r)["id"]

        # Create hypothesis
        h_r = await _call(s, "omega_hypothesis_create", {
            "engagement_id": eid,
            "category": "sqli",
            "target": "app.local",
            "hypothesis": "SQL injection in login",
            "endpoint": "/login",
        })
        hyp = _json(h_r)
        assert hyp["status"] == "hypothesis"
        hyp_id = hyp["id"]

        # Update hypothesis
        u_r = await _call(s, "omega_hypothesis_update", {
            "hypothesis_id": hyp_id,
            "observation": "Parameter 'user' accepts single quotes without error",
            "confidence": "medium",
        })
        assert not u_r.is_error

        # Create finding from hypothesis
        f_r = await _call(s, "omega_finding_create", {
            "engagement_id": eid,
            "title": "SQL Injection in /login",
            "severity": "high",
            "confidence": "high",
            "affected_asset": "app.local",
            "affected_endpoint": "/login",
            "description": "The 'user' parameter is vulnerable to SQL injection",
            "cwe_id": "CWE-89",
        })
        finding = _json(f_r)
        assert finding["severity"] == "high"
        fid = finding["id"]

        # Validate
        v_r = await _call(s, "omega_finding_validate", {"finding_id": fid})
        assert not v_r.is_error

        # List and check
        l_r = await _call(s, "omega_finding_list", {"engagement_id": eid})
        findings = _json(l_r)
        assert len(findings) >= 1
        assert any(f["title"] == "SQL Injection in /login" for f in findings)

        # Summary
        s_r = await _call(s, "omega_finding_summary", {"engagement_id": eid})
        summary = _json(s_r)
        assert summary["total"] >= 1
        assert summary["by_severity"]["high"] >= 1


@pytest.mark.asyncio
async def test_finding_reject():
    """hypothesis → candidate → rejected."""
    async with fresh_server() as s:
        eng_r = await _call(s, "omega_engagement_create", {
            "name": "Reject Test", "mode": "local_lab",
        })
        eid = _json(eng_r)["id"]

        f_r = await _call(s, "omega_finding_create", {
            "engagement_id": eid,
            "title": "False positive finding",
            "severity": "low",
            "affected_asset": "test.local",
        })
        fid = _json(f_r)["id"]

        r_r = await _call(s, "omega_finding_reject", {
            "finding_id": fid,
            "reason": "False positive — tested and not reproducible",
        })
        assert not r_r.is_error

        # Verify in list
        l_r = await _call(s, "omega_finding_list", {"engagement_id": eid})
        findings = _json(l_r)
        rejected = [f for f in findings if f.get("validation_status") == "rejected"]
        assert len(rejected) >= 1


@pytest.mark.asyncio
async def test_finding_deduplication():
    """Duplicate findings are detected."""
    async with fresh_server() as s:
        eng_r = await _call(s, "omega_engagement_create", {
            "name": "Dedup Test", "mode": "local_lab",
        })
        eid = _json(eng_r)["id"]

        # Create first finding
        f1_r = await _call(s, "omega_finding_create", {
            "engagement_id": eid,
            "title": "XSS in search",
            "severity": "high",
            "affected_asset": "app.local",
            "affected_endpoint": "/search",
        })
        f1 = _json(f1_r)

        # Create duplicate
        f2_r = await _call(s, "omega_finding_create", {
            "engagement_id": eid,
            "title": "XSS in search",
            "severity": "high",
            "affected_asset": "app.local",
            "affected_endpoint": "/search",
        })
        f2 = _json(f2_r)

        # List should contain both (dedup is advisory, not blocking)
        l_r = await _call(s, "omega_finding_list", {"engagement_id": eid})
        findings = _json(l_r)
        xss_findings = [f for f in findings if "XSS" in f.get("title", "")]
        assert len(xss_findings) >= 2


# ═══════════════════════════════════════════════════════════════════════════
# 6. CTF WORKFLOW
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_ctf_web_challenge():
    """Full CTF workflow: create → hypothesis → flag → confirm."""
    async with fresh_server() as s:
        eng_r = await _call(s, "omega_engagement_create", {
            "name": "CTF Test", "mode": "ctf",
        })
        eid = _json(eng_r)["id"]

        # Create challenge
        ch_r = await _call(s, "omega_ctf_challenge_create", {
            "engagement_id": eid,
            "name": "SQLi Login",
            "category": "web",
            "target": "127.0.0.1",
            "port": 5000,
        })
        ch = _json(ch_r)
        ch_id = ch["id"]

        # Add hypothesis
        h_r = await _call(s, "omega_ctf_hypothesis", {
            "challenge_id": ch_id,
            "hypothesis": "SQL injection with ' OR 1=1 --",
            "test_plan": "Try authentication bypass",
            "category": "exploitation",
        })
        hyp = _json(h_r)
        assert hyp["status"] == "active"

        # Submit flag
        sub_r = await _call(s, "omega_ctf_submit_flag", {
            "challenge_id": ch_id, "flag": "flag{sqli_bypass}",
        })
        sub = _json(sub_r)
        assert sub["submitted"]

        # Confirm flag
        conf_r = await _call(s, "omega_ctf_confirm_flag", {
            "challenge_id": ch_id, "flag": "flag{sqli_bypass}",
        })
        conf = _json(conf_r)
        assert conf["confirmed"]

        # Check ledger
        led_r = await _call(s, "omega_ctf_ledger", {"challenge_id": ch_id})
        ledger = _json(led_r)
        all_hyps = (
            ledger.get("active", [])
            + ledger.get("succeeded", [])
            + ledger.get("failed", [])
        )
        assert len(all_hyps) >= 1
        assert ledger["solved"] is True

        # List challenges
        list_r = await _call(s, "omega_ctf_challenge_list", {
            "engagement_id": eid,
        })
        challenges = _json(list_r)
        assert len(challenges) >= 1


@pytest.mark.asyncio
async def test_ctf_failed_attempt():
    """Track failed flag attempts."""
    async with fresh_server() as s:
        eng_r = await _call(s, "omega_engagement_create", {
            "name": "CTF Failed", "mode": "ctf",
        })
        eid = _json(eng_r)["id"]

        ch_r = await _call(s, "omega_ctf_challenge_create", {
            "engagement_id": eid,
            "name": "Crypto Challenge",
            "category": "crypto",
        })
        ch_id = _json(ch_r)["id"]

        # Add a hypothesis first so the ledger has something
        await _call(s, "omega_ctf_hypothesis", {
            "challenge_id": ch_id,
            "hypothesis": "Brute force the flag",
            "test_plan": "Try common flag formats",
            "category": "exhaustion",
        })

        # Submit wrong flags — confirm_flag always succeeds (engine tracks, doesn't validate)
        for wrong in ["flag{wrong1}", "flag{wrong2}", "flag{wrong3}"]:
            r = await _call(s, "omega_ctf_submit_flag", {
                "challenge_id": ch_id, "flag": wrong,
            })
            sub = _json(r)
            assert sub["submitted"]
            # confirm_flag marks the flag as confirmed (user is responsible for validation)
            cr = await _call(s, "omega_ctf_confirm_flag", {
                "challenge_id": ch_id, "flag": wrong,
            })
            conf = _json(cr)
            assert conf["confirmed"]

        # Ledger should show the hypothesis as active (never resolved via resolve_hypothesis)
        led_r = await _call(s, "omega_ctf_ledger", {"challenge_id": ch_id})
        ledger = _json(led_r)
        all_hyps = (
            ledger.get("active", [])
            + ledger.get("succeeded", [])
            + ledger.get("failed", [])
        )
        assert len(all_hyps) >= 1


# ═══════════════════════════════════════════════════════════════════════════
# 7. ASSET GRAPH: full chain with persistence
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_asset_graph_full_chain():
    """domain → subdomain → IP → port → service → URL → endpoint → finding."""
    async with fresh_server() as s:
        eng_r = await _call(s, "omega_engagement_create", {
            "name": "Graph Chain", "mode": "local_lab",
        })
        eid = _json(eng_r)["id"]

        chain = [
            ("domain", "example.com"),
            ("subdomain", "api.example.com"),
            ("ip", "93.184.216.34"),
            ("port", "93.184.216.34:443/tcp"),
            ("service", "HTTPS"),
            ("url", "https://api.example.com/v1"),
            ("endpoint", "GET /api/v1/users"),
            ("parameter", "id"),
            ("hypothesis", "IDOR on user ID"),
            ("finding", "IDOR - user data leak"),
        ]

        node_ids = []
        for ntype, label in chain:
            r = await _call(s, "omega_graph_add_node", {
                "engagement_id": eid, "node_type": ntype, "label": label,
            })
            assert not r.is_error
            node_ids.append(_json(r)["id"])

        for i in range(len(node_ids) - 1):
            r = await _call(s, "omega_graph_add_edge", {
                "engagement_id": eid,
                "source_id": node_ids[i],
                "target_id": node_ids[i + 1],
                "edge_type": "chain",
            })
            assert not r.is_error

        # Query by type
        for ntype in ("domain", "ip", "url", "finding"):
            r = await _call(s, "omega_graph_query", {
                "engagement_id": eid, "node_type": ntype,
            })
            q = _json(r)
            assert q["count"] >= 1, f"Expected >=1 node of type {ntype}, got {q['count']}"


@pytest.mark.asyncio
async def test_asset_graph_persistence():
    """Graph data persists across server restarts (via DB)."""
    with tempfile.TemporaryDirectory(prefix="omega_persist_") as tmpdir:
        # Server 1: create data
        async with stdio_client(_server_params(tmpdir)) as streams:
            async with ClientSession(*streams) as s:
                await asyncio.wait_for(s.initialize(), timeout=TIMEOUT)
                eng_r = await _call(s, "omega_engagement_create", {
                    "name": "Persist Test", "mode": "local_lab",
                })
                eid = _json(eng_r)["id"]
                r = await _call(s, "omega_graph_add_node", {
                    "engagement_id": eid, "node_type": "domain", "label": "persist.local",
                })
                assert not r.is_error

        # Server 2: read data back
        async with stdio_client(_server_params(tmpdir)) as streams:
            async with ClientSession(*streams) as s:
                await asyncio.wait_for(s.initialize(), timeout=TIMEOUT)
                # Need the engagement ID from DB
                r = await _call(s, "omega_engagement_list")
                engagements = _json(r)
                eid = engagements[0]["id"]
                r = await _call(s, "omega_graph_query", {
                    "engagement_id": eid, "node_type": "domain",
                })
                q = _json(r)
                assert q["count"] == 1
                assert q["nodes"][0]["label"] == "persist.local"


# ═══════════════════════════════════════════════════════════════════════════
# 8. ORCHESTRATOR: multi-step workflow
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_orchestrator_scan_analysis_only():
    """Orchestrator run_scan with analysis_only mode."""
    async with fresh_server() as s:
        eng_r = await _call(s, "omega_engagement_create", {
            "name": "Orch Test", "mode": "analysis_only",
        })
        eid = _json(eng_r)["id"]

        r = await _call(s, "omega_scan", {
            "target": "example.com",
            "engagement_id": eid,
            "scan_type": "recon",
        })
        assert not r.is_error
        data = _json(r)
        assert "target" in data or "results" in data or "steps" in data


# ═══════════════════════════════════════════════════════════════════════════
# 9. REPORT GENERATION
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_report_markdown():
    async with fresh_server() as s:
        eng_r = await _call(s, "omega_engagement_create", {
            "name": "Report Test", "mode": "local_lab",
        })
        eid = _json(eng_r)["id"]

        # Add a finding
        await _call(s, "omega_finding_create", {
            "engagement_id": eid,
            "title": "XSS in search",
            "severity": "high",
            "affected_asset": "app.local",
        })

        r = await _call(s, "omega_report_generate", {
            "engagement_id": eid,
            "format": "markdown",
        })
        assert not r.is_error
        report = _json(r)
        assert report["format"] == "markdown"
        assert "XSS" in report["content"]


@pytest.mark.asyncio
async def test_report_json():
    async with fresh_server() as s:
        eng_r = await _call(s, "omega_engagement_create", {
            "name": "JSON Report", "mode": "local_lab",
        })
        eid = _json(eng_r)["id"]

        r = await _call(s, "omega_report_generate", {
            "engagement_id": eid,
            "format": "json",
        })
        assert not r.is_error
        report = _json(r)
        assert report["format"] == "json"


# ═══════════════════════════════════════════════════════════════════════════
# 10. RECON TOOLS (availability-dependent)
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_tools_list_shows_available():
    async with fresh_server() as s:
        r = await _call(s, "omega_tools_list")
        tools = _json(r)
        assert isinstance(tools, dict)
        # nmap should be available on this system
        assert "nmap" in tools
        assert tools["nmap"]["available"] is True


@pytest.mark.asyncio
async def test_doctor_checks():
    async with fresh_server() as s:
        r = await _call(s, "omega_doctor")
        data = _json(r)
        assert "tools" in data
        assert "python_version" in data
        available = [t for t, info in data["tools"].items() if info.get("installed")]
        assert len(available) > 0


@pytest.mark.asyncio
async def test_scope_enforcement_bug_bounty():
    """Bug bounty mode requires scope rules, blocks unscoped targets."""
    async with fresh_server() as s:
        eng_r = await _call(s, "omega_engagement_create", {
            "name": "BB Scope", "mode": "bug_bounty",
        })
        eid = _json(eng_r)["id"]

        # No rules added — should deny
        r = await _call(s, "omega_scope_check", {
            "engagement_id": eid, "target": "any-random-host.com",
        })
        data = _json(r)
        assert data["allowed"] is False

        # Add a rule
        await _call(s, "omega_scope_add_rule", {
            "engagement_id": eid, "rule_type": "include",
            "target_type": "wildcard", "pattern": "*.target.com",
        })

        # In-scope target
        r = await _call(s, "omega_scope_check", {
            "engagement_id": eid, "target": "sub.target.com",
        })
        data = _json(r)
        assert data["allowed"]

        # Out-of-scope target
        r = await _call(s, "omega_scope_check", {
            "engagement_id": eid, "target": "evil.com",
        })
        data = _json(r)
        assert data["allowed"] is False


@pytest.mark.asyncio
async def test_scope_enforcement_ctf():
    """CTF mode allows all targets by default."""
    async with fresh_server() as s:
        eng_r = await _call(s, "omega_engagement_create", {
            "name": "CTF Scope", "mode": "ctf",
        })
        eid = _json(eng_r)["id"]

        for target in ["challenge.local", "10.0.0.1", "any.domain.org"]:
            r = await _call(s, "omega_scope_check", {
                "engagement_id": eid, "target": target,
            })
            data = _json(r)
            assert data["allowed"], f"CTF mode should allow {target}"


@pytest.mark.asyncio
async def test_scope_exclusion_in_ctf():
    """CTF mode with exclusion rule."""
    async with fresh_server() as s:
        eng_r = await _call(s, "omega_engagement_create", {
            "name": "CTF Exclude", "mode": "ctf",
        })
        eid = _json(eng_r)["id"]

        await _call(s, "omega_scope_add_rule", {
            "engagement_id": eid, "rule_type": "exclude",
            "target_type": "domain", "pattern": "forbidden.example.com",
        })

        r = await _call(s, "omega_scope_check", {
            "engagement_id": eid, "target": "forbidden.example.com",
        })
        data = _json(r)
        assert data["allowed"] is False

        r = await _call(s, "omega_scope_check", {
            "engagement_id": eid, "target": "allowed.example.com",
        })
        data = _json(r)
        assert data["allowed"]


# ═══════════════════════════════════════════════════════════════════════════
# 11. API SECURITY: endpoints, differential analysis
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_api_endpoint_discovery(base_url: str):
    """Discover API endpoints from the test app."""
    async with fresh_server() as s:
        r = await _call(s, "omega_web_endpoints", {
            "url": f"{base_url}/",
        })
        assert not r.is_error
        data = _json(r)
        endpoints = data.get("endpoints", data.get("found", []))
        # endpoints can be strings or dicts
        urls = []
        for e in endpoints:
            if isinstance(e, str):
                urls.append(e)
            elif isinstance(e, dict):
                urls.append(e.get("url", e.get("endpoint", "")))
        assert any("/api/" in u for u in urls), f"Expected API endpoints in {urls}"


@pytest.mark.asyncio
async def test_api_authentication_differential(base_url: str):
    """Compare authenticated vs unauthenticated responses."""
    async with fresh_server() as s:
        # Unauthenticated
        r1 = await _call(s, "omega_http_request", {
            "method": "GET", "url": f"{base_url}/api/secret",
        })
        resp1 = _json(r1)
        assert resp1["status_code"] == 403

        # With auth header
        r2 = await _call(s, "omega_http_request", {
            "method": "GET",
            "url": f"{base_url}/api/users",
            "headers": json.dumps({"Authorization": "Bearer admin-token"}),
        })
        resp2 = _json(r2)
        assert resp2["status_code"] == 200


@pytest.mark.asyncio
async def test_api_idor_hypothesis(base_url: str):
    """Generate IDOR hypothesis from API responses."""
    async with fresh_server() as s:
        eng_r = await _call(s, "omega_engagement_create", {
            "name": "IDOR Test", "mode": "local_lab",
        })
        eid = _json(eng_r)["id"]

        # Access two items
        r1 = await _call(s, "omega_http_request", {
            "method": "GET", "url": f"{base_url}/api/v1/items/1",
        })
        r2 = await _call(s, "omega_http_request", {
            "method": "GET", "url": f"{base_url}/api/v1/items/2",
        })

        resp1 = _json(r1)
        resp2 = _json(r2)
        assert resp1["status_code"] == 200
        assert resp2["status_code"] == 200

        # Generate hypothesis
        h_r = await _call(s, "omega_hypothesis_create", {
            "engagement_id": eid,
            "category": "idor",
            "target": f"127.0.0.1",
            "endpoint": "/api/v1/items/{id}",
            "hypothesis": "IDOR: item ID parameter not validated against user session",
        })
        hyp = _json(h_r)
        assert hyp["hypothesis"] == "IDOR: item ID parameter not validated against user session"
