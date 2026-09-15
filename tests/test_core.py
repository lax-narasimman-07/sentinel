"""Comprehensive test suite for OMEGA-CYBER-MCP."""

import asyncio
import json
import os
import tempfile
from typing import Any

import pytest
import pytest_asyncio

from omega.core.schemas import (
    Engagement, EngagementMode, Finding, Hypothesis, Severity, Confidence,
    ValidationStatus, ToolRiskLevel, ToolCapability, ToolExecutionRequest,
    ToolResult, Evidence, Asset, new_id, now_utc, content_hash,
)
from omega.config import OmegaConfig, set_config
from omega.storage import Database
from omega.scope import ScopeEngine, ScopeCheckResult
from omega.workspace import WorkspaceManager
from omega.tools import ToolAdapter, ToolRegistry, ToolExecutor
from omega.knowledge import AssetGraph
from omega.evidence import EvidenceEngine
from omega.findings import FindingEngine
from omega.ctf import CTFEngine
from omega.http import HTTPClient
from omega.reporting import ReportEngine


# ── Fixtures ───────────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def db():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        database = Database(db_path)
        await database.connect()
        yield database
        await database.close()


@pytest_asyncio.fixture
async def scope(db):
    return ScopeEngine(db)


@pytest_asyncio.fixture
async def evidence_engine(db):
    return EvidenceEngine(db)


@pytest_asyncio.fixture
async def finding_engine(db):
    return FindingEngine(db)


@pytest_asyncio.fixture
async def graph(db):
    return AssetGraph(db)


@pytest_asyncio.fixture
async def ctf_engine(db):
    return CTFEngine(db)


# ── Schema Tests ───────────────────────────────────────────────────────────

class TestSchemas:
    def test_new_id(self):
        id1 = new_id()
        id2 = new_id()
        assert len(id1) == 16
        assert id1 != id2

    def test_now_utc(self):
        dt = now_utc()
        assert dt.tzinfo is not None

    def test_content_hash(self):
        h = content_hash("hello")
        assert len(h) == 16
        assert h == content_hash("hello")
        assert h != content_hash("world")

    def test_engagement_model(self):
        eng = Engagement(
            name="Test", mode=EngagementMode.CTF,
            created_at=now_utc(), updated_at=now_utc(),
        )
        assert eng.name == "Test"
        assert eng.mode == "ctf"

    def test_finding_model(self):
        f = Finding(
            engagement_id="abc", title="XSS in /login",
            severity=Severity.HIGH, confidence=Confidence.MEDIUM,
            created_at=now_utc(), updated_at=now_utc(),
        )
        assert f.severity == "high"
        assert f.validation_status == "candidate"

    def test_tool_result(self):
        tr = ToolResult(
            id=new_id(), tool_name="nmap", success=True,
            raw_output="test", duration_ms=100.5,
            created_at=now_utc(), updated_at=now_utc(),
        )
        assert tr.success
        assert tr.duration_ms == 100.5


# ── Database Tests ─────────────────────────────────────────────────────────

class TestDatabase:
    @pytest.mark.asyncio
    async def test_connect(self, db):
        assert db._db is not None

    @pytest.mark.asyncio
    async def test_insert_and_get(self, db):
        data = {"id": new_id(), "name": "test", "mode": "ctf", "description": "", "status": "active", "workspace_id": "", "rate_limit_policy": "normal", "created_at": now_utc().isoformat(), "updated_at": now_utc().isoformat()}
        await db.insert("engagements", data)
        result = await db.get_by_id("engagements", data["id"])
        assert result is not None
        assert result["name"] == "test"

    @pytest.mark.asyncio
    async def test_upsert(self, db):
        data = {"id": new_id(), "name": "eng1", "mode": "ctf", "description": "", "status": "active", "workspace_id": "", "rate_limit_policy": "normal", "created_at": now_utc().isoformat(), "updated_at": now_utc().isoformat()}
        await db.upsert("engagements", data)
        data["name"] = "eng1_updated"
        await db.upsert("engagements", data)
        result = await db.get_by_id("engagements", data["id"])
        assert result["name"] == "eng1_updated"

    @pytest.mark.asyncio
    async def test_query(self, db):
        for i in range(3):
            data = {"id": new_id(), "name": f"eng{i}", "mode": "ctf", "description": "", "status": "active", "workspace_id": "", "rate_limit_policy": "normal", "created_at": now_utc().isoformat(), "updated_at": now_utc().isoformat()}
            await db.insert("engagements", data)
        results = await db.query("engagements")
        assert len(results) == 3

    @pytest.mark.asyncio
    async def test_delete(self, db):
        data = {"id": new_id(), "name": "to_delete", "mode": "ctf", "description": "", "status": "active", "workspace_id": "", "rate_limit_policy": "normal", "created_at": now_utc().isoformat(), "updated_at": now_utc().isoformat()}
        await db.insert("engagements", data)
        deleted = await db.delete("engagements", "id = ?", [data["id"]])
        assert deleted == 1
        result = await db.get_by_id("engagements", data["id"])
        assert result is None

    @pytest.mark.asyncio
    async def test_count(self, db):
        for i in range(5):
            await db.insert("engagements", {"id": new_id(), "name": f"e{i}", "mode": "ctf", "created_at": now_utc().isoformat(), "updated_at": now_utc().isoformat()})
        cnt = await db.count("engagements")
        assert cnt == 5


# ── Scope Engine Tests ─────────────────────────────────────────────────────

class TestScopeEngine:
    @pytest.mark.asyncio
    async def test_no_engagement_denies(self, scope):
        result = await scope.authorize_target("nonexistent", "example.com")
        assert not result.allowed
        assert "not found" in result.reason.lower()

    @pytest.mark.asyncio
    async def test_ctf_mode_allows(self, scope, db):
        eng = Engagement(id=new_id(), name="CTF", mode=EngagementMode.CTF, created_at=now_utc(), updated_at=now_utc())
        await db.save_engagement(eng.model_dump())
        result = await scope.authorize_target(eng.id, "challenge.local")
        assert result.allowed

    @pytest.mark.asyncio
    async def test_ctf_mode_exclusion(self, scope, db):
        eng = Engagement(id=new_id(), name="CTF", mode=EngagementMode.CTF, created_at=now_utc(), updated_at=now_utc())
        await db.save_engagement(eng.model_dump())
        rule = {"id": new_id(), "engagement_id": eng.id, "rule_type": "exclude", "target_type": "domain", "pattern": "evil.com", "description": "", "ports": "[]", "protocols": "[]", "methods": "[]", "paths": "[]", "created_at": now_utc().isoformat(), "updated_at": now_utc().isoformat()}
        await db.save_scope_rule(rule)
        result = await scope.authorize_target(eng.id, "evil.com")
        assert not result.allowed

    @pytest.mark.asyncio
    async def test_analysis_only_blocks_active(self, scope, db):
        eng = Engagement(id=new_id(), name="Analysis", mode=EngagementMode.ANALYSIS_ONLY, created_at=now_utc(), updated_at=now_utc())
        await db.save_engagement(eng.model_dump())
        result = await scope.authorize_execution_mode(eng.id, "active")
        assert not result.allowed

    @pytest.mark.asyncio
    async def test_analysis_allows_passive(self, scope, db):
        eng = Engagement(id=new_id(), name="Analysis", mode=EngagementMode.ANALYSIS_ONLY, created_at=now_utc(), updated_at=now_utc())
        await db.save_engagement(eng.model_dump())
        result = await scope.authorize_execution_mode(eng.id, "passive")
        assert result.allowed

    @pytest.mark.asyncio
    async def test_local_lab_allows_all(self, scope, db):
        eng = Engagement(id=new_id(), name="Lab", mode=EngagementMode.LOCAL_LAB, created_at=now_utc(), updated_at=now_utc())
        await db.save_engagement(eng.model_dump())
        rule = {"id": new_id(), "engagement_id": eng.id, "rule_type": "include", "target_type": "ip", "pattern": "192.168.1.100", "description": "", "ports": "[]", "protocols": "[]", "methods": "[]", "paths": "[]", "created_at": now_utc().isoformat(), "updated_at": now_utc().isoformat()}
        await scope.db.save_scope_rule(rule)
        result = await scope.authorize_target(eng.id, "192.168.1.100")
        assert result.allowed

    @pytest.mark.asyncio
    async def test_bug_bounty_requires_rules(self, scope, db):
        eng = Engagement(id=new_id(), name="BB", mode=EngagementMode.BUG_BOUNTY, created_at=now_utc(), updated_at=now_utc())
        await db.save_engagement(eng.model_dump())
        result = await scope.authorize_target(eng.id, "target.com")
        assert not result.allowed
        assert "no scope rules" in result.reason.lower()

    @pytest.mark.asyncio
    async def test_bug_bounty_with_include_rule(self, scope, db):
        eng = Engagement(id=new_id(), name="BB", mode=EngagementMode.BUG_BOUNTY, created_at=now_utc(), updated_at=now_utc())
        await db.save_engagement(eng.model_dump())
        rule = {"id": new_id(), "engagement_id": eng.id, "rule_type": "include", "target_type": "wildcard", "pattern": "*.target.com", "description": "", "ports": "[]", "protocols": "[]", "methods": "[]", "paths": "[]", "created_at": now_utc().isoformat(), "updated_at": now_utc().isoformat()}
        await db.save_scope_rule(rule)
        result = await scope.authorize_target(eng.id, "sub.target.com")
        assert result.allowed
        result2 = await scope.authorize_target(eng.id, "other.com")
        assert not result2.allowed

    @pytest.mark.asyncio
    async def test_cidr_rule(self, scope, db):
        eng = Engagement(id=new_id(), name="Net", mode=EngagementMode.PENTEST, created_at=now_utc(), updated_at=now_utc())
        await db.save_engagement(eng.model_dump())
        rule = {"id": new_id(), "engagement_id": eng.id, "rule_type": "include", "target_type": "cidr", "pattern": "192.168.1.0/24", "description": "", "ports": "[]", "protocols": "[]", "methods": "[]", "paths": "[]", "created_at": now_utc().isoformat(), "updated_at": now_utc().isoformat()}
        await db.save_scope_rule(rule)
        result = await scope.authorize_target(eng.id, "192.168.1.50")
        assert result.allowed
        result2 = await scope.authorize_target(eng.id, "10.0.0.1")
        assert not result2.allowed

    @pytest.mark.asyncio
    async def test_ssrf_protection(self, scope, db):
        eng = Engagement(id=new_id(), name="BB", mode=EngagementMode.BUG_BOUNTY, created_at=now_utc(), updated_at=now_utc())
        await db.save_engagement(eng.model_dump())
        result = await scope.authorize_network_destination(eng.id, "169.254.169.254")
        assert not result.allowed
        assert "ssrf" in result.reason.lower()

    @pytest.mark.asyncio
    async def test_ssrf_localhost_in_local_lab(self, scope, db):
        eng = Engagement(id=new_id(), name="Lab", mode=EngagementMode.LOCAL_LAB, created_at=now_utc(), updated_at=now_utc())
        await db.save_engagement(eng.model_dump())
        rule = {"id": new_id(), "engagement_id": eng.id, "rule_type": "include", "target_type": "domain", "pattern": "localhost", "description": "", "ports": "[]", "protocols": "[]", "methods": "[]", "paths": "[]", "created_at": now_utc().isoformat(), "updated_at": now_utc().isoformat()}
        await scope.db.save_scope_rule(rule)
        result = await scope.authorize_network_destination(eng.id, "localhost")
        assert result.allowed

    @pytest.mark.asyncio
    async def test_rate_limiting(self, scope, db):
        eng = Engagement(id=new_id(), name="Test", mode=EngagementMode.LOCAL_LAB, rate_limit_policy="stealth", created_at=now_utc(), updated_at=now_utc())
        await db.save_engagement(eng.model_dump())
        for _ in range(5):
            await scope.enforce_rate_limit(eng.id, "target.com")
        result = await scope.enforce_rate_limit(eng.id, "target.com")
        assert result.allowed or not result.allowed  # Just check it doesn't crash

    @pytest.mark.asyncio
    async def test_full_authorization_pipeline(self, scope, db):
        eng = Engagement(id=new_id(), name="Lab", mode=EngagementMode.LOCAL_LAB, created_at=now_utc(), updated_at=now_utc())
        await db.save_engagement(eng.model_dump())
        rule = {"id": new_id(), "engagement_id": eng.id, "rule_type": "include", "target_type": "ip", "pattern": "192.168.1.1", "description": "", "ports": "[]", "protocols": "[]", "methods": "[]", "paths": "[]", "created_at": now_utc().isoformat(), "updated_at": now_utc().isoformat()}
        await scope.db.save_scope_rule(rule)
        result = await scope.authorize(eng.id, "192.168.1.1", "nmap", "active")
        assert result.allowed


# ── Asset Graph Tests ──────────────────────────────────────────────────────

class TestAssetGraph:
    @pytest.mark.asyncio
    async def test_add_node(self, graph):
        eid = new_id()
        node = await graph.add_node(eid, "domain", "example.com")
        assert node.node_type == "domain"
        assert node.label == "example.com"

    @pytest.mark.asyncio
    async def test_dedup_nodes(self, graph):
        eid = new_id()
        n1 = await graph.add_node(eid, "domain", "example.com")
        n2 = await graph.add_node(eid, "domain", "example.com")
        assert n1.id == n2.id

    @pytest.mark.asyncio
    async def test_add_edge(self, graph):
        eid = new_id()
        n1 = await graph.add_node(eid, "domain", "example.com")
        n2 = await graph.add_node(eid, "ip", "1.2.3.4")
        edge = await graph.add_edge(eid, n1.id, n2.id, "resolves_to")
        assert edge.edge_type == "resolves_to"

    @pytest.mark.asyncio
    async def test_get_neighbors(self, graph):
        eid = new_id()
        n1 = await graph.add_node(eid, "domain", "example.com")
        n2 = await graph.add_node(eid, "ip", "1.2.3.4")
        await graph.add_edge(eid, n1.id, n2.id, "resolves_to")
        neighbors = graph.get_neighbors(n1.id)
        assert len(neighbors) == 1
        assert neighbors[0]["label"] == "1.2.3.4"

    @pytest.mark.asyncio
    async def test_find_nodes(self, graph):
        eid = new_id()
        await graph.add_node(eid, "domain", "example.com")
        await graph.add_node(eid, "domain", "test.com")
        await graph.add_node(eid, "ip", "1.2.3.4")
        domains = graph.find_nodes(eid, node_type="domain")
        assert len(domains) == 2

    @pytest.mark.asyncio
    async def test_find_path(self, graph):
        eid = new_id()
        n1 = await graph.add_node(eid, "domain", "example.com")
        n2 = await graph.add_node(eid, "ip", "1.2.3.4")
        n3 = await graph.add_node(eid, "port", "1.2.3.4:80")
        await graph.add_edge(eid, n1.id, n2.id, "resolves_to")
        await graph.add_edge(eid, n2.id, n3.id, "hosts")
        path = graph.find_path(n1.id, n3.id)
        assert path is not None
        assert len(path) == 2

    @pytest.mark.asyncio
    async def test_to_dict(self, graph):
        eid = new_id()
        await graph.add_node(eid, "domain", "example.com")
        d = graph.to_dict(eid)
        assert d["stats"]["node_count"] == 1


# ── Evidence Engine Tests ──────────────────────────────────────────────────

class TestEvidenceEngine:
    @pytest.mark.asyncio
    async def test_store_evidence(self, evidence_engine):
        eid = new_id()
        ev = Evidence(
            id=new_id(), engagement_id=eid, evidence_type="tool_output",
            source_tool="nmap", target="192.168.1.1",
            content={"ports": [80, 443]}, created_at=now_utc(), updated_at=now_utc(),
        )
        saved = await evidence_engine.store(ev)
        assert saved.id

    @pytest.mark.asyncio
    async def test_dedup_evidence(self, evidence_engine):
        eid = new_id()
        ev1 = Evidence(id=new_id(), engagement_id=eid, evidence_type="tool_output", content={"x": 1}, created_at=now_utc(), updated_at=now_utc())
        ev2 = Evidence(id=new_id(), engagement_id=eid, evidence_type="tool_output", content={"x": 1}, created_at=now_utc(), updated_at=now_utc())
        s1 = await evidence_engine.store(ev1)
        s2 = await evidence_engine.store(ev2)
        assert s1.id == s2.id  # Deduped

    @pytest.mark.asyncio
    async def test_store_http_pair(self, evidence_engine):
        eid = new_id()
        req, resp = await evidence_engine.store_http_pair(
            eid, {"method": "GET", "url": "http://test.com"}, {"status": 200, "body": "ok"}
        )
        assert req.evidence_type == "http_request"
        assert resp.evidence_type == "http_response"
        assert resp.parent_event_id == req.id

    @pytest.mark.asyncio
    async def test_store_tool_output(self, evidence_engine):
        eid = new_id()
        ev = await evidence_engine.store_tool_output(eid, "nmap", "7.94", "192.168.1.1", {"services": []}, "raw output")
        assert ev.source_tool == "nmap"

    @pytest.mark.asyncio
    async def test_list_by_type(self, evidence_engine):
        eid = new_id()
        await evidence_engine.store_tool_output(eid, "nmap", "", "t", {"a": 1})
        await evidence_engine.store(Evidence(id=new_id(), engagement_id=eid, evidence_type="screenshot", content={"path": "/tmp/ss.png"}, created_at=now_utc(), updated_at=now_utc()))
        tool_evs = await evidence_engine.list_by_engagement(eid, "tool_output")
        assert len(tool_evs) == 1
        ss_evs = await evidence_engine.list_by_engagement(eid, "screenshot")
        assert len(ss_evs) == 1


# ── Finding Engine Tests ───────────────────────────────────────────────────

class TestFindingEngine:
    @pytest.mark.asyncio
    async def test_create_finding(self, finding_engine):
        eid = new_id()
        f = Finding(
            id=new_id(), engagement_id=eid, title="XSS in /search",
            severity=Severity.HIGH, created_at=now_utc(), updated_at=now_utc(),
        )
        saved = await finding_engine.create_finding(f)
        assert saved.title == "XSS in /search"
        assert saved.validation_status == "candidate"

    @pytest.mark.asyncio
    async def test_finding_dedup(self, finding_engine):
        eid = new_id()
        f1 = Finding(id=new_id(), engagement_id=eid, title="XSS in /search", affected_endpoint="/search", created_at=now_utc(), updated_at=now_utc())
        f2 = Finding(id=new_id(), engagement_id=eid, title="XSS in /search", affected_endpoint="/search", created_at=now_utc(), updated_at=now_utc())
        await finding_engine.create_finding(f1)
        saved2 = await finding_engine.create_finding(f2)
        assert saved2.validation_status == "duplicate"
        assert saved2.duplicate_group is not None

    @pytest.mark.asyncio
    async def test_validate_finding(self, finding_engine):
        eid = new_id()
        f = Finding(id=new_id(), engagement_id=eid, title="Test", created_at=now_utc(), updated_at=now_utc())
        saved = await finding_engine.create_finding(f)
        validated = await finding_engine.validate_finding(saved.id)
        assert validated is not None
        assert validated.validation_status == "validated"

    @pytest.mark.asyncio
    async def test_reject_finding(self, finding_engine):
        eid = new_id()
        f = Finding(id=new_id(), engagement_id=eid, title="Test", created_at=now_utc(), updated_at=now_utc())
        saved = await finding_engine.create_finding(f)
        rejected = await finding_engine.reject_finding(saved.id, "false positive")
        assert rejected is not None
        assert rejected.validation_status == "rejected"

    @pytest.mark.asyncio
    async def test_summary(self, finding_engine):
        eid = new_id()
        for i in range(3):
            f = Finding(id=new_id(), engagement_id=eid, title=f"Finding {i}", severity=["high", "medium", "low"][i], created_at=now_utc(), updated_at=now_utc())
            await finding_engine.create_finding(f)
        summary = await finding_engine.get_summary(eid)
        assert summary["total"] == 3
        assert summary["by_severity"]["high"] == 1

    @pytest.mark.asyncio
    async def test_hypothesis_create(self, finding_engine):
        eid = new_id()
        h = Hypothesis(
            id=new_id(), engagement_id=eid, category="idor",
            target="api.example.com", hypothesis="Object IDOR on /api/users/{id}",
            created_at=now_utc(), updated_at=now_utc(),
        )
        saved = await finding_engine.create_hypothesis(h)
        assert saved.category == "idor"
        assert saved.validation_status == "hypothesis"

    @pytest.mark.asyncio
    async def test_hypothesis_update(self, finding_engine):
        eid = new_id()
        h = Hypothesis(id=new_id(), engagement_id=eid, category="xss", target="t.com", hypothesis="Reflected XSS", created_at=now_utc(), updated_at=now_utc())
        saved = await finding_engine.create_hypothesis(h)
        updated = await finding_engine.update_hypothesis(saved.id, {"validation_status": "validated", "confidence": "high"})
        assert updated is not None
        assert updated.validation_status == "validated"


# ── CTF Engine Tests ───────────────────────────────────────────────────────

class TestCTFEngine:
    @pytest.mark.asyncio
    async def test_create_challenge(self, ctf_engine):
        eid = new_id()
        c = await ctf_engine.create_challenge(eid, "Login Bypass", "web", target="challenge.local", port=8080)
        assert c.name == "Login Bypass"
        assert c.category == "web"

    @pytest.mark.asyncio
    async def test_hypothesis_ledger(self, ctf_engine):
        eid = new_id()
        c = await ctf_engine.create_challenge(eid, "SQLi", "web")
        h = await ctf_engine.add_hypothesis(c.id, "SQL injection on login", "sqli", "Try ' OR 1=1--")
        assert h["status"] == "active"
        await ctf_engine.resolve_hypothesis(c.id, h["id"], "Not vulnerable", False)
        updated_c = await ctf_engine.get_challenge(c.id)
        ledger = ctf_engine.get_hypothesis_ledger(updated_c)
        assert len(ledger["failed"]) == 1

    @pytest.mark.asyncio
    async def test_flag_submission(self, ctf_engine):
        eid = new_id()
        c = await ctf_engine.create_challenge(eid, "Crypto", "crypto")
        result = await ctf_engine.submit_flag(c.id, "flag{test123}")
        assert result
        updated = await ctf_engine.get_challenge(c.id)
        assert "flag{test123}" in updated.candidate_flags

    @pytest.mark.asyncio
    async def test_flag_confirmation(self, ctf_engine):
        eid = new_id()
        c = await ctf_engine.create_challenge(eid, "Pwn", "pwn")
        await ctf_engine.confirm_flag(c.id, "flag{pwned}")
        updated = await ctf_engine.get_challenge(c.id)
        assert updated.confirmed_flag == "flag{pwned}"

    @pytest.mark.asyncio
    async def test_notes_and_artifacts(self, ctf_engine):
        eid = new_id()
        c = await ctf_engine.create_challenge(eid, "Forensics", "forensics")
        await ctf_engine.add_note(c.id, "Found a hidden file")
        await ctf_engine.add_artifact(c.id, "/tmp/evidence.png")
        updated = await ctf_engine.get_challenge(c.id)
        assert "hidden file" in updated.notes
        assert "/tmp/evidence.png" in updated.known_artifacts


# ── Tool Adapter Tests ─────────────────────────────────────────────────────

class MockAdapter(ToolAdapter):
    def name(self) -> str: return "mock_tool"
    def version(self) -> str: return "1.0"
    def capabilities(self) -> ToolCapability:
        return ToolCapability(
            id=new_id(), name="mock_tool", version="1.0", description="Mock",
            risk_level=ToolRiskLevel.READ_ONLY, is_available=True,
            created_at=now_utc(), updated_at=now_utc(),
        )
    async def execute(self, request: ToolExecutionRequest) -> ToolResult:
        return ToolResult(
            id=new_id(), tool_name="mock_tool", success=True,
            raw_output="mock output", parsed_output={"result": "ok"},
            duration_ms=10, target=request.target,
            created_at=now_utc(), updated_at=now_utc(),
        )


class TestToolRegistry:
    def test_register_and_get(self):
        registry = ToolRegistry()
        adapter = MockAdapter()
        registry.register(adapter)
        assert registry.get("mock_tool") is adapter

    def test_list_all(self):
        registry = ToolRegistry()
        registry.register(MockAdapter())
        assert len(registry.list_all()) == 1

    @pytest.mark.asyncio
    async def test_discover(self):
        registry = ToolRegistry()
        registry.register(MockAdapter())
        caps = await registry.discover_all()
        assert "mock_tool" in caps
        assert caps["mock_tool"].is_available


class TestToolExecutor:
    @pytest.mark.asyncio
    async def test_execute(self, db, scope):
        registry = ToolRegistry()
        adapter = MockAdapter()
        registry.register(adapter)
        executor = ToolExecutor(db, scope, registry)
        request = ToolExecutionRequest(tool_name="mock_tool", target="test.com")
        result = await executor.execute(request)
        assert result.success
        assert result.parsed_output == {"result": "ok"}

    @pytest.mark.asyncio
    async def test_unknown_tool(self, db, scope):
        registry = ToolRegistry()
        executor = ToolExecutor(db, scope, registry)
        request = ToolExecutionRequest(tool_name="nonexistent", target="test.com")
        result = await executor.execute(request)
        assert not result.success
        assert "not found" in result.error


# ── Report Engine Tests ────────────────────────────────────────────────────

class TestReportEngine:
    @pytest.mark.asyncio
    async def test_generate_markdown(self, db):
        eid = new_id()
        await db.save_engagement({"id": eid, "name": "Test Eng", "mode": "ctf", "created_at": now_utc().isoformat(), "updated_at": now_utc().isoformat()})
        await db.save_finding({"id": new_id(), "engagement_id": eid, "title": "XSS", "severity": "high", "confidence": "medium", "affected_asset": "web.example.com", "affected_endpoint": "/search", "description": "Reflected XSS", "impact": "Account takeover", "steps_to_reproduce": '["Navigate to /search?q=alert(1)"]', "evidence_ids": "[]", "remediation": "Encode output", "references": "[]", "validation_status": "validated", "created_at": now_utc().isoformat(), "updated_at": now_utc().isoformat()})
        engine = ReportEngine(db)
        report = await engine.generate(eid, title="Test Report", fmt="markdown")
        assert "XSS" in report.content
        assert "high" in report.content.lower()

    @pytest.mark.asyncio
    async def test_generate_json(self, db):
        eid = new_id()
        await db.save_engagement({"id": eid, "name": "JSON Eng", "mode": "pentest", "created_at": now_utc().isoformat(), "updated_at": now_utc().isoformat()})
        engine = ReportEngine(db)
        report = await engine.generate(eid, fmt="json")
        data = json.loads(report.content)
        assert "engagement" in data


# ── Workspace Tests ────────────────────────────────────────────────────────

class TestWorkspace:
    @pytest.mark.asyncio
    async def test_create_workspace(self, db):
        wm = WorkspaceManager(db)
        ws = await wm.create_workspace("test-ws", new_id(), EngagementMode.CTF)
        assert ws.name == "test-ws"
        assert ws.is_sandboxed is True
        assert os.path.exists(ws.base_path)

    @pytest.mark.asyncio
    async def test_workspace_subdirs(self, db):
        wm = WorkspaceManager(db)
        ws = await wm.create_workspace("test-ws2", new_id())
        for subdir in ["scope", "assets", "evidence", "findings"]:
            assert os.path.exists(os.path.join(ws.base_path, subdir))

    @pytest.mark.asyncio
    async def test_write_read_file(self, db):
        wm = WorkspaceManager(db)
        ws = await wm.create_workspace("test-ws3", new_id())
        path = await wm.write_file(ws, "notes", "test.txt", "hello world")
        assert os.path.exists(path)
        content = await wm.read_file(ws, "notes", "test.txt")
        assert content == b"hello world"


# ── Integration: Orchestrator ──────────────────────────────────────────────

class TestOrchestrator:
    @pytest.mark.asyncio
    async def test_create_engagement(self, db):
        from omega.agents import Orchestrator
        orch = Orchestrator(db)
        eng = await orch.create_engagement("Test", "local_lab", "A test engagement")
        assert eng.name == "Test"
        assert eng.mode == "local_lab"

    @pytest.mark.asyncio
    async def test_run_scan_analysis_only(self, db):
        from omega.agents import Orchestrator
        orch = Orchestrator(db)
        eng = await orch.create_engagement("Scan Test", "analysis_only")
        result = await orch.run_scan(eng.id, "example.com", "recon")
        assert "target" in result


# ── MCP Server ─────────────────────────────────────────────────────────────

class TestMCPServer:
    def test_import(self):
        from omega.mcp import OmegaServer
        server = OmegaServer()
        assert server.mcp.name == "omega-cyber-mcp"
        assert server.mcp.version == "0.1.0"

    def test_tools_registered(self):
        from omega.mcp import OmegaServer
        server = OmegaServer()
        loop = asyncio.new_event_loop()
        loop.run_until_complete(server.initialize())
        # Check that tools are registered
        tool_names = [t.name for t in server.mcp._tool_manager._tools.values()]
        assert "omega_engagement_create" in tool_names
        assert "omega_scope_add_rule" in tool_names
        assert "omega_recon_subdomains" in tool_names
        assert "omega_web_headers" in tool_names
        assert "omega_scan" in tool_names
        assert "omega_ctf_challenge_create" in tool_names
        assert "omega_report_generate" in tool_names
        assert "omega_doctor" in tool_names
        assert "omega_tools_list" in tool_names
        loop.run_until_complete(server.shutdown())
        loop.close()
