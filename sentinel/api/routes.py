"""REST API routes wrapping the real SENTINEL engines."""

from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from sentinel.config import SentinelConfig
from sentinel.storage import Database
from sentinel.scope import ScopeEngine
from sentinel.tools import ToolRegistry, ToolExecutor, ToolExecutionRequest, load_adapters
from sentinel.knowledge import AssetGraph
from sentinel.evidence import EvidenceEngine
from sentinel.findings import FindingEngine
from sentinel.ctf import CTFEngine
from sentinel.http import HTTPClient
from sentinel.web import WebSecurityEngine
from sentinel.api import APISecurityEngine
from sentinel.reporting import ReportEngine
from sentinel.orchestration import JobManager
from sentinel.agents import Orchestrator
from sentinel.crypto import CryptoEngine
from sentinel.forensics import ForensicsEngine
from sentinel.recon import register_all_recon_adapters
from sentinel.browser import BrowserEngine
from sentinel.core.schemas import (
    Engagement, EngagementMode, Finding, Hypothesis, Severity, Confidence,
    ValidationStatus, new_id, now_utc, ToolRiskLevel,
)

logger = logging.getLogger("sentinel.api.routes")

router = APIRouter(prefix="/api", tags=["dashboard"])


def _broadcast(event_type: str, data: dict) -> None:
    """Lazy import to avoid circular dependency with sentinel.api."""
    try:
        from sentinel.api import broadcast_event as _be
        _be(event_type, data)
    except Exception:
        pass


# ── Module-level lazy singletons ─────────────────────────────────────────────

_db: Database | None = None
_registry: ToolRegistry | None = None
_scope: ScopeEngine | None = None
_graph: AssetGraph | None = None
_evidence_engine: EvidenceEngine | None = None
_finding_engine: FindingEngine | None = None
_ctf_engine: CTFEngine | None = None
_http_client: HTTPClient | None = None
_web_engine: WebSecurityEngine | None = None
_api_engine: APISecurityEngine | None = None
_report_engine: ReportEngine | None = None
_crypto_engine: CryptoEngine | None = None
_forensics_engine: ForensicsEngine | None = None
_orchestrator: Orchestrator | None = None
_job_manager: JobManager | None = None
_browser_engine: BrowserEngine | None = None


async def _get_db() -> Database:
    global _db
    if _db is None:
        _db = Database()
        await _db.connect()
    return _db


async def _get_registry() -> ToolRegistry:
    global _registry
    if _registry is None:
        _registry = ToolRegistry()
        load_adapters(_registry)
    return _registry


async def _get_scope() -> ScopeEngine:
    global _scope
    if _scope is None:
        db = await _get_db()
        _scope = ScopeEngine(db)
    return _scope


async def _gate(engagement_id: str, target: str, action: str, risk_level: str = "passive") -> None:
    """Authorize a live-target action, raising HTTP 403 when denied.

    Mirrors the MCP ``_scope_denial`` posture: no engagement_id means the
    action runs open-world (ungated); *analysis_only* engagements always allow
    *passive* actions (observation-only); otherwise the full scope
    authorization pipeline applies.
    """
    if not engagement_id or not target:
        return
    db = await _get_db()
    eng = await db.get_engagement(engagement_id)
    mode = eng.get("mode", "") if eng else ""
    if mode == "analysis_only" and risk_level == "passive":
        return
    scope = await _get_scope()
    result = await scope.authorize(engagement_id, target, action, risk_level)
    if not result.allowed:
        raise HTTPException(status_code=403, detail=f"Scope denied: {result.reason}")


async def _get_graph() -> AssetGraph:
    global _graph
    if _graph is None:
        db = await _get_db()
        _graph = AssetGraph(db)
    return _graph


async def _get_evidence_engine() -> EvidenceEngine:
    global _evidence_engine
    if _evidence_engine is None:
        db = await _get_db()
        _evidence_engine = EvidenceEngine(db)
    return _evidence_engine


async def _get_finding_engine() -> FindingEngine:
    global _finding_engine
    if _finding_engine is None:
        db = await _get_db()
        _finding_engine = FindingEngine(db)
    return _finding_engine


async def _get_ctf_engine() -> CTFEngine:
    global _ctf_engine
    if _ctf_engine is None:
        db = await _get_db()
        _ctf_engine = CTFEngine(db)
    return _ctf_engine


async def _get_http_client() -> HTTPClient:
    global _http_client
    if _http_client is None:
        db = await _get_db()
        _http_client = HTTPClient(db)
    return _http_client


async def _get_web_engine() -> WebSecurityEngine:
    global _web_engine
    if _web_engine is None:
        db = await _get_db()
        _web_engine = WebSecurityEngine(db)
    return _web_engine


async def _get_api_engine() -> APISecurityEngine:
    global _api_engine
    if _api_engine is None:
        db = await _get_db()
        _api_engine = APISecurityEngine(db)
    return _api_engine


async def _get_report_engine() -> ReportEngine:
    global _report_engine
    if _report_engine is None:
        db = await _get_db()
        _report_engine = ReportEngine(db)
    return _report_engine


async def _get_crypto_engine() -> CryptoEngine:
    global _crypto_engine
    if _crypto_engine is None:
        _crypto_engine = CryptoEngine()
    return _crypto_engine


async def _get_forensics_engine() -> ForensicsEngine:
    global _forensics_engine
    if _forensics_engine is None:
        _forensics_engine = ForensicsEngine()
    return _forensics_engine


async def _get_orchestrator() -> Orchestrator:
    global _orchestrator
    if _orchestrator is None:
        db = await _get_db()
        _orchestrator = Orchestrator(db)
    return _orchestrator


async def _get_job_manager() -> JobManager:
    global _job_manager
    if _job_manager is None:
        db = await _get_db()
        scope = await _get_scope()
        registry = await _get_registry()
        executor = ToolExecutor(db, scope, registry)
        _job_manager = JobManager(db, executor)
    return _job_manager


async def _get_browser_engine() -> BrowserEngine:
    global _browser_engine
    if _browser_engine is None:
        _browser_engine = BrowserEngine()
    return _browser_engine


# ── Request models ────────────────────────────────────────────────────────────


class CreateEngagementRequest(BaseModel):
    name: str
    target: str = ""
    mode: str = "analysis_only"
    description: str = ""


class CreateChallengeRequest(BaseModel):
    engagement_id: str
    name: str
    category: str = "web"
    target: str = ""
    port: int = 0
    protocol: str = "tcp"
    description: str = ""


class RunReconRequest(BaseModel):
    engagement_id: str
    target: str
    tool: str = "subdomains"
    params: dict[str, Any] = {}


class RunWebScanRequest(BaseModel):
    engagement_id: str
    target: str
    scan_type: str = "full"


class HypothesisRequest(BaseModel):
    engagement_id: str
    category: str = ""
    target: str = ""
    hypothesis: str
    endpoint: str = ""


class CTFHypothesisRequest(BaseModel):
    hypothesis: str
    category: str = "general"
    test_plan: str = ""


class FindingRequest(BaseModel):
    engagement_id: str
    title: str
    severity: str = "informational"
    confidence: str = "none"
    affected_asset: str = ""
    description: str = ""


class FlagRequest(BaseModel):
    challenge_id: str
    flag: str


class HttpRequestModel(BaseModel):
    method: str = "GET"
    url: str
    headers: dict[str, str] = {}
    body: str = ""
    engagement_id: str = ""


class BrowserNavRequest(BaseModel):
    url: str
    context_id: str = ""
    engagement_id: str = ""


class CryptoAnalyzeRequest(BaseModel):
    data: str


class ReportRequestModel(BaseModel):
    engagement_id: str
    format: str = "markdown"
    title: str = ""


# ── Recon helper ──────────────────────────────────────────────────────────────


async def _run_tool(
    db: Database,
    registry: ToolRegistry,
    scope: ScopeEngine,
    tool_name: str,
    target: str,
    params: dict[str, Any],
    engagement_id: str,
) -> dict[str, Any]:
    """Create a job, execute a tool, store results, broadcast event."""
    job_id = new_id()
    await db.save_job({
        "id": job_id,
        "engagement_id": engagement_id,
        "tool_name": tool_name,
        "target": target,
        "status": "running",
        "parameters": json.dumps(params, default=str),
        "started_at": now_utc().isoformat(),
        "created_at": now_utc().isoformat(),
        "updated_at": now_utc().isoformat(),
    })
    _broadcast("log", {
        "time": now_utc().isoformat(),
        "level": "info",
        "message": f"Starting {tool_name} on {target}...",
    })

    adapter = registry.get(tool_name)
    if not adapter:
        await db.save_job({
            "id": job_id,
            "status": "failed",
            "error": f"Tool {tool_name} not found",
            "completed_at": now_utc().isoformat(),
            "updated_at": now_utc().isoformat(),
        })
        return {"error": f"Tool {tool_name} not found", "job_id": job_id}

    request = ToolExecutionRequest(
        tool_name=tool_name,
        target=target,
        parameters=params,
        engagement_id=engagement_id,
    )
    executor = ToolExecutor(db, scope, registry)
    result = await executor.execute(request, engagement_id)

    result_dict = result.model_dump(mode="json") if hasattr(result, "model_dump") else str(result)
    await db.save_job({
        "id": job_id,
        "status": "completed" if result.success else "failed",
        "result": json.dumps(result_dict, default=str)[:50000],
        "completed_at": now_utc().isoformat(),
        "updated_at": now_utc().isoformat(),
    })

    graph = await _get_graph()
    if result.success:
        normalized = result.normalized_output or {}
        for asset in normalized.get("assets", []):
            asset_type = asset.get("type", "unknown")
            asset_value = asset.get("value", "")
            if asset_value:
                await graph.add_node(
                    engagement_id, asset_type, asset_value,
                    properties=asset.get("metadata", {}),
                )

    _broadcast("log", {
        "time": now_utc().isoformat(),
        "level": "info" if result.success else "error",
        "message": f"{tool_name} {'completed' if result.success else 'failed'} on {target}",
    })

    return {
        "job_id": job_id,
        "success": result.success,
        "result": result_dict,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# ENGAGEMENTS
# ═══════════════════════════════════════════════════════════════════════════════


@router.post("/engagements")
async def create_engagement(req: CreateEngagementRequest):
    db = await _get_db()
    orch = await _get_orchestrator()
    engagement = await orch.create_engagement(
        name=req.name, mode=req.mode, description=req.description,
    )
    _broadcast("engagement", {
        "id": engagement.id, "name": engagement.name,
        "target": req.target, "mode": engagement.mode,
        "status": "active", "created_at": now_utc().isoformat(),
    })
    return {
        "id": engagement.id, "name": engagement.name, "target": req.target,
        "mode": engagement.mode, "description": engagement.description,
        "status": "active",
    }


@router.get("/engagements")
async def list_engagements():
    db = await _get_db()
    engagements = await db.list_engagements()
    return {"engagements": engagements}


@router.get("/engagements/{engagement_id}")
async def get_engagement(engagement_id: str):
    db = await _get_db()
    engagement = await db.get_engagement(engagement_id)
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")
    scope = await _get_scope()
    rules = await db.get_scope_rules(engagement_id)
    return {**engagement, "scope_rules": rules}


@router.post("/engagements/{engagement_id}/stop")
async def stop_engagement(engagement_id: str):
    db = await _get_db()
    engagement = await db.get_engagement(engagement_id)
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")
    engagement["status"] = "completed"
    engagement["updated_at"] = now_utc().isoformat()
    await db.save_engagement(engagement)
    return engagement


# ═══════════════════════════════════════════════════════════════════════════════
# CTF
# ═══════════════════════════════════════════════════════════════════════════════


@router.post("/ctf/challenges")
async def create_challenge(req: CreateChallengeRequest):
    ctf = await _get_ctf_engine()
    challenge = await ctf.create_challenge(
        engagement_id=req.engagement_id,
        name=req.name,
        category=req.category,
        target=req.target,
        port=req.port or None,
        protocol=req.protocol,
        description=req.description,
    )
    return challenge.to_dict()


@router.get("/ctf/challenges")
async def list_challenges(engagement_id: str = Query(...)):
    ctf = await _get_ctf_engine()
    challenges = await ctf.list_challenges(engagement_id)
    return {"challenges": [c.to_dict() for c in challenges]}


@router.get("/ctf/challenges/{challenge_id}")
async def get_challenge(challenge_id: str):
    ctf = await _get_ctf_engine()
    challenge = await ctf.get_challenge(challenge_id)
    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")
    return challenge.to_dict()


@router.post("/ctf/challenges/{challenge_id}/hypothesis")
async def add_hypothesis(challenge_id: str, req: CTFHypothesisRequest):
    ctf = await _get_ctf_engine()
    result = await ctf.add_hypothesis(
        challenge_id=challenge_id,
        hypothesis=req.hypothesis,
        category=req.category,
        test_plan=req.test_plan,
    )
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.post("/ctf/challenges/{challenge_id}/flag")
async def submit_flag(challenge_id: str, req: FlagRequest):
    ctf = await _get_ctf_engine()
    ok = await ctf.submit_flag(challenge_id, req.flag)
    if not ok:
        raise HTTPException(status_code=404, detail="Challenge not found")
    return {"submitted": True, "flag": req.flag[:50] + "..."}


@router.post("/ctf/challenges/{challenge_id}/confirm")
async def confirm_flag(challenge_id: str, req: FlagRequest):
    ctf = await _get_ctf_engine()
    ok = await ctf.confirm_flag(challenge_id, req.flag)
    if not ok:
        raise HTTPException(status_code=404, detail="Challenge not found")
    return {"confirmed": True}


@router.get("/ctf/challenges/{challenge_id}/ledger")
async def get_hypothesis_ledger(challenge_id: str):
    ctf = await _get_ctf_engine()
    challenge = await ctf.get_challenge(challenge_id)
    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")
    return ctf.get_hypothesis_ledger(challenge)


@router.post("/ctf/challenges/{challenge_id}/note")
async def add_note(challenge_id: str, body: dict[str, Any]):
    ctf = await _get_ctf_engine()
    note = body.get("note", "")
    challenge = await ctf.get_challenge(challenge_id)
    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")
    await ctf.add_note(challenge_id, note)
    return {"added": True}


@router.post("/ctf/challenges/{challenge_id}/artifact")
async def add_artifact(challenge_id: str, body: dict[str, Any]):
    ctf = await _get_ctf_engine()
    artifact = body.get("artifact", "")
    challenge = await ctf.get_challenge(challenge_id)
    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")
    await ctf.add_artifact(challenge_id, artifact)
    return {"added": True}


# ═══════════════════════════════════════════════════════════════════════════════
# SCOPE
# ═══════════════════════════════════════════════════════════════════════════════


@router.post("/scope/{engagement_id}/rules")
async def add_scope_rule(engagement_id: str, body: dict[str, Any]):
    db = await _get_db()
    rule_id = new_id()
    ts = now_utc().isoformat()
    rule = {
        "id": rule_id,
        "engagement_id": engagement_id,
        "rule_type": body.get("rule_type", "include"),
        "target_type": body.get("target_type", "domain"),
        "pattern": body.get("pattern", ""),
        "description": body.get("description", ""),
        "ports": body.get("ports", []),
        "protocols": body.get("protocols", []),
        "methods": body.get("methods", []),
        "paths": body.get("paths", []),
        "rate_limit_requests_per_second": body.get("rate_limit_requests_per_second"),
        "time_window_start": body.get("time_window_start"),
        "time_window_end": body.get("time_window_end"),
        "created_at": ts,
        "updated_at": ts,
    }
    saved = await db.save_scope_rule(rule)
    return saved


@router.get("/scope/{engagement_id}/rules")
async def list_scope_rules(engagement_id: str):
    db = await _get_db()
    rules = await db.get_scope_rules(engagement_id)
    return {"rules": rules}


@router.post("/scope/{engagement_id}/check")
async def check_scope(engagement_id: str, body: dict[str, Any]):
    scope = await _get_scope()
    target = body.get("target", "")
    result = await scope.authorize_target(engagement_id, target)
    return result.to_dict()


# ═══════════════════════════════════════════════════════════════════════════════
# RECON
# ═══════════════════════════════════════════════════════════════════════════════


@router.post("/recon/subdomains")
async def recon_subdomains(req: RunReconRequest):
    db = await _get_db()
    registry = await _get_registry()
    scope = await _get_scope()
    return await _run_tool(
        db, registry, scope,
        "subfinder", req.target, req.params, req.engagement_id,
    )


@router.post("/recon/probe")
async def recon_probe(req: RunReconRequest):
    db = await _get_db()
    registry = await _get_registry()
    scope = await _get_scope()
    return await _run_tool(
        db, registry, scope,
        "httpx", req.target, req.params, req.engagement_id,
    )


@router.post("/recon/portscan")
async def recon_portscan(req: RunReconRequest):
    db = await _get_db()
    registry = await _get_registry()
    scope = await _get_scope()
    return await _run_tool(
        db, registry, scope,
        "nmap", req.target, req.params, req.engagement_id,
    )


@router.post("/recon/fuzz")
async def recon_fuzz(req: RunReconRequest):
    db = await _get_db()
    registry = await _get_registry()
    scope = await _get_scope()
    return await _run_tool(
        db, registry, scope,
        "ffuf", req.target, req.params, req.engagement_id,
    )


@router.post("/recon/tech")
async def recon_tech(req: RunReconRequest):
    db = await _get_db()
    registry = await _get_registry()
    scope = await _get_scope()
    return await _run_tool(
        db, registry, scope,
        "whatweb", req.target, req.params, req.engagement_id,
    )


@router.post("/recon/crawl")
async def recon_crawl(req: RunReconRequest):
    db = await _get_db()
    registry = await _get_registry()
    scope = await _get_scope()
    return await _run_tool(
        db, registry, scope,
        "katana", req.target, req.params, req.engagement_id,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# WEB SECURITY
# ═══════════════════════════════════════════════════════════════════════════════


@router.post("/web/headers")
async def web_headers(body: dict[str, Any]):
    web = await _get_web_engine()
    url = body.get("url", "")
    engagement_id = body.get("engagement_id", "")
    await _gate(engagement_id, url, "web_headers")
    return await web.analyze_headers(url, engagement_id)


@router.post("/web/cors")
async def web_cors(body: dict[str, Any]):
    web = await _get_web_engine()
    url = body.get("url", "")
    engagement_id = body.get("engagement_id", "")
    await _gate(engagement_id, url, "web_cors")
    return await web.analyze_cors(url, engagement_id)


@router.post("/web/cookies")
async def web_cookies(body: dict[str, Any]):
    web = await _get_web_engine()
    url = body.get("url", "")
    engagement_id = body.get("engagement_id", "")
    await _gate(engagement_id, url, "web_cookies")
    return await web.analyze_cookies(url, engagement_id)


@router.post("/web/js")
async def web_js(body: dict[str, Any]):
    web = await _get_web_engine()
    url = body.get("url", "")
    engagement_id = body.get("engagement_id", "")
    await _gate(engagement_id, url, "web_js")
    return await web.analyze_javascript(url, engagement_id)


@router.post("/web/jwt")
async def web_jwt(body: dict[str, Any]):
    web = await _get_web_engine()
    url = body.get("url", "")
    engagement_id = body.get("engagement_id", "")
    await _gate(engagement_id, url, "web_jwt")
    return await web.analyze_jwt(url, engagement_id)


@router.post("/web/tech")
async def web_tech(body: dict[str, Any]):
    web = await _get_web_engine()
    url = body.get("url", "")
    engagement_id = body.get("engagement_id", "")
    await _gate(engagement_id, url, "web_tech")
    return await web.detect_technologies(url, engagement_id)


@router.post("/web/full-scan")
async def web_full_scan(req: RunWebScanRequest):
    web = await _get_web_engine()
    await _gate(req.engagement_id, req.target, "web_full_scan", "active")
    return await web.full_scan(req.target, req.engagement_id)


@router.post("/web/endpoints")
async def web_endpoints(body: dict[str, Any]):
    web = await _get_web_engine()
    url = body.get("url", "")
    body_text = body.get("body", "")
    engagement_id = body.get("engagement_id", "")
    await _gate(engagement_id, url, "web_endpoints")
    return await web.extract_endpoints(url, body_text, engagement_id)


# ═══════════════════════════════════════════════════════════════════════════════
# API SECURITY
# ═══════════════════════════════════════════════════════════════════════════════


@router.post("/api-security/openapi")
async def api_security_openapi(body: dict[str, Any]):
    api = await _get_api_engine()
    base_url = body.get("url", "")
    engagement_id = body.get("engagement_id", "")
    await _gate(engagement_id, base_url, "api_security_openapi")
    return await api.discover_openapi(base_url)


@router.post("/api-security/graphql")
async def api_security_graphql(body: dict[str, Any]):
    api = await _get_api_engine()
    base_url = body.get("url", "")
    engagement_id = body.get("engagement_id", "")
    await _gate(engagement_id, base_url, "api_security_graphql")
    return await api.discover_graphql(base_url)


@router.post("/api-security/auth")
async def api_security_auth(body: dict[str, Any]):
    api = await _get_api_engine()
    url = body.get("url", "")
    engagement_id = body.get("engagement_id", "")
    await _gate(engagement_id, url, "api_security_auth")
    return await api.analyze_authentication(url)


@router.post("/api-security/idor")
async def api_security_idor(body: dict[str, Any]):
    api = await _get_api_engine()
    url_pattern = body.get("url_pattern", "")
    id_values = body.get("id_values")
    engagement_id = body.get("engagement_id", "")
    await _gate(engagement_id, url_pattern, "api_security_idor", "active")
    return await api.test_idor(url_pattern, id_values, engagement_id)


# ═══════════════════════════════════════════════════════════════════════════════
# TOOLS
# ═══════════════════════════════════════════════════════════════════════════════


@router.get("/tools")
async def list_tools():
    registry = await _get_registry()
    capabilities = await registry.discover_all()
    tools = {}
    for name, cap in capabilities.items():
        tools[name] = cap.model_dump(mode="json") if hasattr(cap, "model_dump") else str(cap)
    return {"tools": tools}


@router.get("/tools/{tool_name}")
async def get_tool(tool_name: str):
    registry = await _get_registry()
    adapter = registry.get(tool_name)
    if not adapter:
        raise HTTPException(status_code=404, detail=f"Tool '{tool_name}' not found")
    cap = await adapter.discover()
    return cap.model_dump(mode="json") if hasattr(cap, "model_dump") else str(cap)


# ═══════════════════════════════════════════════════════════════════════════════
# JOBS
# ═══════════════════════════════════════════════════════════════════════════════


@router.get("/jobs")
async def list_jobs(engagement_id: str = Query("")):
    db = await _get_db()
    if engagement_id:
        jobs = await db.list_jobs(engagement_id)
    else:
        jobs = await db.query("jobs", limit=100)
    return {"jobs": jobs}


@router.get("/jobs/{job_id}")
async def get_job(job_id: str):
    db = await _get_db()
    job = await db.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@router.post("/jobs/{job_id}/cancel")
async def cancel_job(job_id: str):
    jm = await _get_job_manager()
    cancelled = await jm.cancel(job_id)
    if not cancelled:
        db = await _get_db()
        job = await db.get_job(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
    return {"cancelled": True, "job_id": job_id}


# ═══════════════════════════════════════════════════════════════════════════════
# FINDINGS
# ═══════════════════════════════════════════════════════════════════════════════


@router.get("/findings")
async def list_findings(engagement_id: str = Query(""), severity: str = Query("")):
    fe = await _get_finding_engine()
    if engagement_id:
        findings = await fe.list_findings(engagement_id, severity or None)
        return {"findings": [f.model_dump(mode="json") for f in findings]}
    db = await _get_db()
    rows = await db.query("findings", limit=200)
    return {"findings": rows}


@router.get("/findings/summary")
async def findings_summary(engagement_id: str = Query("")):
    fe = await _get_finding_engine()
    if not engagement_id:
        db = await _get_db()
        all_findings = await db.query("findings", limit=1000)
        by_severity: dict[str, int] = {}
        for f in all_findings:
            s = f.get("severity", "informational")
            by_severity[s] = by_severity.get(s, 0) + 1
        return {"total": len(all_findings), "by_severity": by_severity}
    return await fe.get_summary(engagement_id)


@router.post("/findings")
async def create_finding(req: FindingRequest):
    fe = await _get_finding_engine()
    finding = Finding(
        id=new_id(),
        engagement_id=req.engagement_id,
        title=req.title,
        severity=req.severity,
        confidence=req.confidence,
        affected_asset=req.affected_asset,
        description=req.description,
        created_at=now_utc(),
        updated_at=now_utc(),
    )
    saved = await fe.create_finding(finding)
    _broadcast("finding", saved.model_dump(mode="json"))
    return saved.model_dump(mode="json")


@router.post("/findings/{finding_id}/validate")
async def validate_finding(finding_id: str, body: dict[str, Any] | None = None):
    fe = await _get_finding_engine()
    evidence_ids = (body or {}).get("evidence_ids")
    result = await fe.validate_finding(finding_id, evidence_ids)
    if not result:
        raise HTTPException(status_code=404, detail="Finding not found")
    return result.model_dump(mode="json")


@router.post("/findings/{finding_id}/reject")
async def reject_finding(finding_id: str, body: dict[str, Any] | None = None):
    fe = await _get_finding_engine()
    reason = (body or {}).get("reason", "")
    result = await fe.reject_finding(finding_id, reason)
    if not result:
        raise HTTPException(status_code=404, detail="Finding not found")
    return result.model_dump(mode="json")


# ═══════════════════════════════════════════════════════════════════════════════
# EVIDENCE
# ═══════════════════════════════════════════════════════════════════════════════


@router.get("/evidence")
async def list_evidence(engagement_id: str = Query(""), evidence_type: str = Query("")):
    db = await _get_db()
    if engagement_id:
        evidence = await db.get_evidence(engagement_id, evidence_type or None)
    else:
        evidence = await db.query("evidence", limit=200)
    return {"evidence": evidence}


@router.get("/evidence/{evidence_id}")
async def get_evidence(evidence_id: str):
    db = await _get_db()
    ev = await db.get_by_id("evidence", evidence_id)
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return ev


# ═══════════════════════════════════════════════════════════════════════════════
# HYPOTHESES
# ═══════════════════════════════════════════════════════════════════════════════


@router.get("/hypotheses")
async def list_hypotheses(engagement_id: str = Query("")):
    fe = await _get_finding_engine()
    if engagement_id:
        hyps = await fe.list_hypotheses(engagement_id)
        return {"hypotheses": [h.model_dump(mode="json") for h in hyps]}
    db = await _get_db()
    rows = await db.query("hypotheses", limit=200)
    return {"hypotheses": rows}


@router.post("/hypotheses")
async def create_hypothesis(req: HypothesisRequest):
    fe = await _get_finding_engine()
    hyp = Hypothesis(
        id=new_id(),
        engagement_id=req.engagement_id,
        category=req.category,
        target=req.target,
        endpoint=req.endpoint,
        hypothesis=req.hypothesis,
        created_at=now_utc(),
        updated_at=now_utc(),
    )
    saved = await fe.create_hypothesis(hyp)
    return saved.model_dump(mode="json")


@router.post("/hypotheses/{hypothesis_id}/update")
async def update_hypothesis(hypothesis_id: str, body: dict[str, Any]):
    fe = await _get_finding_engine()
    result = await fe.update_hypothesis(hypothesis_id, body)
    if not result:
        raise HTTPException(status_code=404, detail="Hypothesis not found")
    return result.model_dump(mode="json")


# ═══════════════════════════════════════════════════════════════════════════════
# GRAPH
# ═══════════════════════════════════════════════════════════════════════════════


@router.get("/graph/{engagement_id}")
async def get_graph(engagement_id: str):
    graph = await _get_graph()
    await graph.load(engagement_id)
    return graph.to_dict(engagement_id)


@router.post("/graph/{engagement_id}/node")
async def add_graph_node(engagement_id: str, body: dict[str, Any]):
    graph = await _get_graph()
    await graph.load(engagement_id)
    node = await graph.add_node(
        engagement_id,
        body.get("node_type", "unknown"),
        body.get("label", ""),
        properties=body.get("properties"),
    )
    return node.model_dump(mode="json")


@router.post("/graph/{engagement_id}/edge")
async def add_graph_edge(engagement_id: str, body: dict[str, Any]):
    graph = await _get_graph()
    await graph.load(engagement_id)
    edge = await graph.add_edge(
        engagement_id,
        body.get("source_node_id", ""),
        body.get("target_node_id", ""),
        body.get("edge_type", "references"),
        properties=body.get("properties"),
    )
    return edge.model_dump(mode="json")


# ═══════════════════════════════════════════════════════════════════════════════
# REPORTS
# ═══════════════════════════════════════════════════════════════════════════════


@router.post("/reports/generate")
async def generate_report(req: ReportRequestModel):
    re_ = await _get_report_engine()
    report = await re_.generate(
        engagement_id=req.engagement_id,
        title=req.title,
        fmt=req.format,
    )
    return {
        "id": report.id,
        "title": report.title,
        "format": report.format,
        "content": report.content,
        "finding_ids": report.finding_ids,
        "evidence_ids": report.evidence_ids,
    }


@router.get("/reports")
async def list_all_reports():
    db = await _get_db()
    reports = await db.query("reports")
    return {"reports": reports}


@router.get("/reports/{engagement_id}")
async def list_reports(engagement_id: str):
    db = await _get_db()
    reports = await db.query("reports", where="engagement_id = ?", params=[engagement_id])
    return {"reports": reports}


# ═══════════════════════════════════════════════════════════════════════════════
# HTTP WORKSPACE
# ═══════════════════════════════════════════════════════════════════════════════


@router.post("/http/request")
async def http_request(req: HttpRequestModel):
    risk = "active" if req.method.upper() not in ("GET", "HEAD", "OPTIONS") else "passive"
    await _gate(req.engagement_id, req.url, "http_request", risk)
    http = await _get_http_client()
    resp = await http.request(
        method=req.method,
        url=req.url,
        headers=req.headers or None,
        body=req.body or None,
    )
    if req.engagement_id:
        await http.store_request(req.engagement_id, req.method, req.url, resp)
    return resp


@router.get("/http/history")
async def http_history(engagement_id: str = Query("")):
    db = await _get_db()
    if engagement_id:
        history = await db.get_request_history(engagement_id)
    else:
        history = await db.query("requests_history", limit=100)
    return {"history": history}


# ═══════════════════════════════════════════════════════════════════════════════
# BROWSER
# ═══════════════════════════════════════════════════════════════════════════════


@router.post("/browser/launch")
async def browser_launch(body: dict[str, Any] | None = None):
    params = body or {}
    be = await _get_browser_engine()
    return await be.launch(
        headless=params.get("headless", True),
        browser_type=params.get("browser_type", "chromium"),
    )


@router.post("/browser/navigate")
async def browser_navigate(req: BrowserNavRequest):
    be = await _get_browser_engine()
    context_id = req.context_id
    if not context_id:
        context_id = await be.new_context(engagement_id=req.engagement_id)
    result = await be.navigate(context_id, req.url)
    result["context_id"] = context_id
    return result


@router.post("/browser/screenshot")
async def browser_screenshot(body: dict[str, Any]):
    be = await _get_browser_engine()
    context_id = body.get("context_id", "")
    full_page = body.get("full_page", False)
    if not context_id:
        raise HTTPException(status_code=400, detail="context_id required")
    return await be.screenshot(context_id, full_page)


@router.post("/browser/js")
async def browser_js(body: dict[str, Any]):
    be = await _get_browser_engine()
    context_id = body.get("context_id", "")
    script = body.get("script", "")
    if not context_id:
        raise HTTPException(status_code=400, detail="context_id required")
    return await be.execute_js(context_id, script)


@router.get("/browser/cookies")
async def browser_cookies(context_id: str = Query(...)):
    be = await _get_browser_engine()
    return await be.get_cookies(context_id)


@router.post("/browser/close")
async def browser_close(body: dict[str, Any] | None = None):
    be = await _get_browser_engine()
    params = body or {}
    context_id = params.get("context_id", "")
    if context_id:
        await be.close_context(context_id)
        return {"closed": True, "context_id": context_id}
    await be.close()
    return {"closed": True, "all": True}


# ═══════════════════════════════════════════════════════════════════════════════
# CRYPTO
# ═══════════════════════════════════════════════════════════════════════════════


@router.post("/crypto/analyze")
async def crypto_analyze(req: CryptoAnalyzeRequest):
    engine = await _get_crypto_engine()
    return await engine.analyze_input(req.data)


@router.post("/crypto/caesar")
async def crypto_caesar(body: dict[str, Any]):
    engine = await _get_crypto_engine()
    ciphertext = body.get("ciphertext", "")
    max_shift = body.get("max_shift", 26)
    results = await engine.caesar_shifts(ciphertext, max_shift)
    return {"results": results}


@router.post("/crypto/xor")
async def crypto_xor(body: dict[str, Any]):
    engine = await _get_crypto_engine()
    data_hex = body.get("data", "")
    try:
        data_bytes = bytes.fromhex(data_hex)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid hex data")
    results = await engine.xor_single_byte(data_bytes)
    return {"results": results}


@router.post("/crypto/hash")
async def crypto_hash(body: dict[str, Any]):
    engine = await _get_crypto_engine()
    hash_str = body.get("hash", "")
    return await engine.analyze_hash(hash_str)


# ═══════════════════════════════════════════════════════════════════════════════
# SYSTEM
# ═══════════════════════════════════════════════════════════════════════════════


@router.get("/system")
async def system_status():
    registry = await _get_registry()
    capabilities = await registry.discover_all()
    available = sum(1 for c in capabilities.values() if c.is_available)
    return {
        "status": "running",
        "version": "1.0.0",
        "tools_available": available,
        "tools_total": len(capabilities),
        "timestamp": now_utc().isoformat(),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# SEARCH
# ═══════════════════════════════════════════════════════════════════════════════


@router.get("/search")
async def global_search(q: str = Query(""), engagement_id: str = Query("")):
    """Search across engagements, findings, evidence, hypotheses, jobs, tools."""
    db = await _get_db()
    results: dict[str, list] = {
        "engagements": [], "findings": [], "evidence": [],
        "hypotheses": [], "jobs": [], "ctf_challenges": [],
    }
    if not q:
        all_eng = await db.list_engagements()
        results["engagements"] = all_eng[:20]
        return results

    like = f"%{q}%"
    for table, key in [
        ("engagements", "engagements"), ("findings", "findings"),
        ("evidence", "evidence"), ("hypotheses", "hypotheses"),
        ("ctf_challenges", "ctf_challenges"),
    ]:
        try:
            rows = await db.query(table, where="id LIKE ? OR engagement_id LIKE ?", params=[like, like], limit=20)
            results[key] = rows
        except Exception:
            pass

    try:
        jobs = await db.query("jobs", where="tool_name LIKE ? OR target LIKE ?", params=[like, like], limit=20)
        results["jobs"] = jobs
    except Exception:
        pass

    return results


# ═══════════════════════════════════════════════════════════════════════════════
# WORKFLOWS (User-saved)
# ═══════════════════════════════════════════════════════════════════════════════


@router.get("/workflows")
async def list_user_workflows():
    db = await _get_db()
    try:
        workflows = await db.query("workspaces", limit=100)
    except Exception:
        workflows = []
    return {"workflows": workflows}


@router.post("/workflows")
async def save_user_workflow(body: dict[str, Any]):
    db = await _get_db()
    wf_id = body.get("id", new_id())
    ts = now_utc().isoformat()
    workflow = {
        "id": wf_id,
        "name": body.get("name", "Untitled"),
        "engagement_id": body.get("engagement_id", ""),
        "mode": body.get("mode", "analysis_only"),
        "base_path": json.dumps(body.get("steps", [])),
        "is_sandboxed": 0,
        "created_at": ts,
        "updated_at": ts,
    }
    saved = await db.save_workspace(workflow)
    return saved


@router.delete("/workflows/{workflow_id}")
async def delete_user_workflow(workflow_id: str):
    db = await _get_db()
    await db.delete("workspaces", "id = ?", params=[workflow_id])
    return {"deleted": True}


# ═══════════════════════════════════════════════════════════════════════════════
# FORENSICS
# ═══════════════════════════════════════════════════════════════════════════════


@router.post("/forensics/analyze")
async def forensics_analyze(body: dict[str, Any]):
    engine = await _get_forensics_engine()
    path = body.get("path", "")
    if not path:
        raise HTTPException(status_code=400, detail="path is required")
    return await engine.analyze_file(path)


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL HEALTH
# ═══════════════════════════════════════════════════════════════════════════════


@router.get("/tools-health")
async def tools_health():
    """Detailed tool health with detection status, version, path."""
    registry = await _get_registry()
    capabilities = await registry.discover_all()
    tools = []
    for name, cap in capabilities.items():
        entry = cap.model_dump(mode="json") if hasattr(cap, "model_dump") else str(cap)
        entry["category"] = _tool_category(name)
        entry["install_hint"] = _install_hint(name)
        tools.append(entry)
    return {"tools": tools, "total": len(tools), "installed": sum(1 for t in tools if t.get("is_available"))}


def _tool_category(name: str) -> str:
    cats = {
        "subfinder": "recon", "amass": "recon", "dnsx": "dns",
        "httpx": "http", "naabu": "network", "nmap": "network",
        "masscan": "network", "katana": "crawling", "gospider": "crawling",
        "ffuf": "fuzzing", "gobuster": "fuzzing", "feroxbuster": "fuzzing",
        "nuclei": "vulnerability", "nikto": "vulnerability", "wafw00f": "web",
        "whatweb": "web", "dalfox": "web", "sqlmap": "web",
        "gowitness": "browser", "gitleaks": "secrets", "semgrep": "sast",
    }
    return cats.get(name, "recon")


def _install_hint(name: str) -> str:
    hints = {
        "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "httpx": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "nmap": "apt install nmap  OR  brew install nmap",
        "ffuf": "go install -v github.com/ffuf/ffuf/v2@latest",
        "nuclei": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "katana": "go install -v github.com/projectdiscovery/katana/cmd/katana@latest",
        "gobuster": "go install -v github.com/OJ/gobuster/v3@latest",
        "naabu": "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
        "whatweb": "apt install whatweb  OR  gem install whatweb",
        "nikto": "apt install nikto  OR  git clone https://github.com/sullo/nikto",
        "wafw00f": "pip install wafw00f",
        "gospider": "go install -v github.com/jaeles-project/gospider@latest",
        "dnsx": "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        "masscan": "apt install masscan  OR  git clone https://github.com/robertdavidgraham/masscan",
        "dalfox": "go install -v github.com/hahwul/dalfox/v2@latest",
        "sqlmap": "apt install sqlmap  OR  pip install sqlmap",
        "gowitness": "go install -v github.com/sensepost/gowitness@latest",
        "gitleaks": "go install -v github.com/gitleaks/gitleaks@latest",
        "semgrep": "pip install semgrep  OR  brew install semgrep",
    }
    return hints.get(name, f"go install {name}  OR  pip install {name}")


@router.post("/tools/{tool_name}/recheck")
async def recheck_tool(tool_name: str):
    """Re-discover a single tool's availability."""
    registry = await _get_registry()
    adapter = registry.get(tool_name)
    if not adapter:
        raise HTTPException(status_code=404, detail=f"Tool '{tool_name}' not registered")
    cap = await adapter.discover()
    entry = cap.model_dump(mode="json") if hasattr(cap, "model_dump") else str(cap)
    entry["category"] = _tool_category(tool_name)
    entry["install_hint"] = _install_hint(tool_name)
    return entry


# ═══════════════════════════════════════════════════════════════════════════════
# SCOPE DELETE
# ═══════════════════════════════════════════════════════════════════════════════


@router.delete("/scope/{engagement_id}/rules/{rule_id}")
async def delete_scope_rule(engagement_id: str, rule_id: str):
    db = await _get_db()
    await db.delete("scope_rules", "id = ? AND engagement_id = ?", params=[rule_id, engagement_id])
    return {"deleted": True}


# ═══════════════════════════════════════════════════════════════════════════════
# AUDIT LOG
# ═══════════════════════════════════════════════════════════════════════════════


@router.get("/audit/{engagement_id}")
async def get_audit_log(engagement_id: str):
    db = await _get_db()
    logs = await db.get_audit_log(engagement_id)
    return {"audit_log": logs}


# ═══════════════════════════════════════════════════════════════════════════════
# AUTH / AUTHORIZATION TESTING
# ═══════════════════════════════════════════════════════════════════════════════


@router.get("/authorizations/{engagement_id}")
async def list_authorizations(engagement_id: str):
    db = await _get_db()
    rows = await db.query("authorizations", where="engagement_id = ?", params=[engagement_id])
    return {"authorizations": rows}


@router.post("/authorizations/{engagement_id}")
async def save_authorization(engagement_id: str, body: dict[str, Any]):
    db = await _get_db()
    ts = now_utc().isoformat()
    auth = {
        "id": body.get("id", new_id()),
        "engagement_id": engagement_id,
        "credentials": body.get("credentials", {}),
        "tokens": body.get("tokens", []),
        "cookies": body.get("cookies", []),
        "notes": body.get("notes", ""),
        "created_at": ts,
        "updated_at": ts,
    }
    saved = await db.upsert("authorizations", auth)
    return saved


@router.post("/auth/diff-test")
async def authorization_differential_test(body: dict[str, Any]):
    """Compare responses between two identity sets for differential authorization testing."""
    http = await _get_http_client()
    url_a = body.get("url_a", "")
    url_b = body.get("url_b", "")
    headers_a = body.get("headers_a", {})
    headers_b = body.get("headers_b", {})
    method = body.get("method", "GET")
    engagement_id = body.get("engagement_id", "")

    if not url_a or not url_b:
        raise HTTPException(status_code=400, detail="url_a and url_b required")

    risk = "active" if method.upper() not in ("GET", "HEAD", "OPTIONS") else "passive"
    await _gate(engagement_id, url_a, "auth_diff_test", risk)
    await _gate(engagement_id, url_b, "auth_diff_test", risk)

    resp_a = await http.request(method=method, url=url_a, headers=headers_a or None)
    resp_b = await http.request(method=method, url=url_b, headers=headers_b or None)

    return {
        "identity_a": {"url": url_a, "status": resp_a.get("status_code"), "body_length": resp_a.get("body_length", 0)},
        "identity_b": {"url": url_b, "status": resp_b.get("status_code"), "body_length": resp_b.get("body_length", 0)},
        "status_match": resp_a.get("status_code") == resp_b.get("status_code"),
        "length_diff": abs(resp_a.get("body_length", 0) - resp_b.get("body_length", 0)),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# API SECURITY FULL SCAN
# ═══════════════════════════════════════════════════════════════════════════════


@router.post("/api-security/full-scan")
async def api_security_full_scan(body: dict[str, Any]):
    api = await _get_api_engine()
    target = body.get("url", "")
    engagement_id = body.get("engagement_id", "")
    await _gate(engagement_id, target, "api_security_full_scan", "active")
    return await api.full_scan(target, engagement_id)


@router.post("/api-security/introspection")
async def api_security_introspection(body: dict[str, Any]):
    api = await _get_api_engine()
    graphql_url = body.get("url", "")
    engagement_id = body.get("engagement_id", "")
    await _gate(engagement_id, graphql_url, "api_security_introspection")
    return await api.analyze_graphql_introspection(graphql_url)


@router.post("/api-security/endpoints")
async def api_security_endpoints(body: dict[str, Any]):
    api = await _get_api_engine()
    base_url = body.get("url", "")
    engagement_id = body.get("engagement_id", "")
    await _gate(engagement_id, base_url, "api_security_endpoints")
    return await api.infer_endpoints(base_url)
