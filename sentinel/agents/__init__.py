"""Multi-agent orchestrator — coordinates specialist agents for security testing."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from sentinel.core.schemas import (
    Confidence,
    Engagement,
    EngagementMode,
    Finding,
    Hypothesis,
    Severity,
    ValidationStatus,
    new_id,
    now_utc,
)
from sentinel.ctf import CTFEngine
from sentinel.evidence import EvidenceEngine
from sentinel.findings import FindingEngine
from sentinel.http import HTTPClient
from sentinel.knowledge import AssetGraph
from sentinel.scope import ScopeEngine
from sentinel.tools import ToolExecutionRequest, ToolExecutor, ToolRegistry
from sentinel.web import WebSecurityEngine

if TYPE_CHECKING:
    from sentinel.storage import Database

logger = logging.getLogger("sentinel.agents")


class AgentContext:
    """Shared context passed between agents."""

    def __init__(
        self,
        engagement: Engagement,
        db: Database,
        scope: ScopeEngine,
        executor: ToolExecutor,
        registry: ToolRegistry,
        evidence: EvidenceEngine,
        findings: FindingEngine,
        graph: AssetGraph,
        web: WebSecurityEngine,
        http: HTTPClient,
    ) -> None:
        self.engagement = engagement
        self.db = db
        self.scope = scope
        self.executor = executor
        self.registry = registry
        self.evidence = evidence
        self.findings = findings
        self.graph = graph
        self.web = web
        self.http = http
        self.timeline: list[dict[str, Any]] = []


class BaseAgent:
    """Base class for specialist agents."""

    name: str = "base"
    description: str = ""

    def __init__(self, ctx: AgentContext) -> None:
        self.ctx = ctx

    async def run(self, target: str, parameters: dict[str, Any] | None = None) -> dict[str, Any]:
        raise NotImplementedError

    async def _tool(self, tool_name: str, target: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        request = ToolExecutionRequest(
            tool_name=tool_name, target=target,
            parameters=params or {}, engagement_id=self.ctx.engagement.id,
        )
        result = await self.ctx.executor.execute(request, self.ctx.engagement.id)
        return {"success": result.success, "output": result.normalized_output or result.parsed_output, "error": result.error}


class ReconAgent(BaseAgent):
    name = "recon"
    description = "Subdomain enumeration, DNS, HTTP probing"

    async def run(self, target: str, parameters: dict[str, Any] | None = None) -> dict[str, Any]:
        results: dict[str, Any] = {"target": target, "subdomains": [], "live_hosts": [], "technologies": []}

        # 1. Subdomain enumeration
        if "subfinder" in self.ctx.registry.list_available():
            sub_result = await self._tool("subfinder", target)
            if sub_result["success"]:
                subs = [a["value"] for a in sub_result["output"].get("assets", []) if a["type"] == "subdomain"]
                results["subdomains"] = subs
                for s in subs:
                    await self.ctx.graph.add_node(self.ctx.engagement.id, "subdomain", s)
                    await self.ctx.db.save_asset({"id": new_id(), "engagement_id": self.ctx.engagement.id, "asset_type": "subdomain", "value": s, "metadata": "{}", "tags": "[]", "created_at": now_utc().isoformat(), "updated_at": now_utc().isoformat()})

        # 2. HTTP probing
        all_targets = [target] + results.get("subdomains", [])
        if "httpx" in self.ctx.registry.list_available() and all_targets:
            httpx_result = await self._tool("httpx", target, {"targets": all_targets[:50]})
            if httpx_result["success"]:
                for asset in httpx_result["output"].get("assets", []):
                    if asset["type"] == "url":
                        results["live_hosts"].append(asset["value"])

        return results


class WebAgent(BaseAgent):
    name = "web"
    description = "Web security analysis (headers, CORS, cookies, JS)"

    async def run(self, target: str, parameters: dict[str, Any] | None = None) -> dict[str, Any]:
        url = target if target.startswith("http") else f"https://{target}"
        results = await self.ctx.web.full_scan(url, self.ctx.engagement.id)
        return results


class CTFWebAgent(BaseAgent):
    name = "ctf_web"
    description = "CTF web challenge analysis"

    async def run(self, target: str, parameters: dict[str, Any] | None = None) -> dict[str, Any]:
        url = target if target.startswith("http") else f"http://{target}"
        results = {"target": url, "analysis": {}}
        results["analysis"]["headers"] = await self.ctx.web.analyze_headers(url, self.ctx.engagement.id)
        results["analysis"]["cors"] = await self.ctx.web.analyze_cors(url, self.ctx.engagement.id)
        resp = await self.ctx.http.get(url)
        body = resp.get("body", "")
        results["analysis"]["endpoints"] = await self.ctx.web.extract_endpoints(url, body, self.ctx.engagement.id)
        results["analysis"]["body_preview"] = body[:2000]
        return results


class PlannerAgent(BaseAgent):
    name = "planner"
    description = "Coordinates specialist agents based on target characteristics"

    def __init__(self, ctx: AgentContext) -> None:
        super().__init__(ctx)
        self._agents: dict[str, BaseAgent] = {}

    def register_agent(self, agent: BaseAgent) -> None:
        self._agents[agent.name] = agent

    async def run(self, target: str, parameters: dict[str, Any] | None = None) -> dict[str, Any]:
        plan = {"target": target, "steps": [], "results": {}}

        # Determine mode-based strategy
        mode = self.ctx.engagement.mode
        if mode == EngagementMode.CTF:
            plan["steps"] = ["recon", "ctf_web", "web"]
        elif mode in (EngagementMode.WEB_SECURITY, EngagementMode.BUG_BOUNTY):
            plan["steps"] = ["recon", "web"]
        elif mode == EngagementMode.NETWORK_SECURITY:
            plan["steps"] = ["recon"]
        else:
            plan["steps"] = ["recon"]

        for step in plan["steps"]:
            agent = self._agents.get(step)
            if agent:
                try:
                    result = await agent.run(target, parameters)
                    plan["results"][step] = result
                except Exception as e:
                    plan["results"][step] = {"error": str(e)}

        return plan


class Orchestrator:
    """Main orchestrator that wires everything together."""

    def __init__(self, db: Database) -> None:
        self.db = db
        self.scope = ScopeEngine(db)
        self.registry = ToolRegistry()
        self.executor = ToolExecutor(db, self.scope, self.registry)
        self.evidence = EvidenceEngine(db)
        self.findings = FindingEngine(db, self.scope)
        self.graph = AssetGraph(db)
        self.http = HTTPClient(db)
        self.web = WebSecurityEngine(db)
        self._api = None

    @property
    def api(self) -> Any:
        """Lazily constructed API security engine (avoids importing FastAPI surface at startup)."""
        if self._api is None:
            from sentinel.api import APISecurityEngine
            self._api = APISecurityEngine(self.db)
        return self._api

    async def create_engagement(self, name: str, mode: str = "analysis_only", description: str = "") -> Engagement:
        from sentinel.core.schemas import RateLimitPolicy
        engagement = Engagement(
            id=new_id(), name=name, mode=mode, description=description,
            created_at=now_utc(), updated_at=now_utc(),
        )
        await self.db.save_engagement(engagement.model_dump())
        return engagement

    async def run_scan(self, engagement_id: str, target: str, scan_type: str = "full", parameters: dict[str, Any] | None = None) -> dict[str, Any]:
        engagement_data = await self.db.get_engagement(engagement_id)
        if not engagement_data:
            return {"error": "Engagement not found"}

        engagement = Engagement(**engagement_data)
        ctx = AgentContext(
            engagement=engagement, db=self.db, scope=self.scope,
            executor=self.executor, registry=self.registry,
            evidence=self.evidence, findings=self.findings,
            graph=self.graph, web=self.web, http=self.http,
        )

        planner = PlannerAgent(ctx)
        recon = ReconAgent(ctx)
        web = WebAgent(ctx)
        ctf_web = CTFWebAgent(ctx)
        planner.register_agent(recon)
        planner.register_agent(web)
        planner.register_agent(ctf_web)

        return await planner.run(target, parameters)


class NextBestAction:
    """Determines the best next action based on current findings and context."""

    def __init__(self, db: Database, evidence_engine: EvidenceEngine, finding_engine: FindingEngine) -> None:
        self.db = db
        self.evidence = evidence_engine
        self.findings = finding_engine

    async def analyze(self, engagement_id: str, current_findings: list[Finding] | None = None) -> dict[str, Any]:
        """Analyze current state and recommend next actions."""
        # Query recent findings and evidence
        if current_findings:
            findings = current_findings
        elif hasattr(Finding, 'engagement_id'):
            findings = await self.db.query(
                Finding, Finding.engagement_id == engagement_id,
            )
        else:
            findings = []

        findings_list = list(findings) if findings else []

        # Categorize findings
        high_sev = [
            f for f in findings_list
            if hasattr(f, 'severity') and f.severity in ("critical", "high")
        ]
        medium_sev = [
            f for f in findings_list
            if hasattr(f, 'severity') and f.severity == "medium"
        ]

        recommendations = []

        # If no findings yet, recommend reconnaissance
        if not findings_list:
            recommendations.append({
                "priority": 1,
                "action": "reconnaissance",
                "description": "No findings yet. Run comprehensive reconnaissance.",
                "tools": ["subfinder", "httpx", "nuclei", "nikto"],
                "reason": "Initial phase - gather attack surface information",
            })
            recommendations.append({
                "priority": 2,
                "action": "web_security_scan",
                "description": "Run web security header and technology analysis.",
                "tools": ["web_security_headers", "web_cors_analysis", "web_tech_detection"],
                "reason": "Establish baseline web security posture",
            })

        # If we have high-severity findings, prioritize exploitation verification
        if high_sev:
            recommendations.append({
                "priority": 1,
                "action": "verify_critical_findings",
                "description": f"{len(high_sev)} high/critical findings need verification.",
                "findings": [getattr(f, 'title', 'unknown') for f in high_sev[:5]],
                "reason": "High-severity findings should be verified before reporting",
            })

        # If medium findings exist, suggest deeper investigation
        if medium_sev and not high_sev:
            recommendations.append({
                "priority": 1,
                "action": "deep_investigation",
                "description": f"{len(medium_sev)} medium findings need deeper analysis.",
                "findings": [getattr(f, 'title', 'unknown') for f in medium_sev[:5]],
                "reason": "Medium findings may lead to high-severity chains",
            })

        # Always suggest additional recon if we have limited findings
        if len(findings_list) < 5:
            recommendations.append({
                "priority": 2,
                "action": "additional_recon",
                "description": "Expand reconnaissance to find more attack surface.",
                "tools": ["gobuster", "ffuf", "katana", "dnsx"],
                "reason": "Limited findings suggest incomplete attack surface discovery",
            })

        # Suggest API testing if API endpoints were discovered
        if any(getattr(f, 'category', '') == 'api' for f in findings_list):
            recommendations.append({
                "priority": 2,
                "action": "api_security_testing",
                "description": "API endpoints detected. Run comprehensive API security testing.",
                "tools": ["openapi_discovery", "graphql_analysis", "idor_testing"],
                "reason": "API endpoints detected in findings",
            })

        # Suggest dependency scanning if web technologies detected
        if any(getattr(f, 'category', '') == 'technology' for f in findings_list):
            recommendations.append({
                "priority": 3,
                "action": "dependency_analysis",
                "description": "Check for known vulnerable dependencies.",
                "tools": ["version_check", "cve_lookup"],
                "reason": "Technology stack detected - check for known vulnerabilities",
            })

        # Suggest credential testing if auth mechanisms found
        if any(getattr(f, 'category', '') == 'authentication' for f in findings_list):
            recommendations.append({
                "priority": 2,
                "action": "authentication_testing",
                "description": "Test authentication mechanisms for weaknesses.",
                "tools": ["jwt_analysis", "session_testing", "brute_force"],
                "reason": "Authentication mechanisms detected - test for weaknesses",
            })

        # Sort by priority
        recommendations.sort(key=lambda r: r.get("priority", 99))

        return {
            "engagement_id": engagement_id,
            "total_findings": len(findings_list),
            "high_severity_count": len(high_sev),
            "medium_severity_count": len(medium_sev),
            "recommendations": recommendations[:10],  # Top 10
        }


class CriticAgent:
    """Challenges weak conclusions and validates finding quality."""

    def __init__(self, db: Database) -> None:
        self.db = db

    async def review_finding(self, finding: Finding) -> dict[str, Any]:
        """Review a finding for quality and completeness."""
        challenges = []
        score = 100

        # Check for required fields
        if not getattr(finding, 'title', None):
            challenges.append({"type": "missing_title", "severity": "critical", "description": "Finding has no title"})
            score -= 30

        if not getattr(finding, 'evidence', None):
            challenges.append({
                "type": "missing_evidence", "severity": "high",
                "description": "Finding has no evidence",
            })
            score -= 25

        desc = getattr(finding, 'description', None)
        if not desc or (desc and len(desc) < 20):
            challenges.append({
                "type": "weak_description", "severity": "medium",
                "description": "Description is too short or missing",
            })
            score -= 15

        if not getattr(finding, 'remediation', None):
            challenges.append({
                "type": "missing_remediation", "severity": "low",
                "description": "No remediation provided",
            })
            score -= 10

        # Check for vague severity
        if hasattr(finding, 'severity') and finding.severity == "info":
            challenges.append({
                "type": "informational_finding", "severity": "info",
                "description": "Consider if this is actionable enough to report",
            })
            score -= 5

        # Check for potential false positive indicators
        if hasattr(finding, 'description') and finding.description:
            desc_lower = finding.description.lower()
            false_positive_indicators = [
                "possibly", "might be", "could be", "potentially",
                "uncertain", "unclear", "not sure", "may not be",
            ]
            for indicator in false_positive_indicators:
                if indicator in desc_lower:
                    challenges.append({
                        "type": "uncertain_language",
                        "severity": "medium",
                        "description": f"Description contains uncertain language: '{indicator}'",
                    })
                    score -= 10
                    break

        # Check confidence
        if hasattr(finding, 'confidence') and finding.confidence and finding.confidence < 0.5:
            challenges.append({
                "type": "low_confidence",
                "severity": "medium",
                "description": f"Confidence is low ({finding.confidence}). Verify manually.",
            })
            score -= 15

        return {
            "finding_id": getattr(finding, 'id', 'unknown'),
            "score": max(0, score),
            "challenges": challenges,
            "quality": "high" if score >= 70 else "medium" if score >= 40 else "low",
        }

    async def review_report(self, findings: list[Finding]) -> dict[str, Any]:
        """Review an entire report for completeness."""
        total = len(findings)
        reviewed = []
        for f in findings:
            review = await self.review_finding(f)
            reviewed.append(review)

        avg_score = sum(r["score"] for r in reviewed) / total if total > 0 else 0
        quality_dist = {
            "high": sum(1 for r in reviewed if r["quality"] == "high"),
            "medium": sum(1 for r in reviewed if r["quality"] == "medium"),
            "low": sum(1 for r in reviewed if r["quality"] == "low"),
        }

        return {
            "total_findings": total,
            "average_score": round(avg_score, 1),
            "quality_distribution": quality_dist,
            "reviews": reviewed,
            "overall_quality": "high" if avg_score >= 70 else "medium" if avg_score >= 40 else "low",
        }


class ValidatorAgent:
    """Reproduces candidate vulnerabilities and validates them."""

    def __init__(self, db: Database) -> None:
        self.db = db

    async def validate_finding(self, finding: Finding, http_client: HTTPClient | None = None) -> dict[str, Any]:
        """Validate a finding by attempting reproduction."""
        validation_result = {
            "finding_id": getattr(finding, 'id', 'unknown'),
            "validated": False,
            "reproduction_method": "",
            "confidence": 0.0,
            "steps": [],
        }

        category = getattr(finding, 'category', '').lower() if hasattr(finding, 'category') else ''
        target_url = getattr(finding, 'target', '') if hasattr(finding, 'target') else ''

        if not http_client:
            from sentinel.http import HTTPClient
            http_client = HTTPClient(self.db)

        # Basic validation based on finding type
        if category in ('xss', 'injection', 'sqli'):
            validation_result["steps"] = [
                "Send crafted payload to target",
                "Verify response reflects payload",
                "Check for WAF/blocking",
            ]
            # Try basic validation for XSS
            if "xss" in category and target_url:
                try:
                    resp = await http_client.get(f"{target_url}?test=<script>alert(1)</script>")
                    if resp.get("status_code") == 200:
                        body = resp.get("body", "")
                        if "<script>" in body:
                            validation_result["validated"] = True
                            validation_result["confidence"] = 0.8
                except Exception:
                    pass

        elif category in ('idor', 'authorization', 'access_control'):
            validation_result["steps"] = [
                "Attempt access with different user context",
                "Compare response codes and content",
                "Verify authorization bypass",
            ]
            if target_url:
                try:
                    resp = await http_client.get(target_url)
                    validation_result["steps"].append(f"Response: {resp.get('status_code', 'N/A')}")
                except Exception:
                    pass

        elif category in ('cors', 'header', 'configuration'):
            validation_result["steps"] = [
                "Verify header presence/absence",
                "Check configuration",
            ]
            if target_url:
                try:
                    resp = await http_client.get(target_url)
                    headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
                    validation_result["steps"].append(f"Headers verified: {len(headers)}")
                except Exception:
                    pass

        elif category == 'crypto':
            validation_result["steps"] = [
                "Analyze cryptographic implementation",
                "Check for known weaknesses",
            ]

        else:
            validation_result["steps"] = [
                "Manual verification required",
                "No automated validation available for this category",
            ]

        if validation_result["validated"]:
            validation_result["confidence"] = min(1.0, validation_result["confidence"] + 0.1)

        return validation_result
