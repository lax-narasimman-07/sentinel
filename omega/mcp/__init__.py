"""OMEGA-CYBER-MCP Server — the MCP interface to the security platform."""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from omega.config import get_config, OmegaConfig
from omega.storage import Database
from omega.scope import ScopeEngine
from omega.tools import ToolRegistry, ToolExecutor, ToolExecutionRequest
from omega.workspace import WorkspaceManager
from omega.evidence import EvidenceEngine
from omega.findings import FindingEngine
from omega.knowledge import AssetGraph
from omega.ctf import CTFEngine
from omega.http import HTTPClient
from omega.web import WebSecurityEngine
from omega.reporting import ReportEngine
from omega.orchestration import JobManager
from omega.agents import Orchestrator
from omega.recon import (
    register_all_recon_adapters,
    SubfinderAdapter, HttpxAdapter, NmapAdapter, FfufAdapter,
    WhatWebAdapter, GobusterAdapter, KatanaAdapter,
)
from omega.core.schemas import (
    Engagement, EngagementMode, Finding, Hypothesis, Severity, Confidence,
    ValidationStatus, new_id, now_utc,
)
from omega.core.errors import ErrorCode, ToolError, guarded_tool

logger = logging.getLogger("omega.server")


class OmegaServer:
    """Main MCP server for OMEGA-CYBER-MCP."""

    def __init__(self, config: OmegaConfig | None = None) -> None:
        self.config = config or get_config()
        self.mcp = MCPServer(
            name="omega-cyber-mcp",
            title="OMEGA-CYBER-MCP",
            version=self.config.version,
            instructions=(
                "OMEGA-CYBER-MCP is an agentic security research platform. "
                "Use it for CTF solving, authorized bug bounty research, penetration testing, "
                "web/API security testing, reverse engineering, reconnaissance, and vulnerability validation. "
                "Always validate scope before active testing. All operations are audit-logged."
            ),
        )
        self.db: Database | None = None
        self.orchestrator: Orchestrator | None = None
        self._initialized = False

    async def initialize(self) -> None:
        if self._initialized:
            return
        self.db = Database()
        await self.db.connect()
        self.orchestrator = Orchestrator(self.db)
        register_all_recon_adapters(self.orchestrator.registry)
        self._register_tools()
        self._initialized = True
        logger.info("OMEGA-CYBER-MCP server initialized")

    def run(self, transport: str = "stdio", host: str = "127.0.0.1", port: int = 8443) -> None:
        """Run the MCP server (blocking). Initializes, then delegates to MCPServer.run()."""
        asyncio.run(self.initialize())
        self.mcp.run(transport=transport, host=host, port=port)

    async def shutdown(self) -> None:
        if self.db:
            await self.db.close()

    async def _scope_denial(self, engagement_id: str, target: str, action: str, risk_level: str = "passive") -> None:
        """Authorize `target` for `action`, raising :class:`ToolError` if denied.

        No engagement_id means the tool runs open-world (ungated), matching the
        design of the recon adapters. When an engagement is provided the full
        authorization pipeline applies: target scope, action, execution mode,
        and rate limiting.
        """
        orch = self.orchestrator
        assert orch
        if not engagement_id:
            return
        result = await orch.scope.authorize(engagement_id, target, action, risk_level)
        if not result.allowed:
            raise ToolError(ErrorCode.SCOPE_DENIED, f"Scope denied: {result.reason}")

    def _register_tools(self) -> None:
        mcp = self.mcp
        server = self

        # ── Engagement Management ──────────────────────────────────────────

        @mcp.tool(
            name="omega_engagement_create",
            description="Create a new security engagement. Modes: ctf, bug_bounty, pentest, local_lab, analysis_only, reversing, api_security, web_security, network_security",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=False),
        )
        @guarded_tool()
        async def engagement_create(name: str, mode: str = "analysis_only", description: str = "") -> str:
            orch = server.orchestrator
            assert orch
            eng = await orch.create_engagement(name, mode, description)
            return json.dumps(eng.model_dump(mode="json"), default=str)

        @mcp.tool(
            name="omega_engagement_list",
            description="List all engagements",
            annotations=ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False),
        )
        @guarded_tool()
        async def engagement_list() -> str:
            db = server.db
            assert db
            engagements = await db.list_engagements()
            return json.dumps(engagements, default=str)

        @mcp.tool(
            name="omega_engagement_get",
            description="Get engagement details by ID",
            annotations=ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False),
        )
        @guarded_tool()
        async def engagement_get(engagement_id: str) -> str:
            db = server.db
            assert db
            eng = await db.get_engagement(engagement_id)
            if not eng:
                raise ToolError(ErrorCode.NOT_FOUND, "Engagement not found")
            rules = await db.get_scope_rules(engagement_id)
            assets = await db.get_assets(engagement_id)
            return json.dumps({"engagement": eng, "scope_rules": rules, "asset_count": len(assets)}, default=str)

        # ── Scope Management ───────────────────────────────────────────────

        @mcp.tool(
            name="omega_scope_add_rule",
            description="Add a scope rule to an engagement. rule_type: 'include'|'exclude'. target_type: 'domain'|'wildcard'|'ip'|'cidr'|'url'|'port'. For CTF mode, targets are auto-included unless explicitly excluded.",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=False),
        )
        @guarded_tool()
        async def scope_add_rule(engagement_id: str, rule_type: str, target_type: str, pattern: str, description: str = "") -> str:
            db = server.db
            assert db
            rule = {
                "id": new_id(), "engagement_id": engagement_id, "rule_type": rule_type,
                "target_type": target_type, "pattern": pattern, "description": description,
                "ports": "[]", "protocols": "[]", "methods": "[]", "paths": "[]",
                "created_at": now_utc().isoformat(), "updated_at": now_utc().isoformat(),
            }
            await db.save_scope_rule(rule)
            return json.dumps({"success": True, "rule_id": rule["id"], "pattern": pattern})

        @mcp.tool(
            name="omega_scope_check",
            description="Check if a target is in scope for an engagement",
            annotations=ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False),
        )
        @guarded_tool()
        async def scope_check(engagement_id: str, target: str) -> str:
            orch = server.orchestrator
            assert orch
            result = await orch.scope.authorize_target(engagement_id, target)
            return json.dumps(result.to_dict())

        @mcp.tool(
            name="omega_scope_list_rules",
            description="List all scope rules for an engagement",
            annotations=ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False),
        )
        @guarded_tool()
        async def scope_list_rules(engagement_id: str) -> str:
            db = server.db
            assert db
            rules = await db.get_scope_rules(engagement_id)
            return json.dumps(rules, default=str)

        # ── Reconnaissance ─────────────────────────────────────────────────

        @mcp.tool(
            name="omega_recon_subdomains",
            description="Enumerate subdomains using subfinder (passive, safe). Requires an engagement with target in scope.",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True),
        )
        @guarded_tool()
        async def recon_subdomains(target: str, engagement_id: str = "", timeout: int = 120) -> str:
            orch = server.orchestrator
            assert orch
            await server._scope_denial(engagement_id, target, "subfinder", "passive")
            adapter = SubfinderAdapter()
            request = ToolExecutionRequest(tool_name="subfinder", target=target, engagement_id=engagement_id, parameters={"timeout": timeout})
            result = await adapter.execute(request)
            if engagement_id and result.success:
                await orch.evidence.store_tool_output(engagement_id, "subfinder", "latest", target, result.parsed_output, result.raw_output)
                for asset in result.normalized_output.get("assets", []):
                    if asset["type"] == "subdomain":
                        await orch.db.save_asset({"id": new_id(), "engagement_id": engagement_id, "asset_type": "subdomain", "value": asset["value"], "metadata": "{}", "tags": "[]", "created_at": now_utc().isoformat(), "updated_at": now_utc().isoformat()})
            return json.dumps({"success": result.success, "subdomains": result.parsed_output.get("subdomains", []), "error": result.error, "duration_ms": result.duration_ms}, default=str)

        @mcp.tool(
            name="omega_recon_probe",
            description="Probe live HTTP hosts using httpx. Pass targets as newline-separated list or a single target.",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True),
        )
        @guarded_tool()
        async def recon_probe(target: str, engagement_id: str = "", targets: str = "", timeout: int = 120) -> str:
            await server._scope_denial(engagement_id, target, "httpx", "passive")
            adapter = HttpxAdapter()
            target_list = targets.split("\n") if targets else [target]
            request = ToolExecutionRequest(
                tool_name="httpx", target=target,
                parameters={"targets": target_list, "timeout": timeout}, engagement_id=engagement_id,
            )
            result = await adapter.execute(request)
            return json.dumps({"success": result.success, "live_hosts": result.parsed_output.get("live_hosts", []), "error": result.error}, default=str)

        @mcp.tool(
            name="omega_recon_portscan",
            description="Port scan using nmap. Scans for open ports and service detection.",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True),
        )
        @guarded_tool()
        async def recon_portscan(target: str, ports: str = "1-1000", engagement_id: str = "", scan_type: str = "syn", timeout: int = 120) -> str:
            await server._scope_denial(engagement_id, target, "nmap", "active")
            adapter = NmapAdapter()
            request = ToolExecutionRequest(
                tool_name="nmap", target=target,
                parameters={"ports": ports, "scan_type": scan_type, "timeout": timeout}, engagement_id=engagement_id,
            )
            result = await adapter.execute(request)
            return json.dumps({"success": result.success, "services": result.parsed_output.get("services", []), "error": result.error, "duration_ms": result.duration_ms}, default=str)

        @mcp.tool(
            name="omega_recon_fuzz",
            description="Directory/endpoint fuzzing using ffuf. Requires a target URL.",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True),
        )
        @guarded_tool()
        async def recon_fuzz(target: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", engagement_id: str = "", extensions: str = "", timeout: int = 60) -> str:
            await server._scope_denial(engagement_id, target, "ffuf", "active")
            adapter = FfufAdapter()
            request = ToolExecutionRequest(
                tool_name="ffuf", target=target,
                parameters={"wordlist": wordlist, "extensions": extensions, "mode": "directory", "timeout": timeout},
                engagement_id=engagement_id,
            )
            result = await adapter.execute(request)
            return json.dumps({"success": result.success, "results": result.parsed_output.get("results", [])[:100], "error": result.error, "count": len(result.parsed_output.get("results", []))}, default=str)

        @mcp.tool(
            name="omega_recon_tech",
            description="Technology fingerprinting using whatweb",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True),
        )
        @guarded_tool()
        async def recon_tech(target: str, engagement_id: str = "", timeout: int = 30) -> str:
            await server._scope_denial(engagement_id, target, "whatweb", "passive")
            adapter = WhatWebAdapter()
            request = ToolExecutionRequest(tool_name="whatweb", target=target, engagement_id=engagement_id, parameters={"timeout": timeout})
            result = await adapter.execute(request)
            return json.dumps({"success": result.success, "techniques": result.parsed_output.get("techniques", []), "error": result.error}, default=str)

        @mcp.tool(
            name="omega_recon_crawl",
            description="Crawl website and discover endpoints using katana",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True),
        )
        @guarded_tool()
        async def recon_crawl(target: str, depth: int = 2, engagement_id: str = "", timeout: int = 30) -> str:
            await server._scope_denial(engagement_id, target, "katana", "passive")
            adapter = KatanaAdapter()
            request = ToolExecutionRequest(
                tool_name="katana", target=target,
                parameters={"depth": depth, "timeout": timeout}, engagement_id=engagement_id,
            )
            result = await adapter.execute(request)
            return json.dumps({"success": result.success, "urls": result.parsed_output.get("urls", [])[:200], "count": len(result.parsed_output.get("urls", [])), "error": result.error}, default=str)

        # ── Web Security ───────────────────────────────────────────────────

        @mcp.tool(
            name="omega_web_headers",
            description="Analyze HTTP security headers of a URL (HSTS, CSP, X-Frame-Options, etc.)",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True),
        )
        @guarded_tool()
        async def web_headers(url: str, engagement_id: str = "") -> str:
            orch = server.orchestrator
            assert orch
            await server._scope_denial(engagement_id, url, "web_headers")
            result = await orch.web.analyze_headers(url, engagement_id)
            return json.dumps(result, default=str)

        @mcp.tool(
            name="omega_web_cors",
            description="Test CORS configuration of a URL for misconfigurations",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True),
        )
        @guarded_tool()
        async def web_cors(url: str, engagement_id: str = "") -> str:
            orch = server.orchestrator
            assert orch
            await server._scope_denial(engagement_id, url, "web_cors")
            result = await orch.web.analyze_cors(url, engagement_id)
            return json.dumps(result, default=str)

        @mcp.tool(
            name="omega_web_cookies",
            description="Analyze cookies for security properties (HttpOnly, Secure, SameSite)",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True),
        )
        @guarded_tool()
        async def web_cookies(url: str, engagement_id: str = "") -> str:
            orch = server.orchestrator
            assert orch
            await server._scope_denial(engagement_id, url, "web_cookies")
            result = await orch.web.analyze_cookies(url, engagement_id)
            return json.dumps(result, default=str)

        @mcp.tool(
            name="omega_web_endpoints",
            description="Extract endpoints from a page's HTML/JS",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True),
        )
        @guarded_tool()
        async def web_endpoints(url: str, engagement_id: str = "") -> str:
            orch = server.orchestrator
            assert orch
            await server._scope_denial(engagement_id, url, "web_endpoints")
            resp = await orch.http.get(url)
            result = await orch.web.extract_endpoints(url, resp.get("body", ""), engagement_id)
            return json.dumps(result, default=str)

        @mcp.tool(
            name="omega_web_full_scan",
            description="Full web security analysis: headers, CORS, cookies, endpoints",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True),
        )
        @guarded_tool()
        async def web_full_scan(target: str, engagement_id: str = "") -> str:
            orch = server.orchestrator
            assert orch
            await server._scope_denial(engagement_id, target, "web_full_scan")
            result = await orch.web.full_scan(target, engagement_id)
            return json.dumps(result, default=str)

        @mcp.tool(
            name="omega_web_js_analyze",
            description="Analyze a JavaScript file for secrets, endpoints, and sensitive data",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True),
        )
        @guarded_tool()
        async def web_js_analyze(js_url: str, engagement_id: str = "") -> str:
            orch = server.orchestrator
            assert orch
            await server._scope_denial(engagement_id, js_url, "web_js_analyze")
            result = await orch.web.analyze_javascript(js_url, engagement_id)
            return json.dumps(result, default=str)

        # ── HTTP Client ────────────────────────────────────────────────────

        @mcp.tool(
            name="omega_http_request",
            description="Execute an HTTP request (GET/POST/PUT/PATCH/DELETE). Supports headers, cookies, body, JSON.",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True),
        )
        @guarded_tool()
        async def http_request(
            method: str = "GET", url: str = "", headers: str = "", body: str = "",
            cookies: str = "", json_body: str = "", engagement_id: str = "",
        ) -> str:
            orch = server.orchestrator
            assert orch
            risk = "active" if method.upper() not in ("GET", "HEAD", "OPTIONS") else "passive"
            await server._scope_denial(engagement_id, url, "http_request", risk)
            h = json.loads(headers) if headers else None
            c = json.loads(cookies) if cookies else None
            jb = json.loads(json_body) if json_body else None
            resp = await orch.http.request(method, url, headers=h, cookies=c, body=body or None, json_body=jb)
            if engagement_id:
                await orch.db.save_request_history({
                    "id": new_id(), "engagement_id": engagement_id, "method": method, "url": url,
                    "headers": json.dumps(h or {}), "body": body[:100000],
                    "response_status": resp.get("status_code"), "response_headers": json.dumps(resp.get("headers", {})),
                    "response_body": resp.get("body", "")[:100000], "response_time_ms": resp.get("duration_ms", 0),
                    "created_at": now_utc().isoformat(), "updated_at": now_utc().isoformat(),
                })
            # Truncate body for LLM context
            resp_truncated = {**resp, "body": resp.get("body", "")[:5000]}
            return json.dumps(resp_truncated, default=str)

        # ── Full Scan (orchestrated) ───────────────────────────────────────

        @mcp.tool(
            name="omega_scan",
            description="Run an orchestrated security scan. scan_type: 'full', 'recon', 'web', 'ctf_web'. Coordinates multiple agents automatically.",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True),
        )
        @guarded_tool()
        async def scan(target: str, engagement_id: str = "", scan_type: str = "full", parameters: str = "") -> str:
            orch = server.orchestrator
            assert orch
            params = json.loads(parameters) if parameters else None
            result = await orch.run_scan(engagement_id, target, scan_type, params)
            # Limit output to avoid context overflow
            return json.dumps(result, default=str)[:50000]

        # ── Asset Graph ────────────────────────────────────────────────────

        @mcp.tool(
            name="omega_graph_add_node",
            description="Add a node to the asset graph. node_type: domain, subdomain, ip, port, service, url, endpoint, technology, finding, etc.",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=False),
        )
        @guarded_tool()
        async def graph_add_node(engagement_id: str, node_type: str, label: str, properties: str = "") -> str:
            orch = server.orchestrator
            assert orch
            props = json.loads(properties) if properties else {}
            node = await orch.graph.add_node(engagement_id, node_type, label, props)
            return json.dumps({"id": node.id, "type": node.node_type, "label": node.label})

        @mcp.tool(
            name="omega_graph_add_edge",
            description="Add an edge between two graph nodes. edge_type: resolves_to, hosts, serves, calls, uses_technology, etc.",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=False),
        )
        @guarded_tool()
        async def graph_add_edge(engagement_id: str, source_id: str, target_id: str, edge_type: str, properties: str = "") -> str:
            orch = server.orchestrator
            assert orch
            props = json.loads(properties) if properties else {}
            edge = await orch.graph.add_edge(engagement_id, source_id, target_id, edge_type, props)
            return json.dumps({"id": edge.id, "type": edge.edge_type})

        @mcp.tool(
            name="omega_graph_query",
            description="Query the asset graph for an engagement",
            annotations=ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False),
        )
        @guarded_tool()
        async def graph_query(engagement_id: str, node_type: str = "", label_contains: str = "") -> str:
            orch = server.orchestrator
            assert orch
            await orch.graph.load(engagement_id)
            nodes = orch.graph.find_nodes(engagement_id, node_type or None, label_contains or None)
            return json.dumps({"nodes": nodes[:200], "count": len(nodes)}, default=str)

        # ── Findings & Hypotheses ──────────────────────────────────────────

        @mcp.tool(
            name="omega_hypothesis_create",
            description="Create a vulnerability hypothesis for hypothesis-driven testing",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=False),
        )
        @guarded_tool()
        async def hypothesis_create(engagement_id: str, category: str, target: str, hypothesis: str, endpoint: str = "", observation: str = "") -> str:
            orch = server.orchestrator
            assert orch
            hyp = Hypothesis(
                id=new_id(), engagement_id=engagement_id, category=category,
                target=target, endpoint=endpoint, observation=observation,
                hypothesis=hypothesis, created_at=now_utc(), updated_at=now_utc(),
            )
            saved = await orch.findings.create_hypothesis(hyp)
            return json.dumps({"id": saved.id, "hypothesis": saved.hypothesis, "status": saved.validation_status})

        @mcp.tool(
            name="omega_hypothesis_update",
            description="Update a hypothesis status or add evidence",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=False),
        )
        @guarded_tool()
        async def hypothesis_update(hypothesis_id: str, status: str = "", result: str = "", confidence: str = "", next_test: str = "") -> str:
            orch = server.orchestrator
            assert orch
            updates: dict[str, Any] = {}
            if status:
                updates["validation_status"] = status
            if result:
                updates["observation"] = result
            if confidence:
                updates["confidence"] = confidence
            if next_test:
                updates["next_test"] = next_test
            updated = await orch.findings.update_hypothesis(hypothesis_id, updates)
            if not updated:
                raise ToolError(ErrorCode.NOT_FOUND, "Hypothesis not found")
            return json.dumps({"id": updated.id, "status": updated.validation_status, "hypothesis": updated.hypothesis})

        @mcp.tool(
            name="omega_finding_create",
            description="Create a security finding (vulnerability report)",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=False),
        )
        @guarded_tool()
        async def finding_create(
            engagement_id: str, title: str, severity: str = "informational",
            confidence: str = "none", affected_asset: str = "", affected_endpoint: str = "",
            description: str = "", impact: str = "", steps_to_reproduce: str = "",
            evidence_ids: str = "", cwe_id: str = "", remediation: str = "",
        ) -> str:
            orch = server.orchestrator
            assert orch
            finding = Finding(
                id=new_id(), engagement_id=engagement_id, title=title,
                severity=severity, confidence=confidence,
                affected_asset=affected_asset, affected_endpoint=affected_endpoint,
                description=description, impact=impact,
                steps_to_reproduce=json.loads(steps_to_reproduce) if steps_to_reproduce else [],
                evidence_ids=json.loads(evidence_ids) if evidence_ids else [],
                cwe_id=cwe_id or None, remediation=remediation,
                created_at=now_utc(), updated_at=now_utc(),
            )
            saved = await orch.findings.create_finding(finding)
            return json.dumps({"id": saved.id, "title": saved.title, "severity": saved.severity, "status": saved.validation_status})

        @mcp.tool(
            name="omega_finding_list",
            description="List findings for an engagement, optionally filtered by severity",
            annotations=ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False),
        )
        @guarded_tool()
        async def finding_list(engagement_id: str, severity: str = "") -> str:
            orch = server.orchestrator
            assert orch
            findings = await orch.findings.list_findings(engagement_id, severity or None)
            return json.dumps([f.model_dump(mode="json") for f in findings], default=str)[:50000]

        @mcp.tool(
            name="omega_finding_validate",
            description="Mark a finding as validated (confirmed vulnerability)",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=False),
        )
        @guarded_tool()
        async def finding_validate(finding_id: str, evidence_ids: str = "") -> str:
            orch = server.orchestrator
            assert orch
            ids = json.loads(evidence_ids) if evidence_ids else None
            result = await orch.findings.validate_finding(finding_id, ids)
            if not result:
                raise ToolError(ErrorCode.NOT_FOUND, "Finding not found")
            return json.dumps({"id": result.id, "status": result.validation_status})

        @mcp.tool(
            name="omega_finding_reject",
            description="Reject a finding (false positive)",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=False),
        )
        @guarded_tool()
        async def finding_reject(finding_id: str, reason: str = "") -> str:
            orch = server.orchestrator
            assert orch
            result = await orch.findings.reject_finding(finding_id, reason)
            if not result:
                raise ToolError(ErrorCode.NOT_FOUND, "Finding not found")
            return json.dumps({"id": result.id, "status": result.validation_status})

        @mcp.tool(
            name="omega_finding_summary",
            description="Get a summary of findings (counts by severity and status)",
            annotations=ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False),
        )
        @guarded_tool()
        async def finding_summary(engagement_id: str) -> str:
            orch = server.orchestrator
            assert orch
            summary = await orch.findings.get_summary(engagement_id)
            return json.dumps(summary)

        # ── Evidence ───────────────────────────────────────────────────────

        @mcp.tool(
            name="omega_evidence_list",
            description="List evidence records for an engagement, optionally filtered by type",
            annotations=ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False),
        )
        @guarded_tool()
        async def evidence_list(engagement_id: str, evidence_type: str = "") -> str:
            orch = server.orchestrator
            assert orch
            evidence = await orch.evidence.list_by_engagement(engagement_id, evidence_type or None)
            return json.dumps([e.model_dump(mode="json") for e in evidence], default=str)[:50000]

        # ── CTF Engine ─────────────────────────────────────────────────────

        @mcp.tool(
            name="omega_ctf_challenge_create",
            description="Create a CTF challenge workspace. Categories: web, crypto, pwn, rev, forensics, osint, misc, stego, mobile, blockchain",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=False),
        )
        @guarded_tool()
        async def ctf_challenge_create(
            engagement_id: str, name: str, category: str, target: str = "",
            port: int = 0, protocol: str = "", description: str = "",
        ) -> str:
            orch = server.orchestrator
            assert orch
            ctf = CTFEngine(orch.db)
            challenge = await ctf.create_challenge(
                engagement_id, name, category, target, port or None, protocol, description,
            )
            return json.dumps(challenge.to_dict(), default=str)

        @mcp.tool(
            name="omega_ctf_challenge_list",
            description="List all CTF challenges for an engagement",
            annotations=ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False),
        )
        @guarded_tool()
        async def ctf_challenge_list(engagement_id: str) -> str:
            orch = server.orchestrator
            assert orch
            ctf = CTFEngine(orch.db)
            challenges = await ctf.list_challenges(engagement_id)
            return json.dumps([c.to_dict() for c in challenges], default=str)

        @mcp.tool(
            name="omega_ctf_hypothesis",
            description="Add a hypothesis to a CTF challenge (hypothesis-driven solving)",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=False),
        )
        @guarded_tool()
        async def ctf_hypothesis(challenge_id: str, hypothesis: str, test_plan: str = "", category: str = "general") -> str:
            orch = server.orchestrator
            assert orch
            ctf = CTFEngine(orch.db)
            result = await ctf.add_hypothesis(challenge_id, hypothesis, category, test_plan)
            return json.dumps(result, default=str)

        @mcp.tool(
            name="omega_ctf_submit_flag",
            description="Submit a candidate flag for a CTF challenge",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=False),
        )
        @guarded_tool()
        async def ctf_submit_flag(challenge_id: str, flag: str) -> str:
            orch = server.orchestrator
            assert orch
            ctf = CTFEngine(orch.db)
            result = await ctf.submit_flag(challenge_id, flag)
            return json.dumps({"submitted": result, "flag_preview": flag[:50]})

        @mcp.tool(
            name="omega_ctf_confirm_flag",
            description="Confirm a flag as correct for a CTF challenge",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=False),
        )
        @guarded_tool()
        async def ctf_confirm_flag(challenge_id: str, flag: str) -> str:
            orch = server.orchestrator
            assert orch
            ctf = CTFEngine(orch.db)
            result = await ctf.confirm_flag(challenge_id, flag)
            return json.dumps({"confirmed": result})

        @mcp.tool(
            name="omega_ctf_ledger",
            description="Get the hypothesis ledger for a CTF challenge (shows active/succeeded/failed hypotheses)",
            annotations=ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False),
        )
        @guarded_tool()
        async def ctf_ledger(challenge_id: str) -> str:
            orch = server.orchestrator
            assert orch
            ctf = CTFEngine(orch.db)
            challenge = await ctf.get_challenge(challenge_id)
            if not challenge:
                raise ToolError(ErrorCode.NOT_FOUND, "Challenge not found")
            ledger = ctf.get_hypothesis_ledger(challenge)
            return json.dumps(ledger, default=str)

        # ── Reporting ──────────────────────────────────────────────────────

        @mcp.tool(
            name="omega_report_generate",
            description="Generate a report for an engagement. format: 'markdown', 'html', 'json'",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=False),
        )
        @guarded_tool()
        async def report_generate(engagement_id: str, format: str = "markdown", title: str = "", include_evidence: bool = True) -> str:
            orch = server.orchestrator
            assert orch
            report_engine = ReportEngine(orch.db)
            report = await report_engine.generate(engagement_id, title, format, include_evidence)
            content = report.content[:100000]
            return json.dumps({"id": report.id, "title": report.title, "format": report.format, "content": content, "finding_count": len(report.finding_ids)}, default=str)

        # ── Tools Discovery ────────────────────────────────────────────────

        @mcp.tool(
            name="omega_tools_list",
            description="Discover which security tools are installed and available on the system",
            annotations=ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False),
        )
        @guarded_tool()
        async def tools_list() -> str:
            orch = server.orchestrator
            assert orch
            caps = await orch.registry.discover_all()
            result = {}
            for name, cap in caps.items():
                result[name] = {
                    "available": cap.is_available,
                    "binary": cap.binary_path,
                    "risk_level": cap.risk_level,
                    "description": cap.description,
                    "capabilities": cap.capabilities,
                }
            return json.dumps(result, default=str)

        # ── Audit Log ──────────────────────────────────────────────────────

        @mcp.tool(
            name="omega_audit_log",
            description="View the audit log for an engagement (all scope checks, tool executions, etc.)",
            annotations=ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False),
        )
        async def audit_log(engagement_id: str) -> str:
            db = server.db
            assert db
            log = await db.get_audit_log(engagement_id, limit=100)
            return json.dumps(log, default=str)[:50000]

        # ── Doctor ─────────────────────────────────────────────────────────

        @mcp.tool(
            name="omega_doctor",
            description="Self-diagnostics: check installed tools, Python version, MCP SDK, dependencies",
            annotations=ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False),
        )
        @guarded_tool()
        async def doctor() -> str:
            import shutil
            import platform
            checks: dict[str, Any] = {
                "python_version": platform.python_version(),
                "platform": platform.platform(),
                "tools": {},
            }
            for tool_name in ["nmap", "subfinder", "httpx", "ffuf", "gobuster", "katana", "whatweb", "amass", "nuclei", "sqlmap"]:
                path = shutil.which(tool_name)
                checks["tools"][tool_name] = {"installed": path is not None, "path": path}
            return json.dumps(checks, indent=2)


def create_server(config: OmegaConfig | None = None) -> OmegaServer:
    """Factory: return an OmegaServer ready to run."""
    return OmegaServer(config)


async def run_stdio() -> None:
    server = OmegaServer()
    await server.initialize()
    try:
        await server.mcp.run_stdio_async()
    finally:
        await server.shutdown()


async def run_http(host: str = "127.0.0.1", port: int = 8443) -> None:
    server = OmegaServer()
    await server.initialize()
    try:
        await server.mcp.run_streamable_http_async(host=host, port=port)
    finally:
        await server.shutdown()


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="OMEGA-CYBER-MCP Server")
    parser.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")

    if args.transport == "http":
        asyncio.run(run_http(args.host, args.port))
    else:
        asyncio.run(run_stdio())
