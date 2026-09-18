"""SENTINEL Server — the MCP interface to the security platform."""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from sentinel.config import get_config, SentinelConfig
from sentinel.storage import Database
from sentinel.scope import ScopeEngine
from sentinel.tools import ToolRegistry, ToolExecutor, ToolExecutionRequest
from sentinel.workspace import WorkspaceManager
from sentinel.evidence import EvidenceEngine
from sentinel.findings import FindingEngine
from sentinel.knowledge import AssetGraph
from sentinel.ctf import CTFEngine
from sentinel.http import HTTPClient
from sentinel.web import WebSecurityEngine
from sentinel.reporting import ReportEngine
from sentinel.orchestration import JobManager
from sentinel.agents import Orchestrator
from sentinel.recon import (
    register_all_recon_adapters,
    SubfinderAdapter, HttpxAdapter, NmapAdapter, FfufAdapter,
    WhatWebAdapter, GobusterAdapter, KatanaAdapter,
    NucleiAdapter, NiktoAdapter, GospiderAdapter, MasscanAdapter,
    NaabuAdapter, DnsxAdapter, WafW00fAdapter,
)
from sentinel.core.schemas import (
    Engagement, EngagementMode, Finding, Hypothesis, Severity, Confidence,
    ValidationStatus, new_id, now_utc,
)
from sentinel.core.errors import ErrorCode, ToolError, guarded_tool

logger = logging.getLogger("sentinel.server")


class SentinelServer:
    """Main MCP server for SENTINEL."""

    def __init__(self, config: SentinelConfig | None = None) -> None:
        self.config = config or get_config()
        self.mcp = MCPServer(
            name="sentinel",
            title="SENTINEL",
            version=self.config.version,
            instructions=(
                "SENTINEL is an agentic security research platform. "
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
        logger.info("SENTINEL server initialized")

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
        design of the recon adapters.  When an engagement is provided the full
        authorization pipeline applies: target scope, action, execution mode,
        and rate limiting.

        *analysis_only* engagements always allow *passive* tools without
        requiring explicit scope rules (observation-only posture).
        """
        orch = self.orchestrator
        assert orch
        if not engagement_id:
            return
        eng = await orch.db.get_engagement(engagement_id)
        mode = eng.get("mode", "") if eng else ""
        if mode == "analysis_only" and risk_level == "passive":
            return
        result = await orch.scope.authorize(engagement_id, target, action, risk_level)
        if not result.allowed:
            raise ToolError(ErrorCode.SCOPE_DENIED, f"Scope denied: {result.reason}")

    _NUCLEI_SEVERITY_MAP: dict[str, str] = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFORMATIONAL,
        "unknown": Severity.INFORMATIONAL,
        "": Severity.INFORMATIONAL,
    }

    async def _triage_nuclei_findings(
        self, engagement_id: str, target: str, parsed: dict[str, Any],
    ) -> list[str]:
        """Map nuclei parsed_output findings to FindingEngine records.

        Returns list of created Finding IDs.
        """
        if not engagement_id:
            return []
        orch = self.orchestrator
        assert orch
        finding_ids: list[str] = []
        for item in parsed.get("findings", []):
            if item.get("raw"):
                continue
            sev_str = item.get("severity", "info").lower()
            severity = self._NUCLEI_SEVERITY_MAP.get(sev_str, Severity.INFORMATIONAL)
            title = item.get("name", "") or item.get("template_id", "") or "Nuclei finding"
            endpoint = item.get("matched_at", "")
            refs: list[str] = []
            template_id = item.get("template_id", "")
            if template_id:
                refs.append(f"https://github.com/projectdiscovery/nuclei-templates/blob/master/{template_id}")
            finding = Finding(
                id=new_id(), engagement_id=engagement_id,
                title=f"[nuclei] {title}",
                severity=severity,
                confidence=Confidence.MEDIUM,
                affected_asset=target,
                affected_endpoint=endpoint,
                description=item.get("name", ""),
                references=refs,
                tool_sources=["nuclei"],
                technical_details={
                    "template_id": template_id,
                    "matcher_name": item.get("matcher_name", ""),
                    "curl_command": item.get("curl_command", ""),
                },
                created_at=now_utc(), updated_at=now_utc(),
            )
            saved = await orch.findings.create_finding(finding)
            finding_ids.append(saved.id)
        return finding_ids

    async def _triage_nikto_findings(
        self, engagement_id: str, target: str, parsed: dict[str, Any],
    ) -> list[str]:
        """Map nikto parsed_output vulnerabilities to FindingEngine records.

        Returns list of created Finding IDs.
        """
        if not engagement_id:
            return []
        orch = self.orchestrator
        assert orch
        finding_ids: list[str] = []
        for vuln in parsed.get("vulnerabilities", []):
            text = vuln.get("finding", "") or vuln.get("info", "")
            if not text or vuln.get("source") != "nikto":
                continue
            sev = Severity.MEDIUM
            lower = text.lower()
            if "critical" in lower or "high" in lower:
                sev = Severity.HIGH
            elif "low" in lower:
                sev = Severity.LOW
            refs = []
            if "OSVDB" in text:
                import re as _re
                osvdb = _re.findall(r"OSVDB-(\d+)", text)
                for o in osvdb:
                    refs.append(f"http://osvdb.org/show/osvdb/{o}")
            if "CVE" in text:
                import re as _re
                cves = _re.findall(r"(CVE-\d{4}-\d+)", text)
                refs.extend(cves)
            finding = Finding(
                id=new_id(), engagement_id=engagement_id,
                title=f"[nikto] {text[:120]}",
                severity=sev,
                confidence=Confidence.MEDIUM,
                affected_asset=target,
                affected_endpoint=target,
                description=text,
                references=refs,
                tool_sources=["nikto"],
                created_at=now_utc(), updated_at=now_utc(),
            )
            saved = await orch.findings.create_finding(finding)
            finding_ids.append(saved.id)
        return finding_ids

    async def _run_recon(
        self,
        adapter: Any,
        tool_name: str,
        target: str,
        engagement_id: str,
        risk: str,
        parameters: dict[str, Any] | None = None,
    ) -> str:
        """Run a recon adapter with scope gating, evidence capture, and asset ingestion."""
        orch = self.orchestrator
        assert orch
        await self._scope_denial(engagement_id, target, tool_name, risk)
        request = ToolExecutionRequest(
            tool_name=tool_name, target=target, engagement_id=engagement_id,
            parameters=parameters or {},
        )
        result = await adapter.execute(request)
        triaged_finding_ids: list[str] = []
        if engagement_id and result.success:
            await orch.evidence.store_tool_output(
                engagement_id, tool_name, adapter.version(), target,
                result.parsed_output, result.raw_output,
            )
            for asset in result.normalized_output.get("assets", []):
                try:
                    await orch.db.save_asset({
                        "id": new_id(), "engagement_id": engagement_id,
                        "asset_type": asset.get("type", "unknown"),
                        "value": asset.get("value", ""),
                        "metadata": json.dumps(asset.get("metadata", {})),
                        "tags": "[]",
                        "created_at": now_utc().isoformat(),
                        "updated_at": now_utc().isoformat(),
                    })
                except Exception:  # noqa: BLE001 - asset ingestion is best-effort
                    logger.warning("Could not save %s asset for %s", asset.get("type"), tool_name)
            if tool_name == "nuclei":
                triaged_finding_ids = await self._triage_nuclei_findings(
                    engagement_id, target, result.parsed_output,
                )
            elif tool_name == "nikto":
                triaged_finding_ids = await self._triage_nikto_findings(
                    engagement_id, target, result.parsed_output,
                )
        return json.dumps({
            "success": result.success,
            "result": result.parsed_output,
            "assets": result.normalized_output.get("assets", []),
            "triaged_findings": triaged_finding_ids,
            "error": result.error,
            "duration_ms": result.duration_ms,
        }, default=str)

    def _register_tools(self) -> None:
        mcp = self.mcp
        server = self

        # ── Engagement Management ──────────────────────────────────────────

        @mcp.tool(
            name="sentinel_engagement_create",
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
            name="sentinel_engagement_list",
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
            name="sentinel_engagement_get",
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
            name="sentinel_scope_add_rule",
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
            name="sentinel_scope_check",
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
            name="sentinel_scope_list_rules",
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
            name="sentinel_recon_subdomains",
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
            name="sentinel_recon_probe",
            description="Probe live HTTP hosts using httpx. Pass targets as newline-separated list or a single target.",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True),
        )
        @guarded_tool()
        async def recon_probe(target: str, engagement_id: str = "", targets: str = "", timeout: int = 120) -> str:
            target_list = targets.split("\n") if targets else [target]
            await server._scope_denial(engagement_id, target, "httpx", "passive")
            # Every requested target must be individually authorized.
            for t in dict.fromkeys(target_list):
                if isinstance(t, str) and t != target:
                    await server._scope_denial(engagement_id, t, "httpx", "passive")
            adapter = HttpxAdapter()
            request = ToolExecutionRequest(
                tool_name="httpx", target=target,
                parameters={"targets": target_list, "timeout": timeout}, engagement_id=engagement_id,
            )
            result = await adapter.execute(request)
            return json.dumps({"success": result.success, "live_hosts": result.parsed_output.get("live_hosts", []), "error": result.error}, default=str)

        @mcp.tool(
            name="sentinel_recon_portscan",
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
            name="sentinel_recon_fuzz",
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
            name="sentinel_recon_tech",
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
            name="sentinel_recon_crawl",
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

        @mcp.tool(
            name="sentinel_recon_vuln_scan",
            description="Run nuclei vulnerability scan against a target (active)",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True),
        )
        @guarded_tool()
        async def recon_vuln_scan(target: str, engagement_id: str = "", timeout: int = 120, templates: str = "") -> str:
            return await server._run_recon(
                NucleiAdapter(), "nuclei", target, engagement_id, "active",
                {"timeout": timeout, "templates": [t for t in templates.split(",") if t.strip()] if templates else []},
            )

        @mcp.tool(
            name="sentinel_recon_server_audit",
            description="Run nikto web server vulnerability audit against a target (active)",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True),
        )
        @guarded_tool()
        async def recon_server_audit(target: str, engagement_id: str = "", timeout: int = 120) -> str:
            return await server._run_recon(
                NiktoAdapter(), "nikto", target, engagement_id, "active", {"timeout": timeout},
            )

        @mcp.tool(
            name="sentinel_recon_dirbrute",
            description="Enumerate directories and files with gobuster (active)",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True),
        )
        @guarded_tool()
        async def recon_dirbrute(target: str, wordlist: str = "", engagement_id: str = "", timeout: int = 60) -> str:
            return await server._run_recon(
                GobusterAdapter(), "gobuster", target, engagement_id, "active",
                {"wordlist": wordlist, "timeout": timeout},
            )

        @mcp.tool(
            name="sentinel_recon_webcrawl",
            description="Crawl and collect URLs/javascript with gospider (passive)",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True),
        )
        @guarded_tool()
        async def recon_webcrawl(target: str, engagement_id: str = "", timeout: int = 60) -> str:
            return await server._run_recon(
                GospiderAdapter(), "gospider", target, engagement_id, "passive", {"timeout": timeout},
            )

        @mcp.tool(
            name="sentinel_recon_port_rapid",
            description="Rapid full-range port discovery with masscan (active)",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True),
        )
        @guarded_tool()
        async def recon_port_rapid(target: str, engagement_id: str = "", timeout: int = 60, ports: str = "1-1000") -> str:
            return await server._run_recon(
                MasscanAdapter(), "masscan", target, engagement_id, "active",
                {"timeout": timeout, "ports": ports},
            )

        @mcp.tool(
            name="sentinel_recon_fastportscan",
            description="Fast TCP port scan with naabu (active; requires naabu binary)",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True),
        )
        @guarded_tool()
        async def recon_fastportscan(target: str, engagement_id: str = "", timeout: int = 60) -> str:
            return await server._run_recon(
                NaabuAdapter(), "naabu", target, engagement_id, "active", {"timeout": timeout},
            )

        @mcp.tool(
            name="sentinel_recon_dns_lookup",
            description="Resolve DNS records with dnsx (passive; requires dnsx binary)",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True),
        )
        @guarded_tool()
        async def recon_dns_lookup(target: str, engagement_id: str = "", timeout: int = 30) -> str:
            return await server._run_recon(
                DnsxAdapter(), "dnsx", target, engagement_id, "passive", {"timeout": timeout},
            )

        @mcp.tool(
            name="sentinel_recon_waf_detect",
            description="Identify WAF protection with wafw00f (passive; requires wafw00f binary)",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True),
        )
        @guarded_tool()
        async def recon_waf_detect(target: str, engagement_id: str = "", timeout: int = 30) -> str:
            return await server._run_recon(
                WafW00fAdapter(), "wafw00f", target, engagement_id, "passive", {"timeout": timeout},
            )

        # ── Web Security ───────────────────────────────────────────────────

        @mcp.tool(
            name="sentinel_web_headers",
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
            name="sentinel_web_cors",
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
            name="sentinel_web_cookies",
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
            name="sentinel_web_endpoints",
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
            name="sentinel_web_full_scan",
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
            name="sentinel_web_js_analyze",
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

        @mcp.tool(
            name="sentinel_web_jwt",
            description="Analyze JWT tokens found in cookies, headers, or page body for security issues",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True),
        )
        @guarded_tool()
        async def web_jwt(url: str, engagement_id: str = "") -> str:
            orch = server.orchestrator
            assert orch
            await server._scope_denial(engagement_id, url, "web_jwt")
            result = await orch.web.analyze_jwt(url, engagement_id)
            return json.dumps(result, default=str)

        @mcp.tool(
            name="sentinel_web_tech",
            description="Detect technologies/frameworks used by a web application",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True),
        )
        @guarded_tool()
        async def web_tech(url: str, engagement_id: str = "") -> str:
            orch = server.orchestrator
            assert orch
            await server._scope_denial(engagement_id, url, "web_tech")
            result = await orch.web.detect_technologies(url, engagement_id)
            return json.dumps(result, default=str)

        # ── API Security ──────────────────────────────────────────────────

        @mcp.tool(
            name="sentinel_api_openapi",
            description="Discover an OpenAPI/Swagger specification at common paths",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True),
        )
        @guarded_tool()
        async def api_openapi(base_url: str, engagement_id: str = "") -> str:
            orch = server.orchestrator
            assert orch
            await server._scope_denial(engagement_id, base_url, "api_openapi")
            result = await orch.api.discover_openapi(base_url)
            return json.dumps(result, default=str)

        @mcp.tool(
            name="sentinel_api_graphql",
            description="Probe for a GraphQL endpoint at common paths",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True),
        )
        @guarded_tool()
        async def api_graphql(base_url: str, engagement_id: str = "") -> str:
            orch = server.orchestrator
            assert orch
            await server._scope_denial(engagement_id, base_url, "api_graphql")
            result = await orch.api.discover_graphql(base_url)
            return json.dumps(result, default=str)

        @mcp.tool(
            name="sentinel_api_auth",
            description="Analyze API authentication mechanisms (schemes, cookie/header patterns)",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True),
        )
        @guarded_tool()
        async def api_auth(url: str, engagement_id: str = "") -> str:
            orch = server.orchestrator
            assert orch
            await server._scope_denial(engagement_id, url, "api_auth")
            result = await orch.api.analyze_authentication(url)
            return json.dumps(result, default=str)

        @mcp.tool(
            name="sentinel_api_idor",
            description="Test for Insecure Direct Object References by substituting object IDs",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True),
        )
        @guarded_tool()
        async def api_idor(url_pattern: str, id_values: str = "", engagement_id: str = "") -> str:
            orch = server.orchestrator
            assert orch
            await server._scope_denial(engagement_id, url_pattern, "api_idor", "active")
            ids = [i.strip() for i in id_values.split(",") if i.strip()] if id_values else []
            result = await orch.api.test_idor(url_pattern, ids or None, engagement_id)
            return json.dumps(result, default=str)

        @mcp.tool(
            name="sentinel_api_introspection",
            description="Analyze a GraphQL endpoint for enabled introspection",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True),
        )
        @guarded_tool()
        async def api_introspection(graphql_url: str, engagement_id: str = "") -> str:
            orch = server.orchestrator
            assert orch
            await server._scope_denial(engagement_id, graphql_url, "api_introspection")
            result = await orch.api.analyze_graphql_introspection(graphql_url)
            return json.dumps(result, default=str)

        @mcp.tool(
            name="sentinel_api_full_scan",
            description="Run a full API security scan: OpenAPI, GraphQL, authentication, endpoint inference",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True),
        )
        @guarded_tool()
        async def api_full_scan(target: str, engagement_id: str = "") -> str:
            orch = server.orchestrator
            assert orch
            await server._scope_denial(engagement_id, target, "api_full_scan", "active")
            result = await orch.api.full_scan(target, engagement_id)
            return json.dumps(result, default=str)

        # ── HTTP Client ────────────────────────────────────────────────────

        @mcp.tool(
            name="sentinel_http_request",
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
            name="sentinel_scan",
            description="Run an orchestrated security scan. scan_type: 'full', 'recon', 'web', 'ctf_web'. Coordinates multiple agents automatically.",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True),
        )
        @guarded_tool()
        async def scan(target: str, engagement_id: str = "", scan_type: str = "full", parameters: str = "") -> str:
            orch = server.orchestrator
            assert orch
            params = json.loads(parameters) if parameters else None
            # Gate the primary target before any agents run.
            risk = "active" if scan_type != "recon" else "passive"
            await server._scope_denial(engagement_id, target, "sentinel_scan", risk)
            result = await orch.run_scan(engagement_id, target, scan_type, params)
            # Limit output to avoid context overflow
            return json.dumps(result, default=str)[:50000]

        # ── Asset Graph ────────────────────────────────────────────────────

        @mcp.tool(
            name="sentinel_graph_add_node",
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
            name="sentinel_graph_add_edge",
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
            name="sentinel_graph_query",
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
            name="sentinel_hypothesis_create",
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
            name="sentinel_hypothesis_update",
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
            name="sentinel_finding_create",
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
            name="sentinel_finding_list",
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
            name="sentinel_finding_validate",
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
            name="sentinel_finding_reject",
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
            name="sentinel_finding_summary",
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
            name="sentinel_evidence_list",
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
            name="sentinel_ctf_challenge_create",
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
            name="sentinel_ctf_challenge_list",
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
            name="sentinel_ctf_hypothesis",
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
            name="sentinel_ctf_resolve_hypothesis",
            description="Mark a CTF challenge hypothesis as success or failed with a result note",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=False),
        )
        @guarded_tool()
        async def ctf_resolve_hypothesis(challenge_id: str, hypothesis_id: str, result: str, successful: bool) -> str:
            orch = server.orchestrator
            assert orch
            ctf = CTFEngine(orch.db)
            await ctf.resolve_hypothesis(challenge_id, hypothesis_id, result, successful)
            return json.dumps({"challenge_id": challenge_id, "hypothesis_id": hypothesis_id, "resolved": True})

        @mcp.tool(
            name="sentinel_ctf_add_note",
            description="Append a note to a CTF challenge workspace",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=False),
        )
        @guarded_tool()
        async def ctf_add_note(challenge_id: str, note: str) -> str:
            orch = server.orchestrator
            assert orch
            ctf = CTFEngine(orch.db)
            await ctf.add_note(challenge_id, note)
            return json.dumps({"challenge_id": challenge_id, "added": True})

        @mcp.tool(
            name="sentinel_ctf_add_artifact",
            description="Record a discovered artifact (file, string, endpoint) on a CTF challenge",
            annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=False),
        )
        @guarded_tool()
        async def ctf_add_artifact(challenge_id: str, artifact: str) -> str:
            orch = server.orchestrator
            assert orch
            ctf = CTFEngine(orch.db)
            await ctf.add_artifact(challenge_id, artifact)
            return json.dumps({"challenge_id": challenge_id, "added": True})

        @mcp.tool(
            name="sentinel_ctf_hypothesis_ledger",
            description="Get the hypothesis ledger for a CTF challenge",
            annotations=ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False),
        )
        @guarded_tool()
        async def ctf_hypothesis_ledger(challenge_id: str) -> str:
            orch = server.orchestrator
            assert orch
            ctf = CTFEngine(orch.db)
            challenge = await ctf.get_challenge(challenge_id)
            if not challenge:
                raise ToolError(ErrorCode.NOT_FOUND, f"Challenge not found: {challenge_id}")
            return json.dumps(ctf.get_hypothesis_ledger(challenge), default=str)

        @mcp.tool(
            name="sentinel_ctf_submit_flag",
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
            name="sentinel_ctf_confirm_flag",
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
            name="sentinel_ctf_ledger",
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
            name="sentinel_report_generate",
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
            name="sentinel_tools_list",
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
            name="sentinel_audit_log",
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
            name="sentinel_doctor",
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

        @mcp.tool(
            name="sentinel_health_check",
            description="Operational health: DB connectivity, cache, worker pool, tool registry readiness",
            annotations=ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False),
        )
        @guarded_tool()
        async def health_check() -> str:
            orch = server.orchestrator
            assert orch
            ready: dict[str, bool] = {}

            # 1. Database connectivity
            db_ok = False
            try:
                await orch.db.query("engagements", limit=1)
                db_ok = True
            except Exception:  # noqa: BLE001 - health reporting must never raise
                db_ok = False
            ready["database"] = db_ok

            # 2. Tool registry / external binaries
            try:
                caps = await orch.registry.discover_all()
                core_tools = {
                    "nuclei", "nikto", "nmap", "subfinder", "httpx", "ffuf",
                    "whatweb", "gobuster", "katana", "gospider", "masscan",
                }
                installed = sorted(
                    name for name, cap in caps.items()
                    if name in core_tools and cap.is_available
                )
                missing = sorted(
                    name for name, cap in caps.items()
                    if name in core_tools and not cap.is_available
                )
                ready["tool_registry"] = len(caps) > 0
            except Exception:  # noqa: BLE001
                installed, missing, caps = [], [], {}
                ready["tool_registry"] = False

            # 3. Cache availability (fail-open by design)
            try:
                from sentinel.core.cache import cache_get
                probe = await cache_get("__health_probe__", 0)
                ready["cache"] = True
                cache_ok = probe is not None
            except Exception:  # noqa: BLE001
                ready["cache"] = False
                cache_ok = False

            # 4. Worker pool
            try:
                from sentinel.core.concurrency import get_worker_pool
                pool = get_worker_pool()
                ready["worker_pool"] = True
                worker_capacity = pool.max_concurrent
            except Exception:  # noqa: BLE001
                ready["worker_pool"] = False
                worker_capacity = 0

            # Overall assessment
            status = "ready" if all(ready.get(k) for k in ("database", "tool_registry", "worker_pool")) else "degraded"

            return json.dumps({
                "status": status,
                "ready": ready,
                "services": {
                    "worker_pool_capacity": worker_capacity,
                },
                "tools": {
                    "installed": installed,
                    "missing": missing,
                },
                "registry_size": len(caps),
                "database": "connected" if db_ok else "unavailable",
                "cache": "available" if cache_ok else "empty/fail-open",
            }, indent=2)


def create_server(config: SentinelConfig | None = None) -> SentinelServer:
    """Factory: return an SentinelServer ready to run."""
    return SentinelServer(config)


async def run_stdio() -> None:
    server = SentinelServer()
    await server.initialize()
    try:
        await server.mcp.run_stdio_async()
    finally:
        await server.shutdown()


async def run_http(host: str = "127.0.0.1", port: int = 8443) -> None:
    server = SentinelServer()
    await server.initialize()
    try:
        await server.mcp.run_streamable_http_async(host=host, port=port)
    finally:
        await server.shutdown()


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="SENTINEL Server")
    parser.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")

    if args.transport == "http":
        asyncio.run(run_http(args.host, args.port))
    else:
        asyncio.run(run_stdio())
