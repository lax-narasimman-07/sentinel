"""Tool Adapter Framework — universal interface for all security tools."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import time
from abc import ABC, abstractmethod
from typing import Any

from omega.core.schemas import (
    ToolCapability,
    ToolExecutionRequest,
    ToolResult,
    ToolRiskLevel,
    Evidence,
    new_id,
    now_utc,
    content_hash,
)
from omega.scope import ScopeEngine
from omega.storage import Database

logger = logging.getLogger("omega.tools")


class ToolAdapter(ABC):
    """Abstract base class for all tool adapters.

    Every security tool must implement this interface.
    """

    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def version(self) -> str: ...

    @abstractmethod
    def capabilities(self) -> ToolCapability: ...

    @abstractmethod
    async def execute(self, request: ToolExecutionRequest) -> ToolResult: ...

    def input_schema(self) -> dict[str, Any]:
        """Return the JSON Schema describing this tool's input parameters."""
        cap = self.capabilities()
        return cap.input_schema or {}

    def normalize(self, raw_output: str, parsed: dict[str, Any]) -> dict[str, Any]:
        """Override to normalize tool-specific output into common schema."""
        return parsed

    async def discover(self) -> ToolCapability:
        cap = self.capabilities()
        binary = self._find_binary()
        if binary:
            cap.is_available = True
            cap.binary_path = binary
        return cap

    def _find_binary(self) -> str | None:
        """Find the tool binary in PATH."""
        cap = self.capabilities()
        names = [self.name()]
        for name in names:
            path = shutil.which(name)
            if path:
                return path
        return None

    async def _run_subprocess(
        self,
        cmd: list[str],
        timeout: float = 300,
        max_output_bytes: int = 2_000_000,
        env: dict[str, str] | None = None,
    ) -> tuple[str, str, int, float]:
        """Run a subprocess safely. Returns (stdout, stderr, returncode, duration_ms)."""
        start = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            duration = (time.monotonic() - start) * 1000

            stdout_str = stdout.decode("utf-8", errors="replace")[:max_output_bytes]
            stderr_str = stderr.decode("utf-8", errors="replace")[:max_output_bytes]

            return stdout_str, stderr_str, proc.returncode or 0, duration
        except asyncio.TimeoutError:
            duration = (time.monotonic() - start) * 1000
            try:
                proc.kill()
            except Exception:
                pass
            return "", f"Command timed out after {timeout}s", -1, duration
        except Exception as e:
            duration = (time.monotonic() - start) * 1000
            return "", str(e), -1, duration

    async def _run_subprocess_with_input(
        self,
        cmd: list[str],
        input_data: bytes | None = None,
        timeout: float = 300,
        max_output_bytes: int = 2_000_000,
        env: dict[str, str] | None = None,
    ) -> tuple[str, str, int, float]:
        """Run a subprocess with optional stdin input. Returns (stdout, stderr, returncode, duration_ms)."""
        start = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE if input_data else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(input=input_data), timeout=timeout)
            duration = (time.monotonic() - start) * 1000
            return (
                stdout.decode("utf-8", errors="replace")[:max_output_bytes],
                stderr.decode("utf-8", errors="replace")[:max_output_bytes],
                proc.returncode or 0,
                duration,
            )
        except asyncio.TimeoutError:
            duration = (time.monotonic() - start) * 1000
            try:
                proc.kill()
            except Exception:
                pass
            return "", f"Timed out after {timeout}s", -1, duration
        except Exception as e:
            duration = (time.monotonic() - start) * 1000
            return "", str(e), -1, duration


class ToolRegistry:
    """Registry of all available tool adapters."""

    def __init__(self) -> None:
        self._adapters: dict[str, ToolAdapter] = {}
        self._capabilities: dict[str, ToolCapability] = {}

    def register(self, adapter: ToolAdapter) -> None:
        self._adapters[adapter.name()] = adapter

    def get(self, name: str) -> ToolAdapter | None:
        return self._adapters.get(name)

    def list_all(self) -> list[ToolAdapter]:
        return list(self._adapters.values())

    async def discover_all(self) -> dict[str, ToolCapability]:
        caps = {}
        for name, adapter in self._adapters.items():
            cap = await adapter.discover()
            self._capabilities[name] = cap
            caps[name] = cap
        return caps

    def list_available(self) -> dict[str, ToolCapability]:
        return {k: v for k, v in self._capabilities.items() if v.is_available}

    def list_unavailable(self) -> dict[str, ToolCapability]:
        return {k: v for k, v in self._capabilities.items() if not v.is_available}


class ToolExecutor:
    """Executes tools through the scope engine with evidence collection."""

    def __init__(self, db: Database, scope: ScopeEngine, registry: ToolRegistry) -> None:
        self.db = db
        self.scope = scope
        self.registry = registry

    async def execute(self, request: ToolExecutionRequest, engagement_id: str = "") -> ToolResult:
        adapter = self.registry.get(request.tool_name)
        if not adapter:
            return ToolResult(
                id=new_id(),
                tool_name=request.tool_name,
                success=False,
                error=f"Tool '{request.tool_name}' not found in registry",
                created_at=now_utc(),
                updated_at=now_utc(),
            )

        # Scope validation (skip for analysis-only tools)
        cap = adapter.capabilities()
        if cap.risk_level in (ToolRiskLevel.ACTIVE, ToolRiskLevel.DESTRUCTIVE) and engagement_id:
            scope_result = await self.scope.authorize(
                engagement_id,
                request.target,
                request.tool_name,
                cap.risk_level.value,
            )
            if not scope_result.allowed:
                await self._audit_denied(engagement_id, request, scope_result.reason)
                return ToolResult(
                    id=new_id(),
                    tool_name=request.tool_name,
                    success=False,
                    error=f"Scope authorization denied: {scope_result.reason}",
                    created_at=now_utc(),
                    updated_at=now_utc(),
                )

        # Rate limiting
        if engagement_id:
            rate_result = await self.scope.enforce_rate_limit(engagement_id, request.target)
            if not rate_result.allowed:
                return ToolResult(
                    id=new_id(),
                    tool_name=request.tool_name,
                    success=False,
                    error=f"Rate limit exceeded: {rate_result.reason}",
                    created_at=now_utc(),
                    updated_at=now_utc(),
                )

        # Execute
        try:
            result = await adapter.execute(request)
        except Exception as e:
            logger.exception(f"Tool execution failed: {request.tool_name}")
            result = ToolResult(
                id=new_id(),
                tool_name=request.tool_name,
                success=False,
                error=str(e),
                created_at=now_utc(),
                updated_at=now_utc(),
            )

        # Store evidence if successful
        if result.success and engagement_id:
            evidence = Evidence(
                id=new_id(),
                engagement_id=engagement_id,
                evidence_type="tool_output",
                source_tool=request.tool_name,
                source_version=adapter.version(),
                target=request.target,
                content=result.normalized_output or result.parsed_output,
                content_hash=content_hash(result.raw_output[:5000]),
                tags=[request.tool_name],
                created_at=now_utc(),
                updated_at=now_utc(),
            )
            ev_data = await self.db.save_evidence(evidence.model_dump())
            result.evidence_id = ev_data.get("id")

        # Log tool run
        if engagement_id:
            await self.db.save_tool_run({
                "id": new_id(),
                "engagement_id": engagement_id,
                "tool_name": request.tool_name,
                "tool_version": adapter.version(),
                "target": request.target,
                "parameters": request.parameters,
                "success": result.success,
                "raw_output": result.raw_output[:50000],
                "normalized_output": result.normalized_output,
                "error": result.error,
                "duration_ms": result.duration_ms,
                "evidence_id": result.evidence_id,
                "created_at": now_utc().isoformat(),
                "updated_at": now_utc().isoformat(),
            })

        return result

    async def _audit_denied(self, engagement_id: str, request: ToolExecutionRequest, reason: str) -> None:
        await self.db.log_audit({
            "id": new_id(),
            "engagement_id": engagement_id,
            "event_type": "scope_denied",
            "target": request.target,
            "action": request.tool_name,
            "result": reason,
            "allowed": 0,
            "metadata": json.dumps(request.parameters),
            "created_at": now_utc().isoformat(),
            "updated_at": now_utc().isoformat(),
        })


def load_adapters(registry: ToolRegistry) -> None:
    """Load all built-in tool adapters into the given registry.

    This is the single entry point for populating a ToolRegistry with the
    adapters shipped by OMEGA (recon, web, api, etc.).
    """
    from omega.recon import register_all_recon_adapters
    register_all_recon_adapters(registry)
