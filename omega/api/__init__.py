"""API security engine — REST, GraphQL, OpenAPI analysis and testing."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
from typing import Any
from urllib.parse import urlparse, parse_qs

from omega.http import HTTPClient
from omega.storage import Database
from omega.core.schemas import new_id, now_utc
from omega.web import normalize_target_url

logger = logging.getLogger("omega.api")


class APISecurityEngine:
    """API security analysis engine."""

    def __init__(self, db: Database) -> None:
        self.db = db
        self.http = HTTPClient(db)

    async def discover_openapi(self, base_url: str) -> dict[str, Any]:
        """Discover OpenAPI/Swagger specifications."""
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        paths = [
            "/openapi.json", "/swagger.json", "/api-docs",
            "/swagger/v1/swagger.json", "/api/swagger.json",
            "/v1/openapi.json", "/v2/openapi.json",
            "/docs/openapi.json", "/api/v1/openapi.json",
            "/.well-known/openapi.json",
            "/openapi.yaml", "/swagger.yaml",
        ]
        for path in paths:
            url = base + path
            try:
                resp = await self.http.get(url)
                if resp.get("status_code") == 200:
                    body = resp.get("body", "")
                    try:
                        spec = json.loads(body)
                        if "openapi" in spec or "swagger" in spec:
                            paths_count = len(spec.get("paths", {})) if isinstance(spec.get("paths"), dict) else 0
                            spec_capped = self._cap_spec(spec)
                            return {
                                "found": True,
                                "url": url,
                                "spec": spec_capped,
                                "version": spec.get("openapi", spec.get("swagger", "unknown")),
                                "spec_size": len(body),
                                "paths_count": paths_count,
                            }
                    except json.JSONDecodeError:
                        logger.debug("openapi probe %s returned non-JSON body", url)
            except Exception as e:  # noqa: BLE001 - probe failures are expected on many hosts
                logger.debug("openapi probe %s failed: %s", url, e)
        return {"found": False}

    @staticmethod
    def _cap_spec(spec: dict[str, Any], max_paths: int = 500) -> dict[str, Any]:
        """Summarize an OpenAPI spec to keep tool output bounded."""
        if not isinstance(spec.get("paths"), dict) or len(spec["paths"]) <= max_paths:
            return spec
        paths = dict(list(spec["paths"].items())[:max_paths])
        capped = dict(spec)
        capped["paths"] = paths
        capped["_truncated"] = True
        return capped

    async def discover_graphql(self, base_url: str) -> dict[str, Any]:
        """Discover GraphQL endpoints."""
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        paths = ["/graphql", "/graphiql", "/api/graphql", "/v1/graphql", "/query"]
        for path in paths:
            url = base + path
            try:
                resp = await self.http.post(url, json_body={"query": "{ __schema { types { name } } }"})
                if resp.get("status_code") == 200:
                    body = resp.get("body", "")
                    try:
                        data = json.loads(body)
                        if "data" in data:
                            raw_types = data.get("data", {}).get("__schema", {}).get("types", [])
                            if not isinstance(raw_types, list):
                                continue
                            types = sorted({t.get("name", "") for t in raw_types if isinstance(t, dict)})
                            types = [t for t in types if t and not t.startswith("__")]
                            return {"found": True, "url": url, "types": types, "type_count": len(types)}
                    except json.JSONDecodeError:
                        logger.debug("graphql probe %s returned non-JSON body", url)
            except Exception as e:  # noqa: BLE001 - probe failures are expected on many hosts
                logger.debug("graphql probe %s failed: %s", url, e)
        return {"found": False}

    async def infer_endpoints(
        self,
        base_url: str,
        timeout: float = 8,
        concurrency: int = 4,
        deadline: float = 60,
    ) -> dict[str, Any]:
        """Infer API endpoints from common patterns.

        Bounded: requests run with limited concurrency and an overall deadline so
        a slow/unresponsive host can never stall a scan for minutes.
        """
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        common_resources = [
            "users", "accounts", "admin", "auth", "login", "register",
            "profile", "settings", "items", "posts", "comments", "orders",
            "products", "categories", "uploads", "files", "search", "config",
            "status", "health", "version", "info", "docs", "api",
        ]
        probes = [base + prefix + resource for resource in common_resources for prefix in ["/api/", "/api/v1/", "/api/v2/", "/"]]
        sem = asyncio.Semaphore(max(1, min(int(concurrency), 16)))
        discovered: list[dict[str, Any]] = []

        async def _probe(url: str) -> None:
            try:
                async with sem:
                    resp = await self.http.get(url, timeout=timeout)
                status = resp.get("status_code", 0)
                if status in (200, 201, 301, 302, 401, 403):
                    discovered.append({
                        "url": url, "status": status,
                        "requires_auth": status in (401, 403),
                        "method": "GET",
                    })
            except Exception as e:  # noqa: BLE001 - per-probe isolation
                logger.debug("endpoint probe %s failed: %s", url, e)

        try:
            await asyncio.wait_for(asyncio.gather(*[_probe(u) for u in probes]), timeout=deadline)
        except TimeoutError:
            logger.warning("infer_endpoints hit deadline %ss after %d probes", deadline, len(discovered))
        return {"endpoints": discovered, "count": len(discovered)}

    async def analyze_authentication(self, url: str, timeout: float = 8) -> dict[str, Any]:
        """Analyze authentication mechanisms."""
        resp = await self.http.request(
            "GET", url, headers={"Origin": "https://evil.com"}, timeout=timeout,
        )
        headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
        body = resp.get("body", "")
        status = resp.get("status_code", 0)

        auth_methods = []
        findings = []

        www_auth = headers.get("www-authenticate", "")
        if www_auth:
            auth_methods.append({"type": "www-authenticate", "value": www_auth})

        for name in resp.get("cookies", {}):
            if any(kw in name.lower() for kw in ("session", "token", "auth", "jwt")):
                auth_methods.append({"type": "cookie", "name": name})

        auth_patterns = [
            (r'login|signin|sign.in', "login_form"),
            (r'oauth|authorize', "oauth"),
            (r'api[_-]?key|apikey', "api_key"),
            (r'jwt|bearer', "jwt"),
        ]
        for pattern, name in auth_patterns:
            if re.search(pattern, body, re.I):
                auth_methods.append({"type": "body_reference", "name": name})

        acao = headers.get("access-control-allow-origin", "")
        if acao == "https://evil.com":
            findings.append({"type": "cors_auth_risk", "severity": "medium", "description": "CORS reflects evil origin - auth may be at risk"})

        return {"url": url, "status_code": status, "auth_methods": auth_methods, "findings": findings}

    async def test_idor(self, url_pattern: str, id_values: list[int | str] | None = None, engagement_id: str = "", timeout: float = 8) -> dict[str, Any]:
        """Test for IDOR by comparing responses to different IDs."""
        if "{id}" not in url_pattern and ":id" not in url_pattern:
            return {
                "url_pattern": url_pattern,
                "error": "url_pattern must contain an {id} or :id placeholder",
                "success": False,
            }
        if not id_values:
            id_values = [1, 2, 3]
        results = []
        responses = []
        for vid in id_values:
            test_url = url_pattern.replace("{id}", str(vid)).replace(":id", str(vid))
            resp = await self.http.get(test_url, timeout=timeout)
            responses.append({"id": vid, "status": resp.get("status_code"), "body_length": len(resp.get("body", ""))})

        statuses = [r["status"] for r in responses] or [0]
        lengths = [r["body_length"] for r in responses]
        all_same_status = len(set(statuses)) == 1
        all_same_length = len(set(lengths)) == 1

        idor_risk = all_same_status and statuses[0] == 200 and not all_same_length

        return {
            "url_pattern": url_pattern,
            "results": responses,
            "idor_risk": idor_risk,
            "severity": "high" if idor_risk else "informational",
        }

    async def analyze_graphql_introspection(self, graphql_url: str, timeout: float = 8) -> dict[str, Any]:
        """Analyze GraphQL introspection for security issues."""
        result: dict[str, Any] = {"url": graphql_url, "introspection_enabled": False, "types": [], "findings": []}
        try:
            resp = await self.http.post(graphql_url, json_body={"query": "{ __schema { types { name fields { name type { name kind ofType { name } } } } } }"}, timeout=timeout)
            if resp.get("status_code") == 200:
                data = json.loads(resp.get("body", "{}"))
                if "data" in data and data["data"].get("__schema"):
                    result["introspection_enabled"] = True
                    schema = data["data"]["__schema"]
                    types = schema.get("types", []) if isinstance(schema.get("types"), list) else []
                    parsed_types = [
                        {"name": t.get("name", "?"), "fields": [f.get("name", "?") for f in t.get("fields", []) if isinstance(f, dict)]}
                        for t in types if isinstance(t, dict) and not t.get("name", "").startswith("__")
                    ]
                    result["types"] = parsed_types
                    result["findings"].append({"type": "introspection_enabled", "severity": "medium", "description": "GraphQL introspection is enabled"})
        except Exception as e:  # noqa: BLE001 - introspection is a best-effort probe
            logger.debug("graphql introspection %s failed: %s", graphql_url, e)
        return result

    async def full_scan(self, target: str, engagement_id: str = "") -> dict[str, Any]:
        """Run comprehensive API security scan.

        Each sub-analysis is isolated so a single failed component never crashes
        the whole scan. Failures are surfaced in ``scan_errors``.
        """
        url = normalize_target_url(target)
        results: dict[str, Any] = {"target": url, "success": False, "scan_errors": []}

        async def _safe(name: str, awaitable: Any) -> dict[str, Any]:
            try:
                return await awaitable
            except Exception as e:  # noqa: BLE001 - surface component failure, never crash the scan
                msg = f"{type(e).__name__}: {e}"
                results["scan_errors"].append({"component": name, "error": msg})
                logger.warning("full_scan component '%s' failed for %s: %s", name, url, msg)
                return {"error": msg, "success": False}

        results["openapi"] = await _safe("openapi", self.discover_openapi(url))
        results["graphql"] = await _safe("graphql", self.discover_graphql(url))
        results["auth"] = await _safe("auth", self.analyze_authentication(url))
        results["endpoints"] = await _safe("endpoints", self.infer_endpoints(url))
        results["success"] = not results["scan_errors"]
        return results


# ============================================================
# Web Dashboard Backend (FastAPI)
# ============================================================

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from datetime import datetime

dashboard_app = FastAPI(title="OMEGA Dashboard", version="1.0.0")

dashboard_app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost", "http://127.0.0.1", "https://localhost"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include the comprehensive API routes
_api_routes_loaded = False
try:
    from omega.api.routes import router as api_router
    dashboard_app.include_router(api_router)
    _api_routes_loaded = True
except Exception as e:
    logger.warning("Could not load API routes: %s: %s", type(e).__name__, e)

from fastapi import Request


@dashboard_app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Convert any uncaught engine/server error into a structured JSON error."""
    logger.error(
        "Unhandled exception on %s %s: %s", request.method, request.url.path, exc, exc_info=True
    )
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "error": {
                "code": "INTERNAL_ERROR",
                "message": f"{type(exc).__name__}: {exc}",
                "details": {"path": request.url.path, "method": request.method},
            },
        },
    )

_dashboard_state: dict[str, Any] = {
    "engagements": [],
    "findings": [],
    "evidence": [],
    "logs": [],
    "system": {
        "status": "running",
        "version": "1.0.0",
        "start_time": None,
        "tools_available": 0,
    },
}


@dashboard_app.get("/")
async def index():
    """Serve the dashboard UI."""
    from omega.api.frontend import get_dashboard_html
    return HTMLResponse(content=get_dashboard_html())


@dashboard_app.get("/api/health")
async def api_health() -> JSONResponse:
    """Lightweight liveness probe exposing whether the API routes loaded."""
    return JSONResponse(
        content={
            "status": "ok" if _api_routes_loaded else "degraded",
            "version": "1.0.0",
            "api_routes_loaded": _api_routes_loaded,
        }
    )


@dashboard_app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        await websocket.send_json({"type": "system", **_dashboard_state["system"]})
        while True:
            data = await websocket.receive_text()
            msg = json.loads(data)
            if msg.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        pass
    except json.JSONDecodeError as e:
        logger.warning("WebSocket client sent malformed JSON: %s", e)
        with contextlib.suppress(Exception):  # noqa: S110 - connection may already be closed
            await websocket.send_json({"type": "error", "message": f"Invalid JSON: {e}"})
    except Exception as e:  # noqa: BLE001 - keep the socket alive on unexpected errors
        logger.warning("WebSocket handler error: %s", e)


def broadcast_event(event_type: str, data: dict) -> None:
    """Queue an event for WebSocket broadcast, bounding each list."""
    if event_type == "finding":
        _dashboard_state["findings"].append(data)
        while len(_dashboard_state["findings"]) > 500:
            _dashboard_state["findings"].pop(0)
    elif event_type == "log":
        _dashboard_state["logs"].append(data)
        while len(_dashboard_state["logs"]) > 500:
            _dashboard_state["logs"].pop(0)
    elif event_type == "engagement":
        _dashboard_state["engagements"].append(data)
        while len(_dashboard_state["engagements"]) > 500:
            _dashboard_state["engagements"].pop(0)
    elif event_type == "evidence":
        _dashboard_state["evidence"].append(data)
        while len(_dashboard_state["evidence"]) > 500:
            _dashboard_state["evidence"].pop(0)
