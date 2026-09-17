"""Edge-case hardening tests for the web/API security engines (Phase 3 follow-up)."""

from __future__ import annotations

import base64
import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from omega.api import APISecurityEngine, _dashboard_state, broadcast_event
from omega.web import WebSecurityEngine, normalize_target_url

# ═══════════════════════════════════════════════════════════════════════════
# normalize_target_url — scheme allowlist
# ═══════════════════════════════════════════════════════════════════════════

def test_normalize_target_url_prefixes_bare_host():
    assert normalize_target_url("example.com") == "http://example.com"
    assert normalize_target_url("127.0.0.1:8080") == "http://127.0.0.1:8080"


def test_normalize_target_url_keeps_safe_schemes():
    assert normalize_target_url("https://x.com") == "https://x.com"
    assert normalize_target_url("http://x.com") == "http://x.com"
    assert normalize_target_url("ws://x.com") == "ws://x.com"
    assert normalize_target_url("wss://x.com") == "wss://x.com"


def test_normalize_target_url_rejects_dangerous_schemes():
    for bad in ("javascript:alert(1)", "data:text/html,<x>", "file:///etc/passwd", "ftp://x.com"):
        with pytest.raises(ValueError):
            normalize_target_url(bad)


def test_normalize_target_url_empty_is_empty():
    assert normalize_target_url("") == ""
    assert normalize_target_url("   ") == ""


# ═══════════════════════════════════════════════════════════════════════════
# Fake HTTP transport
# ═══════════════════════════════════════════════════════════════════════════

class FakeHTTP:
    """Minimal fake HTTPClient for offline engine tests."""

    def __init__(self, response: dict | None = None) -> None:
        self.response = response or self._default()
        self.get_calls: list[str] = []
        self.request_calls: list[tuple[str, str, dict]] = []

    @staticmethod
    def _default() -> dict:
        return {
            "url": "", "status_code": 200,
            "headers": {}, "body": "", "body_length": 0,
            "cookies": {}, "error": None,
        }

    async def get(self, url: str, **kwargs) -> dict:
        self.get_calls.append(url)
        resp = dict(self.response)
        resp["url"] = url
        return resp

    async def post(self, url: str, **kwargs) -> dict:
        resp = dict(self.response)
        resp["url"] = url
        return resp

    async def request(self, method: str, url: str, headers: dict | None = None, **kwargs) -> dict:
        self.request_calls.append((method, url, headers or {}))
        return dict(self.response)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _make_jwt(exp: int) -> str:
    header = _b64url(json.dumps({"alg": "HS256"}).encode())
    payload = _b64url(json.dumps({"exp": exp, "user": "admin"}).encode())
    return f"{header}.{payload}.signature"


def _jwt_response(body: str, cookies: dict, headers: dict) -> dict:
    return {
        "url": "", "status_code": 200,
        "headers": headers, "body": body, "body_length": len(body),
        "cookies": cookies, "error": None,
    }


# ═══════════════════════════════════════════════════════════════════════════
# analyze_jwt — redaction + expiry
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_analyze_jwt_redacts_tokens():
    exp_past = 1_600_000_000  # ~Sep 2020
    jwt = _make_jwt(exp_past)
    assert len(jwt) > 50
    engine = WebSecurityEngine(MagicMock())
    engine.http = FakeHTTP(_jwt_response(
        body=f"token {jwt}",
        cookies={"session": jwt},
        headers={"authorization": f"Bearer {jwt}"},
    ))
    result = await engine.analyze_jwt("http://t.com")
    assert result["jwt_tokens"], "expected at least one token from cookie"
    for entry in result["jwt_tokens"]:
        assert "token" not in entry, "full JWT must never be serialized to output"
        assert "token_preview" in entry
        assert entry["token_preview"].endswith("…")
    assert any(f["type"] == "jwt_expired" for f in result["findings"])


@pytest.mark.asyncio
async def test_analyze_jwt_no_expired_for_fresh_token():
    exp_future = 2_000_000_000_000  # ~2033
    jwt = _make_jwt(exp_future)
    engine = WebSecurityEngine(MagicMock())
    engine.http = FakeHTTP(_jwt_response(body="", cookies={"session": jwt}, headers={}))
    result = await engine.analyze_jwt("http://t.com")
    assert not any(f["type"] == "jwt_expired" for f in result["findings"])


@pytest.mark.asyncio
async def test_analyze_jwt_malformed_token_does_not_crash():
    engine = WebSecurityEngine(MagicMock())
    engine.http = FakeHTTP(_jwt_response(body="not a jwt", cookies={"session": "short"}, headers={}))
    result = await engine.analyze_jwt("http://t.com")
    assert isinstance(result, dict)
    assert "jwt_tokens" in result


# ═══════════════════════════════════════════════════════════════════════════
# extract_endpoints — no quote pollution, API hints clean
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_extract_endpoints_strips_quotes():
    engine = WebSecurityEngine(MagicMock())
    body = '<a href="/login">Login</a>\n<script>fetch("http://cdn.example.com/app.js")</script>\nconst w = new WebSocket("wss://sock.example.com/ws");'
    result = await engine.extract_endpoints("http://t.com", body)
    endpoints = result["endpoints"]
    assert not any(e.startswith('"') for e in endpoints), f"quoted endpoints leaked: {endpoints}"
    assert any(e == "http://t.com/login" for e in endpoints)
    assert any(e == "http://cdn.example.com/app.js" for e in endpoints)
    assert any(e == "wss://sock.example.com/ws" for e in endpoints)


@pytest.mark.asyncio
async def test_extract_endpoints_no_bare_keyword_hints():
    engine = WebSecurityEngine(MagicMock())
    body = "swagger graphql openapi.json schema.json .graphql"
    result = await engine.extract_endpoints("http://t.com", body)
    assert result["count"] == 0, f"bare keywords must not become endpoints: {result['endpoints']}"


# ═══════════════════════════════════════════════════════════════════════════
# analyze_javascript — no null findings
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_analyze_javascript_findings_has_no_none():
    body = "const x = 1;"  # no secrets, no sinks -> both findings would be None
    engine = WebSecurityEngine(MagicMock())
    engine.http = FakeHTTP(_jwt_response(body=body, cookies={}, headers={}))
    result = await engine.analyze_javascript("http://t.com/app.js")
    assert all(f is not None for f in result["findings"])


# ═══════════════════════════════════════════════════════════════════════════
# web full_scan — single body fetch, isolated components
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_web_full_scan_fetches_body_once():
    body_html = '<html><body><a href="/api/users">users</a></body></html>'
    response = {
        "url": "", "status_code": 200,
        "headers": {"server": "Test"}, "body": body_html,
        "body_length": len(body_html), "cookies": {}, "error": None,
    }
    engine = WebSecurityEngine(MagicMock())
    fake = FakeHTTP(response)
    engine.http = fake
    result = await engine.full_scan("http://t.com")
    # analyze_headers + analyze_cookies + detect_technologies = 3 GETs (no 4th body fetch)
    assert len(fake.get_calls) == 3
    assert any(e == "http://t.com/api/users" for e in result["endpoints"].get("endpoints", []))
    assert result["success"] is True
    assert result["scan_errors"] == []


# ═══════════════════════════════════════════════════════════════════════════
# APISecurityEngine — summaries, isolation, validation
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_discover_openapi_summary_fields():
    spec = {"openapi": "3.0.0", "paths": {f"/p{i}": {} for i in range(600)}}
    engine = APISecurityEngine(MagicMock())
    engine.http = FakeHTTP(_jwt_response(body=json.dumps(spec), cookies={}, headers={}))
    result = await engine.discover_openapi("http://t.com")
    assert result["found"] is True
    assert result["paths_count"] == 600
    assert result["spec"]["_truncated"] is True, "huge spec must be capped"
    assert len(result["spec"]["paths"]) <= 500


@pytest.mark.asyncio
async def test_discover_openapi_not_found_tolerant():
    engine = APISecurityEngine(MagicMock())
    engine.http = FakeHTTP({
        "url": "", "status_code": 404, "headers": {}, "body": "not found",
        "body_length": 10, "cookies": {}, "error": None,
    })
    result = await engine.discover_openapi("http://t.com")
    assert result == {"found": False}


@pytest.mark.asyncio
async def test_graphql_introspection_tolerates_missing_names():
    hurt = {
        "url": "", "status_code": 200, "headers": {}, "cookies": {}, "error": None,
        "body": json.dumps({
            "data": {"__schema": {"types": [
                {"name": "User", "fields": [{"name": "id"}, {}]},
                {"fields": [{"name": "orphan"}]},
            ]}},
        }),
        "body_length": 0,
    }
    engine = APISecurityEngine(MagicMock())
    engine.http = FakeHTTP(hurt)
    result = await engine.analyze_graphql_introspection("http://t.com/graphql")
    assert result["introspection_enabled"] is True
    assert result["types"], "types must survive malformed entries"
    assert all(t.get("name") for t in result["types"])


@pytest.mark.asyncio
async def test_idor_requires_placeholder():
    engine = APISecurityEngine(MagicMock())
    result = await engine.test_idor("http://t.com/users/1")
    assert result.get("success") is False
    assert "placeholder" in result["error"]


@pytest.mark.asyncio
async def test_idor_with_placeholder_makes_distinct_requests():
    engine = APISecurityEngine(MagicMock())
    fake = FakeHTTP(_jwt_response(body="x", cookies={}, headers={}))
    engine.http = fake
    result = await engine.test_idor("http://t.com/users/{id}", [1, 2], timeout=2)
    assert result["idor_risk"] is not None
    assert [r["id"] for r in result["results"]] == [1, 2]


@pytest.mark.asyncio
async def test_api_full_scan_isolates_component_failures():
    engine = APISecurityEngine(MagicMock())
    engine.discover_openapi = AsyncMock(return_value={"found": False})
    engine.discover_graphql = AsyncMock(side_effect=RuntimeError("boom"))
    engine.analyze_authentication = AsyncMock(return_value={"url": "http://t.com"})
    engine.infer_endpoints = AsyncMock(return_value={"endpoints": [], "count": 0})
    result = await engine.full_scan("http://t.com")
    assert result["success"] is False
    assert any(e["component"] == "graphql" for e in result["scan_errors"])
    assert result["openapi"] == {"found": False}  # partial results preserved


# ═══════════════════════════════════════════════════════════════════════════
# Dashboard state — bounded event lists
# ═══════════════════════════════════════════════════════════════════════════

def test_broadcast_event_finding_overflow():
    saved = _dashboard_state["findings"]
    try:
        _dashboard_state["findings"] = [{"title": f"f{i}"} for i in range(500)]
        broadcast_event("finding", {"title": "overflow"})
        assert len(_dashboard_state["findings"]) <= 500
        assert _dashboard_state["findings"][-1]["title"] == "overflow"
    finally:
        _dashboard_state["findings"] = saved


def test_broadcast_event_engagement_overflow():
    saved = _dashboard_state["engagements"]
    try:
        _dashboard_state["engagements"] = [{"name": f"e{i}"} for i in range(500)]
        broadcast_event("engagement", {"name": "overflow"})
        assert len(_dashboard_state["engagements"]) <= 500
        assert _dashboard_state["engagements"][-1]["name"] == "overflow"
    finally:
        _dashboard_state["engagements"] = saved
