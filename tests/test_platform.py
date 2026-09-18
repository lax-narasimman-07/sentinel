"""Platform integration tests."""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch

from sentinel.core.schemas import new_id, now_utc


# ===== Dashboard API Tests =====

from sentinel.api import dashboard_app


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    return TestClient(dashboard_app)


def test_dashboard_ui_serves(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "SENTINEL" in response.text
    assert "Security" in response.text


def test_dashboard_ui_contains_react(client):
    response = client.get("/")
    assert "react" in response.text.lower()


def test_dashboard_api_system(client):
    response = client.get("/api/system")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert data["status"] == "running"


def test_dashboard_api_create_engagement(client):
    response = client.post(
        "/api/engagements",
        json={"name": "test", "target": "example.com", "mode": "bug_bounty"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "test"
    assert data["target"] == "example.com"
    assert data["mode"] == "bug_bounty"
    assert "id" in data


def test_dashboard_api_create_and_list_engagements(client):
    client.post("/api/engagements", json={"name": "e1", "target": "a.com", "mode": "ctf"})
    client.post("/api/engagements", json={"name": "e2", "target": "b.com", "mode": "pentest"})
    response = client.get("/api/engagements")
    assert response.status_code == 200
    engagements = response.json()["engagements"]
    assert len(engagements) >= 2
    names = [e["name"] for e in engagements]
    assert "e1" in names
    assert "e2" in names


def test_dashboard_api_stop_engagement(client):
    create_resp = client.post(
        "/api/engagements",
        json={"name": "stop-test", "target": "test.com", "mode": "ctf"},
    )
    eng_id = create_resp.json()["id"]
    stop_resp = client.post(f"/api/engagements/{eng_id}/stop")
    assert stop_resp.status_code == 200
    assert stop_resp.json()["status"] == "completed"


def test_dashboard_api_create_multiple_stop_first(client):
    r1 = client.post("/api/engagements", json={"name": "first", "target": "a.com", "mode": "ctf"})
    r2 = client.post("/api/engagements", json={"name": "second", "target": "b.com", "mode": "ctf"})
    id1 = r1.json()["id"]
    id2 = r2.json()["id"]
    client.post(f"/api/engagements/{id1}/stop")
    resp = client.get("/api/engagements")
    engs = resp.json()["engagements"]
    first = next(e for e in engs if e["id"] == id1)
    second = next(e for e in engs if e["id"] == id2)
    assert first["status"] == "completed"
    assert second["status"] == "active"


def test_dashboard_api_tools(client):
    response = client.get("/api/tools")
    assert response.status_code == 200
    data = response.json()
    assert "tools" in data


def test_dashboard_api_findings(client):
    response = client.get("/api/findings")
    assert response.status_code == 200


def test_dashboard_api_evidence(client):
    response = client.get("/api/evidence")
    assert response.status_code == 200


# ===== Broadcast Event Tests =====

from sentinel.api import broadcast_event, _dashboard_state


def test_broadcast_event_finding():
    initial_len = len(_dashboard_state["findings"])
    broadcast_event("finding", {"title": "test finding", "severity": "high"})
    assert len(_dashboard_state["findings"]) == initial_len + 1
    assert _dashboard_state["findings"][-1]["title"] == "test finding"


def test_broadcast_event_log():
    initial_len = len(_dashboard_state["logs"])
    broadcast_event("log", {"level": "info", "message": "test log"})
    assert len(_dashboard_state["logs"]) == initial_len + 1


def test_broadcast_event_engagement():
    initial_len = len(_dashboard_state["engagements"])
    broadcast_event("engagement", {"name": "broadcast eng"})
    assert len(_dashboard_state["engagements"]) == initial_len + 1


def test_broadcast_event_log_overflow():
    _dashboard_state["logs"] = [{"level": "info", "message": f"log{i}"} for i in range(500)]
    broadcast_event("log", {"level": "error", "message": "overflow"})
    assert len(_dashboard_state["logs"]) <= 500


def test_broadcast_event_unknown_type():
    initial = len(_dashboard_state["findings"])
    broadcast_event("unknown_type", {"data": "value"})
    assert len(_dashboard_state["findings"]) == initial


# ===== API Scope-Gating Tests (Phase 2 follow-up) =====


import pytest as _pytest
from unittest.mock import AsyncMock, patch as _patch


def _make_engagement(client, name: str, mode: str = "pentest") -> str:
    r = client.post("/api/engagements", json={"name": name, "target": "test.local", "mode": mode})
    return r.json()["id"]


def test_api_web_tech_denied_no_scope(client):
    """Passive live-target endpoint denies when engagement has no scope rules."""
    eid = _make_engagement(client, "gate-pentest-web-tech")
    r = client.post("/api/web/tech", json={"url": "http://web.example.com", "engagement_id": eid})
    assert r.status_code == 403
    assert "scope" in r.json()["detail"].lower()


def test_api_web_full_scan_denied_analysis_only(client):
    """Active web/full-scan denied under analysis_only (observation-only)."""
    eid = _make_engagement(client, "gate-analysis-fullscan", "analysis_only")
    with _patch("sentinel.api.routes._get_web_engine") as get_web:
        web_mock = AsyncMock()
        web_mock.full_scan = AsyncMock(return_value={})
        get_web.return_value = web_mock
        r = client.post("/api/web/full-scan", json={"target": "http://scan.example.com", "engagement_id": eid})
    assert r.status_code == 403
    assert "scope" in r.json()["detail"].lower()


def test_api_web_tech_allowed_analysis_only(client):
    """Passive web/tech proceeds under analysis_only (observation-only)."""
    eid = _make_engagement(client, "gate-analysis-web-tech", "analysis_only")
    with _patch("sentinel.api.routes._get_web_engine") as get_web:
        web_mock = AsyncMock()
        web_mock.detect_technologies = AsyncMock(return_value={"tech": []})
        get_web.return_value = web_mock
        r = client.post("/api/web/tech", json={"url": "http://tech.example.com", "engagement_id": eid})
    assert r.status_code == 200
    web_mock.detect_technologies.assert_awaited_once()


def test_api_http_request_denied_no_scope(client):
    """GET via API http/request denies without scope rules."""
    eid = _make_engagement(client, "gate-pentest-http")
    r = client.post("/api/http/request", json={"method": "GET", "url": "http://api.example.com/x", "engagement_id": eid})
    assert r.status_code == 403
    assert "scope" in r.json()["detail"].lower()


def test_api_http_request_ungated_without_engagement(client):
    """http/request without engagement_id runs open-world (no gate)."""
    with _patch("sentinel.api.routes._get_http_client") as get_http:
        http_mock = AsyncMock()
        http_mock.request = AsyncMock(return_value={"status_code": 200, "body": "", "body_length": 0})
        get_http.return_value = http_mock
        r = client.post("/api/http/request", json={"method": "GET", "url": "http://open.example.com/"})
    assert r.status_code == 200
    http_mock.request.assert_awaited_once()


def test_api_auth_diff_test_denied_no_scope(client):
    """auth/diff-test fires two requests; gate denies both for out-of-scope."""
    eid = _make_engagement(client, "gate-pentest-diff")
    r = client.post("/api/auth/diff-test", json={
        "url_a": "http://a.example.com/profile",
        "url_b": "http://b.example.com/profile",
        "engagement_id": eid,
    })
    assert r.status_code == 403
    assert "scope" in r.json()["detail"].lower()


def test_api_auth_diff_test_ungated_without_engagement(client):
    """auth/diff-test without engagement_id runs open-world."""
    with _patch("sentinel.api.routes._get_http_client") as get_http:
        http_mock = AsyncMock()
        http_mock.request = AsyncMock(return_value={"status_code": 200, "body_length": 10})
        get_http.return_value = http_mock
        r = client.post("/api/auth/diff-test", json={
            "url_a": "http://a.example.com/",
            "url_b": "http://b.example.com/",
        })
    assert r.status_code == 200
    assert r.json()["status_match"]


def test_api_http_post_denied_active_risk(client):
    """POST via http/request treated as active risk; denies for pentest with no rules."""
    eid = _make_engagement(client, "gate-pentest-http-post")
    r = client.post("/api/http/request", json={"method": "POST", "url": "http://api.example.com/data", "engagement_id": eid})
    assert r.status_code == 403


def test_api_idor_denied_no_scope(client):
    """API security IDOR test is active; denies without scope rules."""
    eid = _make_engagement(client, "gate-pentest-idor")
    r = client.post("/api/api-security/idor", json={
        "url_pattern": "http://api.example.com/users/{id}",
        "id_values": ["1", "2"], "engagement_id": eid,
    })
    assert r.status_code == 403
