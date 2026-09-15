"""Platform integration tests."""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch

from omega.core.schemas import new_id, now_utc


# ===== Dashboard API Tests =====

from omega.api import dashboard_app


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    return TestClient(dashboard_app)


def test_dashboard_ui_serves(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "OMEGA" in response.text
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

from omega.api import broadcast_event, _dashboard_state


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
