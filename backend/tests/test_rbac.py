"""Unit tests for the opt-in RBAC helper."""

from __future__ import annotations

import httpx
from fastapi.testclient import TestClient
from starlette.requests import Request

from app.core.exceptions import AppException
from app.core.rbac import require_role, resolve_role
from app.main import app

client = TestClient(app)

VIEWER = {"X-ThreatLens-Role": "viewer"}
ANALYST = {"X-ThreatLens-Role": "analyst"}
ADMIN = {"X-ThreatLens-Role": "admin"}


def _request(headers: dict[str, str] | None = None) -> Request:
    raw = [(key.lower().encode(), value.encode()) for key, value in (headers or {}).items()]
    return Request({"type": "http", "headers": raw, "method": "GET", "path": "/"})


def test_disabled_rbac_grants_admin(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.core.rbac.get_settings", lambda: type("S", (), {"rbac_enabled": False})()
    )
    assert resolve_role(_request()) == "admin"
    assert require_role("admin")(_request()) == "admin"


def test_enabled_rbac_reads_header_and_enforces_rank(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.core.rbac.get_settings", lambda: type("S", (), {"rbac_enabled": True})()
    )
    assert resolve_role(_request({"X-ThreatLens-Role": "analyst"})) == "analyst"
    assert require_role("analyst")(_request({"X-ThreatLens-Role": "admin"})) == "admin"

    try:
        require_role("admin")(_request({"X-ThreatLens-Role": "viewer"}))
    except AppException as exc:
        assert exc.status_code == 403
    else:  # pragma: no cover - defensive
        raise AssertionError("viewer must not satisfy the admin requirement")


def test_enabled_rbac_rejects_missing_or_invalid_role(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.core.rbac.get_settings", lambda: type("S", (), {"rbac_enabled": True})()
    )
    for headers in ({}, {"X-ThreatLens-Role": "root"}):
        try:
            resolve_role(_request(headers))
        except AppException as exc:
            assert exc.status_code == 401
        else:  # pragma: no cover - defensive
            raise AssertionError("missing/invalid role must be rejected")


def _install_vt_mock() -> None:
    from app.services.virustotal_service import VirusTotalService

    report = {
        "data": {
            "id": "d" * 64,
            "type": "file",
            "attributes": {
                "sha256": "d" * 64,
                "sha1": "e" * 40,
                "md5": "f" * 32,
                "reputation": -5,
                "tags": ["peexe"],
                "threat_names": ["Trojan"],
                "total_votes": {"harmless": 0, "malicious": 2},
                "first_submission_date": 1700000000,
                "last_analysis_date": 1700000001,
                "last_analysis_stats": {
                    "harmless": 1,
                    "malicious": 6,
                    "suspicious": 1,
                    "undetected": 1,
                    "timeout": 0,
                },
                "last_analysis_results": {},
            },
        }
    }
    app.state.virustotal_service = VirusTotalService(
        api_key="test-key",
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json=report)),
    )


def test_endpoint_matrix_enforces_roles(monkeypatch) -> None:
    """viewer < analyst < admin across reads, writes, analyze and admin routes."""
    monkeypatch.setattr(
        "app.core.rbac.get_settings", lambda: type("S", (), {"rbac_enabled": True})()
    )

    # Reads stay open to every authenticated role.
    assert client.get("/api/v1/iocs", headers=VIEWER).status_code == 200
    assert client.get("/api/v1/history", headers=VIEWER).status_code == 200

    # Analyze endpoints require analyst (viewer read-only, missing header 401).
    payload = {"hash": "d" * 64}
    assert client.post("/api/v1/analyze/hash", json=payload, headers=VIEWER).status_code == 403
    assert client.post("/api/v1/analyze/hash", json=payload, headers={"X-ThreatLens-Role": "root"}).status_code == 401

    # Write endpoints require analyst.
    watch_body = {"value": "8.8.8.8", "primary_type": "IP"}
    assert client.post("/api/v1/watchlist", json=watch_body, headers=VIEWER).status_code == 403
    created_watch = client.post("/api/v1/watchlist", json=watch_body, headers=ANALYST)
    assert created_watch.status_code == 201, created_watch.text
    watch_id = created_watch.json()["id"]

    rule_body = {"name": "score>=50", "condition": "score_ge", "threshold": 50}
    assert client.post("/api/v1/watchlist/rules", json=rule_body, headers=VIEWER).status_code == 403
    created_rule = client.post("/api/v1/watchlist/rules", json=rule_body, headers=ADMIN)
    assert created_rule.status_code == 201, created_rule.text
    rule_id = created_rule.json()["id"]

    assert client.delete(f"/api/v1/watchlist/rules/{rule_id}", headers=ANALYST).status_code == 403
    assert client.delete(f"/api/v1/watchlist/rules/{rule_id}", headers=ADMIN).status_code == 204

    assert client.post("/api/v1/watchlist/alerts/mark-seen", headers=VIEWER).status_code == 403
    assert client.post("/api/v1/watchlist/alerts/mark-seen", headers=ANALYST).status_code == 200

    # Per-item rescan: analyst allowed, but full rescan stays admin-only.
    _install_vt_mock()
    assert client.post(f"/api/v1/watchlist/{watch_id}/rescan", headers=VIEWER).status_code == 403
    rescanned = client.post(f"/api/v1/watchlist/{watch_id}/rescan", headers=ANALYST)
    assert rescanned.status_code == 200, rescanned.text
    assert client.post("/api/v1/watchlist/rescan/all", headers=ANALYST).status_code == 403
    assert client.post("/api/v1/watchlist/rescan/all", headers=ADMIN).status_code == 200

    # Investigation writes require analyst; only admin may delete a case.
    case_body = {"title": "rbac case", "severity": "low"}
    assert client.post("/api/v1/investigations", json=case_body, headers=VIEWER).status_code == 403
    created_case = client.post("/api/v1/investigations", json=case_body, headers=ANALYST)
    assert created_case.status_code == 201, created_case.text
    case_id = created_case.json()["id"]
    assert client.patch(f"/api/v1/investigations/{case_id}", json={"status": "active"}, headers=VIEWER).status_code == 403
    assert client.delete(f"/api/v1/investigations/{case_id}", headers=ANALYST).status_code == 403
    assert client.delete(f"/api/v1/investigations/{case_id}", headers=ADMIN).status_code == 204