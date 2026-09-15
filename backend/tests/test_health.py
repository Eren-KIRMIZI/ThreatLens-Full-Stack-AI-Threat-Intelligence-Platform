"""Health endpoint and global error-shape tests."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_returns_ok() -> None:
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["service"] == "threatlens-api"
    assert payload["version"]
    assert payload["environment"] == "development"
    assert payload["checks"] == {"core": "ok"}


def test_root_returns_service_info() -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["service"] == "ThreatLens API"


def test_unknown_route_returns_clean_404() -> None:
    response = client.get("/api/v1/does-not-exist")
    assert response.status_code == 404
    payload = response.json()
    assert payload["error"]["code"] == "not_found"
    assert "stack" not in str(payload).lower()