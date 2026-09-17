"""Unit tests for the opt-in RBAC helper."""

from __future__ import annotations

from starlette.requests import Request

from app.core.exceptions import AppException
from app.core.rbac import require_role, resolve_role


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