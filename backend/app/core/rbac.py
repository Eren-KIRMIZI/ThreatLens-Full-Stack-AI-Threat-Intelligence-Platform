"""Lightweight, opt-in role-based access control.

ThreatLens has no user directory by default, so RBAC activates only when
``RBAC_ENABLED=true``. Clients then pass their role in the ``X-ThreatLens-Role``
header (``viewer`` < ``analyst`` < ``admin``). With RBAC disabled every request
is treated as ``admin`` so local development and tests stay frictionless.
"""

from __future__ import annotations

from typing import Callable

from fastapi import Request

from app.core.config import get_settings
from app.core.exceptions import AppException

ROLES = ("viewer", "analyst", "admin")
_ROLE_RANK = {role: index for index, role in enumerate(ROLES)}
ROLE_HEADER = "X-ThreatLens-Role"


def resolve_role(request: Request) -> str:
    """Resolve the caller's role from the header (or the RBAC setting)."""
    if not get_settings().rbac_enabled:
        return "admin"
    raw = request.headers.get(ROLE_HEADER, "").strip().lower()
    if raw not in _ROLE_RANK:
        raise AppException(
            status_code=401,
            code="rbac_missing_role",
            message=(
                f"RBAC is enabled; send a valid {ROLE_HEADER} header "
                f"({', '.join(ROLES)})."
            ),
        )
    return raw


def require_role(minimum: str) -> Callable[[Request], str]:
    """Build a dependency that enforces a minimum role."""

    def dependency(request: Request) -> str:
        role = resolve_role(request)
        if _ROLE_RANK[role] < _ROLE_RANK[minimum]:
            raise AppException(
                status_code=403,
                code="rbac_forbidden",
                message=f"This action requires the {minimum} role or higher.",
            )
        return role

    return dependency