"""Service health endpoint."""

from datetime import datetime, timezone

from fastapi import APIRouter

from app.core.config import get_settings
from app.schemas.health import HealthResponse

router = APIRouter()

_STARTED_AT = datetime.now(timezone.utc)


@router.get("/health", response_model=HealthResponse, tags=["health"])
async def health_check() -> HealthResponse:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    return HealthResponse(
        status="ok",
        service="threatlens-api",
        version=settings.app_version,
        environment=settings.environment,
        timestamp=now,
        uptime_seconds=round((now - _STARTED_AT).total_seconds(), 2),
        checks={"core": "ok"},
    )