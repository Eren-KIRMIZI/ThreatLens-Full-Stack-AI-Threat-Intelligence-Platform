"""Watchlist, alert rules, alert inbox and rescan endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.deps import (
    get_analysis_service,
    get_registry_repository,
    get_watchlist_repository,
)
from app.core.exceptions import NotFoundError
from app.core.rbac import require_role
from app.repositories.registry_repository import RegistryRepository
from app.repositories.watchlist_repository import WatchlistRepository
from app.schemas.watchlist import (
    AlertOut,
    AlertsPage,
    RescanOutcome,
    RescanReport,
    RuleIn,
    RuleOut,
    WatchlistCreate,
    WatchlistItemOut,
    WatchlistPage,
)
from app.services.alert_engine import SUPPORTED_CONDITIONS
from app.services.analysis_service import AnalysisService
from app.services.rescan_service import RescanService
from app.utils.ioc import canonical_value

router = APIRouter(prefix="/watchlist", tags=["watchlist"])


def _build_rescan(
    analysis: Annotated[AnalysisService, Depends(get_analysis_service)],
    watchlist: Annotated[WatchlistRepository, Depends(get_watchlist_repository)],
    registry: Annotated[RegistryRepository, Depends(get_registry_repository)],
) -> RescanService:
    return RescanService(analysis, watchlist, registry)


@router.get("", response_model=WatchlistPage, summary="List watchlist items")
async def list_watchlist(
    repository: Annotated[WatchlistRepository, Depends(get_watchlist_repository)],
    enabled_only: bool = False,
    limit: int = 50,
    offset: int = 0,
) -> WatchlistPage:
    rows, total = await repository.list(
        limit=min(limit, 200), offset=offset, enabled_only=enabled_only
    )
    return WatchlistPage(
        items=[WatchlistItemOut(**row.__dict__) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
        enabled_only=enabled_only,
    )


@router.post("", response_model=WatchlistItemOut, status_code=201)
async def add_watchlist(
    body: WatchlistCreate,
    repository: Annotated[WatchlistRepository, Depends(get_watchlist_repository)],
) -> WatchlistItemOut:
    row = await repository.add(
        value=canonical_value(body.primary_type, body.value) or body.value,
        primary_type=body.primary_type,
        enabled=body.enabled,
    )
    return WatchlistItemOut(**row.__dict__)


@router.delete("/{watchlist_id}", status_code=204)
async def remove_watchlist(
    watchlist_id: str,
    repository: Annotated[WatchlistRepository, Depends(get_watchlist_repository)],
) -> None:
    if not await repository.remove(watchlist_id):
        raise NotFoundError(
            "The watchlist item was not found.", code="watchlist_not_found"
        )


@router.patch("/{watchlist_id}", response_model=WatchlistItemOut)
async def set_watchlist_enabled(
    watchlist_id: str,
    enabled: bool,
    repository: Annotated[WatchlistRepository, Depends(get_watchlist_repository)],
) -> WatchlistItemOut:
    row = await repository.set_enabled(watchlist_id, enabled)
    if row is None:
        raise NotFoundError(
            "The watchlist item was not found.", code="watchlist_not_found"
        )
    return WatchlistItemOut(**row.__dict__)


# --- rescan ------------------------------------------------------------------ #


@router.post(
    "/rescan/all",
    response_model=RescanReport,
    summary="Force re-analysis of every enabled watchlist item",
)
async def rescan_all(
    rescan: Annotated[RescanService, Depends(_build_rescan)],
    _role: Annotated[str, Depends(require_role("admin"))],
) -> RescanReport:
    return await rescan.rescan_all()


@router.post("/{watchlist_id}/rescan", response_model=RescanOutcome)
async def rescan_one(
    watchlist_id: str,
    rescan: Annotated[RescanService, Depends(_build_rescan)],
) -> RescanOutcome:
    outcome = await rescan.rescan_one(watchlist_id)
    if outcome is None:
        raise NotFoundError(
            "The watchlist item was not found or is disabled.",
            code="watchlist_not_found",
        )
    return outcome


# --- alert rules -------------------------------------------------------------- #


@router.get("/rules", response_model=list[RuleOut])
async def list_rules(
    repository: Annotated[WatchlistRepository, Depends(get_watchlist_repository)],
) -> list[RuleOut]:
    rows = await repository.list_rules()
    return [
        RuleOut(id=r.id, name=r.name, condition=r.condition, threshold=r.threshold, enabled=r.enabled)
        for r in rows
    ]


@router.post("/rules", response_model=RuleOut, status_code=201)
async def upsert_rule(
    body: RuleIn,
    repository: Annotated[WatchlistRepository, Depends(get_watchlist_repository)],
) -> RuleOut:
    if body.condition not in SUPPORTED_CONDITIONS:
        from app.core.exceptions import AppException

        raise AppException(
            status_code=422,
            code="invalid_rule_condition",
            message=f"Unsupported condition {body.condition!r}; "
            f"expected one of {', '.join(sorted(SUPPORTED_CONDITIONS))}.",
        )
    row = await repository.upsert_rule(
        rule_id=body.id,
        name=body.name,
        condition=body.condition,
        threshold=body.threshold,
        enabled=body.enabled,
    )
    return RuleOut(id=row.id, name=row.name, condition=row.condition, threshold=row.threshold, enabled=row.enabled)


@router.delete("/rules/{rule_id}", status_code=204)
async def delete_rule(
    rule_id: str,
    repository: Annotated[WatchlistRepository, Depends(get_watchlist_repository)],
    _role: Annotated[str, Depends(require_role("admin"))],
) -> None:
    if not await repository.delete_rule(rule_id):
        raise NotFoundError("The alert rule was not found.", code="rule_not_found")


# --- alerts ------------------------------------------------------------------- #


@router.get("/alerts", response_model=AlertsPage)
async def list_alerts(
    repository: Annotated[WatchlistRepository, Depends(get_watchlist_repository)],
    unseen_only: bool = False,
    limit: int = 50,
    offset: int = 0,
) -> AlertsPage:
    rows, total = await repository.list_alerts(
        limit=min(limit, 200), offset=offset, unseen_only=unseen_only
    )
    return AlertsPage(
        items=[AlertOut(**row.__dict__) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
        unseen_only=unseen_only,
    )


@router.post("/alerts/mark-seen", response_model=dict)
async def mark_alerts_seen(
    repository: Annotated[WatchlistRepository, Depends(get_watchlist_repository)],
) -> dict:
    await repository.mark_all_seen()
    return {"seen": True}