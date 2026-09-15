"""Paginated, filterable analysis history."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from app.api.deps import get_analysis_repository
from app.models.analysis import Analysis
from app.repositories.analysis_repository import AnalysisRepository
from app.schemas.analysis import DetectionStats
from app.schemas.history import HistoryItem, HistoryPage, ThreatFilter

router = APIRouter(prefix="/history", tags=["history"])


def _to_history_item(row: Analysis) -> HistoryItem:
    payload = row.payload
    return HistoryItem(
        analysis_id=row.id,
        indicator=row.indicator,
        indicator_type=row.indicator_type,
        meaningful_name=row.meaningful_name,
        stats=DetectionStats(**payload["stats"]),
        detected_vendors=row.malicious_count,
        threat_score=row.threat_score,
        threat_level=row.threat_level,
        analyzed_at=payload["analyzed_at"],
        created_at=row.created_at,
    )


@router.get(
    "",
    response_model=HistoryPage,
    summary="List stored analyses (history)",
)
async def list_history(
    repository: Annotated[AnalysisRepository, Depends(get_analysis_repository)],
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    offset: Annotated[int, Query(ge=0)] = 0,
    risk: Annotated[ThreatFilter, Query(alias="filter")] = "all",
    search: Annotated[str | None, Query(max_length=2048)] = None,
) -> HistoryPage:
    rows, total = await repository.list_history(
        limit=limit,
        offset=offset,
        threat_filter=risk,
        search=search,
    )
    return HistoryPage(
        items=[_to_history_item(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
        filter=risk,
    )