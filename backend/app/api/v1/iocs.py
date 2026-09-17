"""IOC registry, indicator timeline and provider health endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.deps import (
    get_registry_repository,
    get_virustotal_service,
)
from app.core.exceptions import NotFoundError
from app.repositories.registry_repository import RegistryRepository
from app.schemas.analysis import AnalysisResult
from app.schemas.registry import (
    IOCDetail,
    IOCItem,
    IOCPage,
    ProviderHealthReport,
    ProviderHealthRow,
    SnapshotPoint,
)
from app.services.virustotal_service import VirusTotalService
from app.utils.ioc import canonical_value, primary_type

router = APIRouter(prefix="/iocs", tags=["iocs"])


@router.get("", response_model=IOCPage, summary="List the distinct-IOC inventory")
async def list_iocs(
    registry: Annotated[RegistryRepository, Depends(get_registry_repository)],
    search: str | None = None,
    primary_type: str | None = None,
    limit: int = 25,
    offset: int = 0,
) -> IOCPage:
    rows, total = await registry.list_indicators(
        limit=min(limit, 200),
        offset=offset,
        search=search,
        primary_type=primary_type,
    )
    return IOCPage(
        items=[
            IOCItem(
                id=item.id,
                value=item.value,
                primary_type=item.primary_type,
                observations=item.observations,
                latest_score=item.latest_score,
                latest_level=item.latest_level,
                first_seen_at=item.first_seen_at,
                last_seen_at=item.last_seen_at,
            )
            for item in rows
        ],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{value}",
    response_model=IOCDetail,
    summary="History, timeline and observations of one canonical IOC",
)
async def get_ioc(
    value: str,
    registry: Annotated[RegistryRepository, Depends(get_registry_repository)],
) -> IOCDetail:
    indicator = await registry.get_indicator(value)
    if indicator is None:
        raise NotFoundError(
            "The indicator is not in the registry yet; run an analysis first.",
            code="ioc_not_found",
        )
    timeline = await registry.snapshot_timeline(value)
    analyses = await registry.analyses_for_indicator(value)
    return IOCDetail(
        indicator=IOCItem(
            id=indicator.id,
            value=indicator.value,
            primary_type=indicator.primary_type,
            observations=indicator.observations,
            latest_score=indicator.latest_score,
            latest_level=indicator.latest_level,
            first_seen_at=indicator.first_seen_at,
            last_seen_at=indicator.last_seen_at,
        ),
        observations=indicator.observations,
        timeline=[
            SnapshotPoint(
                analysis_id=item.analysis_id,
                threat_score=item.threat_score,
                threat_level=item.threat_level,
                malicious=item.malicious_count,
                suspicious=item.suspicious_count,
                analyzed_at=item.analyzed_at,
            )
            for item in timeline
        ],
        analyses=[AnalysisResult(**row.payload).model_dump(mode="json") for row in analyses],
    )


@router.get(
    "/{value}/analyses",
    response_model=list[AnalysisResult],
    summary="All stored analyses for one canonical IOC",
)
async def ioc_analyses(
    value: str,
    registry: Annotated[RegistryRepository, Depends(get_registry_repository)],
) -> list[AnalysisResult]:
    rows = await registry.analyses_for_indicator(value)
    if not rows:
        raise NotFoundError(
            "The indicator is not in the registry yet; run an analysis first.",
            code="ioc_not_found",
        )
    return [AnalysisResult(**row.payload) for row in rows]


@router.get(
    "/health/providers",
    response_model=ProviderHealthReport,
    summary="Aggregated provider health from the last 24h of enrichment",
)
async def provider_health(
    registry: Annotated[RegistryRepository, Depends(get_registry_repository)],
    since_hours: int = 24,
) -> ProviderHealthReport:
    usage = await registry.provider_health(since_hours=min(since_hours, 7 * 24))
    grouped: dict[str, list] = {}
    for row in usage:
        grouped.setdefault(row.provider, []).append(row)

    rows: list[ProviderHealthRow] = []
    for provider, entries in sorted(grouped.items()):
        ok_count = sum(1 for entry in entries if entry.ok)
        latencies = [entry.latency_ms for entry in entries if entry.latency_ms is not None]
        last = entries[0]
        rows.append(
            ProviderHealthRow(
                provider=provider,
                ok=last.ok,
                latency_ms=last.latency_ms,
                indicator_type=last.indicator_type,
                error=last.error,
                checked_at=last.checked_at,
                checks=len(entries),
                availability=round(ok_count / len(entries) * 100, 1) if entries else None,
            )
        )
    return ProviderHealthReport(since_hours=since_hours, rows=rows)


@router.get(
    "/health/virustotal",
    summary="VirusTotal API key sanity check",
)
async def virustotal_health(
    virustotal: Annotated[VirusTotalService, Depends(get_virustotal_service)],
) -> dict:
    try:
        ok = await virustotal.ping()
        return {"provider": "virustotal", "ok": ok}
    except Exception as exc:
        return {"provider": "virustotal", "ok": False, "error": str(exc)}