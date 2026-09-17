"""Weekly digest + platform-wide search."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.analysis import Analysis, utcnow
from app.models.alerts import Alert
from app.models.ioc import DistinctIndicator
from app.schemas.digest import DigestOut, DigestSection, SearchResponse, SearchResult


async def build_digest(session: AsyncSession, window: str = "week") -> DigestOut:
    """Aggregate the last period's activity into an analyst-facing digest."""
    hours = {"week": 24 * 7, "day": 24, "month": 24 * 30}.get(window, 24 * 7)
    cutoff = utcnow() - timedelta(hours=hours)

    analyzed = (
        await session.execute(
            select(func.count())
            .select_from(Analysis)
            .where(Analysis.created_at >= cutoff)
        )
    ).scalar_one()

    critical = (
        await session.execute(
            select(func.count())
            .select_from(Analysis)
            .where(
                Analysis.created_at >= cutoff,
                Analysis.threat_level == "critical",
            )
        )
    ).scalar_one()

    distinct_iocs = (
        await session.execute(
            select(func.count()).select_from(DistinctIndicator)
        )
    ).scalar_one()

    alerts = (
        await session.execute(
            select(func.count())
            .select_from(Alert)
            .where(Alert.triggered_at >= cutoff)
        )
    ).scalar_one()

    hot_recent = (
        await session.execute(
            select(DistinctIndicator)
            .order_by(DistinctIndicator.last_seen_at.desc())
            .limit(5)
        )
    ).scalars().all()

    sections: list[DigestSection] = [
        DigestSection(label=f"Analyses in the last {window}", value=str(analyzed)),
        DigestSection(label="Critical findings", value=str(critical)),
        DigestSection(label="Distinct IOCs tracked", value=str(distinct_iocs)),
        DigestSection(label="Alerts triggered", value=str(alerts)),
    ]
    if hot_recent:
        top = ", ".join(item.value for item in hot_recent[:3])
        sections.append(DigestSection(label="Most recently observed", value=top))

    return DigestOut(period=window, sections=sections)


async def global_search(session: AsyncSession, query: str, *, limit: int = 25) -> SearchResponse:
    """Search analyses (indicator / meaningful name) and the IOC registry."""
    needle = f"%{query.strip()}%"
    functions = []

    analysis_stmt = (
        select(Analysis)
        .where(
            or_(
                Analysis.indicator.ilike(needle),
                Analysis.meaningful_name.ilike(needle),
            )
        )
        .order_by(Analysis.created_at.desc())
        .limit(limit)
    )
    for row in (await session.scalars(analysis_stmt)).all():
        functions.append(
            SearchResult(
                kind="analysis",
                id=row.id,
                title=row.indicator,
                subtitle=row.meaningful_name or row.indicator_type,
                score=row.threat_score,
                level=row.threat_level,
                analyzed_at=row.analyzed_at,
            )
        )

    ioc_stmt = (
        select(DistinctIndicator)
        .where(DistinctIndicator.value.ilike(needle))
        .order_by(DistinctIndicator.last_seen_at.desc())
        .limit(limit)
    )
    for row in (await session.scalars(ioc_stmt)).all():
        functions.append(
            SearchResult(
                kind="ioc",
                id=row.id,
                title=row.value,
                subtitle=row.primary_type,
                score=row.latest_score,
                level=row.latest_level,
            )
        )

    functions.sort(key=lambda item: item.score or 0, reverse=True)
    return SearchResponse(query=query, total=len(functions), results=functions[:limit])