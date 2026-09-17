"""IOC registry + snapshots + provider telemetry data access.

The registry is the dedup layer: every completed analysis upserts a
distinct-canonical indicator row and appends an immutable snapshot. Queries
here power the IOC inventory, per-indicator timeline and provider health UI.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.analysis import Analysis, utcnow
from app.models.ioc import DistinctIndicator, IndicatorSnapshot, ProviderUsage
from app.schemas.analysis import AnalysisResult


def _uuid() -> str:
    import uuid

    return str(uuid.uuid4())


class RegistryRepository:
    """Request-scoped data access for the IOC registry."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    # --- dedup / snapshot write path (called after every analysis) ---------- #

    async def record_analysis(self, result: AnalysisResult) -> None:
        """Upsert the distinct-indicator row and append an immutable snapshot."""
        now = utcnow()
        value = result.indicator
        primary_type = result.indicator_type
        row: DistinctIndicator | None = await self._session.execute(
            select(DistinctIndicator).where(DistinctIndicator.value == value)
        )
        indicator = row.scalar_one_or_none()
        if indicator is None:
            indicator = DistinctIndicator(
                id=_uuid(),
                value=value,
                primary_type=primary_type,
                observations=0,
                first_seen_at=now,
                last_seen_at=now,
            )
            self._session.add(indicator)
        indicator.observations += 1
        indicator.last_seen_at = now
        if result.threat_score is not None:
            indicator.latest_score = result.threat_score
            indicator.latest_level = result.threat_level

        snapshot = IndicatorSnapshot(
            id=_uuid(),
            value=value,
            primary_type=primary_type,
            analysis_id=result.analysis_id,
            threat_score=result.threat_score,
            threat_level=result.threat_level,
            malicious_count=result.stats.malicious,
            suspicious_count=result.stats.suspicious,
            analyzed_at=result.analyzed_at.replace(tzinfo=None),
        )
        self._session.add(snapshot)
        await self._session.commit()

    async def record_provider_usage(self, provider: str, **fields: Any) -> None:
        row = ProviderUsage(
            id=_uuid(),
            provider=provider,
            indicator_type=fields.get("indicator_type"),
            ok=bool(fields.get("ok", True)),
            latency_ms=fields.get("latency_ms"),
            error=fields.get("error"),
        )
        self._session.add(row)
        await self._session.commit()

    # --- IOC inventory ------------------------------------------------------ #

    async def list_indicators(
        self,
        *,
        limit: int,
        offset: int,
        search: str | None = None,
        primary_type: str | None = None,
    ) -> tuple[list[DistinctIndicator], int]:
        conditions = []
        if search:
            conditions.append(DistinctIndicator.value.ilike(f"%{search}%"))
        if primary_type:
            conditions.append(DistinctIndicator.primary_type == primary_type)
        filters = conditions if conditions else (True,)

        total = (
            await self._session.execute(
                select(func.count())
                .select_from(DistinctIndicator)
                .where(*filters)
            )
        ).scalar_one()
        statement = (
            select(DistinctIndicator)
            .where(*filters)
            .order_by(DistinctIndicator.last_seen_at.desc())
            .offset(offset)
            .limit(limit)
        )
        rows = list((await self._session.scalars(statement)).all())
        return rows, total

    async def get_indicator(self, canonical_value: str) -> DistinctIndicator | None:
        return (
            await self._session.execute(
                select(DistinctIndicator).where(
                    DistinctIndicator.value == canonical_value
                )
            )
        ).scalar_one_or_none()

    async def snapshot_timeline(
        self, canonical_value: str, *, limit: int = 200
    ) -> list[IndicatorSnapshot]:
        statement = (
            select(IndicatorSnapshot)
            .where(IndicatorSnapshot.value == canonical_value)
            .order_by(IndicatorSnapshot.analyzed_at.desc(), IndicatorSnapshot.created_at.desc())
            .limit(limit)
        )
        return list((await self._session.scalars(statement)).all())

    async def analyses_for_indicator(
        self, canonical_value: str, *, limit: int = 50
    ) -> list[Analysis]:
        statement = (
            select(Analysis)
            .where(Analysis.indicator == canonical_value)
            .order_by(Analysis.created_at.desc())
            .limit(limit)
        )
        return list((await self._session.scalars(statement)).all())

    # --- provider health ---------------------------------------------------- #

    async def provider_health(
        self, *, since_hours: int = 24, limit_per_provider: int = 200
    ) -> list[ProviderUsage]:
        cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - __import__(
            "datetime", fromlist=["timedelta"]
        ).timedelta(hours=since_hours)
        statement = (
            select(ProviderUsage)
            .where(ProviderUsage.checked_at >= cutoff)
            .order_by(ProviderUsage.checked_at.desc())
            .limit(limit_per_provider)
        )
        return list((await self._session.scalars(statement)).all())