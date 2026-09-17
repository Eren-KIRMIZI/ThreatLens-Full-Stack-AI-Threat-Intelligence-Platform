"""Analysis persistence and lookups.

In-memory cache is unnecessary: every investigation is stored and a fresh
result within the cache TTL satisfies repeat requests. History doubles as
the cache, so nothing is ever evicted from the recent window.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Literal, overload

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.analysis import Analysis, utcnow
from app.schemas.analysis import AnalysisResult

ThreatFilter = Literal["all", "malicious", "suspicious", "clean"]


class AnalysisRepository:
    """Request-scoped data access for analyses."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def find_cached(
        self,
        *,
        indicator: str,
        indicator_type: str,
        cache_ttl_seconds: int,
    ) -> Analysis | None:
        """Return the most recent stored analysis of an indicator newer than the TTL.

        Freshness is measured by ``created_at`` (when we stored the result),
        not ``analyzed_at`` which reflects the VirusTotal report date.
        """
        cutoff = utcnow() - timedelta(seconds=cache_ttl_seconds)
        statement = (
            select(Analysis)
            .where(
                Analysis.indicator == indicator,
                Analysis.indicator_type == indicator_type,
                Analysis.created_at >= cutoff,
            )
            .order_by(Analysis.created_at.desc())
            .limit(1)
        )
        result = await self._session.execute(statement)
        return result.scalar_one_or_none()

    async def get(self, analysis_id: str) -> Analysis | None:
        return await self._session.get(Analysis, analysis_id)

    async def save(self, result: AnalysisResult) -> None:
        """Insert a normalized analysis result as a history row."""
        now = utcnow()
        row = Analysis(
            id=result.analysis_id,
            indicator=result.indicator,
            indicator_type=result.indicator_type,
            meaningful_name=result.metadata.meaningful_name,
            malicious_count=result.stats.malicious,
            suspicious_count=result.stats.suspicious,
            threat_score=result.threat_score,
            threat_level=result.threat_level,
            payload=result.model_dump(mode="json"),
            analyzed_at=result.analyzed_at.replace(tzinfo=None),
            created_at=now,
        )
        self._session.add(row)
        await self._session.commit()

    async def update_payload(self, analysis_id: str, payload: dict) -> None:
        """Rewrite the stored payload (used to attach a later AI interpretation)."""
        row = await self._session.get(Analysis, analysis_id)
        if row is None:
            return
        row.payload = payload
        await self._session.commit()

    async def count_for_indicator(
        self, indicator: str, indicator_type: str
    ) -> int:
        """Total stored analyses for an indicator (rescan history length)."""
        statement = (
            select(func.count())
            .select_from(Analysis)
            .where(
                Analysis.indicator == indicator,
                Analysis.indicator_type == indicator_type,
            )
        )
        return int((await self._session.execute(statement)).scalar_one())

    async def list_history(
        self,
        *,
        limit: int,
        offset: int,
        threat_filter: ThreatFilter = "all",
        search: str | None = None,
    ) -> tuple[list[Analysis], int]:
        """Return a filtered, paginated slice of the history and its total."""
        conditions = []
        if threat_filter == "malicious":
            conditions.append(Analysis.malicious_count > 0)
        elif threat_filter == "suspicious":
            conditions.append(Analysis.malicious_count == 0)
            conditions.append(Analysis.suspicious_count > 0)
        elif threat_filter == "clean":
            conditions.append(Analysis.malicious_count == 0)
            conditions.append(Analysis.suspicious_count == 0)
        if search:
            conditions.append(Analysis.indicator.ilike(f"%{search}%"))

        filters = conditions if conditions else (True,)

        count_statement = (
            select(func.count()).select_from(Analysis).where(*filters)
        )
        total = (await self._session.execute(count_statement)).scalar_one()

        statement = (
            select(Analysis)
            .where(*filters)
            .order_by(Analysis.created_at.desc(), Analysis.id.desc())
            .offset(offset)
            .limit(limit)
        )
        rows = list((await self._session.scalars(statement)).all())
        return rows, total