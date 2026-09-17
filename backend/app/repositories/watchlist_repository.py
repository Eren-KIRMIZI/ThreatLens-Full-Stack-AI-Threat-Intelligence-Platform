"""Watchlist, alert rules and generated alerts data access."""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alerts import Alert, AlertRule
from app.models.watchlist import WatchlistItem
from app.models.analysis import utcnow


class WatchlistRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    # --- watchlist ------------------------------------------------------------- #

    async def add(
        self, *, value: str, primary_type: str, enabled: bool = True
    ) -> WatchlistItem:
        existing = (
            await self._session.execute(
                select(WatchlistItem).where(WatchlistItem.value == value)
            )
        ).scalar_one_or_none()
        if existing is not None:
            existing.enabled = enabled
            await self._session.commit()
            return existing
        row = WatchlistItem(
            id=str(uuid.uuid4()),
            value=value,
            primary_type=primary_type,
            enabled=enabled,
        )
        self._session.add(row)
        await self._session.commit()
        return row

    async def remove(self, watchlist_id: str) -> bool:
        row = await self._session.get(WatchlistItem, watchlist_id)
        if row is None:
            return False
        await self._session.delete(row)
        await self._session.commit()
        return True

    async def get(self, watchlist_id: str) -> WatchlistItem | None:
        return await self._session.get(WatchlistItem, watchlist_id)

    async def set_enabled(self, watchlist_id: str, enabled: bool) -> WatchlistItem | None:
        row = await self._session.get(WatchlistItem, watchlist_id)
        if row is None:
            return None
        row.enabled = enabled
        await self._session.commit()
        return row

    async def list(self, *, limit: int, offset: int, enabled_only: bool = False):
        conditions = [WatchlistItem.enabled.is_(True)] if enabled_only else [True]
        total = (
            await self._session.execute(
                select(func.count()).select_from(WatchlistItem).where(*conditions)
            )
        ).scalar_one()
        statement = (
            select(WatchlistItem)
            .where(*conditions)
            .order_by(WatchlistItem.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        rows = list((await self._session.scalars(statement)).all())
        return rows, total

    async def enabled_items(self) -> list[WatchlistItem]:
        statement = select(WatchlistItem).where(WatchlistItem.enabled.is_(True))
        return list((await self._session.scalars(statement)).all())

    async def mark_checked(self, watchlist_id: str) -> None:
        row = await self._session.get(WatchlistItem, watchlist_id)
        if row is not None:
            row.last_checked_at = utcnow()
            await self._session.commit()

    # --- alert rules ------------------------------------------------------------ #

    async def list_rules(self) -> list[AlertRule]:
        statement = select(AlertRule).order_by(AlertRule.name)
        return list((await self._session.scalars(statement)).all())

    async def upsert_rule(
        self,
        *,
        rule_id: str | None,
        name: str,
        condition: str,
        threshold: int,
        enabled: bool,
    ) -> AlertRule:
        if rule_id:
            row = await self._session.get(AlertRule, rule_id)
            if row is not None:
                row.name = name
                row.condition = condition
                row.threshold = threshold
                row.enabled = enabled
                await self._session.commit()
                return row
        row = AlertRule(
            id=rule_id or str(uuid.uuid4()),
            name=name,
            condition=condition,
            threshold=threshold,
            enabled=enabled,
        )
        self._session.add(row)
        await self._session.commit()
        return row

    async def delete_rule(self, rule_id: str) -> bool:
        row = await self._session.get(AlertRule, rule_id)
        if row is None:
            return False
        await self._session.delete(row)
        await self._session.commit()
        return True

    # --- alerts ---------------------------------------------------------------- #

    async def create_alert(
        self,
        *,
        watchlist_id: str,
        rule_id: str | None,
        analysis_id: str | None,
        indicator: str,
        level: str,
        message: str,
    ) -> Alert:
        row = Alert(
            id=str(uuid.uuid4()),
            watchlist_id=watchlist_id,
            rule_id=rule_id,
            analysis_id=analysis_id,
            indicator=indicator,
            level=level,
            message=message,
        )
        self._session.add(row)
        await self._session.commit()
        return row

    async def list_alerts(
        self, *, limit: int, offset: int, unseen_only: bool = False
    ) -> tuple[list[Alert], int]:
        conditions = [Alert.seen.is_(False)] if unseen_only else [True]
        total = (
            await self._session.execute(
                select(func.count()).select_from(Alert).where(*conditions)
            )
        ).scalar_one()
        statement = (
            select(Alert)
            .where(*conditions)
            .order_by(Alert.triggered_at.desc())
            .offset(offset)
            .limit(limit)
        )
        rows = list((await self._session.scalars(statement)).all())
        return rows, total

    async def mark_all_seen(self) -> None:
        rows = await self._session.execute(
            select(Alert).where(Alert.seen.is_(False))
        )
        for row in rows.scalars().all():
            row.seen = True
        await self._session.commit()