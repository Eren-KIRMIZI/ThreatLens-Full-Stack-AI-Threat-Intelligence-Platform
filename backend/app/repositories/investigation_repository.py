"""Investigation (case) management data access.

A case groups indicators/analyses, with analyst notes and tags attached at the
analysis level. Pinning surfaces favorite analyses on the dashboard.
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.investigations import (
    AnalysisNote,
    AnalysisTag,
    Investigation,
    InvestigationItem,
    PinnedAnalysis,
)


class InvestigationRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    # --- cases --------------------------------------------------------------- #

    async def create(
        self,
        *,
        title: str,
        description: str | None,
        status: str,
        severity: str,
    ) -> Investigation:
        row = Investigation(
            id=str(uuid.uuid4()),
            title=title,
            description=description,
            status=status,
            severity=severity,
        )
        self._session.add(row)
        await self._session.commit()
        return row

    async def update_core(
        self, investigation_id: str, **fields: str | None
    ) -> Investigation | None:
        row = await self._session.get(Investigation, investigation_id)
        if row is None:
            return None
        for key, value in fields.items():
            if key in {"title", "description", "status", "severity"} and value is not None:
                setattr(row, key, value)
        await self._session.commit()
        return row

    async def delete(self, investigation_id: str) -> bool:
        row = await self._session.get(Investigation, investigation_id)
        if row is None:
            return False
        items = await self._session.execute(
            select(InvestigationItem).where(
                InvestigationItem.investigation_id == investigation_id
            )
        )
        for item in items.scalars().all():
            await self._session.delete(item)
        await self._session.delete(row)
        await self._session.commit()
        return True

    async def list(self, *, limit: int, offset: int, status: str | None = None):
        conditions = [Investigation.status == status] if status else [True]
        total = (
            await self._session.execute(
                select(func.count()).select_from(Investigation).where(*conditions)
            )
        ).scalar_one()
        statement = (
            select(Investigation)
            .where(*conditions)
            .order_by(Investigation.updated_at.desc())
            .offset(offset)
            .limit(limit)
        )
        rows = list((await self._session.scalars(statement)).all())
        return rows, total

    async def get(self, investigation_id: str) -> Investigation | None:
        return await self._session.get(Investigation, investigation_id)

    async def add_item(
        self,
        *,
        investigation_id: str,
        value: str,
        primary_type: str,
        analysis_id: str | None,
    ) -> InvestigationItem | None:
        case = await self._session.get(Investigation, investigation_id)
        if case is None:
            return None
        row = InvestigationItem(
            id=str(uuid.uuid4()),
            investigation_id=investigation_id,
            value=value,
            primary_type=primary_type,
            analysis_id=analysis_id,
        )
        self._session.add(row)
        await self._session.commit()
        return row

    async def items(self, investigation_id: str) -> list[InvestigationItem]:
        statement = (
            select(InvestigationItem)
            .where(InvestigationItem.investigation_id == investigation_id)
            .order_by(InvestigationItem.added_at.desc())
        )
        return list((await self._session.scalars(statement)).all())

    # --- notes & tags -------------------------------------------------------- #

    async def add_note(self, *, analysis_id: str, author: str, body: str) -> AnalysisNote:
        row = AnalysisNote(
            id=str(uuid.uuid4()),
            analysis_id=analysis_id,
            author=author,
            body=body,
        )
        self._session.add(row)
        await self._session.commit()
        return row

    async def notes(self, analysis_id: str) -> list[AnalysisNote]:
        statement = (
            select(AnalysisNote)
            .where(AnalysisNote.analysis_id == analysis_id)
            .order_by(AnalysisNote.created_at.desc())
        )
        return list((await self._session.scalars(statement)).all())

    async def add_tag(self, *, analysis_id: str, tag: str) -> AnalysisTag:
        tag = tag.strip().lower()
        existing = (
            await self._session.execute(
                select(AnalysisTag).where(
                    AnalysisTag.analysis_id == analysis_id,
                    AnalysisTag.tag == tag,
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            return existing
        row = AnalysisTag(id=str(uuid.uuid4()), analysis_id=analysis_id, tag=tag)
        self._session.add(row)
        await self._session.commit()
        return row

    async def tags(self, analysis_id: str) -> list[str]:
        statement = (
            select(AnalysisTag.tag)
            .where(AnalysisTag.analysis_id == analysis_id)
            .order_by(AnalysisTag.tag)
        )
        return list((await self._session.scalars(statement)).all())

    # --- pinning --------------------------------------------------------------- #

    async def set_pinned(self, analysis_id: str, pinned: bool) -> bool:
        row = await self._session.execute(
            select(PinnedAnalysis).where(PinnedAnalysis.analysis_id == analysis_id)
        )
        existing = row.scalar_one_or_none()
        if pinned and existing is None:
            self._session.add(
                PinnedAnalysis(id=str(uuid.uuid4()), analysis_id=analysis_id)
            )
            await self._session.commit()
        elif not pinned and existing is not None:
            await self._session.delete(existing)
            await self._session.commit()
        return True

    async def pinned_ids(self) -> list[str]:
        statement = select(PinnedAnalysis.analysis_id).order_by(
            PinnedAnalysis.pinned_at.desc()
        )
        return list((await self._session.scalars(statement)).all())