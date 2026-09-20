"""Investigation (case) models: cases, items, notes and tags."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.models.analysis import utcnow


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="open", nullable=False)
    severity: Mapped[str] = mapped_column(String(16), default="medium", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class InvestigationItem(Base):
    __tablename__ = "investigation_items"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        String(36), index=True, nullable=False
    )
    analysis_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    primary_type: Mapped[str] = mapped_column(String(16), nullable=False)
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


class AnalysisNote(Base):
    __tablename__ = "analysis_notes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    analysis_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    author: Mapped[str] = mapped_column(String(128), default="analyst", nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


class AnalysisTag(Base):
    __tablename__ = "analysis_tags"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    analysis_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    tag: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


class PinnedAnalysis(Base):
    __tablename__ = "pinned_analyses"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    analysis_id: Mapped[str] = mapped_column(
        String(36), index=True, unique=True, nullable=False
    )
    pinned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


class InvestigationNote(Base):
    """Analyst note attached to a case (investigation) itself."""

    __tablename__ = "investigation_notes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        String(36), index=True, nullable=False
    )
    author: Mapped[str] = mapped_column(String(128), default="analyst", nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


class Campaign(Base):
    """Named campaign grouping evidence inside an investigation."""

    __tablename__ = "campaigns"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        String(36), index=True, nullable=False
    )
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    color: Mapped[str] = mapped_column(String(32), default="info", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


class CampaignEvidence(Base):
    """Evidence record assigned to a campaign."""

    __tablename__ = "campaign_evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    campaign_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    investigation_id: Mapped[str] = mapped_column(
        String(36), index=True, nullable=False
    )
    analysis_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    primary_type: Mapped[str] = mapped_column(String(16), nullable=False)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )