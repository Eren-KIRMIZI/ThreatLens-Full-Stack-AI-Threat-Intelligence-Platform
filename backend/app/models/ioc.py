"""IOC registry models: distinct indicators + immutable history snapshots."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.models.analysis import utcnow


class DistinctIndicator(Base):
    """One canonical indicator across the whole platform (dedup registry)."""

    __tablename__ = "distinct_indicators"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    value: Mapped[str] = mapped_column(String(2048), index=True)
    primary_type: Mapped[str] = mapped_column(String(16), index=True)
    observations: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    latest_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    latest_level: Mapped[str | None] = mapped_column(String(16), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


class IndicatorSnapshot(Base):
    """Append-only record of how an indicator scored at one point in time."""

    __tablename__ = "indicator_snapshots"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    value: Mapped[str] = mapped_column(String(2048), index=True)
    primary_type: Mapped[str] = mapped_column(String(16), index=True)
    analysis_id: Mapped[str] = mapped_column(String(36), index=True)
    threat_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    threat_level: Mapped[str | None] = mapped_column(String(16), nullable=True)
    malicious_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    suspicious_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    analyzed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


class ProviderUsage(Base):
    """Telemetry row per enrichment fan-out: provider health over time."""

    __tablename__ = "provider_usage"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    provider: Mapped[str] = mapped_column(String(48), index=True)
    indicator_type: Mapped[str] = mapped_column(String(16), nullable=True)
    ok: Mapped[bool] = mapped_column(default=True, nullable=False)
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error: Mapped[str | None] = mapped_column(String(512), nullable=True)
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )