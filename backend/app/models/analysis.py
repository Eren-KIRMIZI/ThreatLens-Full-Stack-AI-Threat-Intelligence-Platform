"""SQLAlchemy ORM models.

Analysis is stored as a single denormalized row per investigation: the
full normalized payload (JSON) plus a few indexed columns that power the
history table and the cache lookup.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


def utcnow() -> datetime:
    """Naive UTC timestamp for storage (matches SQLite's DateTime handling)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Analysis(Base):
    __tablename__ = "analyses"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    indicator: Mapped[str] = mapped_column(String(2048), index=True)
    indicator_type: Mapped[str] = mapped_column(String(16), index=True)
    meaningful_name: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # Denormalized counters for filterable history queries.
    malicious_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    suspicious_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Populated by the threat scoring phase.
    threat_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    threat_level: Mapped[str | None] = mapped_column(String(16), nullable=True)

    # Full normalized analysis payload (AnalysisResult dump).
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)

    analyzed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )