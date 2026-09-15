"""Response schemas for the history table."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from app.schemas.analysis import DetectionStats

ThreatFilter = Literal["all", "malicious", "suspicious", "clean"]


class HistoryItem(BaseModel):
    """A compact, table-friendly view of one stored investigation."""

    analysis_id: str
    indicator: str
    indicator_type: str
    meaningful_name: str | None = None
    stats: DetectionStats
    detected_vendors: int = Field(..., description="Vendors that flagged the indicator")
    threat_score: int | None = None
    threat_level: str | None = None
    analyzed_at: datetime
    created_at: datetime


class HistoryPage(BaseModel):
    items: list[HistoryItem]
    total: int
    limit: int
    offset: int
    filter: ThreatFilter = "all"