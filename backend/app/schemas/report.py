"""Structured report document schema.

One canonical document model feeds both the JSON preview endpoint and the
rendered PDF, so the frontend preview and the downloadable artifact never
drift apart.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from app.schemas.analysis import IndicatorType, ThreatLevel


class ReportRow(BaseModel):
    label: str
    value: str


class ReportTable(BaseModel):
    columns: list[str]
    rows: list[list[str]]


class ReportBlock(BaseModel):
    kind: Literal["paragraph", "facts", "table"]
    heading: str
    text: str | None = None
    facts: list[ReportRow] = Field(default_factory=list)
    table: ReportTable | None = None


class ReportDocument(BaseModel):
    title: str
    subtitle: str
    generated_at: datetime
    indicator: str
    indicator_type: IndicatorType
    threat_score: int | None = None
    threat_level: ThreatLevel | None = None
    blocks: list[ReportBlock] = Field(default_factory=list)