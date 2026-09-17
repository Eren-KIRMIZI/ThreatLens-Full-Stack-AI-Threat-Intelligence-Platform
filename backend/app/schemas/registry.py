"""Schema models for the IOC registry, snapshots and provider health."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class IOCItem(BaseModel):
    id: str
    value: str
    primary_type: str
    observations: int
    latest_score: int | None = None
    latest_level: str | None = None
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None


class IOCPage(BaseModel):
    items: list[IOCItem]
    total: int
    limit: int
    offset: int


class SnapshotPoint(BaseModel):
    analysis_id: str
    threat_score: int | None = None
    threat_level: str | None = None
    malicious: int = 0
    suspicious: int = 0
    analyzed_at: datetime | None = None


class IOCDetail(BaseModel):
    indicator: IOCItem
    observations: int
    timeline: list[SnapshotPoint] = Field(default_factory=list)
    analyses: list[dict] = Field(default_factory=list)


class ProviderHealthRow(BaseModel):
    provider: str
    ok: bool
    latency_ms: int | None = None
    indicator_type: str | None = None
    error: str | None = None
    checked_at: datetime | None = None
    checks: int | None = None
    availability: float | None = None


class ProviderHealthReport(BaseModel):
    since_hours: int
    rows: list[ProviderHealthRow]