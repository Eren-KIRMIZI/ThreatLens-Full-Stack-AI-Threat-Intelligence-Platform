"""Watchlist, alert rule and alert schema models."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class WatchlistCreate(BaseModel):
    value: str
    primary_type: str = "HASH"
    enabled: bool = True


class WatchlistItemOut(BaseModel):
    id: str
    value: str
    primary_type: str
    enabled: bool
    last_checked_at: datetime | None = None
    created_at: datetime | None = None


class WatchlistPage(BaseModel):
    items: list[WatchlistItemOut]
    total: int
    limit: int
    offset: int
    enabled_only: bool


class RuleIn(BaseModel):
    id: str | None = None
    name: str
    condition: str
    threshold: int = 70
    enabled: bool = True


class RuleOut(BaseModel):
    id: str
    name: str
    condition: str
    threshold: int
    enabled: bool


class AlertOut(BaseModel):
    id: str
    watchlist_id: str
    rule_id: str | None = None
    analysis_id: str | None = None
    indicator: str
    level: str
    message: str
    seen: bool
    triggered_at: datetime | None = None


class AlertsPage(BaseModel):
    items: list[AlertOut]
    total: int
    limit: int
    offset: int
    unseen_only: bool


class RescanOutcome(BaseModel):
    watchlist_id: str
    value: str
    primary_type: str
    analysis_id: str | None = None
    threat_score: int | None = None
    threat_level: str | None = None
    alerts: list[AlertOut] = Field(default_factory=list)
    error: str | None = None


class RescanReport(BaseModel):
    checked: int
    outcomes: list[RescanOutcome]