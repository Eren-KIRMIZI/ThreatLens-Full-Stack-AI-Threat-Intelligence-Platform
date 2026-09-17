"""Investigation / case schema models."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

STATUSES = ("open", "active", "closed")
SEVERITIES = ("low", "medium", "high", "critical")


class InvestigationCreate(BaseModel):
    title: str
    description: str | None = None
    status: str = "open"
    severity: str = "medium"


class InvestigationUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    status: str | None = None
    severity: str | None = None


class InvestigationItemOut(BaseModel):
    id: str
    value: str
    primary_type: str
    analysis_id: str | None = None
    added_at: datetime | None = None


class InvestigationOut(BaseModel):
    id: str
    title: str
    description: str | None = None
    status: str
    severity: str
    created_at: datetime | None = None
    updated_at: datetime | None = None
    items: list[InvestigationItemOut] = Field(default_factory=list)


class InvestigationPage(BaseModel):
    items: list[InvestigationOut]
    total: int
    limit: int
    offset: int


class NoteCreate(BaseModel):
    author: str = "analyst"
    body: str


class NoteOut(BaseModel):
    id: str
    analysis_id: str
    author: str
    body: str
    created_at: datetime | None = None


class TagCreate(BaseModel):
    tag: str