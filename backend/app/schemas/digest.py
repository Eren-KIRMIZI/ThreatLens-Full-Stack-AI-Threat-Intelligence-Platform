"""Digest / export / search schema models."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class SearchResult(BaseModel):
    kind: str
    id: str
    title: str
    subtitle: str
    score: int | None = None
    level: str | None = None
    analyzed_at: datetime | None = None


class SearchResponse(BaseModel):
    query: str
    total: int
    results: list[SearchResult]


class DigestSection(BaseModel):
    label: str
    value: str


class DigestOut(BaseModel):
    period: str
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    sections: list[DigestSection] = Field(default_factory=list)