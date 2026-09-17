"""Normalized multi-provider enrichment schemas.

Every threat provider (VirusTotal, AbuseIPDB, OTX, URLhaus, ThreatFox,
MalwareBazaar, RDAP/WHOIS, GeoIP, DNS) emits a common ``NormalizedEvidence``
object. Downstream consumers (confidence scoring, AI, reports, IOC graph)
depend only on this normalized form, never on a provider's raw JSON.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.schemas.common import ThreatLevel

EvidenceVerdict = Literal["malicious", "suspicious", "clean", "unknown"]
EvidenceType = Literal[
    "detection",
    "reputation",
    "threat_feed",
    "pulse",
    "whois",
    "geoip",
    "dns",
    "relationship",
]


class NormalizedEvidence(BaseModel):
    """A single normalized observation from one provider.

    ``id`` is a deterministic hash of the evidence content so identical
    observations across providers can be de-duplicated.
    """

    id: str
    provider: str
    evidence_type: EvidenceType
    title: str = Field(..., description="Short human label, e.g. '5 malicious detections'")
    value: str = Field(..., description="The raw observation, e.g. '18/94' or '185.1.2.3'")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Provider-assigned confidence 0-1")
    verdict: EvidenceVerdict = "unknown"
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    observed_at: datetime | None = None
    source_ref: str | None = Field(default=None, description="Public URL back to the source")
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Provider-specific extras (engine, asn, country, counts…)"
    )


class ProviderStatus(BaseModel):
    """Outcome of a single provider call during enrichment."""

    provider: str
    ok: bool
    error: str | None = None
    latency_ms: int | None = None


class SourceConfidence(BaseModel):
    """Per-provider explainable score and its contributing signals."""

    source: str
    score: int = Field(..., ge=0, le=100)
    verdict: ThreatLevel | Literal["unknown"]
    signals: list[str] = Field(default_factory=list)


class ConfidenceBreakdown(BaseModel):
    """Aggregated, fully explainable multi-source confidence."""

    overall: int = Field(..., ge=0, le=100)
    verdict: ThreatLevel | Literal["unknown"]
    sources: list[SourceConfidence] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)


class Enrichment(BaseModel):
    """Everything learned about an indicator beyond the core VirusTotal data."""

    sources: list[str] = Field(default_factory=list)
    evidence: list[NormalizedEvidence] = Field(default_factory=list)
    provider_status: list[ProviderStatus] = Field(default_factory=list)
    confidence: ConfidenceBreakdown | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    rescanned_count: int = Field(
        default=0, description="How many times this canonical IOC has been investigated"
    )