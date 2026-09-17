"""Analysis request and response schemas (standardized API contract)."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal, Union

from pydantic import BaseModel, Field, field_validator

from app.schemas.ai import AIAnalysis
from app.schemas.common import IndicatorType, ThreatLevel
from app.schemas.enrichment import Enrichment
from app.utils import validators


class AIRequestMixin(BaseModel):
    """Optional evidence-based AI interpretation on any analysis request."""

    ai: bool | None = Field(
        default=None,
        description="Run the evidence-based AI interpretation. "
        "Defaults to the server's AI_ASSIST_DEFAULT setting.",
    )


# --------------------------------------------------------------------------- #
# Requests
# --------------------------------------------------------------------------- #


class HashAnalysisRequest(AIRequestMixin):
    hash: Annotated[str, Field(min_length=32, max_length=64)]

    @field_validator("hash")
    @classmethod
    def _validate_hash(cls, value: str) -> str:
        return validators.validate_hash(value)


class UrlAnalysisRequest(AIRequestMixin):
    url: str

    @field_validator("url")
    @classmethod
    def _validate_url(cls, value: str) -> str:
        return validators.validate_url(value)


class DomainAnalysisRequest(AIRequestMixin):
    domain: str

    @field_validator("domain")
    @classmethod
    def _validate_domain(cls, value: str) -> str:
        return validators.validate_domain(value)


class IpAnalysisRequest(AIRequestMixin):
    ip: str

    @field_validator("ip")
    @classmethod
    def _validate_ip(cls, value: str) -> str:
        return validators.validate_ip(value)


# --------------------------------------------------------------------------- #
# Responses
# --------------------------------------------------------------------------- #


class DetectionStats(BaseModel):
    malicious: int = 0
    suspicious: int = 0
    undetected: int = 0
    harmless: int = 0
    timeout: int = 0


class DetectionEntry(BaseModel):
    engine: str
    result: str | None = None
    category: str
    method: str | None = None


class IndicatorMetadata(BaseModel):
    """Common evidence shared by every indicator type."""

    kind: Literal["file", "url", "domain", "ip"]
    reputation: int | None = None
    tags: list[str] = Field(default_factory=list)
    threat_names: list[str] = Field(default_factory=list)
    total_votes: dict[str, int] = Field(default_factory=dict)
    first_submission_date: datetime | None = None
    last_analysis_date: datetime | None = None


class FileMetadata(IndicatorMetadata):
    kind: Literal["file"]
    sha256: str | None = None
    sha1: str | None = None
    md5: str | None = None
    names: list[str] = Field(default_factory=list)
    meaningful_name: str | None = None
    type_description: str | None = None
    size: int | None = None


class UrlMetadata(IndicatorMetadata):
    kind: Literal["url"]
    url: str | None = None
    final_url: str | None = None
    title: str | None = None


class DomainMetadata(IndicatorMetadata):
    kind: Literal["domain"]
    registrar: str | None = None
    creation_date: datetime | None = None


class IpMetadata(IndicatorMetadata):
    kind: Literal["ip"]
    country: str | None = None
    as_owner: str | None = None
    asn: int | None = None


class AnalysisResult(BaseModel):
    analysis_id: str
    indicator: str
    indicator_type: IndicatorType
    source: Literal["virustotal"] = "virustotal"
    submitted_at: datetime
    analyzed_at: datetime
    stats: DetectionStats
    detections: list[DetectionEntry]
    metadata: Annotated[
        Union[FileMetadata, UrlMetadata, DomainMetadata, IpMetadata],
        Field(discriminator="kind"),
    ]
    threat_score: int | None = Field(
        default=None,
        ge=0,
        le=100,
        description="Deterministic evidence-based score (0-100)",
    )
    threat_level: ThreatLevel | None = None
    ai: AIAnalysis | None = None
    enrichment: Enrichment | None = Field(
        default=None,
        description="Multi-provider evidence and explainable confidence",
    )