"""Schemas for the structured, evidence-based AI interpretation.

The model is a strict contract: the LLM is never allowed to invent
behavior, hashes, IOCs or actors. Every claim must be traceable to the
normalized VirusTotal evidence handed to it (evidence_refs).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field

Confidence = Literal["low", "medium", "high"]
ThreatAssessment = Literal["clean", "suspicious", "malicious", "critical"]


class AITactic(BaseModel):
    """An attack technique mapped to a common phase of an attack."""

    phase: str = Field(..., description="Attack phase, e.g. Execution, Defense Evasion")
    technique_id: str | None = Field(default=None, description="MITRE ATT&CK technique ID (Txxxx)")
    technique_name: str | None = None
    notes: str | None = None


class AIThreatActor(BaseModel):
    """Best-effort threat actor / family profiling from the evidence."""

    name: str | None = None
    campaign: str | None = None
    description: str | None = None
    confidence: Confidence | None = None


class AICapability(BaseModel):
    """A single capability or impact of the threat."""

    capability: str = Field(..., description="e.g. Data exfiltration, Persistence")
    description: str = Field(..., description="Evidence-backed explanation")


class AIAnalysis(BaseModel):
    """Structured AI interpretation of the normalized evidence."""

    summary: str = Field(..., description="One-paragraph, evidence-based overview")
    tactics: list[AITactic] = Field(default_factory=list)
    threat_actor_profile: AIThreatActor | None = None
    capabilities: list[AICapability] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    lifecycle_stage: Literal[
        "direction",
        "collection",
        "processing",
        "analysis",
        "dissemination",
        "feedback",
    ] | None = None
    correlations: list[str] = Field(default_factory=list)
    threat_level_assessment: ThreatAssessment | None = None
    evidence_refs: list[str] = Field(
        default_factory=list,
        description="Engine names actually cited from the evidence; validated server-side",
    )
    model: str | None = None
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )