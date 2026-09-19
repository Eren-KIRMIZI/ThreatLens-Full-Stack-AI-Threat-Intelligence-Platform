"""Explainable multi-provider confidence scoring.

Consumes the normalized evidence list and produces a per-source 0-100 score,
its human-readable "why" signals, and a weighted overall confidence. The
scoring is fully deterministic — same evidence always yields the same result.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.schemas.analysis import ThreatLevel
from app.schemas.enrichment import (
    ConfidenceBreakdown,
    NormalizedEvidence,
    SourceConfidence,
)
from app.services.scoring import level_for_score

# Per-provider weight in the overall aggregation.
PROVIDER_WEIGHTS: dict[str, float] = {
    "virustotal": 1.0,
    "abuseipdb": 0.55,
    "otx": 0.4,
    "rdap": 0.3,
    "geoip": 0.1,
    "dns": 0.15,
}

# Domain registration age used to flag freshly-registered domains.
SUSPICIOUS_DOMAIN_AGE_DAYS = 90


def _clamp(score: float) -> int:
    return max(0, min(100, round(score)))


def _age_days(created: datetime | None) -> int | None:
    if created is None:
        return None
    age = (datetime.now(timezone.utc) - created).days
    return max(0, age)


def _score_provider(provider: str, evidences: list[NormalizedEvidence]) -> SourceConfidence:
    """Compute the explainable sub-score for a single provider."""
    weight = PROVIDER_WEIGHTS.get(provider, 0.4)
    score = 0.0
    signals: list[str] = []

    for evidence in evidences:
        stats = evidence.metadata.get("stats") if isinstance(evidence.metadata, dict) else None
        if evidence.evidence_type == "detection" and stats:
            malicious = int(stats.get("malicious") or 0)
            suspicious = int(stats.get("suspicious") or 0)
            # VT-style magnitude contribution, scaled by the provider weight.
            score += min(malicious, 12) * 5.5 * weight
            score += min(suspicious, 10) * 1.0 * weight
            if malicious:
                signals.append(f"{malicious} malicious engines agree")
            elif suspicious:
                signals.append(f"{suspicious} engines report suspicious")
        elif evidence.evidence_type == "reputation" and provider == "abuseipdb":
            if evidence.verdict == "malicious":
                score += (evidence.confidence * 70) * weight
                signals.append(f"AbuseIPDB score {evidence.metadata.get('abuse_confidence_score') or evidence.value}")
            else:
                signals.append("clean on AbuseIPDB")
        elif evidence.evidence_type == "threat_feed":
            if evidence.verdict == "malicious":
                score += (55 * evidence.confidence) * weight
                signals.append(f"listed by {provider}")
            else:
                signals.append(f"not listed by {provider}")
        elif evidence.evidence_type == "pulse":
            if evidence.verdict == "malicious":
                score += (40 * evidence.confidence) * weight
                signals.append("present in OTX pulses")
            elif evidence.verdict == "clean":
                score -= 4 * weight
                signals.append("no OTX pulse membership")
        elif evidence.evidence_type == "whois":
            created = evidence.first_seen
            age = _age_days(created)
            if age is not None and age < SUSPICIOUS_DOMAIN_AGE_DAYS:
                score += 40 * weight
                signals.append("domain registered very recently")
            else:
                score -= 4 * weight
                signals.append(f"domain registered {age or '?'} days ago")
        elif evidence.verdict == "malicious":
            score += (30 * evidence.confidence) * weight
        elif evidence.verdict == "suspicious":
            score += (12 * evidence.confidence) * weight
        elif evidence.verdict == "clean":
            score -= 6 * weight

    final = _clamp(score)
    verdict = _verdict_for(final)

    if not signals:
        signals = ["no strong signals on this source"]
    if isinstance(verdict, str) and verdict == "unknown":
        signals = ["insufficient provider coverage"]

    return SourceConfidence(source=provider, score=final, verdict=verdict, signals=signals[:6])


def _verdict_for(score: int) -> ThreatLevel | str:
    if score >= 70:
        return "critical"
    if score >= 40:
        return "malicious"
    if score >= 20:
        return "suspicious"
    if score == 0:
        return "unknown"
    return "clean"


def compute_confidence(evidence: list[NormalizedEvidence]) -> ConfidenceBreakdown:
    """Aggregate normalized evidence into a fully explainable confidence."""
    grouped: dict[str, list[NormalizedEvidence]] = {}
    for item in evidence:
        grouped.setdefault(item.provider, []).append(item)

    sources: list[SourceConfidence] = []
    total_weight = 0.0
    weighted = 0.0
    for provider, items in grouped.items():
        source = _score_provider(provider, items)
        sources.append(source)
        weight = PROVIDER_WEIGHTS.get(provider, 0.4)
        total_weight += weight
        weighted += source.score * weight

    overall = _clamp(weighted / total_weight) if total_weight else 0

    reasons: list[str] = []
    for source in sorted(sources, key=lambda s: -s.score):
        for signal in source.signals[:3]:
            reasons.append(f"{source.source}: {signal}")

    return ConfidenceBreakdown(
        overall=overall,
        verdict=level_for_score(overall) if overall else "unknown",
        sources=sources,
        reasons=reasons[:10],
    )


def min_max_seen(evidence: list[NormalizedEvidence]) -> tuple[datetime | None, datetime | None]:
    """Return (earliest, latest) observed_at across evidence items."""
    timestamps = [
        ts
        for item in evidence
        for ts in (item.first_seen, item.last_seen, item.observed_at)
        if isinstance(ts, datetime)
    ]
    if not timestamps:
        return None, None
    return min(timestamps), max(timestamps)