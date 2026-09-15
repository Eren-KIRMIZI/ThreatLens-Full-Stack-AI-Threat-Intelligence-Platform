"""Deterministic, evidence-based threat scoring.

The score is a transparent, explainable rubric — never a black box:

    score = clamp( 10*malicious_engines
                 + 4*suspicious_engines
                 + reputation_adjustment   (-10..+10)
                 + vote_adjustment         (-10..+10), 0..100 )

Level bands (the threat_level):
    clean(0-19)  suspicious(20-39)  malicious(40-69)  critical(70-100)

Keeping the formula independent from the AI layer guarantees the same
evidence always yields the same verdict, while the AI (Phase 5) can still
contribute its own qualitative ``threat_level_assessment`` separately.
"""

from __future__ import annotations

from app.schemas.analysis import AnalysisResult, DetectionStats, ThreatLevel


def compute_score(
    stats: DetectionStats,
    *,
    reputation: int | None = None,
    total_votes: dict[str, int] | None = None,
) -> tuple[int, ThreatLevel]:
    """Return (score, level) derived only from the normalized evidence."""
    scores = [
        10 * stats.malicious,
        4 * stats.suspicious,
    ]

    if reputation is not None:
        # Negative reputation (VT signal of malevolence) raises the score.
        scores.append(max(-10, min(10, -reputation / 100.0)))

    votes = total_votes or {}
    votes_malicious = int(votes.get("malicious", 0) or 0)
    votes_harmless = int(votes.get("harmless", 0) or 0)
    scores.append(max(-10, min(10, votes_malicious - votes_harmless)))

    score = round(sum(scores))
    score = max(0, min(100, score))
    return score, level_for_score(score)


def level_for_score(score: int) -> ThreatLevel:
    if score >= 70:
        return "critical"
    if score >= 40:
        return "malicious"
    if score >= 20:
        return "suspicious"
    return "clean"


def score_analysis(result: AnalysisResult) -> tuple[int, ThreatLevel]:
    """Score a fully normalized analysis result."""
    return compute_score(
        result.stats,
        reputation=result.metadata.reputation,
        total_votes=result.metadata.total_votes,
    )