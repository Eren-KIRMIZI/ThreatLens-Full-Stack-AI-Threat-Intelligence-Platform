"""Confidence scoring (explainable multi-provider) tests."""

from datetime import datetime, timedelta, timezone

from app.schemas.enrichment import NormalizedEvidence
from app.services.confidence import compute_confidence, min_max_seen


def _evidence(
    provider: str,
    evidence_type: str,
    title: str,
    value: str,
    verdict: str = "unknown",
    confidence: float = 1.0,
    metadata: dict | None = None,
    first_seen=None,
) -> NormalizedEvidence:
    return NormalizedEvidence(
        id=f"{provider}|{title}|{value}",
        provider=provider,
        evidence_type=evidence_type,  # type: ignore[arg-type]
        title=title,
        value=value,
        confidence=confidence,
        verdict=verdict,  # type: ignore[arg-type]
        observed_at=datetime.now(timezone.utc),
        first_seen=first_seen,
        metadata=metadata or {},
    )


def test_virustotal_detections_drive_high_score() -> None:
    confidence = compute_confidence(
        [
            _evidence(
                "virustotal",
                "detection",
                "detections",
                "18/94",
                metadata={"stats": {"malicious": 18, "suspicious": 2}},
            )
        ]
    )
    assert confidence.overall >= 60
    assert confidence.verdict in {"malicious", "critical"}
    assert any("18 malicious engines agree" in r for r in confidence.reasons)


def test_clean_sources_produce_low_score() -> None:
    confidence = compute_confidence(
        [
            _evidence("otx", "pulse", "pulses", "0 pulses", verdict="clean"),
            _evidence("abuseipdb", "reputation", "score", "0/100", verdict="clean"),
        ]
    )
    assert confidence.overall < 40
    assert {"otx", "abuseipdb"} <= {s.source for s in confidence.sources}


def test_recently_registered_domain_raises_score() -> None:
    confidence = compute_confidence(
        [
            NormalizedEvidence(
                id="rdap|whois|recent",
                provider="rdap",
                evidence_type="whois",
                title="registration",
                value="registrar X · registered today",
                confidence=0.6,
                verdict="unknown",
                first_seen=datetime.now(timezone.utc),
            )
        ]
    )
    source = confidence.sources[0]
    assert source.score >= 10
    assert any("registered very recently" in s for s in source.signals)


def test_min_max_seen_window() -> None:
    now = datetime.now(timezone.utc)
    early = now - timedelta(days=400)
    seen = min_max_seen(
        [
            _evidence("a", "pulse", "t", "v", first_seen=now),
            NormalizedEvidence(
                id="x",
                provider="a",
                evidence_type="pulse",
                title="t2",
                value="v2",
                confidence=1.0,
                verdict="unknown",
                first_seen=early,
            ),
        ]
    )
    assert seen[0] is not None and seen[1] is not None
    assert seen[0] <= seen[1]


def test_empty_evidence_yields_unknown_confidence() -> None:
    confidence = compute_confidence([])
    assert confidence.overall == 0
    assert confidence.verdict == "unknown"