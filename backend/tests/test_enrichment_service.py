"""Enrichment orchestrator tests with in-memory fake providers."""

from datetime import datetime, timezone

from app.schemas.enrichment import NormalizedEvidence
from app.services.enrichment_service import EnrichmentService
from app.services.providers.base import ProviderBase


class FakeProvider(ProviderBase):
    name = "fake"

    def __init__(self, items, *, fail: bool = False) -> None:
        super().__init__()
        self.items = items
        self.fail = fail

    def supports(self, indicator_type) -> bool:
        return True

    async def check(self, indicator_type, indicator) -> list[NormalizedEvidence]:
        if self.fail:
            raise RuntimeError("boom")
        return self.items


def _evidence(value: str) -> NormalizedEvidence:
    return NormalizedEvidence(
        id=value,
        provider="fake",
        evidence_type="pulse",
        title="fake",
        value=value,
        confidence=0.5,
        verdict="suspicious",
        observed_at=datetime.now(timezone.utc),
    )


async def test_enrichment_fans_out_and_dedupes() -> None:
    service = EnrichmentService(
        providers=[
            FakeProvider([_evidence("a"), _evidence("a")]),  # dup within provider
            FakeProvider([_evidence("b")]),
        ],
        timeout=5,
    )
    enrichment = await service.enrich("IP", "1.2.3.4")
    await service.aclose()
    assert [e.value for e in enrichment.evidence] == ["a", "b"]
    assert set(enrichment.sources) == {"fake"}
    assert enrichment.confidence is not None


async def test_failing_provider_is_isolated() -> None:
    failing = FakeProvider([_evidence("a")], fail=True)
    service = EnrichmentService(providers=[failing], timeout=5)
    enrichment = await service.enrich("DOMAIN", "evil.com")
    await service.aclose()
    assert enrichment.evidence == []
    assert len(enrichment.provider_status) == 1
    status = enrichment.provider_status[0]
    assert status.ok is False
    assert "boom" in (status.error or "")


async def test_seeded_virustotal_evidence_merged() -> None:
    seeded = [
        NormalizedEvidence(
            id="vt1",
            provider="virustotal",
            evidence_type="detection",
            title="detections",
            value="5/60",
            confidence=1.0,
            verdict="malicious",
        )
    ]
    service = EnrichmentService(providers=[FakeProvider([_evidence("x")])], timeout=5)
    enrichment = await service.enrich("HASH", "a" * 64, seeded_vt=seeded, rescan_count=3)
    await service.aclose()
    assert enrichment.rescanned_count == 3
    assert {e.provider for e in enrichment.evidence} == {"virustotal", "fake"}