"""Provider health telemetry: enrichment outcomes mirror to the registry."""

from __future__ import annotations

from app.repositories.analysis_repository import AnalysisRepository
from app.repositories.registry_repository import RegistryRepository
from app.schemas.enrichment import (
    Enrichment,
    NormalizedEvidence,
    ProviderStatus,
)
from app.services.analysis_service import AnalysisService
from app.services import normalizer
from sqlalchemy import select

from app.models.ioc import ProviderUsage


class _FakeEnrichment:
    async def enrich(self, indicator_type, indicator, *, seeded_vt=None, rescan_count=0):
        return Enrichment(
            evidence=[
                NormalizedEvidence(
                    id="e1",
                    provider="fake",
                    evidence_type="pulse",
                    title="sighting",
                    value="v",
                    confidence=0.5,
                    verdict="suspicious",
                )
            ],
            provider_status=[
                ProviderStatus(provider="fake", ok=True, latency_ms=12),
                ProviderStatus(provider="dead", ok=False, error="boom", latency_ms=None),
            ],
        )


def _url_result() -> object:
    node = {
        "attributes": {
            "url": "https://evil.com",
            "reputation": -3,
            "tags": [],
            "threat_names": [],
            "total_votes": {},
            "first_submission_date": 1700000000,
            "last_analysis_date": 1700000001,
            "last_analysis_stats": {
                "harmless": 1,
                "malicious": 2,
                "suspicious": 0,
                "undetected": 0,
                "timeout": 0,
            },
            "last_analysis_results": {},
        }
    }
    return normalizer.build_url_analysis("https://evil.com", node, "fetched")


async def test_enrichment_outcomes_are_recorded_as_telemetry(test_database) -> None:
    async with test_database.session_factory() as session:
        service = AnalysisService(
            virustotal=None,
            repository=AnalysisRepository(session),
            ai_service=None,
            enrichment=_FakeEnrichment(),
            registry=RegistryRepository(session),
        )

        result = await service._apply_enrichment(_url_result())

        assert result.enrichment is not None
        rows = (
            await session.execute(
                select(ProviderUsage).order_by(ProviderUsage.provider)
            )
        ).scalars().all()
        assert rows, "provider usage rows must be recorded"
        observed = {(row.provider, row.ok, row.indicator_type) for row in rows}
        assert observed == {
            ("fake", True, "URL"),
            ("dead", False, "URL"),
        }
        dead = next(row for row in rows if not row.ok)
        assert dead.error == "boom"