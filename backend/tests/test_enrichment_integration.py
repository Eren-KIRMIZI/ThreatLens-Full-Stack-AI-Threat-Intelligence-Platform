"""Integration: enrichment attaches to normalized analyses end-to-end."""

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.repositories.analysis_repository import AnalysisRepository
from app.schemas.enrichment import NormalizedEvidence
from app.services.analysis_service import AnalysisService
from app.services.enrichment_service import EnrichmentService
from app.services.providers.base import ProviderBase
from app.services.virustotal_service import VirusTotalService

HASH = "ab" * 32

FILE_REPORT = {
    "data": {
        "id": HASH,
        "type": "file",
        "attributes": {
            "sha256": HASH,
            "type_description": "Win32 EXE",
            "size": 1234,
            "meaningful_name": "t.exe",
            "reputation": -20,
            "threat_names": ["Trojan:A"],
            "total_votes": {"harmless": 0, "malicious": 4},
            "first_submission_date": 1700000000,
            "last_analysis_date": 1700000001,
            "last_analysis_stats": {
                "malicious": 12,
                "suspicious": 1,
                "undetected": 5,
                "harmless": 60,
                "timeout": 0,
            },
            "last_analysis_results": {
                "Microsoft": {"category": "malicious", "result": "Trojan", "method": "blacklist"}
            },
        },
    }
}


class FakeVT(VirusTotalService):
    async def get_file(self, hash_value: str) -> dict:
        return FILE_REPORT["data"]


class FakeAI:
    async def interpret(self, result):
        raise AssertionError("AI should not run when with_ai=False")


class GraphProvider(ProviderBase):
    name = "graphfake"

    def supports(self, indicator_type) -> bool:
        return True

    async def check(self, indicator_type, indicator) -> list[NormalizedEvidence]:
        return [
            NormalizedEvidence(
                id="g1",
                provider=self.name,
                evidence_type="threat_feed",
                title="related indicator",
                value="resolves-to 5.5.5.5",
                confidence=0.7,
                verdict="malicious",
            )
        ]


async def _make_service() -> AnalysisService:
    engine = create_async_engine(
        "sqlite+aiosqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    session = factory()

    repository = AnalysisRepository(session)
    enrichment = EnrichmentService(providers=[GraphProvider()], timeout=5)
    await session.commit()
    service = AnalysisService(FakeVT(), repository, FakeAI(), enrichment=enrichment)
    service._cleanup = (engine, session)  # type: ignore[attr-defined]
    return service


async def _dispose(service: AnalysisService) -> None:
    engine, session = service._cleanup  # type: ignore[attr-defined]
    await session.close()
    await engine.dispose()


async def test_analysis_includes_enrichment_and_persists() -> None:
    service = await _make_service()
    try:
        result = await service.analyze_hash(HASH)
        assert result.enrichment is not None
        assert {"virustotal", "graphfake"} <= set(result.enrichment.sources)
        assert result.enrichment.confidence is not None and result.enrichment.confidence.overall > 0
        assert result.threat_score is not None
    finally:
        await _dispose(service)


async def test_cached_repeat_returns_persisted_enrichment() -> None:
    service = await _make_service()
    try:
        first = await service.analyze_hash(HASH)
        second = await service.analyze_hash(HASH)
        assert first.analysis_id == second.analysis_id
        assert second.enrichment is not None
    finally:
        await _dispose(service)