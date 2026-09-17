"""Orchestrates indicator analysis against the normalized VirusTotal evidence.

Every produced result is persisted to the history table, which also acts as
the freshness cache: a repeat investigation of the same indicator within the
configured TTL is answered from storage without calling VirusTotal again.
"""

from __future__ import annotations

from fastapi import UploadFile

from app.core.config import get_settings
from app.core.exceptions import AppException, NotFoundError
from app.core.logging import get_logger
from app.repositories.analysis_repository import AnalysisRepository
from app.repositories.registry_repository import RegistryRepository
from app.schemas.analysis import AnalysisResult
from app.services import normalizer
from app.services.ai_service import AIService
from app.services.enrichment_service import EnrichmentService
from app.services.providers.virustotal import evidence_from_analysis
from app.services.scoring import score_analysis
from app.services.virustotal_service import VirusTotalService
from app.utils.hashing import compute_hashes
from app.utils.ioc import canonical_value
from app.utils.validators import sanitize_filename

logger = get_logger(__name__)


class AnalysisService:
    def __init__(
        self,
        virustotal: VirusTotalService,
        repository: AnalysisRepository,
        ai_service: AIService,
        enrichment: EnrichmentService | None = None,
        registry: RegistryRepository | None = None,
    ) -> None:
        self._virustotal = virustotal
        self._repository = repository
        self._ai_service = ai_service
        self._enrichment = enrichment
        self._registry = registry

    async def _record_complete(self, result: AnalysisResult) -> None:
        """Dedup registry + immutable snapshot after every fresh analysis."""
        if self._registry is None:
            return
        try:
            await self._registry.record_analysis(result)
        except Exception:
            logger.warning(
                "failed to record IOC registry snapshot",
                indicator=result.indicator,
                analysis_id=result.analysis_id,
            )

    async def _apply_enrichment(self, result: AnalysisResult) -> AnalysisResult:
        """Attach multi-provider enrichment (with seeded VirusTotal evidence)."""
        if self._enrichment is None:
            return result
        try:
            rescan_count = await self._repository.count_for_indicator(
                result.indicator, result.indicator_type
            )
            result.enrichment = await self._enrichment.enrich(
                result.indicator_type,
                result.indicator,
                seeded_vt=evidence_from_analysis(result),
                rescan_count=rescan_count,
            )
        except Exception:
            # Enrichment is additive, never fail a core analysis because of it.
            logger.warning(
                "enrichment failed, continuing with core result",
                indicator=result.indicator,
                indicator_type=result.indicator_type,
            )
        return result

    async def _apply_ai(self, result: AnalysisResult) -> AnalysisResult:
        """Attach the evidence-based AI interpretation to a result."""
        result.ai = await self._ai_service.interpret(result)
        return result

    async def _persist(self, result: AnalysisResult) -> None:
        try:
            await self._repository.save(result)
        except Exception:
            # Persistence is auxiliary: never fail an analysis due to storage.
            logger.warning(
                "failed to persist analysis",
                analysis_id=result.analysis_id,
                indicator=result.indicator,
            )

    async def _cache_or(
        self,
        indicator: str,
        indicator_type: str,
        fetch_and_build,
        *,
        with_ai: bool = False,
        force_refresh: bool = False,
    ) -> AnalysisResult:
        """Return a fresh stored result, else build, persist and return one.

        When AI is requested but a cached result lacks it, the interpretation
        is generated for the cached evidence and the stored row is updated.
        ``force_refresh`` skips the freshness cache (used by scheduled rescans).
        """
        settings = get_settings()
        if not force_refresh:
            cached = await self._repository.find_cached(
                indicator=indicator,
                indicator_type=indicator_type,
                cache_ttl_seconds=settings.cache_ttl_seconds,
            )
            if cached is not None:
                result = AnalysisResult(**cached.payload)
                if result.threat_score is None:
                    # Backfill rows written before scoring existed (dev data).
                    result.threat_score, result.threat_level = score_analysis(result)
                if result.enrichment is None:
                    # Backfill rows stored before multi-provider enrichment existed.
                    result = await self._apply_enrichment(result)
                    try:
                        await self._repository.update_payload(
                            result.analysis_id, result.model_dump(mode="json")
                        )
                    except Exception:
                        logger.warning(
                            "failed to attach enrichment to stored analysis",
                            analysis_id=result.analysis_id,
                        )
                if not with_ai or result.ai is not None:
                    return result
                result = await self._apply_ai(result)
                try:
                    await self._repository.update_payload(
                        result.analysis_id, result.model_dump(mode="json")
                    )
                except Exception:
                    logger.warning(
                        "failed to attach ai to stored analysis",
                        analysis_id=result.analysis_id,
                        indicator=result.indicator,
                    )
                return result

        result = await fetch_and_build()
        result.threat_score, result.threat_level = score_analysis(result)
        result = await self._apply_enrichment(result)
        if with_ai:
            result = await self._apply_ai(result)
        await self._persist(result)
        await self._record_complete(result)
        return result

    async def analyze_hash(
        self, hash_value: str, *, with_ai: bool = False, force_refresh: bool = False
    ) -> AnalysisResult:
        async def fetch_and_build() -> AnalysisResult:
            node = await self._virustotal.get_file(hash_value)
            return normalizer.build_file_analysis(hash_value, node)

        return await self._cache_or(
            hash_value, "HASH", fetch_and_build, with_ai=with_ai,
            force_refresh=force_refresh,
        )

    async def analyze_url(
        self, url: str, *, with_ai: bool = False, force_refresh: bool = False
    ) -> AnalysisResult:
        async def fetch_and_build() -> AnalysisResult:
            node, origin = await self._virustotal.get_or_submit_url(url)
            return normalizer.build_url_analysis(url, node, origin)

        return await self._cache_or(
            url, "URL", fetch_and_build, with_ai=with_ai,
            force_refresh=force_refresh,
        )

    async def analyze_domain(
        self, domain: str, *, with_ai: bool = False, force_refresh: bool = False
    ) -> AnalysisResult:
        async def fetch_and_build() -> AnalysisResult:
            node = await self._virustotal.get_domain(domain)
            detections = await self._virustotal.get_last_analysis_results("domains", domain)
            return normalizer.build_domain_analysis(domain, node, detections)

        return await self._cache_or(
            domain, "DOMAIN", fetch_and_build, with_ai=with_ai,
            force_refresh=force_refresh,
        )

    async def analyze_ip(
        self, ip: str, *, with_ai: bool = False, force_refresh: bool = False
    ) -> AnalysisResult:
        async def fetch_and_build() -> AnalysisResult:
            node = await self._virustotal.get_ip(ip)
            detections = await self._virustotal.get_last_analysis_results("ip_addresses", ip)
            return normalizer.build_ip_analysis(ip, node, detections)

        return await self._cache_or(
            ip, "IP", fetch_and_build, with_ai=with_ai,
            force_refresh=force_refresh,
        )

    async def analyze_any(
        self,
        primary_type: str,
        value: str,
        *,
        with_ai: bool = False,
        force_refresh: bool = False,
    ) -> AnalysisResult:
        """Dispatch an analysis by primary indicator type (watchlist rescan)."""
        normalized = primary_type.upper()
        if normalized in {"HASH", "FILE"}:
            return await self.analyze_hash(value, with_ai=with_ai, force_refresh=force_refresh)
        if normalized == "URL":
            return await self.analyze_url(value, with_ai=with_ai, force_refresh=force_refresh)
        if normalized == "DOMAIN":
            return await self.analyze_domain(value, with_ai=with_ai, force_refresh=force_refresh)
        if normalized == "IP":
            return await self.analyze_ip(value, with_ai=with_ai, force_refresh=force_refresh)
        raise AppException(
            status_code=422,
            code="unsupported_indicator_type",
            message=f"Unsupported indicator type: {primary_type}",
        )

    async def analyze_file(
        self, upload: UploadFile, *, with_ai: bool = False, force_refresh: bool = False
    ) -> AnalysisResult:
        """Compute hashes server-side and analyze an uploaded file.

        The raw bytes are never persisted and never reach the AI layer;
        only the normalized VirusTotal evidence is retained.
        """
        try:
            filename = sanitize_filename(upload.filename or "")
        except ValueError as exc:
            raise AppException(
                status_code=422,
                code="invalid_filename",
                message=str(exc),
            ) from exc

        settings = get_settings()
        max_bytes = settings.max_upload_size_bytes
        content = await upload.read(max_bytes + 1)

        if not content:
            raise AppException(
                status_code=422,
                code="empty_file",
                message="The uploaded file is empty.",
            )
        if len(content) > max_bytes:
            raise AppException(
                status_code=413,
                code="file_too_large",
                message=f"The file exceeds the {settings.max_upload_size_mb} MB upload limit.",
            )

        hashes = compute_hashes(content)
        sha256 = hashes["sha256"]

        async def fetch_and_build() -> AnalysisResult:
            try:
                node = await self._virustotal.get_file(sha256)
            except NotFoundError:
                analysis_node = await self._virustotal.upload_file(filename, content)
                completed = await self._virustotal.wait_for_analysis(analysis_node["id"])
                return normalizer.build_file_analysis(
                    sha256,
                    completed,
                    hashes=hashes,
                    filename=filename,
                    indicator_type="FILE",
                )
            return normalizer.build_file_analysis(
                sha256,
                node,
                filename=filename,
                indicator_type="FILE",
            )

        return await self._cache_or(
            sha256, "FILE", fetch_and_build, with_ai=with_ai,
            force_refresh=force_refresh,
        )