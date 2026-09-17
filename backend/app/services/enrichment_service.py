"""Enrichment orchestrator.

Fans out an indicator query to every configured (and applicable) secondary
provider in parallel, normalizes each answer to ``NormalizedEvidence``,
de-duplicates, times every call, computes the explainable confidence
breakdown and first/last seen window.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from app.core.config import get_settings
from app.core.logging import get_logger
from app.schemas.analysis import IndicatorType
from app.schemas.enrichment import (
    Enrichment,
    NormalizedEvidence,
    ProviderStatus,
)
from app.services.confidence import compute_confidence, min_max_seen
from app.services.providers.base import ProviderBase, filter_by_support
from app.services.providers.registry import build_extra_providers

logger = get_logger(__name__)


class EnrichmentService:
    """Parallel, resilient multi-provider enrichment."""

    def __init__(
        self,
        providers: list[ProviderBase] | None = None,
        *,
        timeout: float | None = None,
        transport=None,
    ) -> None:
        self._providers = providers if providers is not None else build_extra_providers(transport=transport)
        self._timeout = timeout if timeout is not None else get_settings().enrichment_timeout_seconds

    async def enrich(
        self,
        indicator_type: IndicatorType,
        indicator: str,
        *,
        seeded_vt: list[NormalizedEvidence] | None = None,
        rescan_count: int = 0,
    ) -> Enrichment:
        providers = filter_by_support(self._providers, indicator_type)

        async def _run(provider: ProviderBase) -> tuple[ProviderBase, list[NormalizedEvidence], float, str | None]:
            started = time.monotonic()
            try:
                items = await asyncio.wait_for(
                    provider.check(indicator_type, indicator),
                    timeout=self._timeout,
                )
                return provider, items, (time.monotonic() - started) * 1000, None
            except Exception as exc:  # noqa: BLE001 - provider isolation
                return provider, [], (time.monotonic() - started) * 1000, str(exc)[:200]

        results = await asyncio.gather(*(_run(p) for p in providers))

        evidence: list[NormalizedEvidence] = list(seeded_vt or [])
        statuses: list[ProviderStatus] = []
        for provider, items, latency, error in results:
            statuses.append(
                ProviderStatus(provider=provider.name, ok=error is None, error=error, latency_ms=round(latency))
            )
            if error is None:
                evidence.extend(items)

        evidence = self._dedupe(evidence)
        confidence = compute_confidence(evidence)
        first_seen, last_seen = min_max_seen(evidence)
        sources = sorted({item.provider for item in evidence})

        return Enrichment(
            sources=sources,
            evidence=evidence,
            provider_status=statuses,
            confidence=confidence,
            first_seen=first_seen,
            last_seen=last_seen,
            rescanned_count=rescan_count,
        )

    @staticmethod
    def _dedupe(evidence: list[NormalizedEvidence]) -> list[NormalizedEvidence]:
        seen: set[str] = set()
        unique: list[NormalizedEvidence] = []
        for item in evidence:
            if item.id in seen:
                continue
            seen.add(item.id)
            unique.append(item)
        return unique

    async def aclose(self) -> None:
        for provider in self._providers:
            await provider.aclose()

    @property
    def configured_provider_names(self) -> list[str]:
        return [p.name for p in self._providers if p.configured]