"""Provider adapter protocol.

Every threat-intelligence source implements ``ProviderBase`` and produces a
plain list of ``NormalizedEvidence``. The enrichment orchestrator depends only
on this interface, so adding a provider is a small, isolated change.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from hashlib import sha256
from typing import Any, Sequence

import httpx

from app.schemas.analysis import IndicatorType
from app.schemas.enrichment import NormalizedEvidence


def evidence_id(
    provider: str,
    indicator_type: IndicatorType,
    indicator: str,
    evidence_type: str,
    value: str,
) -> str:
    """Deterministic identity for an evidence item (dedup key)."""
    canonical = f"{provider}|{indicator_type}|{indicator}|{evidence_type}|{value}"
    return sha256(canonical.encode("utf-8")).hexdigest()[:32]


class ProviderBase(ABC):
    """Contract implemented by every threat provider."""

    name: str = "base"

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        timeout: float = 20.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._api_key = api_key
        self._base_url = base_url
        self._timeout = timeout
        self._transport = transport
        self._client: httpx.AsyncClient | None = None

    @property
    def configured(self) -> bool:
        return True

    def supports(self, indicator_type: IndicatorType) -> bool:
        """Whether this provider has data for the indicator type."""
        return True

    @abstractmethod
    async def check(
        self, indicator_type: IndicatorType, indicator: str
    ) -> list[NormalizedEvidence]:
        """Return normalized evidence for the indicator, or [] if none."""

    def _client_instance(self) -> httpx.AsyncClient:
        if self._client is None:
            headers: dict[str, str] = {}
            if self._api_key:
                headers["x-apikey"] = self._api_key
            self._client = httpx.AsyncClient(
                base_url=self._base_url,
                headers=headers,
                timeout=httpx.Timeout(self._timeout, connect=8.0),
                transport=self._transport,
            )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _evidence(
        self,
        *,
        indicator_type: IndicatorType,
        indicator: str,
        evidence_type: str,
        title: str,
        value: str,
        confidence: float,
        verdict: str = "unknown",
        first_seen: Any = None,
        last_seen: Any = None,
        observed_at: Any = None,
        source_ref: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> NormalizedEvidence:
        return NormalizedEvidence(
            id=evidence_id(
                self.name, indicator_type, indicator, evidence_type, value
            ),
            provider=self.name,
            evidence_type=evidence_type,  # type: ignore[arg-type]
            title=title,
            value=value,
            confidence=confidence,
            verdict=verdict,  # type: ignore[arg-type]
            first_seen=first_seen,
            last_seen=last_seen,
            observed_at=observed_at,
            source_ref=source_ref,
            metadata=metadata or {},
        )

    @staticmethod
    def _safe_text(data: dict[str, Any], *keys: str, default: str | None = None) -> str | None:
        node: Any = data
        for key in keys:
            if not isinstance(node, dict) or key not in node:
                return default
            node = node[key]
        return str(node) if node is not None else default

    @staticmethod
    def _require(api_key: str | None, env_name: str) -> None:
        raise NotImplementedError  # implemented per-provider below


def filter_by_support(
    providers: Sequence[ProviderBase], indicator_type: IndicatorType
) -> list[ProviderBase]:
    return [p for p in providers if p.configured and p.supports(indicator_type)]