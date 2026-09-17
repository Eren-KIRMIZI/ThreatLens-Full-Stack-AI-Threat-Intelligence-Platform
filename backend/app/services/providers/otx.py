"""AlienVault OTX provider: open pulses & related IOCs (API key required)."""

from __future__ import annotations

from datetime import datetime, timezone

import httpx

from app.core.config import get_settings
from app.core.exceptions import ConfigurationError
from app.core.logging import get_logger
from app.schemas.analysis import IndicatorType
from app.schemas.enrichment import NormalizedEvidence
from app.services.providers.base import ProviderBase

logger = get_logger(__name__)

OTX_API_URL = "https://otx.alienvault.com/api/v1"

_OTX_TYPES: dict[IndicatorType, tuple[str, ...]] = {
    "HASH": ("file",),
    "FILE": ("file",),
    "URL": ("url",),
    "DOMAIN": ("domain", "hostname"),
    "IP": ("IPv4", "IPv6"),
}


def _related_from_pulse(indicator: str, pulse: dict) -> list[dict]:
    """Coerce OTX pulse indicators into typed related-IOC records."""
    otx_to_type = {
        "file": "HASH",
        "hash": "HASH",
        "ipv4": "IP",
        "IPv4": "IP",
        "ipv6": "IP",
        "IPv6": "IP",
        "domain": "DOMAIN",
        "hostname": "DOMAIN",
        "url": "URL",
    }
    related: list[dict] = []
    for item in (pulse.get("indicators") or [])[:10]:
        raw = item.get("indicator") if isinstance(item, dict) else None
        otx_type = item.get("type") if isinstance(item, dict) else None
        target = otx_to_type.get(str(otx_type)) if otx_type else None
        if not raw or not target or str(raw) == str(indicator):
            continue
        related.append(
            {"value": str(raw), "type": target, "relation": "campaign member"}
        )
    return related


class OTXProvider(ProviderBase):
    name = "otx"

    def __init__(
        self,
        *,
        api_key: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        super().__init__(
            api_key=api_key
            if api_key is not None
            else get_settings().otx_api_key,
            base_url=OTX_API_URL,
            timeout=15.0,
            transport=transport,
        )

    @staticmethod
    def _epoch(value) -> datetime | None:
        if value:
            return datetime.fromtimestamp(int(value), tz=timezone.utc)
        return None

    @property
    def configured(self) -> bool:
        return bool(self._api_key)

    def supports(self, indicator_type: IndicatorType) -> bool:
        return indicator_type in _OTX_TYPES

    async def _get_pulse_info(
        self, client: httpx.AsyncClient, otx_type: str, indicator: str
    ) -> dict:
        url = f"/indicators/{otx_type}/{indicator}/pulse_info"
        try:
            response = await client.get(
                url, params={"limit": "10", "page": "1"},
                headers={"X-OTX-API-KEY": str(self._api_key)},
            )
        except httpx.HTTPError:
            return {}
        if response.status_code != 200:
            if response.status_code == 403:
                raise ConfigurationError(
                    "OTX rejected the configured API key.",
                    code="otx_auth_error",
                )
            return {}
        return response.json().get("data", {}) or {}

    async def check(
        self, indicator_type: IndicatorType, indicator: str
    ) -> list[NormalizedEvidence]:
        items: list[NormalizedEvidence] = []
        client = self._client_instance()
        for otx_type in _OTX_TYPES[indicator_type]:
            info = await self._get_pulse_info(client, otx_type, indicator)
            pulses = info.get("pulses", []) or []
            pulse_count = info.get("count", 0)
            if pulse_count and pulses:
                top = pulses[0]
                items.append(
                    self._evidence(
                        indicator_type=indicator_type,
                        indicator=indicator,
                        evidence_type="pulse",
                        title="OTX pulse membership",
                        value=(
                            f"{pulse_count} pulses; latest: "
                            f"{top.get('name', 'untitled')} "
                            f"({top.get('author', {}).get('username', '?')})"
                        ),
                        confidence=min(1.0, 0.4 + pulse_count / 20),
                        verdict="suspicious",
                        last_seen=self._epoch(top.get("modified")),
                        observed_at=datetime.now(timezone.utc),
                        source_ref=(
                            f"https://otx.alienvault.com/pulse/{top.get('id')}"
                            if top.get("id") else None
                        ),
                        metadata={
                            "pulse_count": pulse_count,
                            "threat_actors": [
                                top.get("actor") for _ in [top] if top.get("actor")
                            ],
                            "hashes": top.get("indicators", [])[:10],
                            "attack_ids": (top.get("attack_ids") or [])[:10],
                            "related": _related_from_pulse(indicator, top),
                        },
                    )
                )
            #  Explicit "not tagged" signal improves explainability.
            if not pulse_count:
                items.append(
                    self._evidence(
                        indicator_type=indicator_type,
                        indicator=indicator,
                        evidence_type="pulse",
                        title="No OTX pulse membership",
                        value="0 pulses",
                        confidence=0.1,
                        verdict="clean",
                        observed_at=datetime.now(timezone.utc),
                        source_ref=None,
                        metadata={"pulse_count": 0},
                    )
                )
        return items