"""ThreatFox provider: shared IOC repository (free API key required)."""

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

THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1"

_TYPE_HINTS: dict[IndicatorType, list[str]] = {
    "HASH": ["hash"],
    "FILE": ["hash"],
    "URL": ["url"],
    "DOMAIN": ["domain"],
    "IP": ["ip:port", "ip"],
}


class ThreatFoxProvider(ProviderBase):
    name = "threatfox"

    def __init__(
        self,
        *,
        api_key: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        super().__init__(
            api_key=api_key
            if api_key is not None
            else get_settings().threatfox_api_key,
            base_url=THREATFOX_API_URL,
            timeout=15.0,
            transport=transport,
        )

    @property
    def configured(self) -> bool:
        return bool(self._api_key)

    def supports(self, indicator_type: IndicatorType) -> bool:
        return indicator_type in _TYPE_HINTS

    async def check(
        self, indicator_type: IndicatorType, indicator: str
    ) -> list[NormalizedEvidence]:
        if not self._api_key:
            return []
        client = self._client_instance()
        payload = {
            "query": "search_ioc",
            "search_term": indicator,
            "authkey": str(self._api_key),
        }
        try:
            response = await client.post("/", json=payload)
        except httpx.HTTPError:
            logger.warning("threatfox request failed", indicator=indicator)
            return []
        if response.status_code == 403:
            raise ConfigurationError(
                "ThreatFox rejected the configured API key.",
                code="threatfox_auth_error",
            )
        if response.status_code != 200:
            return []
        data = response.json()
        if data.get("query_status") != "ok":
            return []
        entries = data.get("data") or []
        if not isinstance(entries, list) or not entries:
            return []
        top = entries[0]
        first_seen = top.get("first_seen")
        last_seen = top.get("last_seen")
        return [
            self._evidence(
                indicator_type=indicator_type,
                indicator=indicator,
                evidence_type="threat_feed",
                title="ThreatFox IOC entry",
                value=(
                    f"{top.get('malware', 'unknown')} "
                    f"({top.get('malware_printable', '')})"
                ),
                confidence=0.9,
                verdict="malicious",
                first_seen=(
                    datetime.fromisoformat(first_seen) if first_seen else None
                ),
                last_seen=(
                    datetime.fromisoformat(last_seen) if last_seen else None
                ),
                observed_at=datetime.now(timezone.utc),
                source_ref=f"https://threatfox.abuse.ch/browse.php?search={indicator}",
                metadata={
                    "malware": top.get("malware"),
                    "malware_printable": top.get("malware_printable"),
                    "threat_type": top.get("threat_type"),
                    "family": top.get("family"),
                    "reporter": top.get("reporter"),
                    "tags": (top.get("tags") or [])[:20],
                },
            )
        ]