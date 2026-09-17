"""URLhaus provider: malicious URL / host blacklist (no API key required)."""

from __future__ import annotations

from datetime import datetime, timezone

import httpx

from app.core.logging import get_logger
from app.schemas.analysis import IndicatorType
from app.schemas.enrichment import NormalizedEvidence
from app.services.providers.base import ProviderBase

logger = get_logger(__name__)

URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1"


class URLhausProvider(ProviderBase):
    name = "urlhaus"

    def __init__(
        self,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        super().__init__(base_url=URLHAUS_API_URL, timeout=15.0, transport=transport)

    def supports(self, indicator_type: IndicatorType) -> bool:
        return indicator_type in {"URL", "DOMAIN"}

    async def check(
        self, indicator_type: IndicatorType, indicator: str
    ) -> list[NormalizedEvidence]:
        client = self._client_instance()
        payload: dict[str, str] = {}
        if indicator_type == "DOMAIN":
            name = "host"
        elif indicator_type == "URL":
            name = "url"
        else:
            return []
        payload[name] = indicator
        try:
            response = await client.post(
                f"/{name}/", data=payload,
            )
        except httpx.HTTPError:
            logger.warning("urlhaus request failed", indicator=indicator)
            return []

        if response.status_code != 200:
            logger.warning("urlhaus non-ok", status=response.status_code)
            return []

        data = response.json()
        if data.get("query_status") != "ok":
            return []

        items: list[NormalizedEvidence] = []
        first_seen = data.get("firstseen")
        last_seen = data.get("lastseen")
        items.append(
            self._evidence(
                indicator_type=indicator_type,
                indicator=indicator,
                evidence_type="threat_feed",
                title="Listed on URLhaus blacklist",
                value=(
                    f"{int(data.get('url_count') or 0)} malicious URLs reported"
                    if indicator_type == "DOMAIN"
                    else data.get("url_status", "online")
                ),
                confidence=0.95,
                verdict="malicious",
                first_seen=(
                    datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
                    if first_seen else None
                ),
                last_seen=(
                    datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
                    if last_seen else None
                ),
                observed_at=datetime.now(timezone.utc),
                source_ref=f"https://urlhaus.abuse.ch/host/{indicator}",
                metadata={
                    "blacklist": data.get("blacklist"),
                    "url_count": data.get("url_count"),
                    "payload_count": data.get("payload_count"),
                },
            )
        )
        return items