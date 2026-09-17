"""GeoIP provider: IP geolocation via ip-api.com (free tier, no key)."""

from __future__ import annotations

from datetime import datetime, timezone

import httpx

from app.core.logging import get_logger
from app.schemas.analysis import IndicatorType
from app.schemas.enrichment import NormalizedEvidence
from app.services.providers.base import ProviderBase

logger = get_logger(__name__)

GEOIP_API_URL = "http://ip-api.com/json"


class GeoIPProvider(ProviderBase):
    name = "geoip"

    def __init__(
        self,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        super().__init__(base_url=GEOIP_API_URL, timeout=10.0, transport=transport)

    def supports(self, indicator_type: IndicatorType) -> bool:
        return indicator_type == "IP"

    async def check(
        self, indicator_type: IndicatorType, indicator: str
    ) -> list[NormalizedEvidence]:
        client = self._client_instance()
        try:
            response = await client.get(
                f"/{indicator}",
                params={
                    "fields": "status,message,continent,country,countryCode,"
                    "regionName,city,zip,lat,lon,isp,org,as,asname,timezone"
                },
            )
        except httpx.HTTPError:
            logger.warning("geoip request failed", indicator=indicator)
            return []
        if response.status_code != 200:
            return []
        data = response.json()
        if data.get("status") != "success":
            return []
        asn_raw = (data.get("as") or "").split(" ")[0]
        return [
            self._evidence(
                indicator_type=indicator_type,
                indicator=indicator,
                evidence_type="geoip",
                title="IP geolocation",
                value=(
                    f"{data.get('country', '??')}, {data.get('regionName', '??')} "
                    f"· {data.get('isp', 'unknown ISP')}"
                ),
                confidence=0.8,
                verdict="unknown",
                observed_at=datetime.now(timezone.utc),
                source_ref=f"https://ip-api.com/#{indicator}",
                metadata={
                    "country": data.get("country"),
                    "country_code": data.get("countryCode"),
                    "region": data.get("regionName"),
                    "city": data.get("city"),
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                    "isp": data.get("isp"),
                    "org": data.get("org"),
                    "asn": asn_raw,
                    "asn_name": data.get("asname"),
                },
            )
        ]