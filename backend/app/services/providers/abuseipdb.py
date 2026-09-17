"""AbuseIPDB provider: IP reputation lookups (abuseConfidenceScore)."""

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

ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2"


class AbuseIPDBProvider(ProviderBase):
    name = "abuseipdb"

    def __init__(
        self,
        *,
        api_key: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        super().__init__(
            api_key=api_key
            if api_key is not None
            else get_settings().abuseipdb_api_key,
            base_url=ABUSEIPDB_API_URL,
            timeout=15.0,
            transport=transport,
        )
        if self._api_key:
            self._headers = {"Key": str(self._api_key)}
        else:
            self._headers = {}

    @property
    def configured(self) -> bool:
        return bool(self._api_key)

    def supports(self, indicator_type: IndicatorType) -> bool:
        return indicator_type == "IP"

    async def check(
        self, indicator_type: IndicatorType, indicator: str
    ) -> list[NormalizedEvidence]:
        client = self._client_instance()
        try:
            response = await client.get(
                "/check",
                params={
                    "ipAddress": indicator,
                    "maxAgeInDays": "90",
                    "verbose": "true",
                },
                headers=self._headers,
            )
        except httpx.HTTPError:
            logger.warning("abuseipdb request failed", indicator=indicator)
            return []

        if response.status_code != 200:
            if response.status_code in (401, 403):
                raise ConfigurationError(
                    "AbuseIPDB rejected the configured API key.",
                    code="abuseipdb_auth_error",
                )
            logger.warning(
                "abuseipdb non-ok", status=response.status_code, indicator=indicator
            )
            return []

        attrs = response.json().get("data", {})
        score = int(attrs.get("abuseConfidenceScore") or 0)
        if score == 0 and not attrs.get("totalReports"):
            return []
        return [
            self._evidence(
                indicator_type=indicator_type,
                indicator=indicator,
                evidence_type="reputation",
                title="AbuseIPDB blacklist score",
                value=f"{score}/100 (in {int(attrs.get('totalReports') or 0)} reports)",
                confidence=min(1.0, score / 100),
                verdict="malicious" if score >= 25 else "clean",
                last_seen=(
                    datetime.fromisoformat(attrs["lastReportedAt"].replace("Z", "+00:00"))
                    if attrs.get("lastReportedAt") else None
                ),
                observed_at=datetime.now(timezone.utc),
                source_ref=f"https://www.abuseipdb.com/check/{indicator}",
                metadata={
                    "usage_type": attrs.get("usageType"),
                    "isp": attrs.get("isp"),
                    "country_code": attrs.get("countryCode"),
                    "is_whitelisted": attrs.get("isWhitelisted"),
                    "total_reports": attrs.get("totalReports"),
                    "abuse_confidence_score": score,
                },
            )
        ]