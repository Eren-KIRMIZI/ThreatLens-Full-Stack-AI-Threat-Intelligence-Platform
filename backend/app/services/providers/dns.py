"""DNS enrichment provider via Google Public DNS (dns.google, no key).

Queries A, AAAA, NS and MX records and emits resolved addresses, which also
feed the IOC relationship graph (domain → IP edges).
"""

from __future__ import annotations

from datetime import datetime, timezone

import httpx

from app.core.logging import get_logger
from app.schemas.analysis import IndicatorType
from app.schemas.enrichment import NormalizedEvidence
from app.services.providers.base import ProviderBase

logger = get_logger(__name__)

DNS_API_URL = "https://dns.google/resolve"

_QUERY_TYPES = ["A", "AAAA", "NS", "MX"]


class DNSProvider(ProviderBase):
    name = "dns"

    def __init__(
        self,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        super().__init__(base_url=DNS_API_URL, timeout=10.0, transport=transport)

    def supports(self, indicator_type: IndicatorType) -> bool:
        return indicator_type == "DOMAIN"

    async def check(
        self, indicator_type: IndicatorType, indicator: str
    ) -> list[NormalizedEvidence]:
        client = self._client_instance()
        records: dict[str, list[str]] = {}
        for rtype in _QUERY_TYPES:
            try:
                response = await client.get(
                    "/", params={"name": indicator, "type": rtype}
                )
            except httpx.HTTPError:
                logger.warning("dns resolve failed", type=rtype, name=indicator)
                continue
            if response.status_code != 200:
                continue
            data = response.json()
            answers = data.get("Answer") or []
            records.setdefault(rtype, []).extend(
                answer.get("data") for answer in answers if answer.get("data")
            )
        if not records:
            return []

        ip_addresses = [
            host for rtype in ("A", "AAAA") for host in records.get(rtype, [])
        ]
        items: list[NormalizedEvidence] = []

        for rtype, values in records.items():
            items.append(
                self._evidence(
                    indicator_type=indicator_type,
                    indicator=indicator,
                    evidence_type="dns",
                    title=f"DNS {rtype} records",
                    value=", ".join(values[:5]),
                    confidence=0.8,
                    verdict="unknown",
                    observed_at=datetime.now(timezone.utc),
                    source_ref=f"https://dns.google/resolve?name={indicator}&type={rtype}",
                    metadata={"records": values[:20]},
                )
            )
        if ip_addresses:
            items.append(
                self._evidence(
                    indicator_type=indicator_type,
                    indicator=indicator,
                    evidence_type="relationship",
                    title="Resolved IP addresses",
                    value=", ".join(ip_addresses[:5]),
                    confidence=0.9,
                    verdict="unknown",
                    observed_at=datetime.now(timezone.utc),
                    source_ref=f"https://dns.google/resolve?name={indicator}&type=A",
                    metadata={"ips": ip_addresses[:20]},
                )
            )
        return items