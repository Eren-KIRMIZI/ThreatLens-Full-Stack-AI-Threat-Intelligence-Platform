"""RDAP provider: WHOIS-style registry data for domains and IPs (no key)."""

from __future__ import annotations

from datetime import datetime, timezone

import httpx

from app.core.logging import get_logger
from app.schemas.analysis import IndicatorType
from app.schemas.enrichment import NormalizedEvidence
from app.services.providers.base import ProviderBase

logger = get_logger(__name__)

RDAP_BASE_URL = "https://rdap.org"


class RDAPProvider(ProviderBase):
    name = "rdap"

    def __init__(
        self,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        super().__init__(
            base_url=RDAP_BASE_URL,
            timeout=12.0,
            transport=transport,
        )

    def supports(self, indicator_type: IndicatorType) -> bool:
        return indicator_type in {"DOMAIN", "IP"}

    @staticmethod
    def _event(events: list[dict] | None, kind: str) -> datetime | None:
        if not events:
            return None
        for event in events:
            if event.get("eventAction") == kind and event.get("eventDate"):
                try:
                    return datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
                except ValueError:
                    return None
        return None

    @staticmethod
    def _registrar(entities: list[dict] | None) -> str | None:
        if not entities:
            return None
        for entity in entities:
            for handle in entity.get("vcardArray", []) or []:
                if not isinstance(handle, list):
                    continue
                for item in handle:
                    if isinstance(item, list) and item and item[0] == "fn" and len(item) > 3:
                        return item[3]
        return None

    async def check(
        self, indicator_type: IndicatorType, indicator: str
    ) -> list[NormalizedEvidence]:
        # rdap.org responds over HTTP 302; follow redirects explicitly.
        client = self._client_instance()
        try:
            response = await client.get(
                f"/{ 'domain' if indicator_type == 'DOMAIN' else 'ip' }/{indicator}",
                headers={
                    "Accept": "application/rdap+json",
                    "User-Agent": "ThreatLens/0.1 threat-intel",
                },
                follow_redirects=True,
            )
        except httpx.HTTPError:
            logger.warning("rdap request failed", indicator=indicator)
            return []
        if response.status_code != 200:
            return []
        data = response.json()
        created = self._event(data.get("events"), "registration")
        updated = self._event(data.get("events"), "last changed")
        registrar = self._registrar(data.get("entities"))
        country = self._safe_text(data, "country")

        items: list[NormalizedEvidence] = []
        if indicator_type == "DOMAIN":
            if registrar or created:
                items.append(
                    self._evidence(
                        indicator_type=indicator_type,
                        indicator=indicator,
                        evidence_type="whois",
                        title="Domain registration data",
                        value=(
                            f"{registrar or 'unknown registrar'} · registered "
                            f"{created.date().isoformat() if created else 'unknown'}"
                        ),
                        confidence=0.6,
                        verdict="unknown",
                        first_seen=created,
                        last_seen=updated,
                        observed_at=datetime.now(timezone.utc),
                        source_ref=f"https://rdap.org/domain/{indicator}",
                        metadata={
                            "registrar": registrar,
                            "creation_date": created.isoformat() if created else None,
                            "status": data.get("status"),
                            "nameservers": [
                                n.get("ldhName") for n in (data.get("nameservers") or [])
                            ][:10],
                        },
                    )
                )
        else:
            items.append(
                self._evidence(
                    indicator_type=indicator_type,
                    indicator=indicator,
                    evidence_type="geoip",
                    title="IP network registry (RDAP)",
                    value=(
                        f"{data.get('name') or data.get('handle')} "
                        f"({country or '??'})"
                    ),
                    confidence=0.5,
                    verdict="unknown",
                    first_seen=created,
                    observed_at=datetime.now(timezone.utc),
                    source_ref=f"https://rdap.org/ip/{indicator}",
                    metadata={
                        "handle": data.get("handle"),
                        "name": data.get("name"),
                        "country": country,
                        "parent_handle": data.get("parentHandle"),
                        "status": data.get("status"),
                        "start_address": (data.get("ipVersion") or ""),
                    },
                )
            )
        return items