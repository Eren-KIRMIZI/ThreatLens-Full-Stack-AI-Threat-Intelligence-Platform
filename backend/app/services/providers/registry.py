"""Provider registry: build the configured enrichment provider set."""

from __future__ import annotations

from app.core.config import get_settings
from app.services.providers.abuseipdb import AbuseIPDBProvider
from app.services.providers.base import ProviderBase
from app.services.providers.dns import DNSProvider
from app.services.providers.geoip import GeoIPProvider
from app.services.providers.malwarebazaar import MalwareBazaarProvider
from app.services.providers.otx import OTXProvider
from app.services.providers.rdap import RDAPProvider
from app.services.providers.threatfox import ThreatFoxProvider
from app.services.providers.urlhaus import URLhausProvider


def build_extra_providers(
    *, transport=None,
) -> list[ProviderBase]:
    """Instantiate the secondary (non-VirusTotal) providers from settings."""
    settings = get_settings()
    return [
        AbuseIPDBProvider(api_key=settings.abuseipdb_api_key or None, transport=transport),
        OTXProvider(api_key=settings.otx_api_key or None, transport=transport),
        URLhausProvider(transport=transport),
        ThreatFoxProvider(transport=transport),
        MalwareBazaarProvider(api_key=settings.malwarebazaar_api_key or None, transport=transport),
        RDAPProvider(transport=transport),
        GeoIPProvider(transport=transport),
        DNSProvider(transport=transport),
    ]