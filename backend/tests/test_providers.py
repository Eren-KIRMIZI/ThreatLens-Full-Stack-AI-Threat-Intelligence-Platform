"""Provider HTTP-level tests using httpx MockTransport (no network)."""

import json

import httpx

from app.services.providers.abuseipdb import AbuseIPDBProvider
from app.services.providers.dns import DNSProvider
from app.services.providers.geoip import GeoIPProvider
from app.services.providers.malwarebazaar import MalwareBazaarProvider
from app.services.providers.otx import OTXProvider
from app.services.providers.rdap import RDAPProvider
from app.services.providers.threatfox import ThreatFoxProvider
from app.services.providers.urlhaus import URLhausProvider


def _run(provider, indicator_type: str, indicator: str, handler):
    provider._transport = httpx.MockTransport(handler)
    import asyncio

    async def _check() -> None:
        provider._client = None
        items = await provider.check(indicator_type, indicator)  # type: ignore[arg-type]
        await provider.aclose()
        return items

    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(_check())
    finally:
        loop.close()


def test_abuseipdb_returns_evidence_only_when_score_present() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": {
                    "abuseConfidenceScore": 78,
                    "totalReports": 12,
                    "usageType": "Data Center",
                    "isp": "HostX",
                    "countryCode": "US",
                    "lastReportedAt": "2026-01-01T00:00:00Z",
                }
            },
        )

    provider = AbuseIPDBProvider(api_key="test")
    items = _run(provider, "IP", "1.2.3.4", handler)
    assert len(items) == 1
    assert items[0].provider == "abuseipdb"
    assert items[0].verdict == "malicious"
    assert items[0].confidence == 0.78


def test_abuseipdb_clean_returns_no_evidence() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {"abuseConfidenceScore": 0}})

    provider = AbuseIPDBProvider(api_key="test")
    assert _run(provider, "IP", "1.2.3.4", handler) == []


def test_urlhaus_domain_lookup() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/host/")
        return httpx.Response(
            200,
            json={
                "query_status": "ok",
                "url_count": 5,
                "payload_count": 2,
                "firstseen": "2025-01-01 00:00:00",
                "lastseen": "2025-06-01 00:00:00",
            },
        )

    provider = URLhausProvider()
    items = _run(provider, "DOMAIN", "evil.com", handler)
    assert items and items[0].verdict == "malicious"
    assert items[0].metadata["url_count"] == 5


def test_urlhaus_unlisted_returns_no_evidence() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"query_status": "no_results"})

    provider = URLhausProvider()
    assert _run(provider, "DOMAIN", "good.com", handler) == []


def test_malwarebazaar_hash_info() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "query_status": "ok",
                "data": [
                    {
                        "signature": "Emotet",
                        "file_type": "exe",
                        "mime_type": "application/x-dosexec",
                        "first_seen": "2025-02-01 10:00:00",
                        "tags": ["emotet"],
                    }
                ],
            },
        )

    provider = MalwareBazaarProvider(api_key="test")
    items = _run(provider, "HASH", "a" * 64, handler)
    assert items and items[0].verdict == "malicious"
    assert "Emotet" in items[0].value


def test_otx_pulse_membership() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/indicators/file/ab/pulse_info")
        return httpx.Response(
            200,
            json={
                "data": {
                    "count": 3,
                    "pulses": [
                        {
                            "id": "p1",
                            "name": "Emotet campaign",
                            "modified": 1700000000,
                            "author": {"username": "alice"},
                        }
                    ],
                }
            },
        )

    provider = OTXProvider(api_key="test")
    items = _run(provider, "HASH", "ab", handler)
    assert len(items) == 1
    assert items[0].evidence_type == "pulse"
    assert items[0].value.startswith("3 pulses")


def test_otx_not_configured_is_skipped() -> None:
    field = OTXProvider(api_key=None)
    assert field.configured is False


def test_threatfox_ioc_search() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert body["authkey"] == "secret"
        return httpx.Response(
            200,
            json={
                "query_status": "ok",
                "data": [
                    {
                        "malware": "EMOTET",
                        "malware_printable": "Emotet",
                        "threat_type": "botnet_cc",
                        "first_seen": "2025-03-01 00:00:00",
                    }
                ],
            },
        )

    provider = ThreatFoxProvider(api_key="secret")
    items = _run(provider, "IP", "2.3.4.5", handler)
    assert items and items[0].verdict == "malicious"


def test_rdap_domain_registration() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "events": [
                    {"eventAction": "registration", "eventDate": "2025-01-01T00:00:00Z"}
                ],
                "entities": [
                    {"vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "RegistrarX"]]]}
                ],
            },
        )

    provider = RDAPProvider()
    items = _run(provider, "DOMAIN", "evil.com", handler)
    assert items and items[0].evidence_type == "whois"
    assert items[0].metadata["registrar"] == "RegistrarX"


def test_geoip_success() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "status": "success",
                "country": "Turkey",
                "regionName": "Istanbul",
                "isp": "TurkNet",
                "as": "AS12345 MyASN",
            },
        )

    provider = GeoIPProvider()
    items = _run(provider, "IP", "8.8.8.8", handler)
    assert items and items[0].evidence_type == "geoip"
    assert items[0].metadata["asn"] == "AS12345"


def test_dns_records_and_relationships() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        rtype = request.url.params.get("type")
        mapping = {
            "A": [{"data": "1.2.3.4"}],
            "AAAA": [],
            "NS": [{"data": "ns1.example.com."}],
            "MX": [{"data": "10 mail.example.com."}],
        }
        return httpx.Response(200, json={"Answer": mapping.get(rtype, [])})

    provider = DNSProvider()
    items = _run(provider, "DOMAIN", "example.com", handler)
    types = {item.evidence_type for item in items}
    assert "relationship" in types
    assert "dns" in types