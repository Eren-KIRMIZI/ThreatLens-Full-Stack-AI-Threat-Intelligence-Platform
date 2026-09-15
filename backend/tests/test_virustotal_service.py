"""VirusTotalService unit tests using httpx.MockTransport."""

import pytest
import httpx

from app.core.exceptions import (
    ConfigurationError,
    NotFoundError,
    RateLimitError,
    ServiceUnavailableError,
)
from app.services.virustotal_service import VirusTotalService

DUMMY_SHA256 = "a" * 64
API_KEY = "test-key"

FILE_REPORT = {
    "data": {
        "id": DUMMY_SHA256,
        "type": "file",
        "attributes": {
            "sha256": DUMMY_SHA256,
            "last_analysis_stats": {
                "harmless": 51,
                "malicious": 5,
                "suspicious": 2,
                "undetected": 0,
                "timeout": 0,
                "type-unsupported": 0,
            },
            "last_analysis_results": {
                "Microsoft": {"category": "malicious", "result": "Trojan", "method": "blacklist"}
            },
        },
    }
}


def build_service(handler) -> VirusTotalService:
    transport = httpx.MockTransport(handler)
    return VirusTotalService(api_key=API_KEY, transport=transport)


async def test_missing_api_key_raises_configuration_error() -> None:
    service = VirusTotalService(api_key=None)
    with pytest.raises(ConfigurationError):
        await service.get_file("a" * 64)


async def test_get_file_success() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith(f"/files/{DUMMY_SHA256}")
        assert request.headers["x-apikey"] == API_KEY
        return httpx.Response(200, json=FILE_REPORT)

    service = build_service(handler)
    node = await service.get_file(DUMMY_SHA256)
    assert node["id"] == DUMMY_SHA256
    assert node["attributes"]["last_analysis_stats"]["malicious"] == 5
    await service.aclose()


async def test_404_raises_not_found() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": {"code": "NotFoundError"}})

    service = build_service(handler)
    with pytest.raises(NotFoundError):
        await service.get_file(DUMMY_SHA256)
    await service.aclose()


async def test_429_raises_rate_limited() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={"error": {"code": "TooManyRequestsError"}})

    service = build_service(handler)
    with pytest.raises(RateLimitError):
        await service.get_file(DUMMY_SHA256)
    await service.aclose()


async def test_401_raises_auth_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": {"code": "AuthenticationRequiredError"}})

    service = build_service(handler)
    with pytest.raises(ConfigurationError):
        await service.get_file(DUMMY_SHA256)
    await service.aclose()


async def test_network_error_maps_to_service_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    service = build_service(handler)
    with pytest.raises(ServiceUnavailableError):
        await service.get_file(DUMMY_SHA256)
    await service.aclose()


async def test_url_id_is_unpadded_base64url() -> None:
    url = "https://example.com"
    assert VirusTotalService.url_id(url) == (
        "aHR0cHM6Ly9leGFtcGxlLmNvbQ"
    )


async def test_get_or_submit_url_uses_existing_report() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(f"{request.method} {request.url.path}")
        return httpx.Response(
            200,
            json={"data": {"id": "expect", "type": "url", "attributes": {"url": "https://example.com"}}},
        )

    service = build_service(handler)
    node, origin = await service.get_or_submit_url("https://example.com")
    assert origin == "url"
    assert node["type"] == "url"
    assert len(calls) == 1
    await service.aclose()


async def test_get_or_submit_url_submits_and_polls_until_completed() -> None:
    url_id = VirusTotalService.url_id("https://example.com")

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "GET" and path.endswith(f"/urls/{url_id}"):
            return httpx.Response(404, json={"error": {"code": "NotFoundError"}})
        if request.method == "POST" and path.endswith("/urls"):
            return httpx.Response(
                200,
                json={"data": {"type": "analysis", "id": "u-123"}},
            )
        if request.method == "GET" and path.endswith("/analyses/u-123"):
            return httpx.Response(
                200,
                json={
                    "data": {
                        "type": "analysis",
                        "id": "u-123",
                        "attributes": {
                            "status": "completed",
                            "stats": {"malicious": 1, "suspicious": 0, "harmless": 0, "undetected": 0, "timeout": 0},
                        },
                    }
                },
            )
        return httpx.Response(500, json={})

    service = build_service(handler)
    node, origin = await service.get_or_submit_url("https://example.com")
    assert origin == "analysis"
    assert node["attributes"]["status"] == "completed"
    await service.aclose()


async def test_get_last_analysis_results_returns_attributes() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": [
                    {"attributes": {"engine_name": "Microsoft", "category": "malicious", "result": "Trojan"}},
                    {"attributes": {"engine_name": "Avast", "category": "undetected"}},
                ]
            },
        )

    service = build_service(handler)
    items = await service.get_last_analysis_results("domains", "example.com")
    assert items[0]["engine_name"] == "Microsoft"
    await service.aclose()