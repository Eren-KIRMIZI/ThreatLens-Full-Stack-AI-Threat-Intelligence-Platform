"""Unit tests for the OpenRouter chat-completions client."""

import json

import httpx
import pytest

from app.core.exceptions import AppException
from app.services.openrouter_service import OpenRouterService


def json_completion_handler(content: str):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/api/v1/chat/completions")
        assert request.headers["authorization"] == "Bearer test-key"
        body = json.loads(request.content)
        assert body["response_format"] == {"type": "json_object"}
        assert body["messages"][0]["role"] == "system"
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})

    return handler


async def test_chat_json_parses_valid_response() -> None:
    service = OpenRouterService(
        api_key="test-key",
        transport=httpx.MockTransport(json_completion_handler('{"summary": "ok"}')),
    )
    result = await service.chat_json(system="s", user="u")
    assert result == {"summary": "ok"}


async def test_missing_key_raises_clean_config_error() -> None:
    service = OpenRouterService(
        api_key="",
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json={})),
    )
    with pytest.raises(AppException) as exc:
        await service.chat_json(system="s", user="u")
    assert exc.value.status_code == 503
    assert exc.value.code == "openrouter_config_error"


async def test_unauthorized_key_raises_config_error() -> None:
    service = OpenRouterService(
        api_key="bad",
        transport=httpx.MockTransport(lambda r: httpx.Response(401, json={})),
    )
    with pytest.raises(AppException) as exc:
        await service.chat_json(system="s", user="u")
    assert exc.value.code == "openrouter_config_error"


async def test_rate_limit_raises_clean_error() -> None:
    service = OpenRouterService(
        api_key="k",
        transport=httpx.MockTransport(lambda r: httpx.Response(429, json={})),
    )
    with pytest.raises(AppException) as exc:
        await service.chat_json(system="s", user="u")
    assert exc.value.code == "openrouter_rate_limited"


async def test_upstream_500_raises_clean_error() -> None:
    service = OpenRouterService(
        api_key="k",
        transport=httpx.MockTransport(lambda r: httpx.Response(500, json={})),
    )
    with pytest.raises(AppException) as exc:
        await service.chat_json(system="s", user="u")
    assert exc.value.code == "openrouter_upstream_error"


async def test_non_json_content_raises_invalid_response() -> None:
    service = OpenRouterService(
        api_key="test-key",
        transport=httpx.MockTransport(json_completion_handler("not json")),
    )
    with pytest.raises(AppException) as exc:
        await service.chat_json(system="s", user="u")
    assert exc.value.code == "openrouter_invalid_response"