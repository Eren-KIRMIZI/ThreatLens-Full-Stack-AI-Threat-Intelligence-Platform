"""OpenRouter chat-completions client.

Minimal dependency-free integration: raw HTTP against the OpenAI-compatible
endpoint, returning parsed JSON for schema-validated interpretation.

Free-tier OpenRouter models are frequently overloaded ("Service temporarily
overloaded"), so the client rotates through an ordered model chain whenever the
upstream provider signals unavailability. The API key is resolved lazily so
constructing the service never fails; misconfiguration surfaces as a clean 503
when the LLM is actually used.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx

from app.core.config import get_settings
from app.core.exceptions import AppException
from app.core.logging import get_logger

logger = get_logger(__name__)

_RETRYABLE_CODES = {429, 500, 502, 503, 504}
# Model başına deneme sayısı; kullanıcı zincirine seri deneme eklediğimizde
# toplam gecikmeyi sınırlamak için küçük tutulur. Testlerde transport enjekte
# edildiğinde tek deneme yeterlidir.
_DEFAULT_ATTEMPTS = 2


class OpenRouterService:
    BASE_URL = "https://openrouter.ai"

    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str | None = None,
        fallback_models: list[str] | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        settings = get_settings()
        self._api_key = api_key if api_key is not None else settings.openrouter_api_key
        primary = model or settings.openrouter_model
        extra = fallback_models if fallback_models is not None else settings.openrouter_fallback_models
        # Aynı modeli zincirde tekrarlamaktan kaçının.
        self._models: list[str] = []
        for candidate in [primary, *extra]:
            if candidate and candidate not in self._models:
                self._models.append(candidate)
        self._attempts = 1 if transport is not None else _DEFAULT_ATTEMPTS
        self._client = httpx.AsyncClient(
            base_url=self.BASE_URL,
            timeout=httpx.Timeout(90.0),
            transport=transport,
        )

    @property
    def model(self) -> str:
        """Primary configured model (reported in the AI payload)."""
        return self._models[0]

    async def chat_json(self, *, system: str, user: str) -> dict[str, Any]:
        """Post a chat completion and return the parsed JSON object."""
        if not self._api_key:
            raise AppException(
                status_code=503,
                code="openrouter_config_error",
                message="OPENROUTER_API_KEY is not configured.",
            )

        payload = {
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        headers = {"Authorization": f"Bearer {self._api_key}"}

        hit_rate_limit = False
        saw_invalid_output = False

        for model in self._models:
            for attempt in range(1, self._attempts + 1):
                try:
                    response = await self._client.post(
                        "/api/v1/chat/completions",
                        headers=headers,
                        json={**payload, "model": model},
                    )
                except httpx.RequestError as exc:
                    if attempt < self._attempts:
                        logger.warning(
                            "openrouter request failed",
                            model=model,
                            attempt=attempt,
                            error=str(exc),
                        )
                        await asyncio.sleep(2**attempt)
                        continue
                    logger.warning("openrouter model unreachable", model=model)
                    break

                if response.status_code in (401, 403):
                    raise AppException(
                        status_code=503,
                        code="openrouter_config_error",
                        message="OpenRouter rejected the configured API key.",
                    )
                if response.status_code in _RETRYABLE_CODES:
                    if attempt < self._attempts:
                        logger.warning(
                            "openrouter retryable status",
                            model=model,
                            status=response.status_code,
                            attempt=attempt,
                        )
                        await asyncio.sleep(2**attempt)
                        continue
                    hit_rate_limit = hit_rate_limit or response.status_code == 429
                    logger.warning(
                        "openrouter model exhausted retries",
                        model=model,
                        status=response.status_code,
                    )
                    break
                if response.status_code != 200:
                    logger.error(
                        "openrouter unexpected status",
                        model=model,
                        status=response.status_code,
                        body=response.text[:500],
                    )
                    raise AppException(
                        status_code=502,
                        code="openrouter_upstream_error",
                        message="OpenRouter returned an unexpected response.",
                    )

                try:
                    data = response.json()
                except ValueError:
                    data = {}
                # Providers occasionally answer 200 with an error object in the
                # body (e.g. "Service temporarily overloaded"); treat those as a
                # degraded model and rotate to the next one in the chain.
                if not isinstance(data, dict) or "choices" not in data or "error" in data:
                    if attempt < self._attempts:
                        logger.warning(
                            "openrouter body-level error",
                            model=model,
                            attempt=attempt,
                            body=data.get("error", "missing choices") if isinstance(data, dict) else str(data)[:200],
                        )
                        await asyncio.sleep(1.0)
                        continue
                    logger.warning(
                        "openrouter model degraded",
                        model=model,
                        body=data.get("error", "missing choices") if isinstance(data, dict) else str(data)[:200],
                    )
                    break

                try:
                    content = data["choices"][0]["message"]["content"]
                    parsed = json.loads(content)
                except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
                    saw_invalid_output = True
                    logger.error("openrouter invalid model output", model=model, error=str(exc))
                    break
                if not isinstance(parsed, dict):
                    saw_invalid_output = True
                    break
                return parsed

        if hit_rate_limit:
            raise AppException(
                status_code=503,
                code="openrouter_rate_limited",
                message="OpenRouter rate limit hit; try again shortly.",
            )
        if saw_invalid_output:
            raise AppException(
                status_code=502,
                code="openrouter_invalid_response",
                message="The model response was not valid JSON.",
            )
        raise AppException(
            status_code=503,
            code="openrouter_upstream_error",
            message="OpenRouter reported an upstream error across all configured models.",
        )

    async def aclose(self) -> None:
        await self._client.aclose()