"""OpenRouter chat-completions client.

Minimal dependency-free integration: raw HTTP against the OpenAI-compatible
endpoint, returning parsed JSON for schema-validated interpretation.

The API key is resolved lazily so constructing the service never fails;
misconfiguration surfaces as a clean 503 when the LLM is actually used.
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
_MAX_ATTEMPTS = 4


class OpenRouterService:
    BASE_URL = "https://openrouter.ai"

    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        settings = get_settings()
        self._api_key = api_key if api_key is not None else settings.openrouter_api_key
        self._model = model or settings.openrouter_model
        # Retrying is a production affordance for flaky free-tier providers;
        # with an injected transport (tests) a single attempt keeps timings sane.
        self._attempts = 1 if transport is not None else _MAX_ATTEMPTS
        self._client = httpx.AsyncClient(
            base_url=self.BASE_URL,
            timeout=httpx.Timeout(90.0),
            transport=transport,
        )

    @property
    def model(self) -> str:
        return self._model

    async def chat_json(self, *, system: str, user: str) -> dict[str, Any]:
        """Post a chat completion and return the parsed JSON object."""
        if not self._api_key:
            raise AppException(
                status_code=503,
                code="openrouter_config_error",
                message="OPENROUTER_API_KEY is not configured.",
            )

        payload = {
            "model": self._model,
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        headers = {"Authorization": f"Bearer {self._api_key}"}

        # Free-tier OpenRouter models are frequently rate-limited (429) or
        # flaky at the provider edge; retrying a few times with backoff makes
        # the cheap path usable. Authentication and validation failures are
        # never retried.
        for attempt in range(1, self._attempts + 1):
            try:
                response = await self._client.post(
                    "/api/v1/chat/completions",
                    headers=headers,
                    json=payload,
                )
            except httpx.RequestError as exc:
                if attempt < self._attempts:
                    logger.warning(
                        "openrouter request failed",
                        attempt=attempt,
                        error=str(exc),
                    )
                    await asyncio.sleep(2**attempt)
                    continue
                raise AppException(
                    status_code=503,
                    code="openrouter_unreachable",
                    message="OpenRouter could not be reached.",
                ) from exc

            if response.status_code in (401, 403):
                raise AppException(
                    status_code=503,
                    code="openrouter_config_error",
                    message="OpenRouter rejected the configured API key.",
                )
            if (
                response.status_code in _RETRYABLE_CODES
                and attempt < self._attempts
            ):
                logger.warning(
                    "openrouter retryable status",
                    status=response.status_code,
                    attempt=attempt,
                )
                await asyncio.sleep(2**attempt)
                continue
            if response.status_code == 429:
                raise AppException(
                    status_code=503,
                    code="openrouter_rate_limited",
                    message="OpenRouter rate limit hit; try again shortly.",
                )
            if response.status_code >= 500:
                raise AppException(
                    status_code=503,
                    code="openrouter_upstream_error",
                    message="OpenRouter reported an upstream error.",
                )
            if response.status_code != 200:
                logger.error(
                    "openrouter unexpected status",
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
            # body (e.g. "Service temporarily overloaded"); treat those as
            # retryable upstream failures instead of a valid completion.
            if not isinstance(data, dict) or "choices" not in data or "error" in data:
                if attempt < self._attempts:
                    logger.warning(
                        "openrouter body-level error",
                        attempt=attempt,
                        body=data.get("error", "missing choices") if isinstance(data, dict) else str(data)[:200],
                    )
                    await asyncio.sleep(2**attempt)
                    continue
                raise AppException(
                    status_code=502,
                    code="openrouter_upstream_error",
                    message="OpenRouter reported an upstream error.",
                )
            try:
                content = data["choices"][0]["message"]["content"]
                parsed = json.loads(content)
            except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
                logger.error("openrouter invalid response", error=str(exc))
                raise AppException(
                    status_code=502,
                    code="openrouter_invalid_response",
                    message="The model response was not valid JSON.",
                ) from exc

            if not isinstance(parsed, dict):
                raise AppException(
                    status_code=502,
                    code="openrouter_invalid_response",
                    message="The model response was not a JSON object.",
                )
            return parsed

        raise AppException(
            status_code=503,
            code="openrouter_upstream_error",
            message="OpenRouter could not be reached after retries.",
        )

    async def aclose(self) -> None:
        await self._client.aclose()