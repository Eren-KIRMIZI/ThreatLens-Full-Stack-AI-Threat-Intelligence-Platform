"""VirusTotal API v3 client.

All VirusTotal access flows through this service; the frontend never talks
to VirusTotal directly. Raw responses are returned to the normalizer, which
converts them into ThreatLens' standardized analysis schemas.
"""

from __future__ import annotations

import asyncio
import base64
import time
from typing import Any

import httpx

from app.core.config import get_settings
from app.core.exceptions import (
    ConfigurationError,
    NotFoundError,
    RateLimitError,
    ServiceUnavailableError,
)
from app.core.logging import get_logger

logger = get_logger(__name__)

VT_BASE_URL = "https://www.virustotal.com/api/v3"
ANALYSIS_POLL_INTERVAL_SECONDS = 3.0
ANALYSIS_POLL_TIMEOUT_SECONDS = 60.0


class VirusTotalService:
    """Thin, testable async wrapper around the VirusTotal v3 REST API."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str = VT_BASE_URL,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._api_key = api_key if api_key is not None else get_settings().virustotal_api_key
        self._base_url = base_url.rstrip("/")
        self._transport = transport
        self._client: httpx.AsyncClient | None = None

    @property
    def configured(self) -> bool:
        return bool(self._api_key)

    @staticmethod
    def url_id(url: str) -> str:
        """Compute the VirusTotal URL identifier (base64url, unpadded)."""
        encoded = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii")
        return encoded.rstrip("=")

    def _require_key(self) -> None:
        if not self._api_key:
            raise ConfigurationError(
                "VirusTotal is not configured. Add VIRUSTOTAL_API_KEY to the backend environment.",
                code="virustotal_config_error",
            )

    def _client_instance(self) -> httpx.AsyncClient:
        if self._client is None:
            headers = {"x-apikey": self._api_key} if self._api_key else {}
            self._client = httpx.AsyncClient(
                base_url=self._base_url,
                headers=headers,
                timeout=httpx.Timeout(30.0, connect=10.0),
                transport=self._transport,
            )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # ------------------------------------------------------------------ #
    # Low-level HTTP
    # ------------------------------------------------------------------ #

    async def _get(self, path: str) -> dict[str, Any]:
        self._require_key()
        client = self._client_instance()
        try:
            response = await client.get(path)
        except httpx.HTTPError as exc:
            raise ServiceUnavailableError(
                "Unable to reach VirusTotal. Please try again in a moment.",
                code="virustotal_network_error",
            ) from exc
        return self._decode_response(response, path)

    async def _post_form(self, path: str, data: dict[str, str]) -> dict[str, Any]:
        self._require_key()
        client = self._client_instance()
        try:
            response = await client.post(path, data=data)
        except httpx.HTTPError as exc:
            raise ServiceUnavailableError(
                "Unable to reach VirusTotal. Please try again in a moment.",
                code="virustotal_network_error",
            ) from exc
        return self._decode_response(response, path)

    def _decode_response(self, response: httpx.Response, path: str) -> dict[str, Any]:
        if response.status_code == 200:
            return response.json()
        logger.error(
            "virustotal request failed",
            status_code=response.status_code,
            path=path,
            detail=response.text[:200],
        )
        if response.status_code in (401, 403):
            raise ConfigurationError(
                "VirusTotal rejected the configured API key.",
                code="virustotal_auth_error",
            )
        if response.status_code == 404:
            raise NotFoundError(
                "The indicator was not found on VirusTotal.",
                code="indicator_not_found",
            )
        if response.status_code == 429:
            raise RateLimitError(
                "VirusTotal rate limit exceeded. Please try again in a moment.",
                code="virustotal_rate_limited",
            )
        raise ServiceUnavailableError(
            "VirusTotal is temporarily unavailable. Please try again in a moment.",
            code="virustotal_unavailable",
        )

    # ------------------------------------------------------------------ #
    # Public operations
    # ------------------------------------------------------------------ #

    async def get_file(self, hash_value: str) -> dict[str, Any]:
        """Fetch the file report object's top-level data node."""
        data = await self._get(f"/files/{hash_value}")
        return data["data"]

    async def upload_file(self, filename: str, content: bytes) -> dict[str, Any]:
        """Submit a file to VirusTotal and return the analysis data node."""
        self._require_key()
        client = self._client_instance()
        try:
            response = await client.post(
                "/files",
                files={"file": (filename, content, "application/octet-stream")},
                params={"filename": filename},
            )
        except httpx.HTTPError as exc:
            raise ServiceUnavailableError(
                "Unable to reach VirusTotal. Please try again in a moment.",
                code="virustotal_network_error",
            ) from exc
        payload = self._decode_response(response, "/files")
        return payload["data"]

    async def get_or_submit_url(self, url: str) -> tuple[dict[str, Any], str]:
        """Return the URL report data node and its origin.

        origin is either ``"url"`` (existing report object) or ``"analysis"``
        (a freshly submitted URL whose analysis has completed).
        """
        identifier = self.url_id(url)
        try:
            data = await self._get(f"/urls/{identifier}")
            return data["data"], "url"
        except NotFoundError:
            submission = await self._submit_url(url)
            analysis_id = submission["data"]["id"]
            data = await self.wait_for_analysis(analysis_id)
            return data, "analysis"

    async def get_domain(self, domain: str) -> dict[str, Any]:
        data = await self._get(f"/domains/{domain}")
        return data["data"]

    async def get_ip(self, ip: str) -> dict[str, Any]:
        data = await self._get(f"/ip_addresses/{ip}")
        return data["data"]

    async def get_last_analysis_results(
        self, collection: str, value: str
    ) -> list[dict[str, Any]]:
        """Fetch per-engine detection results for domains / ip addresses."""
        try:
            response = await self._get(f"/{collection}/{value}/last_analysis_results")
        except NotFoundError:
            return []
        return [item.get("attributes", {}) for item in response.get("data", [])]

    async def get_analysis(self, analysis_id: str) -> dict[str, Any]:
        """Fetch an analysis object by id (used by the polling flow)."""
        data = await self._get(f"/analyses/{analysis_id}")
        return data["data"]

    async def wait_for_analysis(
        self,
        analysis_id: str,
        *,
        timeout: float = ANALYSIS_POLL_TIMEOUT_SECONDS,
        interval: float = ANALYSIS_POLL_INTERVAL_SECONDS,
    ) -> dict[str, Any]:
        """Poll an analysis until VirusTotal reports it as completed."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            data = await self.get_analysis(analysis_id)
            status = data.get("attributes", {}).get("status")
            if status == "completed":
                return data
            await asyncio.sleep(interval)
        raise ServiceUnavailableError(
            "The VirusTotal analysis is taking longer than expected. Please try again in a moment.",
            code="virustotal_analysis_timeout",
        )

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    async def _submit_url(self, url: str) -> dict[str, Any]:
        response = await self._post_form("/urls", {"url": url})
        return response