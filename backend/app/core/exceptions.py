"""Domain exceptions and API error serialization.

All errors surfaced to clients are converted into a uniform payload:

    {"error": {"code": str, "message": str, "details": ...}}

Stack traces are only logged server-side and never returned to the client.
"""

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.logging import get_logger

logger = get_logger(__name__)


class AppException(Exception):
    """Base class for domain errors intended to reach the API consumer."""

    status_code = 500
    code = "internal_error"
    message = "An unexpected error occurred."

    def __init__(
        self,
        message: str | None = None,
        *,
        status_code: int | None = None,
        code: str | None = None,
        details: dict[str, Any] | list[Any] | None = None,
    ) -> None:
        self.message = message or self.message
        if status_code is not None:
            self.status_code = status_code
        if code is not None:
            self.code = code
        self.details = details
        super().__init__(self.message)


class ServiceUnavailableError(AppException):
    """Raised when an upstream provider (VirusTotal / OpenRouter) fails."""

    status_code = 503
    code = "service_unavailable"
    message = "The upstream service is temporarily unavailable."


class RateLimitError(AppException):
    """Raised when an upstream provider rate-limits the request."""

    status_code = 429
    code = "rate_limited"
    message = "Rate limit exceeded. Please try again in a moment."


class ConfigurationError(AppException):
    """Raised when required configuration (e.g. an API key) is missing."""

    status_code = 503
    code = "configuration_error"
    message = "The service is not fully configured."


class NotFoundError(AppException):
    status_code = 404
    code = "not_found"
    message = "The requested resource was not found."


def _error_payload(code: str, message: str, details: Any = None) -> dict[str, Any]:
    payload: dict[str, Any] = {"error": {"code": code, "message": message}}
    if details is not None:
        payload["error"]["details"] = details
    return payload


def _serialize_validation_errors(exc: RequestValidationError) -> list[dict[str, str]]:
    errors: list[dict[str, str]] = []
    for err in exc.errors():
        loc = ".".join(str(part) for part in err.get("loc", ()) if part not in {"body", "query", "path", "header"})
        errors.append(
            {
                "field": loc or "request",
                "message": str(err.get("msg", "Invalid value.")),
            }
        )
    return errors


def register_exception_handlers(app: FastAPI) -> None:
    """Register JSON error handlers for every error category."""

    @app.exception_handler(AppException)
    async def app_exception_handler(request: Request, exc: AppException) -> JSONResponse:
        logger.error(
            "domain error handled",
            code=exc.code,
            status_code=exc.status_code,
            path=request.url.path,
        )
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_payload(exc.code, exc.message, exc.details),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content=_error_payload(
                "validation_error",
                "Request validation failed.",
                _serialize_validation_errors(exc),
            ),
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        if exc.status_code == 404:
            return JSONResponse(
                status_code=404,
                content=_error_payload("not_found", "The requested resource was not found."),
            )
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_payload("http_error", str(exc.detail)),
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception(
            "unhandled exception",
            path=request.url.path,
            exc_type=type(exc).__name__,
        )
        return JSONResponse(
            status_code=500,
            content=_error_payload("internal_error", "An unexpected error occurred."),
        )