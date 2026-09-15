"""FastAPI dependency providers for backend services."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db_session
from app.repositories.analysis_repository import AnalysisRepository
from app.services.ai_service import AIService
from app.services.analysis_service import AnalysisService
from app.services.openrouter_service import OpenRouterService
from app.services.virustotal_service import VirusTotalService


def get_virustotal_service(request: Request) -> VirusTotalService:
    """Return the app-scoped VirusTotal service, creating it on demand.

    Created lazily so unit tests that do not exercise the lifespan still work.
    """
    service = getattr(request.app.state, "virustotal_service", None)
    if service is None:
        service = VirusTotalService()
        request.app.state.virustotal_service = service
    return service


def get_openrouter_service(request: Request) -> OpenRouterService:
    """Return the app-scoped OpenRouter service, creating it on demand."""
    service = getattr(request.app.state, "openrouter_service", None)
    if service is None:
        service = OpenRouterService()
        request.app.state.openrouter_service = service
    return service


def get_ai_service(
    openrouter: Annotated[OpenRouterService, Depends(get_openrouter_service)],
) -> AIService:
    return AIService(openrouter)


async def get_analysis_repository(
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> AnalysisRepository:
    """Build a repository bound to the request's database session."""
    return AnalysisRepository(session)


async def get_analysis_service(
    request: Request,
    repository: Annotated[AnalysisRepository, Depends(get_analysis_repository)],
    ai_service: Annotated[AIService, Depends(get_ai_service)],
) -> AnalysisService:
    return AnalysisService(get_virustotal_service(request), repository, ai_service)