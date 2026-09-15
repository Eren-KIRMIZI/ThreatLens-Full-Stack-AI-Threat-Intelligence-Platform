"""Lookup of a single stored analysis result."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.deps import get_ai_service, get_analysis_repository
from app.core.exceptions import NotFoundError
from app.repositories.analysis_repository import AnalysisRepository
from app.schemas.ai import AIAnalysis
from app.schemas.analysis import AnalysisResult
from app.services.ai_service import AIService
from app.services.scoring import score_analysis

router = APIRouter(prefix="/analysis", tags=["analysis"])


@router.get(
    "/{analysis_id}",
    response_model=AnalysisResult,
    summary="Get a stored analysis result",
)
async def get_analysis(
    analysis_id: str,
    repository: Annotated[AnalysisRepository, Depends(get_analysis_repository)],
) -> AnalysisResult:
    row = await repository.get(analysis_id)
    if row is None:
        raise NotFoundError(
            "The requested analysis was not found.",
            code="analysis_not_found",
        )
    return AnalysisResult(**row.payload)


@router.post(
    "/{analysis_id}/ai",
    response_model=AIAnalysis,
    summary="Run / refresh the AI interpretation of a stored analysis",
)
async def enrich_with_ai(
    analysis_id: str,
    repository: Annotated[AnalysisRepository, Depends(get_analysis_repository)],
    ai_service: Annotated[AIService, Depends(get_ai_service)],
) -> AIAnalysis:
    row = await repository.get(analysis_id)
    if row is None:
        raise NotFoundError(
            "The requested analysis was not found.",
            code="analysis_not_found",
        )
    result = AnalysisResult(**row.payload)
    if result.threat_score is None:
        result.threat_score, result.threat_level = score_analysis(result)
        row.payload = result.model_dump(mode="json")
    if result.ai is None:
        result.ai = await ai_service.interpret(result)
        await repository.update_payload(result.analysis_id, result.model_dump(mode="json"))
    return result.ai