"""Indicator analysis endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, UploadFile

from app.api.deps import get_analysis_service
from app.core.config import get_settings
from app.core.rbac import require_role
from app.schemas.analysis import (
    AIRequestMixin,
    AnalysisResult,
    DomainAnalysisRequest,
    HashAnalysisRequest,
    IpAnalysisRequest,
    UrlAnalysisRequest,
)
from app.services.analysis_service import AnalysisService

router = APIRouter(prefix="/analyze", tags=["analyze"])


def _resolve_ai(request: AIRequestMixin) -> bool:
    """Resolve per-request AI flag, falling back to the server default."""
    if request.ai is not None:
        return request.ai
    return get_settings().ai_assist_default


@router.post(
    "/hash",
    response_model=AnalysisResult,
    status_code=201,
    summary="Analyze a hash",
)
async def analyze_hash(
    body: HashAnalysisRequest,
    service: Annotated[AnalysisService, Depends(get_analysis_service)],
    _role: Annotated[str, Depends(require_role("analyst"))],
) -> AnalysisResult:
    """Analyze a SHA256, SHA1 or MD5 hash using the existing VirusTotal report."""
    return await service.analyze_hash(body.hash, with_ai=_resolve_ai(body))


@router.post(
    "/url",
    response_model=AnalysisResult,
    status_code=201,
    summary="Analyze a URL",
)
async def analyze_url(
    body: UrlAnalysisRequest,
    service: Annotated[AnalysisService, Depends(get_analysis_service)],
    _role: Annotated[str, Depends(require_role("analyst"))],
) -> AnalysisResult:
    """Analyze a URL. Submits it for scanning when no report exists yet."""
    return await service.analyze_url(body.url, with_ai=_resolve_ai(body))


@router.post(
    "/domain",
    response_model=AnalysisResult,
    status_code=201,
    summary="Analyze a domain",
)
async def analyze_domain(
    body: DomainAnalysisRequest,
    service: Annotated[AnalysisService, Depends(get_analysis_service)],
    _role: Annotated[str, Depends(require_role("analyst"))],
) -> AnalysisResult:
    """Analyze a domain's reputation and related VirusTotal intelligence."""
    return await service.analyze_domain(body.domain, with_ai=_resolve_ai(body))


@router.post(
    "/ip",
    response_model=AnalysisResult,
    status_code=201,
    summary="Analyze an IP address",
)
async def analyze_ip(
    body: IpAnalysisRequest,
    service: Annotated[AnalysisService, Depends(get_analysis_service)],
    _role: Annotated[str, Depends(require_role("analyst"))],
) -> AnalysisResult:
    """Analyze an IP address reputation and associated indicators."""
    return await service.analyze_ip(body.ip, with_ai=_resolve_ai(body))


@router.post(
    "/file",
    response_model=AnalysisResult,
    status_code=201,
    summary="Analyze an uploaded file",
)
async def analyze_file(
    file: Annotated[UploadFile, File(description="File to analyze")],
    _role: Annotated[str, Depends(require_role("analyst"))],
    service: Annotated[AnalysisService, Depends(get_analysis_service)],
    ai: Annotated[bool, Form(description="Run the evidence-based AI interpretation")] = False,
) -> AnalysisResult:
    """Upload a file; hashes are computed server-side and submitted to VirusTotal.

    The raw sample is never stored and never reaches the AI layer.
    """
    return await service.analyze_file(file, with_ai=ai)