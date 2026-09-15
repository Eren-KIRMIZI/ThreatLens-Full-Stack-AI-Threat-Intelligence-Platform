"""Report generation endpoints (JSON preview + PDF export)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Response

from app.api.deps import get_analysis_repository
from app.core.exceptions import NotFoundError
from app.repositories.analysis_repository import AnalysisRepository
from app.schemas.analysis import AnalysisResult
from app.schemas.report import ReportDocument
from app.services.report_service import build_report, render_pdf, report_filename

router = APIRouter(prefix="/reports", tags=["reports"])


async def _document(
    analysis_id: str,
    repository: AnalysisRepository,
) -> ReportDocument:
    row = await repository.get(analysis_id)
    if row is None:
        raise NotFoundError(
            "The requested analysis was not found.",
            code="analysis_not_found",
        )
    result = AnalysisResult(**row.payload)
    return build_report(result)


@router.get(
    "/{analysis_id}",
    response_model=ReportDocument,
    summary="Get the structured report of a stored analysis",
)
async def get_report(
    analysis_id: str,
    repository: Annotated[AnalysisRepository, Depends(get_analysis_repository)],
) -> ReportDocument:
    return await _document(analysis_id, repository)


@router.get(
    "/{analysis_id}/pdf",
    summary="Download the analysis as a PDF report",
    responses={
        200: {
            "description": "PDF bytes",
            "content": {"application/pdf": {}},
        }
    },
)
async def get_report_pdf(
    analysis_id: str,
    repository: Annotated[AnalysisRepository, Depends(get_analysis_repository)],
) -> Response:
    document = await _document(analysis_id, repository)
    pdf = render_pdf(document)
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{report_filename(document)}"',
            "Content-Length": str(len(pdf)),
        },
    )