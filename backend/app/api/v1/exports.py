"""Export endpoints: history CSV, analysis JSON, STIX 2.1, YARA and Sigma."""

from __future__ import annotations

import csv
import io
import json
from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.responses import Response

from app.api.deps import get_analysis_repository
from app.core.exceptions import NotFoundError
from app.repositories.analysis_repository import AnalysisRepository
from app.schemas.analysis import AnalysisResult
from app.services import signatures, stix

router = APIRouter(prefix="/export", tags=["export"])


async def _analysis_or_404(
    analysis_id: str, repository: AnalysisRepository
) -> AnalysisResult:
    row = await repository.get(analysis_id)
    if row is None:
        raise NotFoundError(
            "The requested analysis was not found.", code="analysis_not_found"
        )
    return AnalysisResult(**row.payload)


@router.get(
    "/history.csv",
    response_class=Response,
    summary="Download the analysis history as CSV",
)
async def export_history_csv(
    repository: Annotated[AnalysisRepository, Depends(get_analysis_repository)],
    filter: str = "all",
    limit: int = 2000,
) -> Response:
    rows, _total = await repository.list_history(
        limit=min(limit, 10000),
        offset=0,
        threat_filter=filter,  # type: ignore[arg-type]
    )
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        ["analysis_id", "indicator", "indicator_type", "threat_score",
         "threat_level", "malicious", "suspicious", "analyzed_at"]
    )
    for row in rows:
        writer.writerow(
            [
                row.id,
                row.indicator,
                row.indicator_type,
                row.threat_score if row.threat_score is not None else "",
                row.threat_level or "",
                row.malicious_count,
                row.suspicious_count,
                row.analyzed_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            ]
        )
    content = buffer.getvalue().encode("utf-8")
    return Response(
        content=content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=threatlens-history.csv"},
    )


@router.get("/analyses/{analysis_id}.json", response_class=Response)
async def export_analysis_json(
    analysis_id: str,
    repository: Annotated[AnalysisRepository, Depends(get_analysis_repository)],
) -> Response:
    row = await repository.get(analysis_id)
    if row is None:
        raise NotFoundError(
            "The requested analysis was not found.", code="analysis_not_found"
        )
    content = json.dumps(row.payload, indent=2).encode("utf-8")
    return Response(
        content=content,
        media_type="application/json",
        headers={
            "Content-Disposition": (
                f'attachment; filename="threatlens-{analysis_id[:8]}.json"'
            )
        },
    )


@router.get("/analyses/{analysis_id}/stix.json", response_class=Response)
async def export_stix(
    analysis_id: str,
    repository: Annotated[AnalysisRepository, Depends(get_analysis_repository)],
) -> Response:
    result = await _analysis_or_404(analysis_id, repository)
    return Response(
        content=stix.stix_to_json(result).encode("utf-8"),
        media_type="application/vnd.oasis.stix+json",
        headers={
            "Content-Disposition": f'attachment; filename="threatlens-{analysis_id[:8]}-stix.json"'
        },
    )


@router.get("/analyses/{analysis_id}/{format}", response_class=Response)
async def export_signature(
    analysis_id: str,
    format: str,
    repository: Annotated[AnalysisRepository, Depends(get_analysis_repository)],
) -> Response:
    result = await _analysis_or_404(analysis_id, repository)
    if format == "yara":
        body = signatures.generate_yara(result)
        mime = "text/yara"
        suffix = "yar"
    elif format == "sigma":
        body = signatures.generate_sigma(result)
        mime = "text/yaml"
        suffix = "yml"
    else:
        raise NotFoundError(
            "Unsupported signature format.",
            code="unsupported_signature_format",
        )
    return Response(
        content=body.encode("utf-8"),
        media_type=mime,
        headers={
            "Content-Disposition": (
                f'attachment; filename="threatlens-{analysis_id[:8]}-rule.{suffix}"'
            )
        },
    )
