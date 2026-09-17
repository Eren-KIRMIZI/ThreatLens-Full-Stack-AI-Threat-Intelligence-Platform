"""MITRE mapping, global search and digest endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_analysis_repository
from app.core.database import get_db_session
from app.core.exceptions import NotFoundError
from app.core.rbac import resolve_role
from app.repositories.analysis_repository import AnalysisRepository
from app.schemas.analysis import AnalysisResult
from app.schemas.digest import DigestOut, SearchResponse
from app.services import mitre
from app.services.enrichment_service import EnrichmentService
from app.services.intel_service import build_digest, global_search

router = APIRouter(prefix="/intel", tags=["intel"])


@router.get("/me", summary="Resolve the caller's role (RBAC introspection)")
async def me(request: Request) -> dict:
    return {"role": resolve_role(request)}


@router.get(
    "/mitre/catalog",
    summary="Curated MITRE ATT&CK technique catalog (validation / autocomplete)",
)
async def mitre_catalog() -> dict:
    return {"tactics": mitre.TACTICS, "techniques": mitre.CATALOG}


@router.get("/mitre/validate/{technique_id}", summary="Validate an ATT&CK technique id")
async def mitre_validate(technique_id: str) -> dict:
    return {"technique_id": technique_id, "valid": mitre.valid_technique(technique_id)}


@router.post("/mitre/map", summary="Map evidence text to ATT&CK techniques")
async def mitre_map(body: dict) -> dict:
    text = body.get("text") or ""
    extra = " ".join(body.get("tags") or [])
    mapped = mitre.map_text_to_techniques(f"{text} {extra}")
    return {"techniques": mapped}


@router.get("/mitre/analysis/{analysis_id}", summary="ATT&CK mapping for a stored analysis")
async def mitre_for_analysis(
    analysis_id: str,
    repository: Annotated[AnalysisRepository, Depends(get_analysis_repository)],
) -> dict:
    row = await repository.get(analysis_id)
    if row is None:
        raise NotFoundError(
            "The requested analysis was not found.", code="analysis_not_found"
        )
    result = AnalysisResult(**row.payload)
    mapped = mitre.map_evidence_to_mitre(result.enrichment.evidence if result.enrichment else [])
    for detection in result.detections:
        for hit in mitre.map_text_to_techniques(
            f"{detection.result or ''} {detection.engine}"
        ):
            if hit["id"] not in {item["id"] for item in mapped}:
                mapped.append(hit)
    # AI-disclosed tactics are validated here as a second pass.
    validated = []
    if result.ai and result.ai.tactics:
        for tactic in result.ai.tactics:
            if tactic.technique_id and mitre.valid_technique(tactic.technique_id):
                validated.append(
                    {
                        "id": tactic.technique_id,
                        "name": tactic.technique_name,
                        "tactic": tactic.phase,
                        "source": "ai",
                    }
                )
    return {
        "indicator": result.indicator,
        "mapped": sorted(
            [{**item, "source": "evidence"} for item in mapped] + validated,
            key=lambda item: item.get("id", ""),
        ),
    }


@router.get("/search", response_model=SearchResponse, summary="Platform-wide search")
async def search(
    q: str,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    limit: int = 25,
) -> SearchResponse:
    return await global_search(session, q, limit=min(limit, 100))


@router.get("/digest", response_model=DigestOut, summary="Analyst digest for a period")
async def digest(
    session: Annotated[AsyncSession, Depends(get_db_session)],
    window: str = "week",
) -> DigestOut:
    return await build_digest(session, window)