"""Investigation (case) management endpoints.

Cases group indicators/analyses. Notes, tags and pinning are analyst
workflow helpers attached at the analysis level.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.deps import (
    get_investigation_repository,
    get_registry_repository,
)
from app.core.exceptions import NotFoundError
from app.core.rbac import require_role
from app.repositories.investigation_repository import InvestigationRepository
from app.repositories.registry_repository import RegistryRepository
from app.schemas.investigations import (
    CampaignCreate,
    CampaignEvidenceCreate,
    CampaignEvidenceOut,
    CampaignEvidenceUpdate,
    CampaignOut,
    CampaignUpdate,
    InvestigationCreate,
    InvestigationItemOut,
    InvestigationNoteCreate,
    InvestigationNoteOut,
    InvestigationOut,
    InvestigationPage,
    InvestigationUpdate,
    NoteCreate,
    NoteOut,
    TagCreate,
)
from app.utils.ioc import canonical_value

router = APIRouter(prefix="/investigations", tags=["investigations"])


@router.get("", response_model=InvestigationPage, summary="List cases")
async def list_investigations(
    repository: Annotated[InvestigationRepository, Depends(get_investigation_repository)],
    limit: int = 25,
    offset: int = 0,
    status: str | None = None,
) -> InvestigationPage:
    rows, total = await repository.list(
        limit=min(limit, 200), offset=offset, status=status
    )
    items = [_to_out(row, await repository.items(row.id)) for row in rows]
    return InvestigationPage(items=items, total=total, limit=limit, offset=offset)


@router.post(
    "", response_model=InvestigationOut, status_code=201, summary="Open a case"
)
async def create_investigation(
    body: InvestigationCreate,
    repository: Annotated[InvestigationRepository, Depends(get_investigation_repository)],
    _role: Annotated[str, Depends(require_role("analyst"))],
) -> InvestigationOut:
    row = await repository.create(
        title=body.title,
        description=body.description,
        status=body.status,
        severity=body.severity,
    )
    return _to_out(row, [])


@router.get("/{investigation_id}", response_model=InvestigationOut)
async def get_investigation(
    investigation_id: str,
    repository: Annotated[InvestigationRepository, Depends(get_investigation_repository)],
) -> InvestigationOut:
    row = await repository.get(investigation_id)
    if row is None:
        raise NotFoundError(
            "The investigation was not found.", code="investigation_not_found"
        )
    return _to_out(row, await repository.items(investigation_id))


@router.patch("/{investigation_id}", response_model=InvestigationOut)
async def update_investigation(
    investigation_id: str,
    body: InvestigationUpdate,
    repository: Annotated[InvestigationRepository, Depends(get_investigation_repository)],
    _role: Annotated[str, Depends(require_role("analyst"))],
) -> InvestigationOut:
    row = await repository.update_core(
        investigation_id,
        **body.model_dump(exclude_none=True),
    )
    if row is None:
        raise NotFoundError(
            "The investigation was not found.", code="investigation_not_found"
        )
    return _to_out(row, await repository.items(investigation_id))


@router.delete("/{investigation_id}", status_code=204)
async def delete_investigation(
    investigation_id: str,
    repository: Annotated[InvestigationRepository, Depends(get_investigation_repository)],
    _role: Annotated[str, Depends(require_role("admin"))],
) -> None:
    if not await repository.delete(investigation_id):
        raise NotFoundError(
            "The investigation was not found.", code="investigation_not_found"
        )


@router.post("/{investigation_id}/items", response_model=InvestigationItemOut, status_code=201)
async def add_item(
    investigation_id: str,
    value: str,
    _role: Annotated[str, Depends(require_role("analyst"))],
    repository: Annotated[InvestigationRepository, Depends(get_investigation_repository)],
    registry: Annotated[RegistryRepository, Depends(get_registry_repository)],
    primary_type: str | None = None,
    analysis_id: str | None = None,
) -> InvestigationItemOut:
    canonical = canonical_value(primary_type or "HASH", value) or value
    item_type = primary_type.upper() if primary_type else None
    if item_type is None:
        item_type = (await _infer_type(registry, canonical)) or "HASH"
    row = await repository.add_item(
        investigation_id=investigation_id,
        value=canonical,
        primary_type=item_type,
        analysis_id=analysis_id,
    )
    if row is None:
        raise NotFoundError(
            "The investigation was not found.", code="investigation_not_found"
        )
    return InvestigationItemOut(**row.__dict__)


@router.post("/{analysis_id}/notes", response_model=NoteOut, status_code=201)
async def add_note(
    analysis_id: str,
    body: NoteCreate,
    repository: Annotated[InvestigationRepository, Depends(get_investigation_repository)],
    _role: Annotated[str, Depends(require_role("analyst"))],
) -> NoteOut:
    row = await repository.add_note(
        analysis_id=analysis_id, author=body.author, body=body.body
    )
    return NoteOut(**row.__dict__)


@router.get("/analysis/{analysis_id}/notes", response_model=list[NoteOut])
async def list_notes(
    analysis_id: str,
    repository: Annotated[InvestigationRepository, Depends(get_investigation_repository)],
) -> list[NoteOut]:
    rows = await repository.notes(analysis_id)
    return [NoteOut(**row.__dict__) for row in rows]


@router.post("/analysis/{analysis_id}/tags", response_model=TagCreate, status_code=201)
async def add_tag(
    analysis_id: str,
    body: TagCreate,
    repository: Annotated[InvestigationRepository, Depends(get_investigation_repository)],
    _role: Annotated[str, Depends(require_role("analyst"))],
) -> TagCreate:
    await repository.add_tag(analysis_id=analysis_id, tag=body.tag)
    return body


@router.get("/analysis/{analysis_id}/tags", response_model=list[str])
async def list_tags(
    analysis_id: str,
    repository: Annotated[InvestigationRepository, Depends(get_investigation_repository)],
) -> list[str]:
    return await repository.tags(analysis_id)


@router.post("/analysis/{analysis_id}/pin", response_model=dict)
async def set_pin(
    analysis_id: str,
    pinned: bool,
    repository: Annotated[InvestigationRepository, Depends(get_investigation_repository)],
    _role: Annotated[str, Depends(require_role("analyst"))],
) -> dict:
    await repository.set_pinned(analysis_id, pinned)
    return {"analysis_id": analysis_id, "pinned": pinned}


@router.get("/pinned/list", response_model=list[str])
async def pinned_list(
    repository: Annotated[InvestigationRepository, Depends(get_investigation_repository)],
) -> list[str]:
    return await repository.pinned_ids()


@router.post(
    "/{investigation_id}/case-notes",
    response_model=InvestigationNoteOut,
    status_code=201,
    summary="Add a note to a case",
)
async def add_case_note(
    investigation_id: str,
    body: InvestigationNoteCreate,
    repository: Annotated[InvestigationRepository, Depends(get_investigation_repository)],
    _role: Annotated[str, Depends(require_role("analyst"))],
) -> InvestigationNoteOut:
    row = await repository.add_case_note(
        investigation_id=investigation_id,
        author=body.author,
        body=body.body,
    )
    if row is None:
        raise NotFoundError(
            "The investigation was not found.", code="investigation_not_found"
        )
    return InvestigationNoteOut(**row.__dict__)


@router.get(
    "/{investigation_id}/case-notes",
    response_model=list[InvestigationNoteOut],
    summary="List notes of a case",
)
async def list_case_notes(
    investigation_id: str,
    repository: Annotated[InvestigationRepository, Depends(get_investigation_repository)],
) -> list[InvestigationNoteOut]:
    rows = await repository.case_notes(investigation_id)
    return [InvestigationNoteOut(**row.__dict__) for row in rows]


@router.delete("/notes/{note_id}", status_code=204)
async def delete_case_note(
    note_id: str,
    repository: Annotated[InvestigationRepository, Depends(get_investigation_repository)],
    _role: Annotated[str, Depends(require_role("analyst"))],
) -> None:
    if not await repository.delete_case_note(note_id):
        raise NotFoundError("The note was not found.", code="note_not_found")


@router.post(
    "/{investigation_id}/campaigns",
    response_model=CampaignOut,
    status_code=201,
    summary="Open a campaign inside a case",
)
async def create_campaign(
    investigation_id: str,
    body: CampaignCreate,
    repository: Annotated[InvestigationRepository, Depends(get_investigation_repository)],
    _role: Annotated[str, Depends(require_role("analyst"))],
) -> CampaignOut:
    row = await repository.create_campaign(
        investigation_id=investigation_id,
        name=body.name.strip(),
        color=body.color,
    )
    if row is None:
        raise NotFoundError(
            "The investigation was not found.", code="investigation_not_found"
        )
    return _campaign_out(row, [])


@router.get(
    "/{investigation_id}/campaigns",
    response_model=list[CampaignOut],
    summary="List campaigns of a case",
)
async def list_campaigns(
    investigation_id: str,
    repository: Annotated[InvestigationRepository, Depends(get_investigation_repository)],
) -> list[CampaignOut]:
    rows = await repository.campaigns(investigation_id)
    return [
        _campaign_out(row, await repository.campaign_evidence(row.id))
        for row in rows
    ]


@router.patch(
    "/campaigns/{campaign_id}",
    response_model=CampaignOut,
    summary="Rename / recolor a campaign",
)
async def update_campaign(
    campaign_id: str,
    body: CampaignUpdate,
    repository: Annotated[InvestigationRepository, Depends(get_investigation_repository)],
    _role: Annotated[str, Depends(require_role("analyst"))],
) -> CampaignOut:
    row = await repository.update_campaign(
        campaign_id, name=body.name, color=body.color
    )
    if row is None:
        raise NotFoundError(
            "The campaign was not found.", code="campaign_not_found"
        )
    return _campaign_out(row, await repository.campaign_evidence(campaign_id))


@router.delete("/campaigns/{campaign_id}", status_code=204)
async def delete_campaign(
    campaign_id: str,
    repository: Annotated[InvestigationRepository, Depends(get_investigation_repository)],
    _role: Annotated[str, Depends(require_role("analyst"))],
) -> None:
    if not await repository.delete_campaign(campaign_id):
        raise NotFoundError("The campaign was not found.", code="campaign_not_found")


@router.post(
    "/campaigns/{campaign_id}/evidence",
    response_model=CampaignEvidenceOut,
    status_code=201,
    summary="Mark an indicator as evidence in a campaign",
)
async def add_campaign_evidence(
    campaign_id: str,
    body: CampaignEvidenceCreate,
    repository: Annotated[InvestigationRepository, Depends(get_investigation_repository)],
    _role: Annotated[str, Depends(require_role("analyst"))],
) -> CampaignEvidenceOut:
    row = await repository.add_campaign_evidence(
        campaign_id=campaign_id,
        analysis_id=body.analysis_id,
        value=canonical_value(body.primary_type, body.value) or body.value,
        primary_type=body.primary_type.upper(),
        note=body.note,
    )
    if row is None:
        raise NotFoundError("The campaign was not found.", code="campaign_not_found")
    return CampaignEvidenceOut(**row.__dict__)


@router.patch(
    "/campaigns/{campaign_id}/evidence/{evidence_id}",
    response_model=CampaignEvidenceOut,
    summary="Annotate an evidence record",
)
async def update_campaign_evidence(
    campaign_id: str,
    evidence_id: str,
    body: CampaignEvidenceUpdate,
    repository: Annotated[InvestigationRepository, Depends(get_investigation_repository)],
    _role: Annotated[str, Depends(require_role("analyst"))],
) -> CampaignEvidenceOut:
    row = await repository.update_campaign_evidence(evidence_id, note=body.note)
    if row is None:
        raise NotFoundError(
            "The evidence was not found.", code="evidence_not_found"
        )
    return CampaignEvidenceOut(**row.__dict__)


@router.delete(
    "/campaigns/{campaign_id}/evidence/{evidence_id}",
    status_code=204,
    summary="Unmark an evidence record",
)
async def delete_campaign_evidence(
    campaign_id: str,
    evidence_id: str,
    repository: Annotated[InvestigationRepository, Depends(get_investigation_repository)],
    _role: Annotated[str, Depends(require_role("analyst"))],
) -> None:
    if not await repository.delete_campaign_evidence(evidence_id):
        raise NotFoundError(
            "The evidence was not found.", code="evidence_not_found"
        )


def _campaign_out(row, evidence_rows) -> CampaignOut:
    return CampaignOut(
        id=row.id,
        investigation_id=row.investigation_id,
        name=row.name,
        color=row.color,
        created_at=row.created_at,
        evidence=[CampaignEvidenceOut(**item.__dict__) for item in evidence_rows],
    )


def _to_out(row, items) -> InvestigationOut:
    return InvestigationOut(
        id=row.id,
        title=row.title,
        description=row.description,
        status=row.status,
        severity=row.severity,
        created_at=row.created_at,
        updated_at=row.updated_at,
        items=[InvestigationItemOut(**item.__dict__) for item in items],
    )


async def _infer_type(registry: RegistryRepository, value: str) -> str | None:
    try:
        item = await registry.get_indicator(value)
    except Exception:
        item = None
    return item.primary_type if item else None