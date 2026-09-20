"""Phishing forensics endpoints.

The submitted message is parsed in-memory, scored deterministically and
discarded. The raw sample never touches disk, the database or the AI
layer — the answer is only ever derived from the bytes you provide.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile

from app.core.rbac import require_role
from app.schemas.forensics import EmailForensicOut, EmailRawRequest
from app.services.email_forensics import analyze_email

router = APIRouter(prefix="/forensics", tags=["forensics"])

MAX_UPLOAD_BYTES = 3_000_000


@router.post(
    "/email",
    response_model=EmailForensicOut,
    status_code=200,
    summary="Analyze an uploaded .eml / raw RFC-822 message",
)
async def forensic_email(
    file: Annotated[UploadFile, File(description="Raw email message (.eml or RFC-822 text)")],
    _role: Annotated[str, Depends(require_role("analyst"))],
) -> EmailForensicOut:
    """Parse and score a message uploaded as a file (no persistence)."""
    payload = await file.read()
    if len(payload) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Uploaded message exceeds the 3 MB limit")
    return analyze_email(payload)


@router.post(
    "/email/raw",
    response_model=EmailForensicOut,
    status_code=200,
    summary="Analyze a pasted raw RFC-822 message",
)
async def forensic_email_raw(
    body: EmailRawRequest,
    _role: Annotated[str, Depends(require_role("analyst"))],
) -> EmailForensicOut:
    """Parse and score a message pasted as raw RFC-822 text."""
    return analyze_email(body.raw)