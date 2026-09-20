"""Phishing email forensic schemas.

The analysis is deterministic and evidence-locked: every finding points
at concrete bytes in the message (extracted URL, header value, attachment
hash) and the risk score is the plain sum of weighted rules, translated
through the shared ``level_for_score`` bands so an email verdict stays
comparable with indicator verdicts.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class EmailHeader(BaseModel):
    """A raw RFC-822 header reproduced for the analyst."""

    name: str
    value: str


class HeaderFinding(BaseModel):
    """Why a specific header is flagged (or noteworthy)."""

    label: str
    detail: str
    risk: int = Field(0, ge=-100, le=100)


class EmailLink(BaseModel):
    """One URL extracted from the message body."""

    url: str
    display_text: str | None = None
    domain: str | None = None
    brand: str | None = None
    brand_risk: bool = False
    https: bool = False
    ip_host: bool = False
    shortener: bool = False
    suspicious_tld: bool = False
    risk: int = Field(0, ge=0, le=100)


class TrackingPixel(BaseModel):
    """A 1x1 / transparent image request used for open tracking."""

    url: str | None = None
    width: str | None = None
    height: str | None = None
    transparent: bool = False


class EmailAttachmentInfo(BaseModel):
    """Attachment metadata; the raw sample is never stored."""

    filename: str | None = None
    content_type: str | None = None
    size_bytes: int | None = None
    sha256: str | None = None
    risky_extension: bool = False


class EmailForensicBrief(BaseModel):
    """Analyst-facing message overview."""

    subject: str | None = None
    date: str | None = None
    sender_display: str | None = None
    sender_email: str | None = None
    sender_domain: str | None = None
    reply_to: str | None = None
    message_id: str | None = None
    headers: list[EmailHeader] = Field(default_factory=list)


class EmailForensicOut(BaseModel):
    """The complete phishing forensics verdict for one message."""

    brief: EmailForensicBrief
    header_findings: list[HeaderFinding] = Field(default_factory=list)
    urls: list[EmailLink] = Field(default_factory=list)
    tracking_pixels: list[TrackingPixel] = Field(default_factory=list)
    attachments: list[EmailAttachmentInfo] = Field(default_factory=list)
    rule_hits: list[str] = Field(default_factory=list)
    risk_score: int = Field(0, ge=0, le=100)
    risk_level: str = "clean"
    summary_points: list[str] = Field(default_factory=list)
    mitigations: list[str] = Field(default_factory=list)
    html_source: str | None = None
    text_body: str | None = None


class EmailRawRequest(BaseModel):
    """Raw RFC-822 payload submitted over JSON."""

    raw: str = Field(min_length=1, max_length=3_000_000)