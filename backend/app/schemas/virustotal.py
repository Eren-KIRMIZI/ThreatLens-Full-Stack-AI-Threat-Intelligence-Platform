"""Type definitions describing the raw VirusTotal API v3 shapes we consume.

Used as an internal contract between VirusTotalService and the normalizer.
"""

from __future__ import annotations

from typing import TypedDict


class VtDetectionResult(TypedDict, total=False):
    category: str
    result: str
    method: str


class VtDetectionStats(TypedDict, total=False):
    harmless: int
    malicious: int
    suspicious: int
    undetected: int
    timeout: int
    "type-unsupported": int


class VtAttributes(TypedDict, total=False):
    """Common attribute keys across file/url/domain/ip objects."""

    sha256: str
    sha1: str
    md5: str
    size: int
    type_description: str
    meaningful_name: str
    threat_names: list[str]
    names: list[str]
    tags: list[str]
    reputation: int
    total_votes: dict[str, int]
    first_submission_date: int
    last_analysis_date: int
    last_analysis_stats: VtDetectionStats
    last_analysis_results: dict[str, VtDetectionResult]

    # url
    url: str
    last_final_url: str
    title: str

    # domain
    registrar: str
    creation_date: int

    # ip
    country: str
    as_owner: str
    asn: int | str

    # analysis
    status: str
    date: int
    stats: VtDetectionStats


class VtObjectNode(TypedDict, total=False):
    """The 'data' node found under every VirusTotal object response."""

    id: str
    type: str
    attributes: VtAttributes


class VtRelationshipItem(TypedDict, total=False):
    attributes: VtDetectionResult


class VtRelationshipResponse(TypedDict, total=False):
    data: list[VtRelationshipItem]