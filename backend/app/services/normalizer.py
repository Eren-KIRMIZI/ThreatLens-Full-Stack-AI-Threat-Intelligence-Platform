"""Normalization: raw VirusTotal objects → standardized ThreatLens schemas.

This is the explicit mapping step in the
`Raw VirusTotal Data → Normalization → Relevant Evidence → LLM` pipeline.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from app.schemas.analysis import (
    AnalysisResult,
    DetectionEntry,
    DetectionStats,
    DomainMetadata,
    FileMetadata,
    IndicatorMetadata,
    IpMetadata,
    UrlMetadata,
)

_CATEGORY_ORDER = {
    "malicious": 0,
    "suspicious": 1,
    "harmless": 2,
    "undetected": 3,
    "timeout": 4,
    "type-unsupported": 5,
}


def _epoch_to_dt(value: Any) -> datetime | None:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(int(value), tz=timezone.utc)
    return None


def _stats(attributes: dict[str, Any]) -> DetectionStats:
    raw = attributes.get("last_analysis_stats") or attributes.get("stats") or {}
    return DetectionStats(
        malicious=int(raw.get("malicious") or 0),
        suspicious=int(raw.get("suspicious") or 0),
        undetected=int(raw.get("undetected") or 0),
        harmless=int(raw.get("harmless") or 0),
        timeout=int(raw.get("timeout") or 0),
    )


def detections_from_mapping(mapping: dict[str, Any]) -> list[DetectionEntry]:
    """Build sorted detections from a ``{engine: {category, result, method}}`` map."""
    entries: list[DetectionEntry] = []
    for engine, info in mapping.items():
        if not isinstance(info, dict):
            continue
        entries.append(
            DetectionEntry(
                engine=engine,
                result=info.get("result"),
                category=info.get("category", "undetected"),
                method=info.get("method"),
            )
        )
    entries.sort(key=lambda entry: _CATEGORY_ORDER.get(entry.category, 9))
    return entries


def detections_from_relationship(items: list[dict[str, Any]]) -> list[DetectionEntry]:
    """Build sorted detections from a ``last_analysis_results`` relationship list."""
    entries: list[DetectionEntry] = []
    for item in items:
        entries.append(
            DetectionEntry(
                engine=item.get("engine_name", "unknown"),
                result=item.get("result"),
                category=item.get("category", "undetected"),
                method=item.get("method"),
            )
        )
    entries.sort(key=lambda entry: _CATEGORY_ORDER.get(entry.category, 9))
    return entries


def _common_metadata(attributes: dict[str, Any], kind: str) -> IndicatorMetadata:
    return IndicatorMetadata(
        kind=kind,  # type: ignore[arg-type]
        reputation=attributes.get("reputation"),
        tags=list(attributes.get("tags") or []),
        threat_names=list(attributes.get("threat_names") or []),
        total_votes=dict(attributes.get("total_votes") or {}),
        first_submission_date=_epoch_to_dt(attributes.get("first_submission_date")),
        last_analysis_date=_epoch_to_dt(attributes.get("last_analysis_date")),
    )


def _build(
    indicator: str,
    indicator_type: str,
    attributes: dict[str, Any],
    detections: list[DetectionEntry],
    metadata: IndicatorMetadata,
) -> AnalysisResult:
    analyzed_at = _epoch_to_dt(attributes.get("last_analysis_date")) or _epoch_to_dt(
        attributes.get("date")
    ) or datetime.now(timezone.utc)
    submitted_at = _epoch_to_dt(attributes.get("first_submission_date")) or analyzed_at
    return AnalysisResult(
        analysis_id=str(uuid4()),
        indicator=indicator,
        indicator_type=indicator_type,  # type: ignore[arg-type]
        submitted_at=submitted_at,
        analyzed_at=analyzed_at,
        stats=_stats(attributes),
        detections=detections,
        metadata=metadata,
    )


def build_file_analysis(
    indicator: str,
    node: dict[str, Any],
    *,
    hashes: dict[str, str] | None = None,
    filename: str | None = None,
    indicator_type: str = "HASH",
) -> AnalysisResult:
    attributes = node.get("attributes", {})

    raw_results = attributes.get("last_analysis_results")
    if raw_results is None:
        raw_results = attributes.get("results")
    detections = detections_from_mapping(raw_results or {})

    names = list(attributes.get("names") or [])
    if filename and not names:
        names = [filename]

    metadata = FileMetadata(
        **_common_metadata(attributes, "file").model_dump(exclude={"kind"}),
        kind="file",
        sha256=attributes.get("sha256") or (hashes or {}).get("sha256"),
        sha1=attributes.get("sha1") or (hashes or {}).get("sha1"),
        md5=attributes.get("md5") or (hashes or {}).get("md5"),
        names=names,
        meaningful_name=attributes.get("meaningful_name") or filename,
        type_description=attributes.get("type_description"),
        size=attributes.get("size"),
    )
    return _build(indicator, indicator_type, attributes, detections, metadata)


def build_url_analysis(
    indicator: str, node: dict[str, Any], origin: str
) -> AnalysisResult:
    attributes = node.get("attributes", {})

    raw_results = attributes.get("last_analysis_results")
    if raw_results is None:
        raw_results = attributes.get("results")
    detections = detections_from_mapping(raw_results or {})

    url_value = attributes.get("url") or indicator
    metadata = UrlMetadata(
        **_common_metadata(attributes, "url").model_dump(exclude={"kind"}),
        kind="url",
        url=url_value,
        final_url=attributes.get("last_final_url"),
        title=attributes.get("title"),
    )
    return _build(indicator, "URL", attributes, detections, metadata)


def build_domain_analysis(
    indicator: str, node: dict[str, Any], relationship_items: list[dict[str, Any]]
) -> AnalysisResult:
    attributes = node.get("attributes", {})
    metadata = DomainMetadata(
        **_common_metadata(attributes, "domain").model_dump(exclude={"kind"}),
        kind="domain",
        registrar=attributes.get("registrar"),
        creation_date=_epoch_to_dt(attributes.get("creation_date")),
    )
    detections = detections_from_relationship(relationship_items)
    return _build(indicator, "DOMAIN", attributes, detections, metadata)


def build_ip_analysis(
    indicator: str, node: dict[str, Any], relationship_items: list[dict[str, Any]]
) -> AnalysisResult:
    attributes = node.get("attributes", {})
    raw_asn = attributes.get("asn")
    metadata = IpMetadata(
        **_common_metadata(attributes, "ip").model_dump(exclude={"kind"}),
        kind="ip",
        country=attributes.get("country"),
        as_owner=attributes.get("as_owner"),
        asn=int(raw_asn) if isinstance(raw_asn, (int, str)) and str(raw_asn).isdigit() else None,
    )
    detections = detections_from_relationship(relationship_items)
    return _build(indicator, "IP", attributes, detections, metadata)