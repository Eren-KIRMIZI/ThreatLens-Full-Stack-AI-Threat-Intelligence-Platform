"""VirusTotal evidence conversion.

VirusTotal is the core provider: its raw data is already fetched and normalized
by ``AnalysisService``. To avoid a second API call during enrichment this
provider converts the already-normalized analysis into ``NormalizedEvidence``
(a "seeded" source) instead of making a fresh HTTP request.
"""

from __future__ import annotations

from app.schemas.analysis import AnalysisResult
from app.schemas.enrichment import NormalizedEvidence, EvidenceVerdict
from app.services.providers.base import evidence_id

NAME = "virustotal"


def _verdict(malicious: int, suspicious: int) -> EvidenceVerdict:
    if malicious > 0:
        return "malicious"
    if suspicious > 0:
        return "suspicious"
    return "clean"


def evidence_from_analysis(result: AnalysisResult) -> list[NormalizedEvidence]:
    """Convert a normalized analysis into source='virustotal' evidence items."""
    stats = result.stats
    total = (
        stats.malicious + stats.suspicious + stats.harmless + stats.undetected
    )
    items: list[NormalizedEvidence] = []

    items.append(
        NormalizedEvidence(
            id=evidence_id(
                NAME, result.indicator_type, result.indicator, "detection",
                f"{stats.malicious}/{total}",
            ),
            provider=NAME,
            evidence_type="detection",
            title="VirusTotal engine detections",
            value=(
                f"{stats.malicious} malicious, {stats.suspicious} suspicious "
                f"of {total} engines"
            ),
            confidence=1.0,
            verdict=_verdict(stats.malicious, stats.suspicious),
            observed_at=result.analyzed_at,
            source_ref=f"https://www.virustotal.com/gui/{_vt_path(result)}",
            metadata={
                "stats": stats.model_dump(),
                "engines": [
                    {"engine": d.engine, "result": d.result, "category": d.category}
                    for d in result.detections[:50]
                ],
            },
        )
    )

    if result.metadata.reputation is not None:
        items.append(
            NormalizedEvidence(
                id=evidence_id(
                    NAME, result.indicator_type, result.indicator, "reputation",
                    str(result.metadata.reputation),
                ),
                provider=NAME,
                evidence_type="reputation",
                title="VirusTotal community reputation",
                value=str(result.metadata.reputation),
                confidence=0.7,
                verdict=(
                    "malicious" if result.metadata.reputation < -50
                    else "clean" if result.metadata.reputation > 50 else "unknown"
                ),
                observed_at=result.analyzed_at,
                source_ref=f"https://www.virustotal.com/gui/{_vt_path(result)}",
            )
        )

    for threat_name in list(result.metadata.threat_names)[:10]:
        items.append(
            NormalizedEvidence(
                id=evidence_id(
                    NAME, result.indicator_type, result.indicator,
                    "threat_feed", threat_name,
                ),
                provider=NAME,
                evidence_type="threat_feed",
                title="VirusTotal threat label",
                value=threat_name,
                confidence=0.9,
                verdict="malicious",
                observed_at=result.analyzed_at,
                source_ref=f"https://www.virustotal.com/gui/{_vt_path(result)}",
            )
        )
    return items


def _vt_path(result: AnalysisResult) -> str:
    mapping = {
        "HASH": "file",
        "URL": "url",
        "DOMAIN": "domain",
        "IP": "ip-address",
        "FILE": "file",
    }
    return f"{mapping.get(result.indicator_type, 'file')}/" + result.indicator