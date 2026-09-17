"""STIX 2.1 export of a stored analysis.

Builds a minimal but standards-compliant bundle: an ``indicator`` per IOC with
an STIX ``pattern``, plus optional ``observed-data`` referencing its detection
engines. Deterministic output means the exporter is trivially testable.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from app.schemas.analysis import AnalysisResult

TYPE_TO_STIX_OBJECT = {
    "HASH": "file",
    "FILE": "file",
    "URL": "url",
    "DOMAIN": "domain-name",
    "IP": "ipv4-addr",
}


def _pattern_for(result: AnalysisResult) -> str:
    stix_type = TYPE_TO_STIX_OBJECT.get(result.indicator_type, "file")
    indicator = result.indicator
    if stix_type == "file":
        return f"[file:hashes.'SHA-256' = '{indicator}']"
    if stix_type == "url":
        return f"[url:value = '{indicator}']"
    if stix_type == "domain-name":
        return f"[domain-name:value = '{indicator}']"
    return f"[ipv4-addr:value = '{indicator}']"


def build_stix_bundle(result: AnalysisResult) -> dict:
    """Serialize one analysis as a STIX 2.1 indicator bundle."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    name = result.metadata.meaningful_name or result.indicator
    pattern = _pattern_for(result)

    indicator = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, result.analysis_id)}",
        "created": now,
        "modified": now,
        "name": name,
        "pattern": pattern,
        "valid_from": result.analyzed_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "labels": (
            ["malicious-activity"]
            if result.threat_score is not None and result.threat_score >= 40
            else ["benign"]
        ),
        "description": (
            f"Threat score {result.threat_score}/100, "
            f"{result.stats.malicious} malicious engines"
        ),
    }

    objects = [indicator]
    if result.stats.malicious + result.stats.suspicious > 0:
        observed = {
            "type": "observed-data",
            "spec_version": "2.1",
            "id": f"observed-data--{uuid.uuid5(uuid.NAMESPACE_URL, result.analysis_id + '-obs')}",
            "created": now,
            "modified": now,
            "first_observed": result.analyzed_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "last_observed": result.analyzed_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "number_observed": 1,
            "object_refs": [indicator["id"]],
            "x_threatlens": {
                "detected_vendors": result.stats.malicious,
                "suspicious_vendors": result.stats.suspicious,
                "level": result.threat_level,
            },
        }
        objects.append(observed)

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": objects,
    }


def stix_to_json(result: AnalysisResult) -> str:
    return json.dumps(build_stix_bundle(result), indent=2)