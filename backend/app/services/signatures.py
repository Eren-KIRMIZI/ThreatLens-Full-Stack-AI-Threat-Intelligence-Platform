"""YARA and Sigma signature generation from a stored analysis.

Intent is analyst scaffolding: explainable, deterministic rules grounded in
the normalized evidence (hashes, threat names, tags, engine results). Rules
are marked ``theoretical`` because they are generated, not field-validated.
"""

from __future__ import annotations

from app.schemas.analysis import AnalysisResult


def _identifier(result: AnalysisResult) -> str:
    base = result.metadata.meaningful_name or result.indicator
    safe = "".join(ch if ch.isalnum() else "_" for ch in base)[:48].strip("_")
    return safe or "indicator"


def _threat_names(result: AnalysisResult) -> list[str]:
    names = result.metadata.threat_names or []
    unique: list[str] = []
    for name in names:
        if name and name not in unique:
            unique.append(name)
    return unique[:8]


def generate_yara(result: AnalysisResult) -> str:
    ident = _identifier(result)
    hashes = result.metadata.sha256 or result.indicator
    threats = _threat_names(result)
    authors = ""
    if threats:
        authors += f"        // matched: {', '.join(threats)}\n"

    return "\n".join(
        [
            "/*",
            "   ThreatLens generated YARA rule",
            f"   indicator: {result.indicator}",
            f"   score {result.threat_score}/100 ({result.threat_level})"
            if result.threat_score is not None
            else "   unscored",
            f"   generated from normalized VirusTotal evidence — theoretical rule",
            "*/",
            f'rule threatlens_{ident.lower()}',
            "{",
            "    meta:",
            '        author = "ThreatLens"',
            '        reference = "https://threatlens.local"',
            "        description = \"Generated from an automated analysis\"",
            "        hash = \"" + hashes + "\"",
            "    condition:",
            "        filesize < 50MB and (",
            f'            hash.sha256 == "{hashes}"',
            "        )",
            "}",
        ]
    )


def generate_sigma(result: AnalysisResult) -> str:
    ident = _identifier(result)
    threats = _threat_names(result)
    detection = ""
    if threats:
        detection = "\n".join(
            f"            - '*{name}*'" for name in threats
        )
    else:
        detection = "            - '*malicious*'"
    return "\n".join(
        [
            "title: ThreatLens detection - " + (threats[0] if threats else ident),
            "id: " + result.analysis_id,
            "status: experimental",
            "description: Generated from normalized VirusTotal evidence.",
            "references:",
            "    - https://threatlens.local",
            "author: ThreatLens",
            "date: " + result.analyzed_at.strftime("%Y/%m/%d"),
            "detection:",
            "    selection:",
            "        fields:",
            "            - DetectionName",
            detection,
            "        condition: selection",
            "level: high",
        ]
    )