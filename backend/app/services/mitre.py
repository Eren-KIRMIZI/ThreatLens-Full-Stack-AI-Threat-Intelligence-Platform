"""MITRE ATT&CK mapper.

Keeps a small immutable catalog of tactics and techniques relevant to
indicator-style evidence, validates AI-supplied technique ids, and maps
provider threat names / signatures to techniques via deterministic keywords.
"""

from __future__ import annotations

from dataclasses import dataclass

_TACTICS = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "Resource Development",
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}

# Deterministic keyword -> (technique_id, technique_name, tactic) mapping used
# to corroborate evidence strings (threat names, signatures, tags).
_KEYWORD_MAP: list[tuple[tuple[str, ...], str, str, str]] = [
    (("phish", "spam"), "T1566", "Phishing", "initial-access"),
    (("ransom", "locker", "cryptolock"), "T1486", "Data Encrypted for Impact", "impact"),
    (("trojan", "backdoor", "rat "), "T1078", "Valid Accounts", "defense-evasion"),
    (("c2", "cnc", "command and control", "botnet"), "T1071", "Application Layer Protocol", "command-and-control"),
    (("dropper", "downloader", "loader"), "T1105", "Ingress Tool Transfer", "command-and-control"),
    (("stealer", "infostealer", "keylog"), "T1056", "Input Capture", "credential-access"),
    (("miner", "coinminer", "cryptomin"), "T1496", "Resource Hijacking", "impact"),
    (("worm", "spreader", "self-propagat"), "T1565", "Data Manipulation", "impact"),
    (("bypass", "uac", "privilege escalation"), "T1548", "Abuse Elevation Control Mechanism", "privilege-escalation"),
    (("exfil", "spy", "screenshot"), "T1041", "Exfiltration Over C2 Channel", "exfiltration"),
]

# Catalog exposed to the API for autocomplete / validation.
CATALOG: list[dict[str, str]] = sorted(
    [
        {"id": tech_id, "name": name, "tactic": _TACTICS[tactic]}
        for keywords, tech_id, name, tactic in _KEYWORD_MAP
    ],
    key=lambda item: item["id"],
)

TACTICS: dict[str, str] = dict(_TACTICS)


def valid_technique(technique_id: str) -> bool:
    """Return whether an id looks like a valid ATT&CK technique id (T####)."""
    if not technique_id or not technique_id.startswith("T"):
        return False
    body = technique_id[1:]
    return len(body) == 4 and body.isdigit()


def map_text_to_techniques(text: str) -> list[dict[str, str]]:
    """Corroborate a threat name / signature string against ATT&CK keywords."""
    lowered = (text or "").lower()
    hits: list[dict[str, str]] = []
    seen: set[str] = set()
    for keywords, tech_id, name, tactic in _KEYWORD_MAP:
        if any(keyword in lowered for keyword in keywords):
            if tech_id not in seen:
                seen.add(tech_id)
                hits.append(
                    {"id": tech_id, "name": name, "tactic": _TACTICS.get(tactic, tactic)}
                )
    return hits


def map_evidence_to_mitre(evidence: list) -> list[dict[str, str]]:
    """Map enrichment evidence titles/values plus verification labels."""
    texts: list[str] = []
    for item in evidence or []:
        title = getattr(item, "title", "") or ""
        value = getattr(item, "value", "") or ""
        texts.append(f"{title} {value}")
    mapping: dict[str, dict[str, str]] = {}
    for text in texts:
        for hit in map_text_to_techniques(text):
            mapping[hit["id"]] = hit
    return sorted(mapping.values(), key=lambda item: item["id"])