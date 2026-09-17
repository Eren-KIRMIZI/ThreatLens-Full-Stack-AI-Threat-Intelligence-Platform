"""Alert rule evaluation.

Rules compare the latest indicator snapshot against configured thresholds and
(optionally) the previous snapshot. Every rule returns an alert candidate when
its condition holds; the rescan loop persists the candidates.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.models.alerts import AlertRule

SUPPORTED_CONDITIONS = ("score_ge", "engines_ge", "new_detection", "level_is")

_LEVEL_PRIORITY = {"clean": 0, "suspicious": 1, "malicious": 2, "critical": 3}


@dataclass
class SnapshotFacts:
    score: int | None
    level: str | None
    malicious: int
    suspicious: int


@dataclass
class AlertCandidate:
    rule_id: str | None
    level: str
    message: str


def _describe(rule: AlertRule, facts: SnapshotFacts) -> str:
    if rule.condition == "score_ge":
        return f"threat score {facts.score}/100 is at or above {rule.threshold}"
    if rule.condition == "engines_ge":
        return (
            f"{facts.malicious} malicious engines exceed the "
            f"{rule.threshold}-engine threshold"
        )
    if rule.condition == "new_detection":
        return f"indicator newly detected as {facts.level or 'unknown'}"
    return f"verdict is {facts.level or 'unknown'} (expected {rule.threshold})"


def evaluate_rule(
    rule: AlertRule,
    latest: SnapshotFacts,
    previous: SnapshotFacts | None,
) -> AlertCandidate | None:
    """Return an alert candidate when ``rule`` fires for the latest snapshot."""
    if not rule.enabled:
        return None

    score = latest.score if latest.score is not None else 0
    engines = latest.malicious
    level = latest.level or "unknown"

    if rule.condition == "score_ge":
        fired = score >= rule.threshold
    elif rule.condition == "engines_ge":
        fired = engines >= rule.threshold
    elif rule.condition == "new_detection":
        prev_level = (previous.level or "clean") if previous else "clean"
        fired = _LEVEL_PRIORITY.get(level, 0) > _LEVEL_PRIORITY.get(prev_level, 0)
    elif rule.condition == "level_is":
        fired = _LEVEL_PRIORITY.get(level, 0) >= _LEVEL_PRIORITY.get(
            {70: "critical", 40: "malicious", 20: "suspicious", 0: "clean"}.get(
                rule.threshold, "malicious"
            ),
            0,
        )
    else:
        return None

    if not fired:
        return None

    severity = {
        "score_ge": "critical" if rule.threshold >= 85 else "high",
        "engines_ge": "high" if rule.threshold >= 3 else "medium",
        "new_detection": "high",
        "level_is": "high",
    }.get(rule.condition, "high")
    return AlertCandidate(
        rule_id=rule.id,
        level=severity,
        message=f'Rule "{rule.name}": {_describe(rule, latest)}.',
    )