"""Shared literal types used across schemas (avoid circular imports)."""

from __future__ import annotations

from typing import Literal

IndicatorType = Literal["FILE", "HASH", "URL", "DOMAIN", "IP"]
ThreatLevel = Literal["clean", "suspicious", "malicious", "critical"]