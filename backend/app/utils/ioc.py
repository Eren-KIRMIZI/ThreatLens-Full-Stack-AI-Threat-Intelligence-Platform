"""IOC canonicalization & identity.

Provides the single source of truth for how an indicator is represented so
``HTTP://Example.COM``, ``http://example.com/`` and ``example.com`` resolve to
the same canonical identity across providers, history and the IOC graph.
"""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from app.schemas.analysis import IndicatorType
from app.utils import validators


def canonicalize_url(value: str) -> str:
    """Normalize a URL: lowercase scheme/host, strip default ports,
    default paths and trailing slash, drop fragments and empty queries."""
    parts = urlsplit(value.strip())
    scheme = (parts.scheme or "http").lower()
    host = (parts.hostname or "").lower()

    if ":" in host:
        # IPv6 without brackets from urlsplit.hostname; re-bracket for netloc.
        authority = f"[{host}]"
    else:
        authority = host
    port = parts.port
    if port and not (
        (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    ):
        authority = f"{authority}:{port}"

    path = parts.path or ""
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    query = parts.query if parts.query else ""

    return urlunsplit((scheme, authority, path or "/", query, ""))


def canonicalize_domain(value: str) -> str:
    return validators.validate_domain(value).lower()


def canonicalize_ip(value: str) -> str:
    return validators.validate_ip(value)


def canonicalize_hash(value: str) -> str:
    return validators.validate_hash(value)


def canonical_value(indicator_type: IndicatorType, value: str) -> str:
    """Return the canonical representation of an indicator value."""
    if indicator_type == "URL":
        return canonicalize_url(value)
    if indicator_type == "DOMAIN":
        return canonicalize_domain(value)
    if indicator_type == "IP":
        return canonicalize_ip(value)
    return canonicalize_hash(value)


def primary_type(indicator: str) -> IndicatorType:
    """Best-effort type guess for an untyped indicator string (used by search)."""
    if validators.hash_algorithm(indicator):
        return "HASH"
    try:
        validators.validate_ip(indicator)
        return "IP"
    except ValueError:
        pass
    if "/" in indicator and (indicator.startswith("http://") or indicator.startswith("https://")):
        return "URL"
    try:
        validators.validate_domain(indicator)
        return "DOMAIN"
    except ValueError:
        pass
    return "HASH"