"""Input validation utilities shared across API schemas and services."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

_HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)


def hash_algorithm(value: str) -> str | None:
    """Return 'md5', 'sha1' or 'sha256' if the value is a hex hash, else None."""
    v = value.strip()
    if _HEX_RE.fullmatch(v) and len(v) in _HASH_LENGTHS:
        return _HASH_LENGTHS[len(v)]
    return None


def validate_hash(value: str) -> str:
    """Validate a SHA256/SHA1/MD5 hex hash and return it lowercased."""
    v = value.strip()
    if hash_algorithm(v) is None:
        raise ValueError("Invalid hash. Provide a SHA256, SHA1 or MD5 hash in hexadecimal form.")
    return v.lower()


def validate_url(value: str) -> str:
    """Validate an absolute http(s) URL. Rejects credentials and non-http schemes."""
    v = value.strip()
    parts = urlsplit(v)
    if parts.scheme not in {"http", "https"}:
        raise ValueError("Invalid URL. Only http and https URLs are supported.")
    if not parts.hostname:
        raise ValueError("Invalid URL. Provide an absolute URL with a hostname.")
    if any(char.isspace() for char in parts.hostname):
        raise ValueError("Invalid URL. The hostname must not contain whitespace.")
    if parts.username or parts.password:
        raise ValueError("Invalid URL. URLs must not contain embedded credentials.")
    return v


def validate_domain(value: str) -> str:
    """Validate a fully-qualified domain name (no scheme, no path)."""
    v = value.strip().lower().rstrip(".")
    if not v or len(v) > 253 or "/" in v or " " in v:
        raise ValueError("Invalid domain.")
    labels = v.split(".")
    if len(labels) < 2:
        raise ValueError("Invalid domain. A fully-qualified domain name is required.")
    if not all(_DOMAIN_LABEL_RE.fullmatch(label) for label in labels):
        raise ValueError("Invalid domain.")
    return v


def validate_ip(value: str) -> str:
    """Validate an IPv4 or IPv6 address using the stdlib ipaddress module."""
    v = value.strip()
    try:
        ipaddress.ip_address(v)
    except ValueError:
        raise ValueError("Invalid IP address.") from None
    return v


def sanitize_filename(value: str) -> str:
    """Return a safe basename, stripping any path traversal components."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("The uploaded file must have a name.")
    raw = value.strip()
    if "\x00" in raw:
        raise ValueError("Invalid file name.")
    # Reject any path separators outright (Windows and POSIX).
    if "/" in raw or "\\" in raw:
        raise ValueError("Invalid file name. A bare filename is required.")
    name = PurePosixPath(Path(raw).name).name
    if not name or name in {".", ".."} or len(name) > 255:
        raise ValueError("Invalid file name.")
    return name