"""Hashing helpers for uploaded file samples."""

from __future__ import annotations

import hashlib


def compute_hashes(content: bytes) -> dict[str, str]:
    """Compute SHA256, SHA1 and MD5 digests of a file's bytes."""
    return {
        "sha256": hashlib.sha256(content).hexdigest(),
        "sha1": hashlib.sha1(content).hexdigest(),
        "md5": hashlib.md5(content).hexdigest(),
    }