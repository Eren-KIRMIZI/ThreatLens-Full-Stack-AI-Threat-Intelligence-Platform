"""IOC canonicalization / deduplication tests."""

import pytest

from app.utils import validators
from app.utils.ioc import canonical_value, canonicalize_url, primary_type


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("http://Example.COM", "http://example.com/"),
        ("https://example.com/", "https://example.com/"),
        ("HTTP://EXAMPLE.com:80/path//", "http://example.com/path"),
        ("https://Example.com:443", "https://example.com/"),
        ("http://example.com:8080/x", "http://example.com:8080/x"),
        ("http://example.com/?a=1#frag", "http://example.com/?a=1"),
        ("http://[2001:db8::1]:8080/", "http://[2001:db8::1]:8080/"),
    ],
)
def test_canonicalize_url(raw: str, expected: str) -> None:
    assert canonicalize_url(raw) == expected


def test_canonical_value_by_type() -> None:
    assert canonical_value("DOMAIN", "EXAMPLE.COM.") == "example.com"
    assert canonical_value("IP", "1.2.3.4") == "1.2.3.4"
    assert canonical_value("HASH", "AA" * 32) == "aa" * 32
    assert canonical_value("URL", "HTTP://Example.COM/") == "http://example.com/"


def test_variants_resolve_to_same_url_identity() -> None:
    variants = [
        "HTTP://Example.COM",
        "http://example.com/",
        "http://example.com:80/",
        "http://example.com",
    ]
    canonical = {canonicalize_url(v) for v in variants}
    assert canonical == {"http://example.com/"}


def test_primary_type_guesses() -> None:
    assert primary_type("a" * 64) == "HASH"
    assert primary_type("10.0.0.1") == "IP"
    assert primary_type("https://evil.example/x") == "URL"
    assert primary_type("evil.example.com") == "DOMAIN"
    assert primary_type("b" * 40) == "HASH"


def test_invalid_inputs_still_rejected() -> None:
    with pytest.raises(ValueError):
        validators.validate_domain("..")
    with pytest.raises(ValueError):
        validators.validate_ip("999.1.1.1")
    with pytest.raises(ValueError):
        validators.validate_hash("zzzz")