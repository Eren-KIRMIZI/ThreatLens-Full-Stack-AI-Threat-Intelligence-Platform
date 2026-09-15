"""Input validation tests."""

import pytest

from app.utils import validators


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("a" * 32, "md5"),
        ("a" * 40, "sha1"),
        ("a" * 64, "sha256"),
        ("A" * 64, "sha256"),
        ("   " + "b" * 64 + "  ", "sha256"),
    ],
)
def test_hash_algorithm_accepts_valid_hashes(value, expected) -> None:
    assert validators.hash_algorithm(value) == expected


@pytest.mark.parametrize(
    "value",
    ["", "abc", "a" * 33, "a" * 41, "zz" * 32, "a" * 65, "xyz-" * 16],
)
def test_hash_algorithm_rejects_invalid_hashes(value) -> None:
    assert validators.hash_algorithm(value) is None


def test_validate_hash_lowercases() -> None:
    assert validators.validate_hash("A" * 64) == "a" * 64


@pytest.mark.parametrize(
    "value",
    [
        "https://example.com",
        "https://example.com/path?a=1&b=2",
        "http://192.168.1.10:8080/x",
    ],
)
def test_validate_url_accepts_absolute_urls(value) -> None:
    assert validators.validate_url(value) == value


@pytest.mark.parametrize(
    "value",
    [
        "example.com",
        "ftp://example.com/file",
        "https://user:pass@example.com",
        "http://",
        "javascript:alert(1)",
        "https://exa mple.com",
    ],
)
def test_validate_url_rejects_invalid_urls(value) -> None:
    with pytest.raises(ValueError):
        validators.validate_url(value)


@pytest.mark.parametrize(
    "value",
    [
        "example.com",
        "sub.example.co.uk",
        "EXAMPLE.COM",
        "xn--bcher-kva.example",
    ],
)
def test_validate_domain_accepts_fqdn(value) -> None:
    result = validators.validate_domain(value)
    assert result == value.strip().lower().rstrip(".")


@pytest.mark.parametrize(
    "value",
    ["", "localhost", "http://example.com", "exa mple.com", "a..b", "-example.com"],
)
def test_validate_domain_rejects_invalid_domains(value) -> None:
    with pytest.raises(ValueError):
        validators.validate_domain(value)


@pytest.mark.parametrize("value", ["8.8.8.8", "1.2.3.4", "2001:db8::1", "::1"])
def test_validate_ip_accepts_valid_addresses(value) -> None:
    assert validators.validate_ip(value) == value


@pytest.mark.parametrize("value", ["999.1.1.1", "8.8.8", "example.com", ""])
def test_validate_ip_rejects_invalid_addresses(value) -> None:
    with pytest.raises(ValueError):
        validators.validate_ip(value)


@pytest.mark.parametrize(
    "value",
    ["myfile.exe", "report.pdf", "a" * 255, "  spaced file.txt  "],
)
def test_sanitize_filename_accepts_safe_names(value) -> None:
    result = validators.sanitize_filename(value)
    assert result == value.strip()


@pytest.mark.parametrize(
    "value",
    ["", "   ", "../../etc/passwd", "C:\\Windows\\system32\\cmd.exe", "a/b/c.exe", "\x00x"],
)
def test_sanitize_filename_rejects_unsafe_names(value) -> None:
    with pytest.raises(ValueError):
        validators.sanitize_filename(value)