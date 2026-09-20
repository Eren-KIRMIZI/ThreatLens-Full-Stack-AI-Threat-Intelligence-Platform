"""Phishing forensics service + endpoint tests."""

from __future__ import annotations

import hashlib

from fastapi.testclient import TestClient

from app.main import app
from app.services.email_forensics import analyze_email

client = TestClient(app)

PHISHING_EML = (
    "From: \"Paypal Security\" <billing@paypa1-alerts.xyz>\r\n"
    "To: victim@example.com\r\n"
    "Reply-To: mike@freemail.none\r\n"
    "Subject: URGENT: your PayPal account has been suspended\r\n"
    "Date: Wed, 10 Jun 2025 09:00:00 +0000\r\n"
    "Message-ID: <final@paypa1-alerts.xyz>\r\n"
    "Received-SPF: fail (billing@paypa1-alerts.xyz: domain does not designate)\r\n"
    "Content-Type: multipart/mixed; boundary=xyz\r\n"
    "\r\n"
    "--xyz\r\n"
    "Content-Type: text/plain; charset=utf-8\r\n"
    "\r\n"
    "Dear customer, click here to verify your password now: http://paypa1-alerts.xyz/reset\r\n"
    "--xyz\r\n"
    "Content-Type: text/html; charset=utf-8\r\n"
    "\r\n"
    '<html><a href="http://paypa1-alerts.xyz/reset">Verify now</a>\r\n'
    '<img src="http://track.paypa1-alerts.xyz/open.gif" width="1" height="1">\r\n'
    "<a href=\"javascript:void(0)\">link</a></html>\r\n"
    "--xyz\r\n"
    'Content-Type: application/octet-stream; name="invoice.pdf.exe"\r\n'
    "Content-Disposition: attachment; filename=\"invoice.pdf.exe\"\r\n"
    "\r\n"
    "MZfake\r\n"
    "--xyz--\r\n"
)

HARMLESS_EML = (
    "From: \"Acme Corp\" <noreply@acme-example.com>\r\n"
    "To: team@acme-example.com\r\n"
    "Subject: Monthly report\r\n"
    "Date: Tue, 09 Jun 2025 08:00:00 +0000\r\n"
    "Authentication-Results: spf=pass dkim=pass\r\n"
    "Content-Type: text/plain; charset=utf-8\r\n"
    "\r\n"
    "Attached is the monthly report. https://acme-example.com/report.pdf thanks\r\n"
)


def test_phishing_message_raises_risk_and_finds_indicators() -> None:
    result = analyze_email(PHISHING_EML)
    assert result.risk_score >= 70
    assert result.risk_level == "critical"

    assert result.brief.sender_display == "Paypal Security"
    assert result.brief.subject == "URGENT: your PayPal account has been suspended"
    assert result.rule_hits == [
        "content:obfuscated-links",
        "content:urgency-language",
        "header:auth-fail",
        "header:brand-impersonation",
        "header:reply-to-mismatch",
    ]

    # brand impersonation finding from display name vs real domain
    label_hits = {f.label for f in result.header_findings}
    assert "Sender impersonates Paypal" in label_hits

    # URL flagged as brand lookalike + no https
    url_hits = [u for u in result.urls if u.url == "http://paypa1-alerts.xyz/reset"]
    assert url_hits
    link = url_hits[0]
    assert link.brand_risk is True
    assert link.brand == "Paypal"
    assert link.https is False
    assert link.risk >= 60

    # tracking pixel already caught by domain pattern too
    assert any(p.transparent for p in result.tracking_pixels)

    # executable attachment with a fake double extension
    assert len(result.attachments) == 1
    att = result.attachments[0]
    assert att.risky_extension is True
    assert att.sha256 == hashlib.sha256(b"MZfake").hexdigest()

    # html source retained but text body also present
    assert "track.paypa1-alerts.xyz" in (result.html_source or "")
    assert "click here" in (result.text_body or "")


def test_harmless_message_stays_clean() -> None:
    result = analyze_email(HARMLESS_EML)
    assert result.risk_score < 20
    assert result.risk_level in ("clean", "suspicious")
    assert result.urls
    good = result.urls[0]
    assert good.brand_risk is False
    assert good.domain == "acme-example.com"


def test_detached_display_name_decoding() -> None:
    eml = (
        "From: =?utf-8?q?G=C3=BCvenli_Banka?= <support@banka.example>\r\n"
        "To: x@y.z\r\n"
        "Subject: =?utf-8?b?S2VsZW0gRG9rcg==?=\r\n"
        "Date: Mon, 08 Jun 2025 08:00:00 +0000\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "hello\r\n"
    )
    result = analyze_email(eml)
    assert result.brief.sender_display == "G\u00fcvenli Banka"
    assert result.brief.subject and result.brief.subject.startswith("Kele")
    assert result.risk_score < 20


def test_upload_endpoint_rejects_oversize() -> None:
    big = b"x" * 3_500_000
    resp = client.post(
        "/api/v1/forensics/email",
        files={"file": ("big.eml", big, "message/rfc822")},
    )
    assert resp.status_code in (413, 403, 422)


def test_raw_endpoint_returns_verdict() -> None:
    resp = client.post(
        "/api/v1/forensics/email/raw",
        json={"raw": "From: a@b.c\r\nSubject: hi\r\n\r\nbody\r\n"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["risk_score"] == 0
    assert body["risk_level"] == "clean"


def test_upload_endpoint_parses_multipart_file() -> None:
    resp = client.post(
        "/api/v1/forensics/email",
        files={
            "file": (
                "phish.eml",
                PHISHING_EML.encode("utf-8"),
                "message/rfc822",
            )
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["risk_score"] >= 70
    assert body["risk_level"] == "critical"