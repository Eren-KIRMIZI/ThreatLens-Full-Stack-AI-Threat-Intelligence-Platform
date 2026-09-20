"""Deterministic phishing email forensics.

The parser works fully offline: it never uploads the raw message anywhere
and never stores it. Everything an analyst sees is derived from the
message bytes themselves, so the same email always produces the same
verdict, and the verdict is easy to audit.

Risk model (additive, transparent):

    risk_score = sum(rule weights below, clamped to 0..100)

Level bands reuse ``level_for_score`` so ``critical/malicious/suspicious/
clean`` mean the same thing here as for indicator analyses.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from email import message_from_bytes, message_from_string
from email.header import decode_header
from email.message import Message
from email.policy import default as default_policy
from email.utils import parseaddr, parsedate_to_datetime
from urllib.parse import urlparse

from app.schemas.forensics import (
    EmailAttachmentInfo,
    EmailForensicBrief,
    EmailForensicOut,
    EmailHeader,
    EmailLink,
    HeaderFinding,
    TrackingPixel,
)
from app.services.scoring import level_for_score

# --------------------------------------------------------------------------
# Reference data (explicit and auditable).
# --------------------------------------------------------------------------

# brand -> canonical host the brand legitimately owns
BRAND_HOSTS: dict[str, str] = {
    "microsoft": "microsoft.com",
    "outlook": "microsoft.com",
    "office365": "microsoft.com",
    "onedrive": "microsoft.com",
    "dropbox": "dropbox.com",
    "google": "google.com",
    "gmail": "google.com",
    "apple": "apple.com",
    "icloud": "apple.com",
    "paypal": "paypal.com",
    "ebay": "ebay.com",
    "amazon": "amazon.com",
    "netflix": "netflix.com",
    "linkedin": "linkedin.com",
    "facebook": "facebook.com",
    "whatsapp": "whatsapp.com",
    "instagram": "instagram.com",
    "chase": "chase.com",
    "wellsfargo": "wellsfargo.com",
    "bankofamerica": "bankofamerica.com",
    "okta": "okta.com",
    "cloudflare": "cloudflare.com",
    "github": "github.com",
    "docusign": "docusign.com",
    "adobe": "adobe.com",
    "steam": "steampowered.com",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "tiny.cc", "goo.gl", "t.co", "cutt.ly",
    "rebrand.ly", "ow.ly", "buff.ly", "is.gd", "rb.gy", "shorturl.at",
    "bl.ink", "v.gd", "lnkd.in", "2.gy", "u.to", "soo.gd",
}

SUSPICIOUS_TLDS = {
    "top", "xyz", "tk", "ml", "ga", "cf", "gq", "quest", "zip",
    "mom", "click", "icu", "club", "online", "site",
}

RISKY_EXTENSIONS = {
    ".exe", ".scr", ".lnk", ".js", ".msi", ".bat", ".cmd", ".vbs",
    ".ps1", ".docm", ".xlsm", ".iso", ".hta", ".jar", ".apk",
}

# Well-known legitimate services that embed a brand keyword in their own
# domain (googleapis, sharepoint, ...). Matching here suppresses the generic
# brand-lookalike flag while still letting the URL through for review.
SAFE_RELATED_SUFFIXES = (
    ".google.com", ".googleapis.com", ".gstatic.com", ".ytimg.com",
    ".googlevideo.com", ".googlesyndication.com", ".office.com",
    ".office.net", ".office365.com", ".microsoftexchangeonline.com",
    ".sharepoint.com", ".onedrive.com", ".live.com", ".akadns.net",
    ".akamaihd.net", ".azureedge.net", ".azurewebsites.net",
    ".cloudfront.net", ".force.com", ".oktapreview.com",
)

URGENCY_WORDS = {
    "password", "verify your", "urgent", "action required", "account suspended",
    "account locked", "invoice", "payment", "payroll", "w-2", "gift card",
    "refund", "crypto", "wallet", "credentials", "sign in", "2fa", "mfa",
    "security alert", "unusual activity", "billing",
}

URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)
HREF_RE = re.compile(r"(?:href|src)=\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
IMG_RE = re.compile(
    r"<img[^>]+>", re.IGNORECASE | re.DOTALL
)
IMG_SRC_RE = re.compile(r"src=\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
IMG_WIDTH_RE = re.compile(r"width=\s*[\"']?([^\"'>\s]+)", re.IGNORECASE)
IMG_HEIGHT_RE = re.compile(r"height=\s*[\"']?([^\"'>\s]+)", re.IGNORECASE)

MAX_STORED_CHARS = 200_000


def _decode(part: Message) -> str:
    """Decode a text part payload to a best-effort unicode string."""
    charset = part.get_content_charset() or "utf-8"
    payload = part.get_payload(decode=True)
    if payload is None:
        return ""
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def _display_name(raw_header: str) -> tuple[str, str]:
    """Split an RFC 5322 address header into (display_name, address)."""
    name, addr = parseaddr(raw_header or "")
    if name:
        try:
            decoded = "".join(
                text if not encoding else text.decode(encoding or "utf-8", "replace")
                for text, encoding in decode_header(name)
            )
            name = decoded
        except Exception:
            pass
    return name.strip(), addr.strip().lower()


def _host_of(address: str) -> str:
    if "@" in address:
        return address.rsplit("@", 1)[1].strip().lower()
    return ""


def _top_level(host: str) -> str:
    parts = host.rsplit(".", 1)
    return parts[-1].lower() if len(parts) > 1 else ""


def _canonical_host(host: str) -> str:
    host = host.strip().lower()
    if host.startswith("www."):
        host = host[4:]
    return host.rstrip(".")


def _brand_for_name(name: str) -> str | None:
    lowered = name.lower()
    for brand in BRAND_HOSTS:
        if brand in lowered:
            return brand
    return None


def _parse_message(raw: str | bytes) -> Message:
    if isinstance(raw, bytes):
        return message_from_bytes(raw, policy=default_policy)
    return message_from_string(raw, policy=default_policy)


def _walk_parts(message: Message) -> list[tuple[Message, bool]]:
    """Return (part, is_attachment) pairs; ``is_attachment`` True skips body."""
    parts: list[tuple[Message, bool]] = []

    def visit(msg: Message, top: bool) -> None:
        if msg.is_multipart():
            for child in msg.get_payload():  # type: ignore[union-attr]
                visit(child, False)
            return
        cd = (msg.get("Content-Disposition") or "").lower()
        ct = (msg.get_content_type() or "").lower()
        is_attachment = top is False and (
            cd.startswith("attachment") or (ct not in ("text/plain", "text/html"))
        )
        parts.append((msg, is_attachment))

    visit(message, top=True)
    return parts


class _RuleWeights:
    """Human-readable weight table, kept as constants for auditability."""

    REPLY_TO_MISMATCH = 10
    URGENCY_WORDS_PER = 5
    ATTACHMENT_EXECUTABLE = 25
    TRACKING_PIXEL_PER = 15
    HTML_JAVASCRIPT_SINK_PER = 30
    HTML_DATA_SCHEME_PER = 10
    SKIP_HEADER = 5
    AUTH_FAIL = 20
    AUTH_PASS_DEDUCT = 10


def analyze_email(raw: str | bytes) -> EmailForensicOut:
    """Parse and score a raw RFC-822 message."""
    msg = _parse_message(raw)

    # --- brief / headers ---------------------------------------------------
    sender_display, sender_email = _display_name(msg.get("From", ""))
    sender_domain = _host_of(sender_email) or None
    reply_raw = msg.get("Reply-To", "")
    _, reply_to = _display_name(reply_raw)
    subject = msg.get("Subject", "") or None
    if subject:
        try:
            subject = "".join(
                text if not enc else text.decode(enc or "utf-8", "replace")
                for text, enc in decode_header(subject)
            )
        except Exception:
            pass
    headers = [
        EmailHeader(name=h, value=v)
        for h, v in sorted(msg.items())
    ]

    date_raw = msg.get("Date", "") or None
    date: str | None = None
    if date_raw:
        try:
            dt = parsedate_to_datetime(date_raw)
            date = dt.astimezone().isoformat()
        except Exception:
            date = str(date_raw)

    brief = EmailForensicBrief(
        subject=subject,
        date=date,
        sender_display=sender_display or None,
        sender_email=sender_email or None,
        sender_domain=sender_domain,
        reply_to=reply_to or None,
        message_id=msg.get("Message-ID", "") or None,
        headers=headers,
    )

    # --- body, html, text, attachments --------------------------------------
    html_source: str | None = None
    text_body: str | None = None
    attachments: list[EmailAttachmentInfo] = []
    for part, is_attachment in _walk_parts(msg):
        ctype = part.get_content_type() or "application/octet-stream"
        if is_attachment:
            payload = part.get_payload(decode=True) or b""
            filename = part.get_filename()
            if filename:
                try:
                    filename = "".join(
                        text if not enc else text.decode(enc or "utf-8", "replace")
                        for text, enc in decode_header(filename)
                    )
                except Exception:
                    pass
            risky = bool(filename and _risky_filename(filename))
            sha = hashlib.sha256(payload).hexdigest() if payload else None
            attachments.append(
                EmailAttachmentInfo(
                    filename=filename or None,
                    content_type=ctype,
                    size_bytes=len(payload),
                    sha256=sha,
                    risky_extension=risky,
                )
            )
        elif ctype == "text/html":
            html_source = _decode(part)[:MAX_STORED_CHARS]
        elif ctype == "text/plain":
            text_body = _decode(part)[:MAX_STORED_CHARS]

    # --- URL extraction -------------------------------------------------------
    hrefs: list[str] = []
    if html_source:
        hrefs.extend(HREF_RE.findall(html_source))
    if text_body:
        for m in URL_RE.finditer(text_body):
            hrefs.append(m.group(0))
    seen: set[str] = set()
    unique_urls: list[str] = []
    for u in hrefs:
        u = u.strip().rstrip(".,;:!?")
        if u and u not in seen:
            seen.add(u)
            unique_urls.append(u)

    urls: list[EmailLink] = []
    for u in unique_urls:
        urls.append(_assess_link(u))

    # --- tracking pixels -------------------------------------------------------
    pixels: list[TrackingPixel] = []
    if html_source:
        for tag in IMG_RE.findall(html_source):
            src_m = IMG_SRC_RE.search(tag)
            w = IMG_WIDTH_RE.search(tag)
            h = IMG_HEIGHT_RE.search(tag)
            width = w.group(1).lower() if w else ""
            height = h.group(1).lower() if h else ""
            src = src_m.group(1) if src_m else None
            one_by_one = ({"1", "1px"} & {width, height}) == {"1", "1px"} or (
                width == height and width == "1"
            )
            pixel_hint = bool(
                src and re.search(r"(pixel|track|open|1x1|\.gif)", src, re.IGNORECASE)
            )
            if one_by_one or pixel_hint or (src and ".gif" in src.lower()):
                pixels.append(
                    TrackingPixel(
                        url=(src if src and src.startswith(("http://", "https://")) else None),
                        width=width or None,
                        height=height or None,
                        transparent=(width == "1" and height == "1") or "transparent" in tag.lower(),
                    )
                )

    # --- header / content rule findings ---------------------------------------
    findings: list[HeaderFinding] = []
    rule_hits: list[str] = []

    if reply_to and sender_email and reply_to != sender_email:
        findings.append(
            HeaderFinding(
                label="Reply-To mismatch",
                detail=f"Reply-To ({reply_to}) differs from From ({sender_email})",
                risk=_RuleWeights.REPLY_TO_MISMATCH,
            )
        )
        rule_hits.append("header:reply-to-mismatch")

    brand_name = _brand_for_name(sender_display)
    if brand_name and sender_domain:
        canonical = BRAND_HOSTS[brand_name]
        if sender_domain != canonical and not sender_domain.endswith("." + canonical):
            findings.append(
                HeaderFinding(
                    label=f"Sender impersonates {brand_name.title()}",
                    detail=(
                        f"Display name claims {brand_name.title()} but the sender "
                        f"domain is {sender_domain} (expected {canonical})"
                    ),
                    risk=35,
                )
            )
            rule_hits.append("header:brand-impersonation")

    auth_results = msg.get_all("Authentication-Results") or []
    auth_lower = " ".join(auth_results).lower()
    spf_tokens = [v.split(None, 1)[0].lower() for v in (msg.get_all("Received-SPF") or [])]
    spf_fail = any(t in ("fail", "softfail") for t in spf_tokens)
    spf_pass = any(t == "pass" for t in spf_tokens)
    if "spf=fail" in auth_lower or "dkim=fail" in auth_lower or spf_fail:
        findings.append(
            HeaderFinding(
                label="Authentication failed",
                detail="SPF or DKIM reports a failure for this message",
                risk=_RuleWeights.AUTH_FAIL,
            )
        )
        rule_hits.append("header:auth-fail")
    elif ("spf=pass" in auth_lower and "dkim=pass" in auth_lower) or (spf_pass and not spf_fail):
        findings.append(
            HeaderFinding(
                label="Authentication passed",
                detail="SPF and DKIM both pass for this message (adds a discount)",
                risk=-_RuleWeights.AUTH_PASS_DEDUCT,
            )
        )

    urgency_count = 0
    searchable = " ".join(
        str(x) for x in (subject or "", html_source or "", text_body or "")
    ).lower()
    for word in URGENCY_WORDS:
        if word in searchable:
            urgency_count += 1
    if urgency_count:
        findings.append(
            HeaderFinding(
                label="Urgency language",
                detail=f"{urgency_count} urgency/credential phrases detected in subject or body",
                risk=min(20, urgency_count * _RuleWeights.URGENCY_WORDS_PER),
            )
        )
        rule_hits.append("content:urgency-language")

    if html_source:
        js_count = 0
        for m in HREF_RE.findall(html_source):
            if m.lower().startswith(("javascript:", "data:text/html")):
                js_count += 1
        if js_count:
            findings.append(
                HeaderFinding(
                    label="Obfuscated link payload",
                    detail=f"{js_count} javascript/data scheme anchor(s) in the HTML source",
                    risk=min(60, js_count * _RuleWeights.HTML_JAVASCRIPT_SINK_PER),
                )
            )
            rule_hits.append("content:obfuscated-links")

    if not subject and not sender_email:
        findings.append(
            HeaderFinding(
                label="Degenerate message",
                detail="Missing both Subject and From headers",
                risk=_RuleWeights.SKIP_HEADER,
            )
        )
        rule_hits.append("header:degenerate")

    # --- weights ----------------------------------------------------------------
    total = sum(f.risk for f in findings)
    total += sum(u.risk for u in urls)
    total += len(pixels) * _RuleWeights.TRACKING_PIXEL_PER
    total += len(
        [a for a in attachments if a.risky_extension]
    ) * _RuleWeights.ATTACHMENT_EXECUTABLE
    risk = max(0, min(100, total))
    level = level_for_score(risk)

    summary_points = _summary(risk, rule_hits, len(urls), len(pixels), len(attachments))
    mitigations = [
        "Do not open attachments or click links in unsolicited email",
        "Verify the sender address, not just the display name",
        "Check for unexpected Reply-To values before responding",
        "Forward the message to your security team as a suspicious sample",
        "Enable multi-factor authentication on every account it touches",
    ]

    return EmailForensicOut(
        brief=brief,
        header_findings=findings,
        urls=urls,
        tracking_pixels=pixels,
        attachments=attachments,
        rule_hits=sorted(set(rule_hits)),
        risk_score=risk,
        risk_level=level,
        summary_points=summary_points,
        mitigations=mitigations,
        html_source=html_source,
        text_body=text_body,
    )


def _risky_filename(filename: str) -> bool:
    lowered = filename.lower().strip('"')
    for ext in RISKY_EXTENSIONS:
        if lowered.endswith(ext):
            return True
    # executable names with a fake double extension, e.g. invoice.pdf.exe
    if lowered.count(".") >= 2 and lowered.endswith((".exe", ".scr", ".lnk", ".js")):
        return True
    return False


def _assess_link(url: str) -> EmailLink:
    parsed = urlparse(url)
    raw_host = parsed.hostname or url.split("/")[2] if "://" in url else url.split("/")[0]
    host = _canonical_host(raw_host or "")
    # strip userinfo @ if a bare host got grabbed
    if "@" in host:
        host = host.rsplit("@", 1)[1]

    risk = 0
    brand: str | None = None
    brand_risk = False
    ip_host = False
    shortener = False
    suspicious_tld = False

    try:
        ipaddress.ip_address(host)
        ip_host = True
        brand_risk = True
        risk += 30
    except ValueError:
        pass

    if not parsed.scheme == "https":
        risk += 25
        brand_risk = brand_risk or False

    if host in SHORTENERS:
        shortener = True
        risk += 15

    tld = _top_level(host)
    if tld in SUSPICIOUS_TLDS:
        suspicious_tld = True
        risk += 10

    if not any(host.endswith(s) for s in SAFE_RELATED_SUFFIXES):
        label = host.split(".", 1)[0].split("-", 1)[0]
        for candidate, canonical in BRAND_HOSTS.items():
            if host == canonical:
                brand = candidate
                break
            if candidate in label or _levenshtein(label, candidate) <= 2:
                brand = candidate
                brand_risk = True
                risk += 40
                break

    return EmailLink(
        url=url,
        display_text=None,
        domain=host or None,
        brand=brand.title() if brand else None,
        brand_risk=brand_risk,
        https=parsed.scheme == "https",
        ip_host=ip_host,
        shortener=shortener,
        suspicious_tld=suspicious_tld,
        risk=max(0, min(100, risk)),
    )


def _levenshtein(a: str, b: str, limit: int = 2) -> int:
    """Edit distance capped so long strings bail out quickly (typosquat check)."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    if len(a) < len(b):
        a, b = b, a
    row = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        prev = row
        row = [i]
        for j, cb in enumerate(b, 1):
            row.append(
                min(
                    prev[j] + 1,
                    row[j - 1] + 1,
                    prev[j - 1] + (ca != cb),
                )
            )
    return row[-1]


def _summary(
    risk: int,
    rule_hits: list[str],
    url_count: int,
    pixel_count: int,
    attachment_count: int,
) -> list[str]:
    points: list[str] = []
    if risk < 20:
        points.append("Message shows no strong phishing indicators")
    elif risk < 40:
        points.append("Message carries suspicious signals worth manual review")
    elif risk < 70:
        points.append("Message exhibits multiple phishing-style indicators")
    else:
        points.append("Message is consistent with a high-impact phishing attempt")

    if url_count:
        risky = "risky" if any(True for _ in rule_hits) else "tracked"
        points.append(f"{url_count} URL(s) extracted from the message")
    if pixel_count:
        points.append(f"{pixel_count} tracking pixel(s)/open counters detected")
    if attachment_count:
        points.append(f"{attachment_count} attachment(s) inspected (raw samples are never stored)")
    if "header:brand-impersonation" in rule_hits:
        points.append("Sender display name does not match its real domain")
    return points