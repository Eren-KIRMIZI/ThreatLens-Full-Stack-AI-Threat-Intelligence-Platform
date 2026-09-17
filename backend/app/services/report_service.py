"""Report compilation and PDF rendering.

``build_report`` turns a stored ``AnalysisResult`` into a deterministic,
human-readable ``ReportDocument`` (executive summary + evidence tables +
optional AI interpretation). ``render_pdf`` renders that document to PDF
bytes with reportlab, so the JSON preview and the PDF always agree.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.schemas.analysis import AnalysisResult, ThreatLevel
from app.schemas.report import (
    ReportBlock,
    ReportDocument,
    ReportRow,
    ReportTable,
)

# --------------------------------------------------------------------------- #
# Building the document
# --------------------------------------------------------------------------- #

_LEVEL_TEXT: dict[ThreatLevel, str] = {
    "clean": "clean",
    "suspicious": "suspicious",
    "malicious": "malicious",
    "critical": "critical",
}


def _friendly_name(result: AnalysisResult) -> str:
    if result.metadata.kind == "file" and result.metadata.meaningful_name:
        return result.metadata.meaningful_name
    return result.indicator


def _summary_text(result: AnalysisResult) -> str:
    score = result.threat_score
    level = result.threat_level
    flagged = result.stats.malicious + result.stats.suspicious
    total = (
        result.stats.malicious
        + result.stats.suspicious
        + result.stats.undetected
        + result.stats.harmless
        + result.stats.timeout
    )
    level_desc = _LEVEL_TEXT.get(level, "unrated") if level else "unrated"

    verdict = (
        f"The indicator was assessed as {level_desc} with a threat "
        f"score of {score} out of 100."
        if score is not None
        else "The indicator has not yet been scored; re-running the analysis will assign one."
    )
    detection = (
        f"Out of {total} consulted detection engines, {flagged} reported the "
        f"indicator as malicious or suspicious."
        if total
        else "No detection engines were available for this indicator."
    )
    reputation = ""
    if result.metadata.reputation is not None:
        sign = "+" if result.metadata.reputation >= 0 else ""
        reputation = (
            f" The VirusTotal community reputation stands at {sign}{result.metadata.reputation}."
        )
    ai_hint = (
        " An evidence-based AI interpretation is included below."
        if result.ai
        else " No AI interpretation is attached yet."
    )
    return (
        f"The reported indicator “{_friendly_name(result)}” was submitted to the "
        f"VirusTotal evidence pipeline and analyzed successfully. {verdict} "
        f"{detection}{reputation}{ai_hint}"
    )


def _profile_rows(result: AnalysisResult) -> list[ReportRow]:
    metadata = result.metadata
    rows: list[ReportRow] = []
    if metadata.kind == "file":
        rows.append(ReportRow(label="SHA-256", value=metadata.sha256 or "—"))
        rows.append(ReportRow(label="SHA-1", value=metadata.sha1 or "—"))
        rows.append(ReportRow(label="MD5", value=metadata.md5 or "—"))
        if metadata.meaningful_name:
            rows.append(ReportRow(label="File name", value=metadata.meaningful_name))
        if metadata.type_description:
            rows.append(ReportRow(label="Type", value=metadata.type_description))
        if metadata.size is not None:
            rows.append(ReportRow(label="Size", value=f"{metadata.size} bytes"))
    elif metadata.kind == "url":
        rows.append(ReportRow(label="URL", value=metadata.url or "—"))
        if metadata.final_url and metadata.final_url != metadata.url:
            rows.append(ReportRow(label="Final URL", value=metadata.final_url))
        if metadata.title:
            rows.append(ReportRow(label="Title", value=metadata.title))
    elif metadata.kind == "domain":
        rows.append(ReportRow(label="Domain", value=result.indicator))
        if metadata.registrar:
            rows.append(ReportRow(label="Registrar", value=metadata.registrar))
        if metadata.creation_date:
            rows.append(
                ReportRow(
                    label="Registered",
                    value=metadata.creation_date.strftime("%Y-%m-%d"),
                )
            )
    elif metadata.kind == "ip":
        rows.append(ReportRow(label="IP address", value=result.indicator))
        if metadata.country:
            rows.append(ReportRow(label="Country", value=metadata.country))
        if metadata.as_owner:
            rows.append(ReportRow(label="AS owner", value=metadata.as_owner))
        if metadata.asn is not None:
            rows.append(ReportRow(label="ASN", value=str(metadata.asn)))

    if metadata.reputation is not None:
        sign = "+" if metadata.reputation >= 0 else ""
        rows.append(ReportRow(label="Reputation", value=f"{sign}{metadata.reputation}"))
    if metadata.threat_names:
        rows.append(
            ReportRow(label="Threat names", value=", ".join(metadata.threat_names))
        )
    if metadata.tags:
        rows.append(ReportRow(label="Tags", value=", ".join(metadata.tags)))
    if metadata.total_votes:
        votes = ", ".join(
            f"{key}: {value}" for key, value in sorted(metadata.total_votes.items())
        )
        rows.append(ReportRow(label="Community votes", value=votes))
    return rows


def build_report(result: AnalysisResult) -> ReportDocument:
    blocks: list[ReportBlock] = []

    blocks.append(
        ReportBlock(
            kind="paragraph",
            heading="Executive summary",
            text=_summary_text(result),
        )
    )

    stats = result.stats
    total = (
        stats.malicious
        + stats.suspicious
        + stats.undetected
        + stats.harmless
        + stats.timeout
    )
    blocks.append(
        ReportBlock(
            kind="facts",
            heading="Detection overview",
            facts=[
                ReportRow(label="Malicious engines", value=str(stats.malicious)),
                ReportRow(label="Suspicious engines", value=str(stats.suspicious)),
                ReportRow(label="Undetected", value=str(stats.undetected)),
                ReportRow(label="Harmless", value=str(stats.harmless)),
                ReportRow(label="Timeout / unsupported", value=str(stats.timeout)),
                ReportRow(label="Engines consulted", value=str(total)),
            ],
        )
    )

    engine_rows = [
        [d.engine, d.category, d.result or "—", d.method or "—"]
        for d in result.detections
    ]
    blocks.append(
        ReportBlock(
            kind="table",
            heading="Per-engine detections",
            table=ReportTable(
                columns=["Engine", "Verdict", "Result", "Method"],
                rows=engine_rows,
            ),
        )
    )

    blocks.append(
        ReportBlock(
            kind="facts", heading="Indicator profile", facts=_profile_rows(result)
        )
    )

    enrichment = result.enrichment
    if enrichment:
        conf_rows: list[ReportRow] = []
        confidence = enrichment.confidence
        if confidence:
            conf_rows.append(
                ReportRow(
                    label="Multi-source confidence",
                    value=f"{confidence.overall}/100 ({confidence.verdict})",
                )
            )
            conf_rows.append(
                ReportRow(
                    label="Per-source breakdown",
                    value=", ".join(
                        f"{source.source}: {source.score}" for source in confidence.sources
                    )
                    or "—",
                )
            )
            for reason in confidence.reasons[:8]:
                conf_rows.append(ReportRow(label="Signal", value=reason))
        conf_rows.append(
            ReportRow(
                label="Sources consulted",
                value=", ".join(enrichment.sources) or "—",
            )
        )
        blocks.append(
            ReportBlock(
                kind="facts",
                heading="Multi-provider enrichment & confidence",
                facts=conf_rows,
            )
        )

    ai = result.ai
    if ai:
        blocks.append(
            ReportBlock(
                kind="paragraph",
                heading="AI security analysis",
                text=ai.summary or "The model produced no narrative for this evidence.",
            )
        )
        if ai.tactics:
            blocks.append(
                ReportBlock(
                    kind="table",
                    heading="Tactics identified",
                    table=ReportTable(
                        columns=["Phase", "Technique", "Notes"],
                        rows=[
                            [
                                tactic.phase,
                                (
                                    f"{tactic.technique_id or ''} {tactic.technique_name or ''}".strip()
                                    or "—"
                                ),
                                tactic.notes or "—",
                            ]
                            for tactic in ai.tactics
                        ],
                    ),
                )
            )
        claims: list[ReportRow] = []
        if ai.threat_actor_profile is not None:
            actor = ai.threat_actor_profile
            name = actor.name or "Unknown / unprofiled"
            canvas = name
            if actor.confidence:
                canvas += f" (confidence: {actor.confidence})"
            if actor.campaign:
                canvas += f" — campaign: {actor.campaign}"
            claims.append(ReportRow(label="Threat actor", value=canvas))
        for capability in ai.capabilities:
            claims.append(
                ReportRow(
                    label="Capability",
                    value=f"{capability.capability}: {capability.description}",
                )
            )
        if ai.lifecycle_stage:
            claims.append(ReportRow(label="Lifecycle stage", value=ai.lifecycle_stage))
        if ai.threat_level_assessment:
            claims.append(
                ReportRow(label="AI assessment", value=ai.threat_level_assessment)
            )
        if ai.evidence_refs:
            claims.append(
                ReportRow(
                    label="Evidence cited",
                    value=", ".join(sorted(ai.evidence_refs)),
                )
            )
        if claims:
            blocks.append(
                ReportBlock(kind="facts", heading="AI assessment details", facts=claims)
            )
        if ai.recommendations:
            blocks.append(
                ReportBlock(
                    kind="paragraph",
                    heading="Recommendations",
                    text="\n".join(f"• {item}" for item in ai.recommendations),
                )
            )
        if ai.correlations:
            blocks.append(
                ReportBlock(
                    kind="paragraph",
                    heading="Correlations",
                    text="; ".join(ai.correlations),
                )
            )

    return ReportDocument(
        title="ThreatLens Security Report",
        subtitle=(
            f"{result.indicator_type} · {result.indicator} · "
            f"analyzed {result.analyzed_at:%Y-%m-%d %H:%M} UTC"
        ),
        generated_at=datetime.now(UTC),
        indicator=result.indicator,
        indicator_type=result.indicator_type,
        threat_score=result.threat_score,
        threat_level=result.threat_level,
        blocks=blocks,
    )


def report_filename(document: ReportDocument) -> str:
    stamp = document.generated_at.astimezone(UTC).strftime("%Y%m%d-%H%M%S")
    return f"threatlens-report-{document.indicator_type.lower()}-{stamp}.pdf"


# --------------------------------------------------------------------------- #
# PDF rendering
# --------------------------------------------------------------------------- #

_LEVEL_HEX: dict[ThreatLevel, str] = {
    "clean": "#16a34a",
    "suspicious": "#ca8a04",
    "malicious": "#c2410c",
    "critical": "#b91c1c",
}

_FONT_PAIR_CANDIDATES = [
    (r"C:\Windows\Fonts\segoeui.ttf", r"C:\Windows\Fonts\segoeuib.ttf"),
    (r"C:\Windows\Fonts\arial.ttf", r"C:\Windows\Fonts\arialbd.ttf"),
]

_FONTS: tuple[str, str] | None = None


def _fonts() -> tuple[str, str]:
    global _FONTS
    if _FONTS is not None:
        return _FONTS
    for path_regular, path_bold in _FONT_PAIR_CANDIDATES:
        if os.path.exists(path_regular) and os.path.exists(path_bold):
            try:
                regular = "ThreatLensFont"
                bold = "ThreatLensFontBold"
                pdfmetrics.registerFont(TTFont(regular, path_regular))
                pdfmetrics.registerFont(TTFont(bold, path_bold))
                _FONTS = (regular, bold)
                return _FONTS
            except Exception:
                continue
    _FONTS = ("Helvetica", "Helvetica-Bold")
    return _FONTS


def _esc(value: str) -> str:
    return escape(value.replace("\u201c", '"').replace("\u201d", '"'))


def _render_blocks(document: ReportDocument) -> list:
    regular, bold = _fonts()
    body = ParagraphStyle(
        "Body",
        fontName=regular,
        fontSize=9.5,
        leading=13.5,
        textColor=colors.HexColor("#1f2430"),
        alignment=TA_LEFT,
    )
    heading = ParagraphStyle(
        "BlockHeading",
        fontName=bold,
        fontSize=11,
        leading=15,
        textColor=colors.HexColor("#11141c"),
        spaceBefore=6,
        spaceAfter=3,
    )
    cell = ParagraphStyle(
        "Cell",
        fontName=regular,
        fontSize=8.5,
        leading=11.5,
        textColor=colors.HexColor("#232a38"),
    )
    cell_bold = ParagraphStyle(
        "CellBold",
        fontName=bold,
        fontSize=8.5,
        leading=11.5,
        textColor=colors.HexColor("#171b26"),
    )
    cell_header = ParagraphStyle(
        "CellHeader",
        fontName=bold,
        fontSize=8.5,
        leading=11,
        textColor=colors.white,
    )

    facts_table_style = TableStyle(
        [
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef1f6")),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d7dce5")),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]
    )

    data_table_style = TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#232a38")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9d0db")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            (
                "ROWBACKGROUNDS",
                (0, 1),
                (-1, -1),
                [colors.white, colors.HexColor("#f4f6fa")],
            ),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]
    )

    elements: list = []
    for block in document.blocks:
        elements.append(Paragraph(_esc(block.heading), heading))
        if block.kind == "paragraph":
            elements.append(Paragraph(_esc(block.text or ""), body))
        elif block.kind == "facts":
            rows = [
                [
                    Paragraph(_esc(row.label), cell_bold),
                    Paragraph(_esc(row.value), cell),
                ]
                for row in block.facts
            ]
            table = Table(rows, colWidths=[42 * mm, 116 * mm])
            table.setStyle(facts_table_style)
            elements.append(table)
        elif block.kind == "table" and block.table and block.table.rows:
            table_model = block.table
            headers = [
                Paragraph(_esc(col), cell_header) for col in table_model.columns
            ]
            rows = [
                [Paragraph(_esc(value), cell) for value in row]
                for row in table_model.rows
            ]
            table = Table([headers, *rows], repeatRows=1)
            table.setStyle(data_table_style)
            elements.append(table)
        elements.append(Spacer(1, 4))

    return elements


def _render_header_footer(document: ReportDocument):
    def draw(_canvas, doc):
        width, _height = A4
        _canvas.saveState()
        _canvas.setStrokeColor(colors.HexColor("#d7dce5"))
        _canvas.setLineWidth(0.4)
        _canvas.line(16 * mm, A4[1] - 12 * mm, width - 16 * mm, A4[1] - 12 * mm)
        _canvas.setFont("Helvetica", 7.5)
        _canvas.setFillColor(colors.HexColor("#5c6675"))
        _canvas.drawString(16 * mm, A4[1] - 10 * mm, "ThreatLens")
        _canvas.drawRightString(
            width - 16 * mm, A4[1] - 10 * mm, "Evidence-based threat intelligence"
        )
        generated = document.generated_at.astimezone(UTC).strftime("%Y-%m-%d %H:%M")
        _canvas.drawString(16 * mm, 11 * mm, f"Generated {generated} UTC")
        _canvas.drawRightString(width - 16 * mm, 11 * mm, f"Page {doc.page}")
        _canvas.restoreState()

    return draw


def render_pdf(document: ReportDocument) -> bytes:
    from io import BytesIO

    regular, bold = _fonts()
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=16 * mm,
        rightMargin=16 * mm,
        topMargin=18 * mm,
        bottomMargin=16 * mm,
        title=document.title,
        author="ThreatLens",
    )

    title_style = ParagraphStyle(
        "Title",
        fontName=bold,
        fontSize=19,
        leading=24,
        textColor=colors.HexColor("#11141c"),
        spaceAfter=2,
    )
    subtitle_style = ParagraphStyle(
        "Subtitle",
        fontName=regular,
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#5c6675"),
        spaceAfter=6,
    )

    story = [
        Paragraph(_esc(document.title), title_style),
        Paragraph(_esc(document.subtitle), subtitle_style),
        Spacer(1, 2),
    ]

    score = document.threat_score
    level = document.threat_level
    if score is not None or level is not None:
        level_hex = _LEVEL_HEX.get(level, "#5c6675") if level else "#5c6675"
        label = f"{score}/100 — {level}" if score is not None else str(level)
        verdict = Paragraph(
            f"<b>{label.upper().replace('—', '–')}</b>",
            ParagraphStyle(
                "Verdict",
                fontName=bold,
                fontSize=11,
                leading=15,
                textColor=colors.white,
            ),
        )
        verdict_table = Table([[verdict]], colWidths=[160 * mm])
        verdict_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(level_hex)),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("TOPPADDING", (0, 0), (-1, -1), 7),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ]
            )
        )
        story.append(verdict_table)
        story.append(Spacer(1, 8))

    story.extend(_render_blocks(document))
    doc.build(
        story,
        onFirstPage=_render_header_footer(document),
        onLaterPages=_render_header_footer(document),
    )
    return buffer.getvalue()