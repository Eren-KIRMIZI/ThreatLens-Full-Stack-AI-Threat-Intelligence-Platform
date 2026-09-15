"""End-to-end tests for the report generation endpoints."""

import httpx
from fastapi.testclient import TestClient

from app.main import app
from app.services.openrouter_service import OpenRouterService

client = TestClient(app)

DUMMY_SHA256 = "a" * 64

FILE_REPORT = {
    "data": {
        "id": DUMMY_SHA256,
        "type": "file",
        "attributes": {
            "sha256": DUMMY_SHA256,
            "sha1": "b" * 40,
            "md5": "c" * 32,
            "type_description": "Win32 EXE",
            "size": 22528,
            "names": ["sample.exe"],
            "meaningful_name": "sample.exe",
            "reputation": -10,
            "tags": ["peexe", "signed"],
            "total_votes": {"harmless": 0, "malicious": 3},
            "first_submission_date": 1699999999,
            "last_analysis_date": 1700000000,
            "last_analysis_stats": {
                "harmless": 50,
                "malicious": 5,
                "suspicious": 2,
                "undetected": 3,
                "timeout": 0,
            },
            "last_analysis_results": {
                "Microsoft": {
                    "category": "malicious",
                    "result": "Trojan:Win32/Test.Z",
                    "method": "blacklist",
                },
                "Kaspersky": {
                    "category": "malicious",
                    "result": "HEUR:Trojan.Win32.Agent",
                    "method": "blacklist",
                },
            },
        },
    }
}


def file_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json=FILE_REPORT)


def install() -> None:
    from app.services.virustotal_service import VirusTotalService

    app.state.virustotal_service = VirusTotalService(
        api_key="test-key", transport=httpx.MockTransport(file_handler)
    )
    app.state.openrouter_service = None


def remove_mocks() -> None:
    app.state.virustotal_service = None
    app.state.openrouter_service = None


def _create_analysis() -> str:
    response = client.post("/api/v1/analyze/hash", json={"hash": DUMMY_SHA256})
    assert response.status_code == 201
    return response.json()["analysis_id"]


def test_report_preview_is_structured_and_complete() -> None:
    install()
    try:
        analysis_id = _create_analysis()
        response = client.get(f"/api/v1/reports/{analysis_id}")
        assert response.status_code == 200
        payload = response.json()

        assert payload["title"] == "ThreatLens Security Report"
        assert payload["indicator"] == DUMMY_SHA256
        assert payload["indicator_type"] == "HASH"
        # Hash analyses are normalized to a file metadata kind.
        assert payload["threat_score"] is not None
        assert payload["threat_level"] == "malicious"

        headings = [block["heading"] for block in payload["blocks"]]
        assert "Executive summary" in headings
        assert "Detection overview" in headings
        assert "Per-engine detections" in headings
        assert "Indicator profile" in headings

        overview = next(
            block for block in payload["blocks"] if block["heading"] == "Detection overview"
        )
        values = {row["label"]: row["value"] for row in overview["facts"]}
        assert values["Malicious engines"] == "5"
        assert values["Engines consulted"] == "60"

        engines = next(
            block
            for block in payload["blocks"]
            if block["heading"] == "Per-engine detections"
        )
        assert engines["table"]["columns"] == ["Engine", "Verdict", "Result", "Method"]
        assert len(engines["table"]["rows"]) == 2
        assert engines["table"]["rows"][0][0] == "Microsoft"
    finally:
        remove_mocks()


def test_report_pdf_returns_valid_pdf_bytes() -> None:
    install()
    try:
        analysis_id = _create_analysis()
        response = client.get(f"/api/v1/reports/{analysis_id}/pdf")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/pdf")
        assert 'attachment; filename="threatlens-report-hash-' in response.headers[
            "content-disposition"
        ]
        body = response.content
        assert body.startswith(b"%PDF")
        assert body.rstrip().endswith(b"%%EOF")
        assert len(body) > 2000
        assert b"ThreatLens Security Report" in body
        # PDF streams are compressed; text correctness is asserted on the model.
        assert b"/Type /Catalog" in body or b"reportlab" in body
    finally:
        remove_mocks()


def test_report_unknown_analysis_returns_404() -> None:
    install()
    try:
        preview = client.get("/api/v1/reports/does-not-exist")
        assert preview.status_code == 404
        assert preview.json()["error"]["code"] == "analysis_not_found"

        pdf = client.get("/api/v1/reports/does-not-exist/pdf")
        assert pdf.status_code == 404
        assert pdf.json()["error"]["code"] == "analysis_not_found"
    finally:
        remove_mocks()


def test_document_model_survives_reportlab_render_roundtrip() -> None:
    """The document model alone (no HTTP) renders to PDF deterministically."""
    from datetime import UTC, datetime

    from app.schemas.analysis import (
        AnalysisResult,
        DetectionEntry,
        DetectionStats,
        FileMetadata,
    )
    from app.schemas.report import ReportBlock, ReportDocument
    from app.services.report_service import build_report, render_pdf

    result = AnalysisResult(
        analysis_id="roundtrip",
        indicator=DUMMY_SHA256,
        indicator_type="HASH",
        submitted_at=datetime.now(UTC),
        analyzed_at=datetime.now(UTC),
        stats=DetectionStats(malicious=2, undetected=10),
        detections=[
            DetectionEntry(engine="Avast", category="malicious", result="Win32:Trojan.X")
        ],
        metadata=FileMetadata(
            kind="file",
            sha256=DUMMY_SHA256,
            sha1="b" * 40,
            md5="c" * 32,
            meaningful_name="payload.bin",
            reputation=-5,
            total_votes={"harmless": 1, "malicious": 2},
        ),
        threat_score=72,
        threat_level="malicious",
    )
    document = build_report(result)
    assert document.threat_score == 72
    summary = next(
        block for block in document.blocks if block.heading == "Executive summary"
    )
    assert "payload.bin" in summary.text
    assert "72 out of 100" in summary.text

    pdf = render_pdf(document)
    assert pdf.startswith(b"%PDF")
    assert pdf.rstrip().endswith(b"%%EOF")


def test_build_report_includes_ai_sections() -> None:
    """When an AI interpretation is attached, its sections become report blocks."""
    from datetime import UTC, datetime

    from app.schemas.ai import AIAnalysis, AICapability, AITactic
    from app.schemas.analysis import (
        AnalysisResult,
        DetectionEntry,
        DetectionStats,
        FileMetadata,
    )
    from app.services.report_service import build_report, render_pdf

    result = AnalysisResult(
        analysis_id="with-ai",
        indicator=DUMMY_SHA256,
        indicator_type="HASH",
        submitted_at=datetime.now(UTC),
        analyzed_at=datetime.now(UTC),
        stats=DetectionStats(malicious=1),
        detections=[
            DetectionEntry(engine="Avast", category="malicious", result="Trojan.X")
        ],
        metadata=FileMetadata(kind="file", sha256=DUMMY_SHA256),
        threat_score=40,
        threat_level="malicious",
        ai=AIAnalysis(
            summary="Evidence indicates a trojan downloader.",
            tactics=[
                AITactic(
                    phase="Execution",
                    technique_id="T1059",
                    technique_name="PowerShell",
                    notes="Engine signs point to script execution.",
                )
            ],
            capabilities=[
                AICapability(
                    capability="Code execution",
                    description="Multiple engines report trojan behaviour.",
                )
            ],
            recommendations=["Block the hash", "Quarantine hosts"],
            correlations=["Correlates with Emotet campaigns"],
            lifecycle_stage="analysis",
            threat_level_assessment="malicious",
            evidence_refs=["Avast"],
        ),
    )

    document = build_report(result)
    headings = [block.heading for block in document.blocks]
    assert "AI security analysis" in headings
    assert "Tactics identified" in headings
    assert "AI assessment details" in headings
    assert "Recommendations" in headings
    assert "Correlations" in headings

    tactics = next(
        block for block in document.blocks if block.heading == "Tactics identified"
    )
    assert tactics.table is not None
    assert tactics.table.rows[0] == [
        "Execution",
        "T1059 PowerShell",
        "Engine signs point to script execution.",
    ]

    recommendations = next(
        block for block in document.blocks if block.heading == "Recommendations"
    )
    assert "Block the hash" in recommendations.text

    # The AI report renders to a valid PDF as well.
    pdf = render_pdf(document)
    assert pdf.startswith(b"%PDF")