"""End-to-end tests for the evidence-based AI interpretation."""

import json

import httpx
from fastapi.testclient import TestClient

from app.main import app
from app.core.config import get_settings
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
            "tags": ["peexe"],
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
                "Microsoft": {"category": "malicious", "result": "Trojan:Win32/Test.Z", "method": "blacklist"},
                "Kaspersky": {"category": "malicious", "result": "HEUR:Trojan.Win32.Agent", "method": "blacklist"},
            },
        },
    }
}

AI_RESPONSE = {
    "summary": "The sample is flagged by multiple engines as a trojan.",
    "tactics": [
        {"phase": "Execution", "technique_id": "T1059", "technique_name": "Command and Scripting Interpreter", "notes": None}
    ],
    "threat_actor_profile": None,
    "capabilities": [
        {"capability": "Code execution", "description": "Multiple engines report trojan behaviour."}
    ],
    "recommendations": ["Block the hash", "Quarantine affected hosts"],
    "lifecycle_stage": "analysis",
    "correlations": [],
    "threat_level_assessment": "malicious",
    "evidence_refs": ["Microsoft", "HallucinatedEngine"],
}


def file_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json=FILE_REPORT)


def ai_handler(request: httpx.Request) -> httpx.Response:
    body = json.loads(request.content)
    user_message = body["messages"][1]["content"]
    assert DUMMY_SHA256 in user_message
    return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(AI_RESPONSE)}}]})


def install(ai_api_key: str | None = "test-key", ai_transport=None) -> None:
    from app.services.virustotal_service import VirusTotalService

    app.state.virustotal_service = VirusTotalService(
        api_key="test-key", transport=httpx.MockTransport(file_handler)
    )
    app.state.openrouter_service = OpenRouterService(
        api_key=ai_api_key, transport=ai_transport or httpx.MockTransport(ai_handler)
    )


def remove_mocks() -> None:
    app.state.virustotal_service = None
    app.state.openrouter_service = None


def test_analyze_hash_with_ai_returns_structured_interpretation() -> None:
    install()
    try:
        response = client.post("/api/v1/analyze/hash", json={"hash": DUMMY_SHA256, "ai": True})
        assert response.status_code == 201
        payload = response.json()

        ai = payload["ai"]
        assert ai is not None
        assert ai["summary"].startswith("The sample")
        assert ai["tactics"][0]["phase"] == "Execution"
        assert ai["threat_level_assessment"] == "malicious"
        # Hallucinated engine removed, only real engines retained.
        assert ai["evidence_refs"] == ["Microsoft"]
        assert ai["model"] == get_settings().openrouter_model
    finally:
        remove_mocks()


def test_analyze_without_ai_skips_openrouter() -> None:
    def forbidden(ai):
        raise AssertionError("OpenRouter must not be called")

    app.state.virustotal_service = None  # reuse install below instead
    install(ai_transport=httpx.MockTransport(forbidden))
    try:
        response = client.post("/api/v1/analyze/hash", json={"hash": DUMMY_SHA256})
        assert response.status_code == 201
        assert response.json()["ai"] is None
    finally:
        remove_mocks()


def test_analyze_fails_cleanly_when_ai_key_missing() -> None:
    install(ai_api_key="")
    try:
        response = client.post("/api/v1/analyze/hash", json={"hash": DUMMY_SHA256, "ai": True})
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "openrouter_config_error"
    finally:
        remove_mocks()


def test_cached_result_with_ai_skips_both_upstreams() -> None:
    install()
    try:
        first = client.post("/api/v1/analyze/hash", json={"hash": DUMMY_SHA256, "ai": True})
        assert first.status_code == 201

        # Second identical request: served from cache (VT, AI not re-called).
        second = client.post("/api/v1/analyze/hash", json={"hash": DUMMY_SHA256, "ai": True})
        assert second.status_code == 201
        assert second.json()["analysis_id"] == first.json()["analysis_id"]
        assert second.json()["ai"]["summary"] == first.json()["ai"]["summary"]
    finally:
        remove_mocks()


def test_enrich_endpoint_attaches_ai_to_stored_analysis() -> None:
    install(ai_transport=httpx.MockTransport(ai_handler))
    try:
        created = client.post("/api/v1/analyze/hash", json={"hash": DUMMY_SHA256})
        assert created.status_code == 201
        assert created.json()["ai"] is None
        analysis_id = created.json()["analysis_id"]

        enriched = client.post(f"/api/v1/analysis/{analysis_id}/ai")
        assert enriched.status_code == 200
        assert enriched.json()["threat_level_assessment"] == "malicious"

        stored = client.get(f"/api/v1/analysis/{analysis_id}")
        assert stored.json()["ai"]["summary"] == enriched.json()["summary"]
    finally:
        remove_mocks()


def test_enrich_unknown_analysis_returns_404() -> None:
    install()
    try:
        response = client.post("/api/v1/analysis/does-not-exist/ai")
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "analysis_not_found"
    finally:
        remove_mocks()