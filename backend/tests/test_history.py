"""Tests for persistence, cache behaviour and the history API."""

import httpx
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

DUMMY_SHA256 = "a" * 64
CLEAN_SHA256 = "b" * 64

FILE_REPORT = {
    "data": {
        "id": DUMMY_SHA256,
        "type": "file",
        "attributes": {
            "sha256": DUMMY_SHA256,
            "sha1": "c" * 40,
            "md5": "d" * 32,
            "type_description": "Win32 EXE",
            "size": 22528,
            "names": ["sample.exe"],
            "meaningful_name": "sample.exe",
            "reputation": -10,
            "tags": [],
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
                "Microsoft": {"category": "malicious", "result": "Trojan", "method": "blacklist"},
            },
        },
    }
}

CLEAN_REPORT = {
    "data": {
        "id": CLEAN_SHA256,
        "type": "file",
        "attributes": {
            "sha256": CLEAN_SHA256,
            "sha1": "e" * 40,
            "md5": "f" * 32,
            "type_description": "Text",
            "size": 4,
            "names": ["clean.txt"],
            "meaningful_name": "clean.txt",
            "reputation": 0,
            "tags": [],
            "total_votes": {"harmless": 1, "malicious": 0},
            "first_submission_date": 1699999999,
            "last_analysis_date": 1700000000,
            "last_analysis_stats": {
                "harmless": 70,
                "malicious": 0,
                "suspicious": 0,
                "undetected": 0,
                "timeout": 0,
            },
            "last_analysis_results": {
                "Avast": {"category": "undetected"},
            },
        },
    }
}


def mixed_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path.endswith(f"/files/{DUMMY_SHA256}"):
        return httpx.Response(200, json=FILE_REPORT)
    if request.url.path.endswith(f"/files/{CLEAN_SHA256}"):
        return httpx.Response(200, json=CLEAN_REPORT)
    return httpx.Response(404, json={})


def install_mock(handler=mixed_handler) -> None:
    from app.services.virustotal_service import VirusTotalService

    app.state.virustotal_service = VirusTotalService(
        api_key="test-key", transport=httpx.MockTransport(handler)
    )


def remove_mock() -> None:
    app.state.virustotal_service = None


def analyze_hash(hash_value: str):
    return client.post("/api/v1/analyze/hash", json={"hash": hash_value})


def test_analysis_is_persisted_and_retrievable() -> None:
    install_mock()
    try:
        created = analyze_hash(DUMMY_SHA256)
        assert created.status_code == 201
        analysis_id = created.json()["analysis_id"]

        detail = client.get(f"/api/v1/analysis/{analysis_id}")
        assert detail.status_code == 200
        assert detail.json()["indicator"] == DUMMY_SHA256
        assert detail.json()["analysis_id"] == analysis_id

        history = client.get("/api/v1/history")
        assert history.status_code == 200
        page = history.json()
        assert page["total"] == 1
        item = page["items"][0]
        assert item["analysis_id"] == analysis_id
        assert item["indicator"] == DUMMY_SHA256
        assert item["indicator_type"] == "HASH"
        assert item["detected_vendors"] == 5
        assert item["stats"]["malicious"] == 5
        assert item["threat_level"] == "malicious"
        assert item["threat_score"] == 61
    finally:
        remove_mock()


def test_missing_analysis_returns_404() -> None:
    response = client.get("/api/v1/analysis/does-not-exist")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "analysis_not_found"


def test_cache_hit_avoids_repeat_virustotal_call() -> None:
    calls = {"get_file": 0}

    def counting_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith(f"/files/{DUMMY_SHA256}"):
            calls["get_file"] += 1
            return httpx.Response(200, json=FILE_REPORT)
        return httpx.Response(404, json={})

    install_mock(counting_handler)
    try:
        first = analyze_hash(DUMMY_SHA256)
        second = analyze_hash(DUMMY_SHA256)
        assert first.status_code == 201
        assert second.status_code == 201
        assert calls["get_file"] == 1
        assert first.json()["analysis_id"] == second.json()["analysis_id"]
        assert first.json()["indicator"] == second.json()["indicator"]
    finally:
        remove_mock()


def test_cache_expired_reinvokes_virustotal(monkeypatch) -> None:
    from app.core.config import get_settings

    # Negative TTL makes the cache window lie entirely in the future,
    # deterministically forcing a miss (avoids same-microsecond races).
    monkeypatch.setattr(get_settings(), "cache_ttl_seconds", -1)
    calls = {"get_file": 0}

    def counting_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith(f"/files/{DUMMY_SHA256}"):
            calls["get_file"] += 1
            return httpx.Response(200, json=FILE_REPORT)
        return httpx.Response(404, json={})

    install_mock(counting_handler)
    try:
        first = analyze_hash(DUMMY_SHA256)
        second = analyze_hash(DUMMY_SHA256)
        assert first.status_code == 201
        assert second.status_code == 201
        assert calls["get_file"] == 2
        assert first.json()["analysis_id"] != second.json()["analysis_id"]
    finally:
        remove_mock()


def test_history_filters_and_search() -> None:
    install_mock()
    try:
        assert analyze_hash(DUMMY_SHA256).status_code == 201
        assert analyze_hash(CLEAN_SHA256).status_code == 201

        malicious = client.get("/api/v1/history", params={"filter": "malicious"})
        assert malicious.status_code == 200
        assert [item["indicator"] for item in malicious.json()["items"]] == [DUMMY_SHA256]

        clean = client.get("/api/v1/history", params={"filter": "clean"})
        assert [item["indicator"] for item in clean.json()["items"]] == [CLEAN_SHA256]

        suspicious = client.get("/api/v1/history", params={"filter": "suspicious"})
        assert suspicious.json()["total"] == 0

        search = client.get("/api/v1/history", params={"search": CLEAN_SHA256})
        assert [item["indicator"] for item in search.json()["items"]] == [CLEAN_SHA256]

        all_page = client.get("/api/v1/history", params={"limit": 1, "offset": 0})
        assert all_page.json()["total"] == 2
        assert len(all_page.json()["items"]) == 1
    finally:
        remove_mock()