"""Endpoint-level tests for the analyze API using a mocked VirusTotal transport."""

import hashlib

import httpx
from fastapi.testclient import TestClient

from app.main import app
from app.services.virustotal_service import VirusTotalService

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
            "tags": ["peexe", "runtime-modules"],
            "threat_names": ["Trojan:Win32/Test"],
            "total_votes": {"harmless": 0, "malicious": 3},
            "first_submission_date": 1699999999,
            "last_analysis_date": 1700000000,
            "last_analysis_stats": {
                "harmless": 50,
                "malicious": 5,
                "suspicious": 2,
                "undetected": 3,
                "timeout": 0,
                "type-unsupported": 0,
            },
            "last_analysis_results": {
                "Microsoft": {"category": "malicious", "result": "Trojan:Win32/Test.Z", "method": "blacklist"},
                "Kaspersky": {"category": "malicious", "result": "HEUR:Trojan.Win32.Agent", "method": "blacklist"},
                "ESET": {"category": "suspicious", "result": "a variant of Win32/Agent", "method": "blacklist"},
                "Avast": {"category": "undetected", "result": None, "method": "blacklist"},
            },
        },
    }
}


def file_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json=FILE_REPORT)


def install_mock(handler=file_handler) -> None:
    app.state.virustotal_service = VirusTotalService(
        api_key="test-key", transport=httpx.MockTransport(handler)
    )


def remove_mock() -> None:
    app.state.virustotal_service = None


def test_analyze_hash_returns_normalized_result() -> None:
    install_mock()
    try:
        response = client.post("/api/v1/analyze/hash", json={"hash": DUMMY_SHA256})
        assert response.status_code == 201
        payload = response.json()

        assert payload["analysis_id"]
        assert payload["indicator"] == DUMMY_SHA256
        assert payload["indicator_type"] == "HASH"
        assert payload["source"] == "virustotal"
        assert payload["stats"] == {
            "malicious": 5,
            "suspicious": 2,
            "undetected": 3,
            "harmless": 50,
            "timeout": 0,
        }

        detections = payload["detections"]
        assert [d["category"] for d in detections] == [
            "malicious",
            "malicious",
            "suspicious",
            "undetected",
        ]
        assert detections[0] == {
            "engine": "Microsoft",
            "result": "Trojan:Win32/Test.Z",
            "category": "malicious",
            "method": "blacklist",
        }

        # FILE_REPORT: 5 malicious + 2 suspicious + reputation -10 + 3 mal votes.
        assert payload["threat_score"] == 61
        assert payload["threat_level"] == "malicious"

        metadata = payload["metadata"]
        assert metadata["kind"] == "file"
        assert metadata["sha256"] == DUMMY_SHA256
        assert metadata["size"] == 22528
        assert metadata["threat_names"] == ["Trojan:Win32/Test"]
        assert metadata["first_submission_date"].startswith("2023-11-14")
    finally:
        remove_mock()


def test_analyze_hash_rejects_invalid_hash() -> None:
    install_mock()
    try:
        response = client.post("/api/v1/analyze/hash", json={"hash": "not-a-hash"})
        assert response.status_code == 422
        payload = response.json()
        assert payload["error"]["code"] == "validation_error"
        assert payload["error"]["details"][0]["field"] == "hash"
    finally:
        remove_mock()


def test_analyze_missing_api_key_returns_clean_error() -> None:
    remove_mock()
    response = client.post("/api/v1/analyze/hash", json={"hash": DUMMY_SHA256})
    assert response.status_code == 503
    payload = response.json()
    assert payload["error"]["code"] == "virustotal_config_error"
    assert "stack" not in str(payload).lower()


def test_analyze_url_rejects_non_http_scheme() -> None:
    install_mock()
    try:
        response = client.post("/api/v1/analyze/url", json={"url": "ftp://example.com/file"})
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "validation_error"
    finally:
        remove_mock()


def test_analyze_domain_fetches_relationship_detections() -> None:
    def domain_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/domains/example.com"):
            return httpx.Response(
                200,
                json={
                    "data": {
                        "id": "example.com",
                        "type": "domain",
                        "attributes": {
                            "registrar": "Example Registrar",
                            "creation_date": 1000000000,
                            "last_analysis_date": 1700000000,
                            "reputation": 0,
                            "last_analysis_stats": {
                                "malicious": 1,
                                "suspicious": 0,
                                "undetected": 10,
                                "harmless": 5,
                                "timeout": 0,
                            },
                        },
                    }
                },
            )
        if request.url.path.endswith("/domains/example.com/last_analysis_results"):
            return httpx.Response(
                200,
                json={
                    "data": [
                        {"attributes": {"engine_name": "G-Data", "category": "malicious", "result": "malware"}},
                        {"attributes": {"engine_name": "CrowdStrike", "category": "undetected"}},
                    ]
                },
            )
        return httpx.Response(404, json={})

    install_mock(domain_handler)
    try:
        response = client.post("/api/v1/analyze/domain", json={"domain": "example.com"})
        assert response.status_code == 201
        payload = response.json()
        assert payload["indicator_type"] == "DOMAIN"
        assert payload["metadata"]["kind"] == "domain"
        assert payload["metadata"]["registrar"] == "Example Registrar"
        assert payload["detections"][0]["engine"] == "G-Data"
        assert payload["detections"][0]["category"] == "malicious"
    finally:
        remove_mock()


def test_analyze_ip_returns_normalized_result() -> None:
    def ip_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/ip_addresses/8.8.8.8"):
            return httpx.Response(
                200,
                json={
                    "data": {
                        "id": "8.8.8.8",
                        "type": "ip_address",
                        "attributes": {
                            "country": "US",
                            "as_owner": "GOOGLE",
                            "asn": 15169,
                            "reputation": 100,
                            "last_analysis_stats": {
                                "malicious": 0,
                                "suspicious": 0,
                                "undetected": 0,
                                "harmless": 10,
                                "timeout": 0,
                            },
                        },
                    }
                },
            )
        return httpx.Response(200, json={"data": []})

    install_mock(ip_handler)
    try:
        response = client.post("/api/v1/analyze/ip", json={"ip": "8.8.8.8"})
        assert response.status_code == 201
        payload = response.json()
        assert payload["indicator_type"] == "IP"
        assert payload["metadata"]["kind"] == "ip"
        assert payload["metadata"]["as_owner"] == "GOOGLE"
        assert payload["metadata"]["asn"] == 15169
        assert payload["stats"]["harmless"] == 10
    finally:
        remove_mock()


SAMPLE_BYTES = b"hello world"
SAMPLE_SHA256 = hashlib.sha256(SAMPLE_BYTES).hexdigest()
SAMPLE_SHA1 = hashlib.sha1(SAMPLE_BYTES).hexdigest()
SAMPLE_MD5 = hashlib.md5(SAMPLE_BYTES).hexdigest()


def upload_handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if request.method == "GET" and path.endswith(f"/files/{SAMPLE_SHA256}"):
        return httpx.Response(404, json={"error": {"code": "NotFoundError"}})
    if request.method == "POST" and path.endswith("/files"):
        return httpx.Response(
            200,
            json={"data": {"id": "file-abc", "type": "analysis"}},
        )
    if request.method == "GET" and path.endswith("/analyses/file-abc"):
        return httpx.Response(
            200,
            json={
                "data": {
                    "id": "file-abc",
                    "type": "analysis",
                    "attributes": {
                        "status": "completed",
                        "date": 1700000000,
                        "stats": {
                            "harmless": 60,
                            "malicious": 4,
                            "suspicious": 1,
                            "undetected": 0,
                            "timeout": 0,
                        },
                        "results": {
                            "Microsoft": {
                                "category": "malicious",
                                "result": "Trojan:Win32/Test",
                                "method": "blacklist",
                            },
                            "Avast": {"category": "undetected"},
                        },
                    },
                }
            },
        )
    return httpx.Response(404, json={})


def test_analyze_file_computes_hashes_uploads_and_polls() -> None:
    install_mock(upload_handler)
    try:
        response = client.post(
            "/api/v1/analyze/file",
            files={"file": ("sample.exe", SAMPLE_BYTES)},
        )
        assert response.status_code == 201
        payload = response.json()

        assert payload["indicator_type"] == "FILE"
        assert payload["indicator"] == SAMPLE_SHA256
        assert payload["stats"]["malicious"] == 4

        metadata = payload["metadata"]
        assert metadata["kind"] == "file"
        assert metadata["sha256"] == SAMPLE_SHA256
        assert metadata["sha1"] == SAMPLE_SHA1
        assert metadata["md5"] == SAMPLE_MD5
        assert metadata["names"] == ["sample.exe"]
        assert metadata["meaningful_name"] == "sample.exe"

        detections = payload["detections"]
        assert detections[0] == {
            "engine": "Microsoft",
            "result": "Trojan:Win32/Test",
            "category": "malicious",
            "method": "blacklist",
        }
    finally:
        remove_mock()


def test_analyze_file_reuses_existing_report_without_uploading() -> None:
    methods: list[str] = []

    def existing_handler(request: httpx.Request) -> httpx.Response:
        methods.append(request.method)
        return httpx.Response(200, json=FILE_REPORT)

    install_mock(existing_handler)
    try:
        response = client.post(
            "/api/v1/analyze/file",
            files={"file": ("sample.exe", SAMPLE_BYTES)},
        )
        assert response.status_code == 201
        assert response.json()["indicator_type"] == "FILE"
        assert "POST" not in methods
    finally:
        remove_mock()


def test_analyze_file_rejects_path_traversal_filename() -> None:
    install_mock(upload_handler)
    try:
        response = client.post(
            "/api/v1/analyze/file",
            files={"file": ("../evil.exe", SAMPLE_BYTES)},
        )
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "invalid_filename"
    finally:
        remove_mock()


def test_analyze_file_returns_413_for_oversized_upload(monkeypatch) -> None:
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "max_upload_size_mb", 1)
    install_mock(upload_handler)
    try:
        payload = b"x" * (2 * 1024 * 1024)
        response = client.post(
            "/api/v1/analyze/file",
            files={"file": ("big.exe", payload)},
        )
        assert response.status_code == 413
        assert response.json()["error"]["code"] == "file_too_large"
    finally:
        remove_mock()


def test_analyze_file_rejects_empty_file() -> None:
    install_mock(upload_handler)
    try:
        response = client.post(
            "/api/v1/analyze/file",
            files={"file": ("empty.exe", b"")},
        )
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "empty_file"
    finally:
        remove_mock()