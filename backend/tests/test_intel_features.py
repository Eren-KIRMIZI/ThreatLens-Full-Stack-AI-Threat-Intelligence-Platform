"""Registry, snapshots, investigations, watchlist/alerts and export tests."""

from __future__ import annotations

import httpx
from fastapi.testclient import TestClient

from app.main import app
from app.services.alert_engine import SnapshotFacts, evaluate_rule

client = TestClient(app)

HASH = "d" * 64

FILE_REPORT = {
    "data": {
        "id": HASH,
        "type": "file",
        "attributes": {
            "sha256": HASH,
            "sha1": "e" * 40,
            "md5": "f" * 32,
            "type_description": "Win32 EXE",
            "size": 1024,
            "meaningful_name": "registry-sample.exe",
            "reputation": -5,
            "tags": ["peexe"],
            "threat_names": ["Trojan:Win32/Registry"],
            "total_votes": {"harmless": 0, "malicious": 2},
            "first_submission_date": 1700000000,
            "last_analysis_date": 1700000001,
            "last_analysis_stats": {
                "harmless": 1,
                "malicious": 6,
                "suspicious": 1,
                "undetected": 1,
                "timeout": 0,
            },
            "last_analysis_results": {
                "Microsoft": {
                    "category": "malicious",
                    "result": "Trojan:Win32/Registry",
                    "method": "blacklist",
                }
            },
        },
    }
}


def install_mock() -> None:
    from app.services.virustotal_service import VirusTotalService

    app.state.virustotal_service = VirusTotalService(
        api_key="test-key",
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json=FILE_REPORT)),
    )


def _analyze() -> str:
    install_mock()
    created = client.post("/api/v1/analyze/hash", json={"hash": HASH})
    assert created.status_code == 201, created.text
    return created.json()["analysis_id"]


# --- registry / dedup --------------------------------------------------------- #


def test_analysis_registers_distinct_ioc_and_snapshot() -> None:
    _analyze()
    listing = client.get(f"/api/v1/iocs?search={HASH}")
    assert listing.status_code == 200
    payload = listing.json()
    assert payload["total"] >= 1
    indicator = payload["items"][0]
    assert indicator["value"] == HASH
    assert indicator["primary_type"] == "HASH"
    assert indicator["observations"] >= 1
    assert indicator["latest_level"] in {"malicious", "critical"}

    detail = client.get(f"/api/v1/iocs/{HASH}")
    assert detail.status_code == 200
    body = detail.json()
    assert body["timeline"], "snapshot timeline must not be empty"
    assert body["observations"] >= 1


def test_repeat_analysis_appends_snapshot() -> None:
    _analyze()
    first = client.get(f"/api/v1/iocs/{HASH}").json()["observations"]
    client.post("/api/v1/watchlist", json={"value": HASH, "primary_type": "HASH"})
    item_id = client.get("/api/v1/watchlist").json()["items"][0]["id"]
    # Force refresh through the watchlist rescan path.
    rescanned = client.post(f"/api/v1/watchlist/{item_id}/rescan")
    assert rescanned.status_code == 200, rescanned.text
    assert rescanned.json()["analysis_id"]
    second = client.get(f"/api/v1/iocs/{HASH}").json()["observations"]
    assert second > first


# --- alert engine unit ------------------------------------------------------- #


class _Rule:
    def __init__(self, condition: str, threshold: int, enabled: bool = True) -> None:
        self.id = "rule-1"
        self.name = "test rule"
        self.condition = condition
        self.threshold = threshold
        self.enabled = enabled


def test_alert_engine_score_threshold() -> None:
    latest = SnapshotFacts(score=91, level="critical", malicious=12, suspicious=1)
    candidate = evaluate_rule(_Rule("score_ge", 85), latest, None)
    assert candidate is not None and candidate.level == "critical"
    assert evaluate_rule(_Rule("score_ge", 95), latest, None) is None


def test_alert_engine_new_detection_compares_previous() -> None:
    latest = SnapshotFacts(score=80, level="malicious", malicious=9, suspicious=0)
    clean_prev = SnapshotFacts(score=0, level="clean", malicious=0, suspicious=0)
    same_prev = SnapshotFacts(score=80, level="malicious", malicious=9, suspicious=0)
    assert evaluate_rule(_Rule("new_detection", 0), latest, clean_prev) is not None
    assert evaluate_rule(_Rule("new_detection", 0), latest, same_prev) is None


def test_alert_engine_disabled_rule_never_fires() -> None:
    latest = SnapshotFacts(score=100, level="critical", malicious=30, suspicious=0)
    assert evaluate_rule(_Rule("score_ge", 10, enabled=False), latest, None) is None


# --- watchlist / rules / alerts ------------------------------------------------ #


def test_watchlist_rule_fires_alert_on_rescan() -> None:
    _analyze()
    created = client.post(
        "/api/v1/watchlist", json={"value": HASH, "primary_type": "HASH"}
    )
    item_id = created.json()["id"]
    rule = client.post(
        "/api/v1/watchlist/rules",
        json={"name": "score>=50", "condition": "score_ge", "threshold": 50},
    )
    assert rule.status_code == 201

    outcome = client.post(f"/api/v1/watchlist/{item_id}/rescan").json()
    assert outcome["threat_score"] is not None
    assert outcome["alerts"], "rule must fire for a malicious sample"
    assert outcome["alerts"][0]["indicator"] == HASH

    alerts = client.get("/api/v1/watchlist/alerts?unseen_only=true").json()
    assert alerts["total"] >= 1
    assert client.post("/api/v1/watchlist/alerts/mark-seen").status_code == 200
    assert client.get("/api/v1/watchlist/alerts?unseen_only=true").json()["total"] == 0


def test_invalid_rule_condition_rejected() -> None:
    response = client.post(
        "/api/v1/watchlist/rules",
        json={"name": "bad", "condition": "does_not_exist", "threshold": 1},
    )
    assert response.status_code == 422


# --- investigations / notes / tags / pin ---------------------------------------- #


def test_investigation_lifecycle() -> None:
    analysis_id = _analyze()
    case = client.post(
        "/api/v1/investigations",
        json={"title": "Registry trojan", "severity": "high"},
    )
    assert case.status_code == 201
    case_id = case.json()["id"]

    item = client.post(
        f"/api/v1/investigations/{case_id}/items?value={HASH}&primary_type=HASH"
    )
    assert item.status_code == 201, item.text

    detail = client.get(f"/api/v1/investigations/{case_id}").json()
    assert detail["items"] and detail["items"][0]["value"] == HASH

    patched = client.patch(
        f"/api/v1/investigations/{case_id}", json={"status": "active"}
    )
    assert patched.json()["status"] == "active"

    note = client.post(
        f"/api/v1/investigations/{analysis_id}/notes",
        json={"author": "eren", "body": "IOC confirmed in the wild."},
    )
    assert note.status_code == 201
    assert len(client.get(f"/api/v1/investigations/analysis/{analysis_id}/notes").json()) == 1

    tag = client.post(
        f"/api/v1/investigations/analysis/{analysis_id}/tags", json={"tag": "Trojan"}
    )
    assert tag.status_code == 201
    assert client.get(f"/api/v1/investigations/analysis/{analysis_id}/tags").json() == ["trojan"]

    assert client.post(
        f"/api/v1/investigations/analysis/{analysis_id}/pin?pinned=true"
    ).status_code == 200
    assert analysis_id in client.get("/api/v1/investigations/pinned/list").json()
    assert client.delete(f"/api/v1/investigations/{case_id}").status_code == 204


# --- mitre / digest / search / exports ------------------------------------------ #


def test_mitre_catalog_validate_and_map() -> None:
    assert client.get("/api/v1/intel/mitre/catalog").status_code == 200
    assert client.get("/api/v1/intel/mitre/validate/T1566").json()["valid"] is True
    assert client.get("/api/v1/intel/mitre/validate/not-a-tech").json()["valid"] is False
    mapped = client.post(
        "/api/v1/intel/mitre/map", json={"text": "Emotet trojan dropper phishing"}
    ).json()["techniques"]
    ids = {item["id"] for item in mapped}
    assert "T1566" in ids and "T1105" in ids


def test_digest_and_search() -> None:
    _analyze()
    digest = client.get("/api/v1/intel/digest?window=week").json()
    assert any("Analyses" in section["label"] for section in digest["sections"])
    search = client.get(f"/api/v1/intel/search?q={HASH}").json()
    assert search["total"] >= 1
    kinds = {item["kind"] for item in search["results"]}
    assert "analysis" in kinds


def test_exports_csv_stix_yara_sigma() -> None:
    analysis_id = _analyze()
    csv_response = client.get("/api/v1/export/history.csv")
    assert csv_response.status_code == 200
    assert "indicator" in csv_response.text
    assert HASH in csv_response.text

    stix = client.get(f"/api/v1/export/analyses/{analysis_id}/stix.json").json()
    assert stix["type"] == "bundle"
    assert any(obj["type"] == "indicator" for obj in stix["objects"])

    yara = client.get(f"/api/v1/export/analyses/{analysis_id}/yara")
    assert yara.status_code == 200 and "rule threatlens_" in yara.text

    sigma = client.get(f"/api/v1/export/analyses/{analysis_id}/sigma")
    assert sigma.status_code == 200 and "detection:" in sigma.text

    bad = client.get(f"/api/v1/export/analyses/{analysis_id}/pepper")
    assert bad.status_code == 404