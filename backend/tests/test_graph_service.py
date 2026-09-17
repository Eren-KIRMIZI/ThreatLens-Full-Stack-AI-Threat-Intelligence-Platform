"""Graph service + endpoint tests."""

from datetime import UTC, datetime

from fastapi.testclient import TestClient

from app.main import app
from app.schemas.enrichment import (
    ConfidenceBreakdown,
    Enrichment,
    NormalizedEvidence,
    ProviderStatus,
)
from app.schemas.graph import IOCGraph
from app.services.graph_service import build_ioc_graph

client = TestClient(app)

HASH = "a" * 64


def _evidence(**overrides):
    base = dict(
        id="ev-1",
        provider="otx",
        evidence_type="pulse",
        title="OTX pulse membership",
        value="1 pulses; latest: Emotet",
        confidence=0.8,
        verdict="suspicious",
        observed_at=datetime.now(UTC),
        metadata={},
    )
    base.update(overrides)
    return NormalizedEvidence(**base)


def _enrichment(*items: NormalizedEvidence) -> Enrichment:
    return Enrichment(
        version="1.0.1",
        sources=["otx"],
        generated_at=datetime.now(UTC),
        evidence=list(items),
        confidence=ConfidenceBreakdown(overall=40, verdict="malicious", sources=[]),
        provider_status=[
            ProviderStatus(
                provider="otx",
                ok=True,
                latency_ms=12,
                supported=True,
                configured=True,
            )
        ],
    )


def test_graph_links_root_source_and_evidence() -> None:
    graph = build_ioc_graph(
        HASH, "HASH", [_evidence(provider="virustotal", evidence_type="detection")]
    )
    assert graph.root == "root"
    kinds = {node.kind for node in graph.nodes}
    assert {"root", "source", "evidence"} <= kinds
    assert any(e.relation == "queried" for e in graph.edges)


def test_graph_exposes_related_campaign_iocs() -> None:
    related = [
        {"value": "b" * 64, "type": "HASH", "relation": "campaign member"},
        {"value": "evil.example.com", "type": "DOMAIN", "relation": "campaign member"},
        {"value": "not-an-ioc", "type": "??", "relation": "related"},
    ]
    items = [
        _evidence(
            metadata={
                "related": related,
                "pulse_count": 1,
                "threat_actors": ["Emotet crew"],
            }
        )
    ]
    graph = build_ioc_graph(HASH, "HASH", items)
    indicators = {
        node.label: node.indicator_type
        for node in graph.nodes
        if node.kind == "indicator"
    }
    assert indicators == {
        "b" * 64: "HASH",
        "evil.example.com": "DOMAIN",
    }
    assert any(
        e.relation == "campaign member" and e.target.startswith("indicator:")
        for e in graph.edges
    )


def test_graph_dedupes_related_iocs() -> None:
    duplicated = [
        {"value": "b" * 64, "type": "HASH", "relation": "campaign member"},
        {"value": "B" * 64, "type": "HASH", "relation": "campaign member"},
    ]
    graph = build_ioc_graph(HASH, "HASH", [_evidence(metadata={"related": duplicated})])
    labels = [node.label.lower() for node in graph.nodes if node.kind == "indicator"]
    assert len(labels) == len(set(labels))


def test_graph_endpoint_roundtrip() -> None:
    import httpx

    from app.services.virustotal_service import VirusTotalService

    report = {
        "data": {
            "id": "c" * 64,
            "type": "file",
            "attributes": {
                "sha256": "c" * 64,
                "sha1": "d" * 40,
                "md5": "e" * 32,
                "type_description": "Win32 EXE",
                "size": 1,
                "meaningful_name": "target.exe",
                "reputation": 0,
                "tags": [],
                "total_votes": {"harmless": 0, "malicious": 1},
                "first_submission_date": 1700000000,
                "last_analysis_date": 1700000000,
                "last_analysis_stats": {
                    "harmless": 0,
                    "malicious": 3,
                    "suspicious": 0,
                    "undetected": 0,
                    "timeout": 0,
                },
                "last_analysis_results": {
                    "Microsoft": {"category": "malicious", "result": "Trojan", "method": "blacklist"}
                },
            },
        }
    }

    app.state.virustotal_service = VirusTotalService(
        api_key="test-key",
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json=report)),
    )
    created = client.post("/api/v1/analyze/hash", json={"hash": "c" * 64})
    assert created.status_code == 201, created.text

    graph = client.get(f"/api/v1/analysis/{created.json()['analysis_id']}/graph")
    assert graph.status_code == 200, graph.text
    payload: IOCGraph = IOCGraph(**graph.json())
    assert payload.root == "root"
    root = next(node for node in payload.nodes if node.id == "root")
    assert root.label == "c" * 64

    missing = client.get("/api/v1/analysis/00000000-0000-0000-0000-000000000000/graph")
    assert missing.status_code == 404