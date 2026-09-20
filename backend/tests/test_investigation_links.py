"""Auto-linking case items / evidence to the latest stored analysis."""

from __future__ import annotations

import asyncio

from fastapi.testclient import TestClient

from app.main import app
from app.models.analysis import Analysis

client = TestClient(app)


def _seed_analysis(value: str, analysis_id: str = "a" * 32) -> None:
    async def seed() -> None:
        from datetime import datetime, timezone

        db = app.state.database
        async with db.session_factory() as session:
            session.add(
                Analysis(
                    id=analysis_id,
                    indicator=value,
                    indicator_type="DOMAIN",
                    analyzed_at=datetime.now(timezone.utc).replace(tzinfo=None),
                    payload={"generator": "test"},
                )
            )
            await session.commit()

    asyncio.run(seed())


def _create_case() -> str:
    response = client.post(
        "/api/v1/investigations",
        json={"title": "link test", "status": "open", "severity": "high"},
    )
    assert response.status_code == 201
    return response.json()["id"]


def test_add_item_auto_links_latest_analysis() -> None:
    _seed_analysis("evil.example")
    case_id = _create_case()

    response = client.post(
        f"/api/v1/investigations/{case_id}/items",
        params={"value": "EVIL.EXAMPLE", "primary_type": "DOMAIN"},
    )
    assert response.status_code == 201
    assert response.json()["analysis_id"] == "a" * 32


def test_add_item_explicit_analysis_id_wins() -> None:
    _seed_analysis("evil.example", analysis_id="cccccccc" * 4)
    case_id = _create_case()

    response = client.post(
        f"/api/v1/investigations/{case_id}/items",
        params={
            "value": "evil.example",
            "primary_type": "DOMAIN",
            "analysis_id": "b" * 32,
        },
    )
    assert response.status_code == 201
    assert response.json()["analysis_id"] == "b" * 32


def test_add_item_unknown_value_keeps_null() -> None:
    case_id = _create_case()
    response = client.post(
        f"/api/v1/investigations/{case_id}/items",
        params={"value": "never-analyzed.example", "primary_type": "DOMAIN"},
    )
    assert response.status_code == 201
    assert response.json()["analysis_id"] is None


def test_campaign_evidence_auto_links() -> None:
    _seed_analysis("tracker.example")
    case_id = _create_case()

    campaign = client.post(
        f"/api/v1/investigations/{case_id}/campaigns",
        json={"name": "campaign-a", "color": "accent"},
    )
    assert campaign.status_code == 201
    campaign_id = campaign.json()["id"]

    response = client.post(
        f"/api/v1/investigations/campaigns/{campaign_id}/evidence",
        json={
            "value": "tracker.example",
            "primary_type": "DOMAIN",
        },
    )
    assert response.status_code == 201
    assert response.json()["analysis_id"] == "a" * 32