"""Tests for behavioral drift detection endpoints."""

import pytest
from httpx import ASGITransport, AsyncClient

from vindicara.api.app import create_app


@pytest.fixture
def app():
    return create_app()


@pytest.mark.asyncio
async def test_record_event(app) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/v1/monitor/events",
            json={"agent_id": "a1", "tool": "crm_read", "data_scope": "accounts.sales"},
            headers={"X-Vindicara-Key": "vnd_test"},
        )
    assert response.status_code == 200
    data = response.json()
    assert data["agent_id"] == "a1"
    assert data["tool"] == "crm_read"
    assert data["timestamp"] != ""


@pytest.mark.asyncio
async def test_get_drift_no_data(app) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(
            "/v1/monitor/drift/a1",
            headers={"X-Vindicara-Key": "vnd_test"},
        )
    assert response.status_code == 200
    data = response.json()
    assert data["agent_id"] == "a1"
    assert data["score"] == 0.0


@pytest.mark.asyncio
async def test_set_breaker(app) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/v1/monitor/breakers",
            json={"agent_id": "a1", "threshold": 0.7, "auto_suspend": True},
            headers={"X-Vindicara-Key": "vnd_test"},
        )
    assert response.status_code == 200
    data = response.json()
    assert data["agent_id"] == "a1"
    assert data["threshold"] == 0.7


@pytest.mark.asyncio
async def test_get_breaker_status(app) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(
            "/v1/monitor/breakers/a1",
            headers={"X-Vindicara-Key": "vnd_test"},
        )
    assert response.status_code == 200
    data = response.json()
    assert data["agent_id"] == "a1"
    assert "tripped" in data
    assert "current_drift" in data


@pytest.mark.asyncio
async def test_full_monitor_flow(app) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        for _ in range(5):
            await client.post(
                "/v1/monitor/events",
                json={"agent_id": "bot-1", "tool": "crm_read"},
                headers={"X-Vindicara-Key": "vnd_test"},
            )

        drift_resp = await client.get(
            "/v1/monitor/drift/bot-1",
            headers={"X-Vindicara-Key": "vnd_test"},
        )
        assert drift_resp.status_code == 200
        assert drift_resp.json()["baseline_event_count"] == 5

        breaker_resp = await client.post(
            "/v1/monitor/breakers",
            json={"agent_id": "bot-1", "threshold": 0.9},
            headers={"X-Vindicara-Key": "vnd_test"},
        )
        assert breaker_resp.status_code == 200

        status_resp = await client.get(
            "/v1/monitor/breakers/bot-1",
            headers={"X-Vindicara-Key": "vnd_test"},
        )
    assert status_resp.status_code == 200
    assert status_resp.json()["tripped"] is False
