"""Tests for the live demo flow."""

import pytest
from httpx import ASGITransport, AsyncClient


@pytest.mark.asyncio
async def test_demo_page_loads(app) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/dashboard/demo")
    assert response.status_code == 200
    assert "Live Demo" in response.text


@pytest.mark.asyncio
async def test_demo_start(app) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/dashboard/api/demo/start")
    assert response.status_code == 200
    assert "agent_" in response.text or "REGISTERING" in response.text


@pytest.mark.asyncio
async def test_demo_full_flow(app) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post("/dashboard/api/demo/start")
        for _ in range(50):
            resp = await client.get("/dashboard/api/demo/status")
            if resp.status_code == 200 and "AGENT NEUTRALIZED" in resp.text:
                break
        final = await client.get("/dashboard/api/demo/status")
    assert final.status_code == 200
    assert "AGENT NEUTRALIZED" in final.text or "SUSPENDED" in final.text
