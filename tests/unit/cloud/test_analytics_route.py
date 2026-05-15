from __future__ import annotations

import os

import pytest
from httpx import ASGITransport, AsyncClient

os.environ.setdefault("VINDICARA_SESSION_SECRET", "test_secret_for_unit_tests_only_0000")

from vindicara.cloud.factory import create_air_cloud_app
from vindicara.cloud.workspace import (
    ApiKey,
    InMemoryApiKeyStore,
    InMemoryWorkspaceStore,
    Workspace,
)


@pytest.fixture()
def analytics_app():  # type: ignore[no-untyped-def]
    ws_store = InMemoryWorkspaceStore()
    key_store = InMemoryApiKeyStore()
    ws = Workspace(workspace_id="ws_a", name="Analytics", owner_email="o@b.com")
    ws_store.create(ws)
    owner = ApiKey(key_id="k_o", workspace_id="ws_a", key="air_analytics_own_0000000000000000000", role="owner")
    key_store.issue(owner)
    return create_air_cloud_app(workspace_store=ws_store, api_key_store=key_store)


@pytest.mark.anyio()
async def test_analytics_summary_shape(analytics_app) -> None:  # type: ignore[no-untyped-def]
    async with AsyncClient(transport=ASGITransport(app=analytics_app), base_url="http://test") as c:
        resp = await c.get(
            "/v1/analytics/summary",
            headers={"X-API-Key": "air_analytics_own_0000000000000000000"},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert "total_capsules" in body
    assert "capsules_this_week" in body
    assert "unique_agents" in body
    assert "active_members" in body
    assert "detector_counts" in body
    assert "chain_health" in body
    assert "daily_ingestion" in body


@pytest.mark.anyio()
async def test_member_forbidden(analytics_app) -> None:  # type: ignore[no-untyped-def]
    # Add a member key
    key_store: InMemoryApiKeyStore = analytics_app.state.cloud_api_keys
    member = ApiKey(key_id="k_m", workspace_id="ws_a", key="air_analytics_mem_0000000000000000000", role="member")
    key_store.issue(member)

    async with AsyncClient(transport=ASGITransport(app=analytics_app), base_url="http://test") as c:
        resp = await c.get(
            "/v1/analytics/summary",
            headers={"X-API-Key": "air_analytics_mem_0000000000000000000"},
        )
    assert resp.status_code == 403
