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
def compliance_app():  # type: ignore[no-untyped-def]
    ws_store = InMemoryWorkspaceStore()
    key_store = InMemoryApiKeyStore()
    ws = Workspace(workspace_id="ws_c", name="Comp", owner_email="o@b.com")
    ws_store.create(ws)
    owner = ApiKey(key_id="k_o", workspace_id="ws_c", key="air_comp_owner_000000000000000000000", role="owner")
    member = ApiKey(key_id="k_m", workspace_id="ws_c", key="air_comp_memb_0000000000000000000000", role="member")
    key_store.issue(owner)
    key_store.issue(member)
    return create_air_cloud_app(workspace_store=ws_store, api_key_store=key_store)


@pytest.mark.anyio()
async def test_owner_gets_compliance_summary(compliance_app) -> None:  # type: ignore[no-untyped-def]
    async with AsyncClient(transport=ASGITransport(app=compliance_app), base_url="http://test") as c:
        resp = await c.get(
            "/v1/compliance/summary",
            headers={"X-API-Key": "air_comp_owner_000000000000000000000"},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert "frameworks" in body
    # Check we get framework scores (the exact count depends on FRAMEWORKS dict)
    assert len(body["frameworks"]) > 0
    # Each framework should have the expected shape
    fw = body["frameworks"][0]
    assert "framework_id" in fw
    assert "name" in fw
    assert "total_controls" in fw
    assert "met_controls" in fw
    assert "coverage_pct" in fw
    assert "controls" in fw


@pytest.mark.anyio()
async def test_member_forbidden(compliance_app) -> None:  # type: ignore[no-untyped-def]
    async with AsyncClient(transport=ASGITransport(app=compliance_app), base_url="http://test") as c:
        resp = await c.get(
            "/v1/compliance/summary",
            headers={"X-API-Key": "air_comp_memb_0000000000000000000000"},
        )
    assert resp.status_code == 403
