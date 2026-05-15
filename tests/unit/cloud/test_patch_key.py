"""tests/unit/cloud/test_patch_key.py"""
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
def patch_app():  # type: ignore[no-untyped-def]
    ws_store = InMemoryWorkspaceStore()
    key_store = InMemoryApiKeyStore()
    ws = Workspace(workspace_id="ws_p", name="Patch", owner_email="o@b.com")
    ws_store.create(ws)
    owner = ApiKey(key_id="k_own", workspace_id="ws_p", key="air_own_00000000000000000000000000000", role="owner")
    member = ApiKey(key_id="k_mem", workspace_id="ws_p", key="air_mem_00000000000000000000000000000", role="member")
    key_store.issue(owner)
    key_store.issue(member)
    return create_air_cloud_app(workspace_store=ws_store, api_key_store=key_store)


@pytest.mark.anyio()
async def test_owner_promotes_member_to_admin(patch_app) -> None:  # type: ignore[no-untyped-def]
    async with AsyncClient(transport=ASGITransport(app=patch_app), base_url="http://test") as c:
        resp = await c.patch(
            "/v1/keys/k_mem",
            json={"role": "admin"},
            headers={"X-API-Key": "air_own_00000000000000000000000000000"},
        )
    assert resp.status_code == 200
    assert resp.json()["role"] == "admin"


@pytest.mark.anyio()
async def test_admin_cannot_promote_to_owner(patch_app) -> None:  # type: ignore[no-untyped-def]
    async with AsyncClient(transport=ASGITransport(app=patch_app), base_url="http://test") as c:
        # First promote member to admin via owner
        await c.patch(
            "/v1/keys/k_mem",
            json={"role": "admin"},
            headers={"X-API-Key": "air_own_00000000000000000000000000000"},
        )
        # Now admin tries to promote to owner
        resp = await c.patch(
            "/v1/keys/k_mem",
            json={"role": "owner"},
            headers={"X-API-Key": "air_mem_00000000000000000000000000000"},
        )
    assert resp.status_code == 403


@pytest.mark.anyio()
async def test_member_cannot_patch(patch_app) -> None:  # type: ignore[no-untyped-def]
    async with AsyncClient(transport=ASGITransport(app=patch_app), base_url="http://test") as c:
        resp = await c.patch(
            "/v1/keys/k_mem",
            json={"role": "admin"},
            headers={"X-API-Key": "air_mem_00000000000000000000000000000"},
        )
    assert resp.status_code == 403
