from __future__ import annotations

import os

import pytest
from httpx import ASGITransport, AsyncClient

os.environ.setdefault("VINDICARA_SESSION_SECRET", "test_secret_for_unit_tests_only_0000")

from vindicara.cloud.factory import create_air_cloud_app
from vindicara.cloud.session_token import SessionClaims, create_session_token
from vindicara.cloud.workspace import (
    ApiKey,
    InMemoryApiKeyStore,
    InMemoryWorkspaceStore,
    Workspace,
)


@pytest.fixture()
def stores() -> tuple[InMemoryWorkspaceStore, InMemoryApiKeyStore]:
    ws_store = InMemoryWorkspaceStore()
    key_store = InMemoryApiKeyStore()
    ws = Workspace(workspace_id="ws_test", name="Test", owner_email="a@b.com")
    ws_store.create(ws)
    key = ApiKey(
        key_id="key_test",
        workspace_id="ws_test",
        key="air_deadbeef1234567890abcdef12345678",
        role="owner",
        name="test",
    )
    key_store.issue(key)
    return ws_store, key_store


@pytest.fixture()
def app(stores: tuple[InMemoryWorkspaceStore, InMemoryApiKeyStore]):  # type: ignore[type-arg]
    ws_store, key_store = stores
    return create_air_cloud_app(
        workspace_store=ws_store,
        api_key_store=key_store,
    )


@pytest.mark.anyio()
async def test_bearer_token_auth(app) -> None:  # type: ignore[no-untyped-def]
    claims = SessionClaims(
        workspace_id="ws_test", role="owner", sub="auth0|x", key_id="key_test"
    )
    token = create_session_token(claims)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get(
            "/v1/workspaces/me",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert resp.status_code == 200
    assert resp.json()["workspace_id"] == "ws_test"


@pytest.mark.anyio()
async def test_expired_bearer_returns_401(app) -> None:  # type: ignore[no-untyped-def]
    claims = SessionClaims(
        workspace_id="ws_test", role="owner", sub="auth0|x", key_id="key_test"
    )
    token = create_session_token(claims, ttl_seconds=-1)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get(
            "/v1/workspaces/me",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert resp.status_code == 401


@pytest.mark.anyio()
async def test_api_key_still_works(app, stores) -> None:  # type: ignore[no-untyped-def]
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get(
            "/v1/workspaces/me",
            headers={"X-API-Key": "air_deadbeef1234567890abcdef12345678"},
        )
    assert resp.status_code == 200


@pytest.mark.anyio()
async def test_no_auth_returns_401(app) -> None:  # type: ignore[no-untyped-def]
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/v1/workspaces/me")
    assert resp.status_code == 401
