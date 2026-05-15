from __future__ import annotations

import os
from unittest.mock import patch

import pytest
from httpx import ASGITransport, AsyncClient

os.environ.setdefault("VINDICARA_SESSION_SECRET", "test_secret_for_unit_tests_only_0000")

from vindicara.cloud.factory import create_air_cloud_app
from vindicara.cloud.session_token import verify_session_token
from vindicara.cloud.sso import SsoConfig
from vindicara.cloud.workspace import (
    InMemoryApiKeyStore,
    InMemoryWorkspaceStore,
    Workspace,
)


@pytest.fixture()
def app_with_sso():  # type: ignore[no-untyped-def]
    ws_store = InMemoryWorkspaceStore()
    key_store = InMemoryApiKeyStore()
    ws = Workspace(workspace_id="ws_sso", name="SSO Test", owner_email="o@b.com")
    ws_store.create(ws)

    from vindicara.cloud.sso import InMemorySsoConfigStore

    sso_store = InMemorySsoConfigStore()
    sso_store.put(
        SsoConfig(
            workspace_id="ws_sso",
            issuer="https://auth.example.com/",
            audience="air-cloud",
            default_role="member",
        )
    )

    app = create_air_cloud_app(
        workspace_store=ws_store,
        api_key_store=key_store,
        sso_config_store=sso_store,
    )
    return app, key_store


@pytest.mark.anyio()
async def test_sso_login_returns_session_token(app_with_sso) -> None:  # type: ignore[no-untyped-def]
    app, key_store = app_with_sso

    fake_claims = {
        "sub": "auth0|user1",
        "iss": "https://auth.example.com/",
        "aud": "air-cloud",
        "email": "user@b.com",
    }

    with patch(
        "vindicara.cloud.routes.sso.verify_oidc_token", return_value=fake_claims
    ):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/v1/sso/login",
                json={"workspace_id": "ws_sso", "token": "fake.jwt.here"},
            )

    assert resp.status_code == 201
    body = resp.json()
    assert "session_token" in body
    assert "api_key" not in body
    assert body["workspace_id"] == "ws_sso"
    assert body["role"] == "member"

    # Verify the session token is valid
    claims = verify_session_token(body["session_token"])
    assert claims.workspace_id == "ws_sso"
    assert claims.role == "member"
    assert claims.sub == "auth0|user1"
