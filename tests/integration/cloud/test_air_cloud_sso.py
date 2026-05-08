"""End-to-end SSO tests.

Build a local RSA keypair + JWKS, mint test tokens with PyJWT, monkey-patch
``PyJWKClient`` so verification reads the in-memory JWKS instead of going to
the network. The route handler under test uses ``jwks_client_factory`` only
through ``verify_oidc_token``; we patch the factory the route imports.
"""
from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

import httpx
import jwt
import pytest
import pytest_asyncio

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    generate_private_key,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from vindicara.cloud.factory import create_air_cloud_app
from vindicara.cloud.workspace import (
    ApiKey,
    InMemoryApiKeyStore,
    InMemoryWorkspaceStore,
    Workspace,
)


class _StaticSigningKey:
    """Stand-in for PyJWK whose ``key`` attribute holds the RSA public key."""

    def __init__(self, key: Any) -> None:
        self.key = key


class _StubJwksClient:
    """Replaces PyJWKClient. Returns the same RSA public key for every JWT."""

    _public_key: Any = None

    def __init__(self, _uri: str) -> None:
        pass

    def get_signing_key_from_jwt(self, _token: str) -> _StaticSigningKey:
        if _StubJwksClient._public_key is None:
            raise RuntimeError("test bug: stub public key not set")
        return _StaticSigningKey(_StubJwksClient._public_key)


@pytest.fixture
def rsa_keypair() -> tuple[RSAPrivateKey, str]:
    private_key = generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode("ascii")
    _StubJwksClient._public_key = private_key.public_key()
    return private_key, pem


def _mint_token(
    private_key: RSAPrivateKey,
    *,
    issuer: str,
    audience: str,
    sub: str,
    email: str | None = None,
    expires_in: int = 300,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": issuer,
        "aud": audience,
        "sub": sub,
        "iat": now,
        "exp": now + expires_in,
    }
    if email is not None:
        claims["email"] = email
    if extra_claims:
        claims.update(extra_claims)
    pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    return jwt.encode(claims, pem, algorithm="RS256")


@pytest_asyncio.fixture
async def cloud_with_sso(
    monkeypatch: pytest.MonkeyPatch,
    rsa_keypair: tuple[RSAPrivateKey, str],
) -> AsyncIterator[tuple[httpx.AsyncClient, dict]]:
    """Spin up an app with SSO routes wired and PyJWKClient stubbed."""
    monkeypatch.setattr("vindicara.cloud.sso.PyJWKClient", _StubJwksClient)

    workspace_store = InMemoryWorkspaceStore()
    api_key_store = InMemoryApiKeyStore()
    workspace = Workspace(workspace_id="acme", name="Acme", owner_email="ops@acme.io")
    workspace_store.create(workspace)
    owner_key = ApiKey(
        key_id="key_acme_owner",
        workspace_id="acme",
        key="air_test_owner",
        role="owner",
    )
    api_key_store.issue(owner_key)

    app = create_air_cloud_app(
        workspace_store=workspace_store,
        api_key_store=api_key_store,
    )
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client, {
            "private_key": rsa_keypair[0],
            "owner_key": owner_key.key,
            "workspace_store": workspace_store,
            "api_key_store": api_key_store,
        }


# -- Config management --------------------------------------------------


@pytest.mark.asyncio
async def test_owner_can_set_and_read_sso_config(cloud_with_sso: tuple[httpx.AsyncClient, dict]) -> None:
    client, ctx = cloud_with_sso
    put = await client.put(
        "/v1/sso/config",
        headers={"X-API-Key": ctx["owner_key"]},
        json={
            "issuer": "https://login.example.com/",
            "audience": "air-cloud:acme",
            "default_role": "member",
            "allowed_email_domains": ["acme.io"],
        },
    )
    assert put.status_code == 200
    body = put.json()
    assert body["issuer"] == "https://login.example.com/"
    assert body["allowed_email_domains"] == ["acme.io"]

    get = await client.get("/v1/sso/config", headers={"X-API-Key": ctx["owner_key"]})
    assert get.status_code == 200
    assert get.json()["audience"] == "air-cloud:acme"


@pytest.mark.asyncio
async def test_set_sso_config_rejects_owner_default_role(cloud_with_sso: tuple[httpx.AsyncClient, dict]) -> None:
    client, ctx = cloud_with_sso
    response = await client.put(
        "/v1/sso/config",
        headers={"X-API-Key": ctx["owner_key"]},
        json={
            "issuer": "https://login.example.com/",
            "audience": "air-cloud:acme",
            "default_role": "owner",
        },
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_get_sso_config_404_when_unset(cloud_with_sso: tuple[httpx.AsyncClient, dict]) -> None:
    client, ctx = cloud_with_sso
    response = await client.get("/v1/sso/config", headers={"X-API-Key": ctx["owner_key"]})
    assert response.status_code == 404


# -- Login flow --------------------------------------------------------


async def _set_sso_config(
    client: httpx.AsyncClient,
    owner_key: str,
    *,
    issuer: str = "https://login.example.com/",
    audience: str = "air-cloud:acme",
    allowed_domains: list[str] | None = None,
    default_role: str = "member",
) -> None:
    body: dict[str, Any] = {
        "issuer": issuer,
        "audience": audience,
        "default_role": default_role,
    }
    if allowed_domains is not None:
        body["allowed_email_domains"] = allowed_domains
    put = await client.put("/v1/sso/config", headers={"X-API-Key": owner_key}, json=body)
    assert put.status_code == 200


@pytest.mark.asyncio
async def test_sso_login_jit_provisions_a_member_key(cloud_with_sso: tuple[httpx.AsyncClient, dict]) -> None:
    client, ctx = cloud_with_sso
    await _set_sso_config(client, ctx["owner_key"])
    token = _mint_token(
        ctx["private_key"],
        issuer="https://login.example.com/",
        audience="air-cloud:acme",
        sub="user-1",
        email="alice@acme.io",
    )
    response = await client.post("/v1/sso/login", json={"workspace_id": "acme", "token": token})
    assert response.status_code == 201
    body = response.json()
    assert body["workspace_id"] == "acme"
    assert body["sub"] == "user-1"
    assert body["email"] == "alice@acme.io"
    assert body["api_key"]["role"] == "member"
    assert body["api_key"]["key"].startswith("air_")
    # The new key should immediately authenticate.
    whoami = await client.get(
        "/v1/workspaces/me",
        headers={"X-API-Key": body["api_key"]["key"]},
    )
    assert whoami.status_code == 200


@pytest.mark.asyncio
async def test_sso_login_returns_existing_key_on_repeat(cloud_with_sso: tuple[httpx.AsyncClient, dict]) -> None:
    client, ctx = cloud_with_sso
    await _set_sso_config(client, ctx["owner_key"])
    token = _mint_token(
        ctx["private_key"],
        issuer="https://login.example.com/",
        audience="air-cloud:acme",
        sub="user-1",
        email="alice@acme.io",
    )
    first = await client.post("/v1/sso/login", json={"workspace_id": "acme", "token": token})
    second = await client.post("/v1/sso/login", json={"workspace_id": "acme", "token": token})
    assert first.json()["api_key"]["key"] == second.json()["api_key"]["key"]
    assert first.json()["api_key"]["key_id"] == second.json()["api_key"]["key_id"]


@pytest.mark.asyncio
async def test_sso_login_distinct_subs_get_distinct_keys(cloud_with_sso: tuple[httpx.AsyncClient, dict]) -> None:
    client, ctx = cloud_with_sso
    await _set_sso_config(client, ctx["owner_key"])
    a_token = _mint_token(ctx["private_key"], issuer="https://login.example.com/", audience="air-cloud:acme", sub="user-a", email="a@acme.io")
    b_token = _mint_token(ctx["private_key"], issuer="https://login.example.com/", audience="air-cloud:acme", sub="user-b", email="b@acme.io")
    a = await client.post("/v1/sso/login", json={"workspace_id": "acme", "token": a_token})
    b = await client.post("/v1/sso/login", json={"workspace_id": "acme", "token": b_token})
    assert a.json()["api_key"]["key"] != b.json()["api_key"]["key"]
    assert a.json()["api_key"]["key_id"] != b.json()["api_key"]["key_id"]


@pytest.mark.asyncio
async def test_sso_login_rejects_wrong_audience(cloud_with_sso: tuple[httpx.AsyncClient, dict]) -> None:
    client, ctx = cloud_with_sso
    await _set_sso_config(client, ctx["owner_key"], audience="air-cloud:acme")
    bad_token = _mint_token(
        ctx["private_key"],
        issuer="https://login.example.com/",
        audience="some-other-app",
        sub="user-1",
    )
    response = await client.post("/v1/sso/login", json={"workspace_id": "acme", "token": bad_token})
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_sso_login_rejects_wrong_issuer(cloud_with_sso: tuple[httpx.AsyncClient, dict]) -> None:
    client, ctx = cloud_with_sso
    await _set_sso_config(client, ctx["owner_key"], issuer="https://login.example.com/")
    bad_token = _mint_token(
        ctx["private_key"],
        issuer="https://attacker.example.com/",
        audience="air-cloud:acme",
        sub="user-1",
    )
    response = await client.post("/v1/sso/login", json={"workspace_id": "acme", "token": bad_token})
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_sso_login_rejects_expired_token(cloud_with_sso: tuple[httpx.AsyncClient, dict]) -> None:
    client, ctx = cloud_with_sso
    await _set_sso_config(client, ctx["owner_key"])
    bad_token = _mint_token(
        ctx["private_key"],
        issuer="https://login.example.com/",
        audience="air-cloud:acme",
        sub="user-1",
        expires_in=-3600,
    )
    response = await client.post("/v1/sso/login", json={"workspace_id": "acme", "token": bad_token})
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_sso_login_email_domain_allowlist_enforced(cloud_with_sso: tuple[httpx.AsyncClient, dict]) -> None:
    client, ctx = cloud_with_sso
    await _set_sso_config(client, ctx["owner_key"], allowed_domains=["acme.io"])
    rejected = await client.post(
        "/v1/sso/login",
        json={
            "workspace_id": "acme",
            "token": _mint_token(
                ctx["private_key"],
                issuer="https://login.example.com/",
                audience="air-cloud:acme",
                sub="user-1",
                email="eve@evil.io",
            ),
        },
    )
    assert rejected.status_code == 401
    accepted = await client.post(
        "/v1/sso/login",
        json={
            "workspace_id": "acme",
            "token": _mint_token(
                ctx["private_key"],
                issuer="https://login.example.com/",
                audience="air-cloud:acme",
                sub="user-1",
                email="alice@acme.io",
            ),
        },
    )
    assert accepted.status_code == 201


@pytest.mark.asyncio
async def test_sso_login_404_for_unknown_workspace(cloud_with_sso: tuple[httpx.AsyncClient, dict]) -> None:
    client, ctx = cloud_with_sso
    token = _mint_token(
        ctx["private_key"],
        issuer="https://login.example.com/",
        audience="air-cloud:acme",
        sub="user-1",
    )
    response = await client.post("/v1/sso/login", json={"workspace_id": "ghost", "token": token})
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_sso_login_400_when_workspace_has_no_config(cloud_with_sso: tuple[httpx.AsyncClient, dict]) -> None:
    client, ctx = cloud_with_sso
    token = _mint_token(
        ctx["private_key"],
        issuer="https://login.example.com/",
        audience="air-cloud:acme",
        sub="user-1",
    )
    response = await client.post("/v1/sso/login", json={"workspace_id": "acme", "token": token})
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_sso_config_403_for_member_role(cloud_with_sso: tuple[httpx.AsyncClient, dict]) -> None:
    """Setting / reading SSO config requires owner+ / admin+; member is denied."""
    client, ctx = cloud_with_sso
    member_key = ApiKey(
        key_id="key_acme_member", workspace_id="acme", key="air_member_key", role="member"
    )
    ctx["api_key_store"].issue(member_key)
    put = await client.put(
        "/v1/sso/config",
        headers={"X-API-Key": member_key.key},
        json={"issuer": "https://x", "audience": "y"},
    )
    assert put.status_code == 403
