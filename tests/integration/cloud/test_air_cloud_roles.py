"""End-to-end tests for the workspace role policy + member invite flow."""
from __future__ import annotations

from typing import TYPE_CHECKING

import httpx
import pytest
import pytest_asyncio
from airsdk.agdr import Signer
from airsdk.types import AgDRPayload, AgDRRecord, StepKind

from vindicara.cloud.capsule_store import InMemoryCapsuleStore
from vindicara.cloud.factory import create_air_cloud_app
from vindicara.cloud.workspace import (
    ApiKey,
    InMemoryApiKeyStore,
    InMemoryWorkspaceStore,
    Workspace,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


def _signed_record(signer: Signer, *, prompt: str = "hi") -> AgDRRecord:
    return signer.sign(
        kind=StepKind.LLM_START,
        payload=AgDRPayload.model_validate({"prompt": prompt}),
    )


@pytest_asyncio.fixture
async def cloud_with_roles() -> AsyncIterator[tuple[httpx.AsyncClient, dict]]:
    """Pre-seed one workspace with one key per role."""
    capsule_store = InMemoryCapsuleStore()
    workspace_store = InMemoryWorkspaceStore()
    api_key_store = InMemoryApiKeyStore()

    workspace = Workspace(workspace_id="acme", name="Acme", owner_email="ops@acme.io")
    workspace_store.create(workspace)

    keys: dict[str, str] = {}
    for role in ("owner", "admin", "member", "viewer"):
        api_key = ApiKey(
            key_id=f"key_acme_{role}",
            workspace_id="acme",
            key=f"air_test_{role}",
            role=role,
            name=f"{role} key",
        )
        api_key_store.issue(api_key)
        keys[role] = api_key.key

    app = create_air_cloud_app(
        capsule_store=capsule_store,
        workspace_store=workspace_store,
        api_key_store=api_key_store,
    )
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client, {
            "capsule_store": capsule_store,
            "workspace_store": workspace_store,
            "api_key_store": api_key_store,
            "keys": keys,
        }


@pytest.fixture
def signer() -> Signer:
    return Signer.generate()


# -- Read-workspace policy ----------------------------------------------


@pytest.mark.asyncio
async def test_every_role_can_read_its_workspace(
    cloud_with_roles: tuple[httpx.AsyncClient, dict],
) -> None:
    client, ctx = cloud_with_roles
    for role, key in ctx["keys"].items():
        response = await client.get("/v1/workspaces/me", headers={"X-API-Key": key})
        assert response.status_code == 200, f"role {role} should read workspace"


# -- Capsule write policy -----------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["owner", "admin", "member"])
async def test_write_capable_roles_can_ingest(
    cloud_with_roles: tuple[httpx.AsyncClient, dict],
    signer: Signer,
    role: str,
) -> None:
    client, ctx = cloud_with_roles
    record = _signed_record(signer)
    response = await client.post(
        "/v1/capsules",
        headers={"X-API-Key": ctx["keys"][role]},
        content=record.model_dump_json(),
    )
    assert response.status_code == 201, f"role {role} should ingest"


@pytest.mark.asyncio
async def test_viewer_cannot_ingest_capsules(
    cloud_with_roles: tuple[httpx.AsyncClient, dict],
    signer: Signer,
) -> None:
    client, ctx = cloud_with_roles
    record = _signed_record(signer)
    response = await client.post(
        "/v1/capsules",
        headers={"X-API-Key": ctx["keys"]["viewer"]},
        content=record.model_dump_json(),
    )
    assert response.status_code == 403
    assert "viewer" in response.json()["detail"]


@pytest.mark.asyncio
async def test_viewer_cannot_bulk_ingest(
    cloud_with_roles: tuple[httpx.AsyncClient, dict],
    signer: Signer,
) -> None:
    client, ctx = cloud_with_roles
    record = _signed_record(signer)
    response = await client.post(
        "/v1/capsules/bulk",
        headers={"X-API-Key": ctx["keys"]["viewer"]},
        content=record.model_dump_json(),
    )
    assert response.status_code == 403


# -- Capsule read policy ------------------------------------------------


@pytest.mark.asyncio
async def test_every_role_can_read_capsules(
    cloud_with_roles: tuple[httpx.AsyncClient, dict],
    signer: Signer,
) -> None:
    client, ctx = cloud_with_roles
    record = _signed_record(signer)
    await client.post(
        "/v1/capsules",
        headers={"X-API-Key": ctx["keys"]["owner"]},
        content=record.model_dump_json(),
    )
    for role, key in ctx["keys"].items():
        response = await client.get("/v1/capsules", headers={"X-API-Key": key})
        assert response.status_code == 200, f"role {role} should read capsules"


# -- Key management policy ----------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["owner", "admin"])
async def test_admin_and_owner_can_list_keys(
    cloud_with_roles: tuple[httpx.AsyncClient, dict],
    role: str,
) -> None:
    client, ctx = cloud_with_roles
    response = await client.get("/v1/keys", headers={"X-API-Key": ctx["keys"][role]})
    assert response.status_code == 200


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["member", "viewer"])
async def test_member_and_viewer_cannot_list_keys(
    cloud_with_roles: tuple[httpx.AsyncClient, dict],
    role: str,
) -> None:
    client, ctx = cloud_with_roles
    response = await client.get("/v1/keys", headers={"X-API-Key": ctx["keys"][role]})
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_admin_can_issue_and_revoke_keys(
    cloud_with_roles: tuple[httpx.AsyncClient, dict],
) -> None:
    client, ctx = cloud_with_roles
    issue = await client.post(
        "/v1/keys",
        headers={"X-API-Key": ctx["keys"]["admin"]},
        json={"name": "ci-bot", "role": "member"},
    )
    assert issue.status_code == 201
    new_id = issue.json()["key_id"]

    revoke = await client.delete(
        f"/v1/keys/{new_id}",
        headers={"X-API-Key": ctx["keys"]["admin"]},
    )
    assert revoke.status_code == 200


@pytest.mark.asyncio
async def test_member_cannot_issue_keys(
    cloud_with_roles: tuple[httpx.AsyncClient, dict],
) -> None:
    client, ctx = cloud_with_roles
    response = await client.post(
        "/v1/keys",
        headers={"X-API-Key": ctx["keys"]["member"]},
        json={"name": "x"},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_issue_key_rejects_unknown_role(
    cloud_with_roles: tuple[httpx.AsyncClient, dict],
) -> None:
    client, ctx = cloud_with_roles
    response = await client.post(
        "/v1/keys",
        headers={"X-API-Key": ctx["keys"]["owner"]},
        json={"name": "x", "role": "godmode"},
    )
    assert response.status_code == 400


# -- Member invite ------------------------------------------------------


@pytest.mark.asyncio
async def test_invite_member_returns_fresh_key(
    cloud_with_roles: tuple[httpx.AsyncClient, dict],
) -> None:
    client, ctx = cloud_with_roles
    response = await client.post(
        "/v1/workspaces/me/members",
        headers={"X-API-Key": ctx["keys"]["owner"]},
        json={"email": "alice@acme.io", "role": "member", "name": "Alice"},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["workspace_id"] == "acme"
    assert body["invited_email"] == "alice@acme.io"
    assert body["api_key"]["role"] == "member"
    assert body["api_key"]["key"].startswith("air_")
    # The new key should immediately authenticate.
    new_key = body["api_key"]["key"]
    whoami = await client.get("/v1/workspaces/me", headers={"X-API-Key": new_key})
    assert whoami.status_code == 200


@pytest.mark.asyncio
async def test_invite_member_admin_can_invite(
    cloud_with_roles: tuple[httpx.AsyncClient, dict],
) -> None:
    client, ctx = cloud_with_roles
    response = await client.post(
        "/v1/workspaces/me/members",
        headers={"X-API-Key": ctx["keys"]["admin"]},
        json={"email": "bob@acme.io", "role": "viewer"},
    )
    assert response.status_code == 201


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["member", "viewer"])
async def test_invite_member_denied_for_non_admin(
    cloud_with_roles: tuple[httpx.AsyncClient, dict],
    role: str,
) -> None:
    client, ctx = cloud_with_roles
    response = await client.post(
        "/v1/workspaces/me/members",
        headers={"X-API-Key": ctx["keys"][role]},
        json={"email": "x@acme.io", "role": "member"},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_invite_member_rejects_owner_role(
    cloud_with_roles: tuple[httpx.AsyncClient, dict],
) -> None:
    """Owners cannot be issued via the invite flow; that path runs through POST /v1/keys."""
    client, ctx = cloud_with_roles
    response = await client.post(
        "/v1/workspaces/me/members",
        headers={"X-API-Key": ctx["keys"]["owner"]},
        json={"email": "co-owner@acme.io", "role": "owner"},
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_invite_member_rejects_invalid_role(
    cloud_with_roles: tuple[httpx.AsyncClient, dict],
) -> None:
    client, ctx = cloud_with_roles
    response = await client.post(
        "/v1/workspaces/me/members",
        headers={"X-API-Key": ctx["keys"]["owner"]},
        json={"email": "x@acme.io", "role": "godmode"},
    )
    assert response.status_code == 400
