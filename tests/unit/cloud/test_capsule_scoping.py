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
def scoped_app():  # type: ignore[no-untyped-def]
    ws_store = InMemoryWorkspaceStore()
    key_store = InMemoryApiKeyStore()
    ws = Workspace(workspace_id="ws_scope", name="Scope", owner_email="o@b.com")
    ws_store.create(ws)

    owner_key = ApiKey(
        key_id="key_owner",
        workspace_id="ws_scope",
        key="air_owner_00000000000000000000000000",
        role="owner",
    )
    member_key = ApiKey(
        key_id="key_member",
        workspace_id="ws_scope",
        key="air_member_000000000000000000000000000",
        role="member",
    )
    key_store.issue(owner_key)
    key_store.issue(member_key)

    return create_air_cloud_app(
        workspace_store=ws_store,
        api_key_store=key_store,
    )


@pytest.mark.anyio()
async def test_member_sees_only_own_capsules(scoped_app) -> None:  # type: ignore[no-untyped-def]
    from airsdk.agdr import Signer
    from airsdk.types import AgDRPayload, StepKind

    signer = Signer.generate()

    def make_record() -> str:
        payload = AgDRPayload(model="test", prompt="test", response="test")
        record = signer.sign(StepKind.LLM_START, payload)
        return record.model_dump_json()

    async with AsyncClient(
        transport=ASGITransport(app=scoped_app), base_url="http://test"
    ) as client:
        # Ingest as member
        resp = await client.post(
            "/v1/capsules",
            content=make_record(),
            headers={
                "X-API-Key": "air_member_000000000000000000000000000",
                "Content-Type": "application/json",
            },
        )
        assert resp.status_code == 201
        member_step_id: str = resp.json()["step_id"]

        # Ingest as owner
        resp = await client.post(
            "/v1/capsules",
            content=make_record(),
            headers={
                "X-API-Key": "air_owner_00000000000000000000000000",
                "Content-Type": "application/json",
            },
        )
        assert resp.status_code == 201
        owner_step_id: str = resp.json()["step_id"]

        # Member sees only their capsule
        resp = await client.get(
            "/v1/capsules",
            headers={"X-API-Key": "air_member_000000000000000000000000000"},
        )
        assert resp.status_code == 200
        records = resp.json()["records"]
        step_ids = [r["step_id"] for r in records]
        assert member_step_id in step_ids
        assert owner_step_id not in step_ids

        # Owner sees all capsules
        resp = await client.get(
            "/v1/capsules",
            headers={"X-API-Key": "air_owner_00000000000000000000000000"},
        )
        assert resp.status_code == 200
        records = resp.json()["records"]
        step_ids = [r["step_id"] for r in records]
        assert member_step_id in step_ids
        assert owner_step_id in step_ids
