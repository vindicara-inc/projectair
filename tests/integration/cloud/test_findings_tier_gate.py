"""The keystone: free sees every finding, free can do nothing.

Drives the real ASGI stack. Seeds a free workspace with real signed capsules
(the concrete demo chain), then asserts:

- ``GET /v1/findings`` returns real findings to the **free** workspace
  (``can_act=False``) - the AUDIT floor: you always see the truth.
- ``POST /v1/findings/{id}/act`` is blocked for free with a 402 upgrade prompt.
- A **pro** workspace may act (204) and the action is recorded.

The findings are computed by the real 16 detectors over the workspace's ingested
capsules, not fixtures, so "free sees real findings" is proven, not asserted.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

import httpx
import pytest
import pytest_asyncio

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

from airsdk._concrete_demo import build_concrete_demo_log
from airsdk.types import AgDRRecord

from vindicara.cloud.capsule_store import InMemoryCapsuleStore
from vindicara.cloud.factory import create_air_cloud_app
from vindicara.cloud.workspace import ApiKey, InMemoryApiKeyStore, InMemoryWorkspaceStore, Workspace


def _demo_records() -> list[dict]:
    """The concrete demo chain as a list of wire-form records (real signatures)."""
    with tempfile.TemporaryDirectory() as tmp:
        log = Path(tmp) / "chain.log"
        build_concrete_demo_log(log)
        out: list[dict] = []
        for line in log.read_text(encoding="utf-8").splitlines():
            if line.strip():
                record = AgDRRecord.model_validate_json(line)
                out.append(json.loads(record.model_dump_json(exclude_none=True)))
        return out


@pytest_asyncio.fixture
async def gated_client() -> AsyncIterator[tuple[httpx.AsyncClient, dict]]:
    workspace_store = InMemoryWorkspaceStore()
    api_key_store = InMemoryApiKeyStore()

    workspace_store.create(Workspace(workspace_id="free_ws", name="Free", owner_email="f@e.com", tier="free"))
    workspace_store.create(Workspace(workspace_id="pro_ws", name="Pro", owner_email="p@e.com", tier="pro"))
    api_key_store.issue(ApiKey(key_id="k_free", workspace_id="free_ws", key="air_free", role="owner"))
    api_key_store.issue(ApiKey(key_id="k_pro", workspace_id="pro_ws", key="air_pro", role="owner"))

    app = create_air_cloud_app(
        capsule_store=InMemoryCapsuleStore(),
        workspace_store=workspace_store,
        api_key_store=api_key_store,
    )
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Seed the free workspace with real signed capsules.
        for record in _demo_records():
            resp = await client.post("/v1/capsules", headers={"X-API-Key": "air_free"}, json=record)
            assert resp.status_code == 201, resp.text
        yield client, {"finding_actions": app.state.finding_actions}


@pytest.mark.asyncio
async def test_free_sees_real_findings(gated_client: tuple[httpx.AsyncClient, dict]) -> None:
    client, _ = gated_client
    resp = await client.get("/v1/findings", headers={"X-API-Key": "air_free"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["tier"] == "free"
    assert body["can_act"] is False
    assert body["count"] > 0  # the detectors really fired on the demo chain
    assert body["count"] == len(body["findings"])
    assert any(f["detector_id"] for f in body["findings"])


@pytest.mark.asyncio
async def test_free_is_blocked_from_acting(gated_client: tuple[httpx.AsyncClient, dict]) -> None:
    client, _ = gated_client
    resp = await client.post(
        "/v1/findings/step-1/act",
        headers={"X-API-Key": "air_free"},
        json={"intent": "resolve"},
    )
    assert resp.status_code == 402
    detail = resp.json()["detail"]
    assert detail["error"] == "action_requires_upgrade"
    assert detail["action"] == "act_on_finding"
    assert "vindicara.io/pricing" in detail["upgrade_url"]


@pytest.mark.asyncio
async def test_pro_can_act_and_it_is_recorded(gated_client: tuple[httpx.AsyncClient, dict]) -> None:
    client, ctx = gated_client
    resp = await client.post(
        "/v1/findings/step-1/act",
        headers={"X-API-Key": "air_pro"},
        json={"intent": "contain"},
    )
    assert resp.status_code == 204
    recorded = ctx["finding_actions"].for_workspace("pro_ws")
    assert len(recorded) == 1
    assert recorded[0].intent == "contain"


@pytest.mark.asyncio
async def test_pro_findings_view_reports_can_act_true(gated_client: tuple[httpx.AsyncClient, dict]) -> None:
    client, _ = gated_client
    resp = await client.get("/v1/findings", headers={"X-API-Key": "air_pro"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["tier"] == "pro"
    assert body["can_act"] is True
