"""Integration tests for the ``/v1/capsules`` ingestion endpoint."""
from __future__ import annotations

import json

import pytest
from airsdk.agdr import Signer
from airsdk.types import AgDRPayload, StepKind
from httpx import ASGITransport, AsyncClient

from tests.conftest import TEST_API_KEY


def _signed_record_json(payload: dict[str, str]) -> str:
    signer = Signer.generate()
    record = signer.sign(StepKind.LLM_START, AgDRPayload.model_validate(payload))
    return record.model_dump_json(exclude_none=True)


@pytest.mark.asyncio
async def test_post_capsule_succeeds_with_valid_signed_record(app) -> None:
    body = _signed_record_json({"prompt": "hello cloud"})

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/v1/capsules",
            content=body,
            headers={"X-Vindicara-Key": TEST_API_KEY, "Content-Type": "application/json"},
        )

    assert resp.status_code == 201
    body_obj = resp.json()
    assert body_obj["stored"] is True
    assert body_obj["step_id"]
    assert app.state.capsule_store.count() == 1


@pytest.mark.asyncio
async def test_post_capsule_rejects_tampered_payload(app) -> None:
    body = _signed_record_json({"prompt": "original prompt"})
    record = json.loads(body)
    record["payload"]["prompt"] = "tampered prompt after signing"
    tampered = json.dumps(record)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/v1/capsules",
            content=tampered,
            headers={"X-Vindicara-Key": TEST_API_KEY, "Content-Type": "application/json"},
        )

    assert resp.status_code == 422
    assert "verify" in resp.json()["detail"].lower() or "hash" in resp.json()["detail"].lower()
    assert app.state.capsule_store.count() == 0


@pytest.mark.asyncio
async def test_post_capsule_rejects_missing_api_key(app) -> None:
    body = _signed_record_json({"prompt": "no auth"})

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/v1/capsules",
            content=body,
            headers={"Content-Type": "application/json"},
        )

    assert resp.status_code == 401
    assert app.state.capsule_store.count() == 0


@pytest.mark.asyncio
async def test_post_capsule_rejects_invalid_body(app) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/v1/capsules",
            content='{"not": "a record"}',
            headers={"X-Vindicara-Key": TEST_API_KEY, "Content-Type": "application/json"},
        )

    assert resp.status_code == 400
    assert app.state.capsule_store.count() == 0


@pytest.mark.asyncio
async def test_post_capsule_isolates_by_workspace(app) -> None:
    body_a = _signed_record_json({"prompt": "tenant A"})
    body_b = _signed_record_json({"prompt": "tenant B"})

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post(
            "/v1/capsules",
            content=body_a,
            headers={"X-Vindicara-Key": TEST_API_KEY, "Content-Type": "application/json"},
        )
        await client.post(
            "/v1/capsules",
            content=body_b,
            headers={"X-Vindicara-Key": TEST_API_KEY, "Content-Type": "application/json"},
        )

    # Both POSTs used the same dev API key, so both records are scoped to the
    # same owner_id ("dev"). Multi-tenancy isolation across distinct keys is
    # phase 2 work; here we verify both records persist under that workspace.
    assert app.state.capsule_store.count("dev") == 2
    items = app.state.capsule_store.for_workspace("dev")
    prompts = sorted(c.record.payload.prompt for c in items)
    assert prompts == ["tenant A", "tenant B"]
