"""Tests for HL7v2 HTTP receiver (Task 8)."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from _helpers import requires_vendor_key
from airsdk.recorder import AIRRecorder

from airsdk_pro.hl7.capture import HL7_FHIR_FEATURE
from airsdk_pro.hl7.redaction import RedactionPolicy
from airsdk_pro.license import install_license, load_license

SAMPLE_ORU = (
    "MSH|^~\\&|LAB|HOSP-MAIN|AI-AGENT|VINDICARA|20260511120000||ORU^R01|MSG001|P|2.5\r"
    "PID|1||MRN-0042^^^HOSP-MAIN^MR||DOE^JANE||19850315|F\r"
    "OBX|1|NM|14749-6^HbA1c^LN||8.4|%|<7.0|H|||F\r"
)


@pytest.fixture
def licensed(
    tmp_path: Path,
    issue_token: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    token = issue_token(
        email="hl7-http-tests@vindicara.io",
        tier="individual",
        features=(HL7_FHIR_FEATURE,),
    )
    license_path = tmp_path / "license.json"
    install_license(token, path=license_path)
    monkeypatch.setattr(
        "airsdk_pro.gate.load_license", lambda: load_license(license_path)
    )
    return license_path


@pytest.fixture
def app_with_hl7(tmp_path: Path, licensed: Path) -> FastAPI:
    from airsdk_pro.hl7.http import create_hl7_router

    app = FastAPI()
    rec = AIRRecorder(tmp_path / "chain.jsonl")
    router = create_hl7_router(rec, redaction_policy=RedactionPolicy())
    app.include_router(router, prefix="/clinical")
    return app


@requires_vendor_key
@pytest.mark.asyncio
async def test_post_valid_message_returns_aa(app_with_hl7: FastAPI) -> None:
    async with AsyncClient(
        transport=ASGITransport(app=app_with_hl7), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/clinical/hl7v2/ingest",
            content=SAMPLE_ORU,
            headers={"Content-Type": "application/hl7-v2"},
        )
    assert resp.status_code == 200
    assert "MSA|AA" in resp.text


@requires_vendor_key
@pytest.mark.asyncio
async def test_post_er7_content_type_returns_aa(app_with_hl7: FastAPI) -> None:
    """x-application/hl7-v2+er7 is also an accepted content-type."""
    async with AsyncClient(
        transport=ASGITransport(app=app_with_hl7), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/clinical/hl7v2/ingest",
            content=SAMPLE_ORU,
            headers={"Content-Type": "x-application/hl7-v2+er7"},
        )
    assert resp.status_code == 200
    assert "MSA|AA" in resp.text


@requires_vendor_key
@pytest.mark.asyncio
async def test_post_malformed_returns_ar(app_with_hl7: FastAPI) -> None:
    async with AsyncClient(
        transport=ASGITransport(app=app_with_hl7), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/clinical/hl7v2/ingest",
            content="NOT VALID HL7",
            headers={"Content-Type": "application/hl7-v2"},
        )
    assert resp.status_code == 400
    assert "MSA|AR" in resp.text


@requires_vendor_key
@pytest.mark.asyncio
async def test_ack_contains_msh_header(app_with_hl7: FastAPI) -> None:
    """ACK response must start with a valid MSH segment."""
    async with AsyncClient(
        transport=ASGITransport(app=app_with_hl7), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/clinical/hl7v2/ingest",
            content=SAMPLE_ORU,
            headers={"Content-Type": "application/hl7-v2"},
        )
    assert resp.status_code == 200
    assert resp.text.startswith("MSH|")


@requires_vendor_key
@pytest.mark.asyncio
async def test_post_pipeline_queue_receives_message(
    tmp_path: Path, licensed: Path
) -> None:
    """When pipeline_queue is provided, the raw message is enqueued."""
    import asyncio

    from airsdk_pro.hl7.http import create_hl7_router

    app = FastAPI()
    queue: asyncio.Queue[str] = asyncio.Queue()
    rec = AIRRecorder(tmp_path / "chain2.jsonl")
    router = create_hl7_router(
        rec, pipeline_queue=queue, redaction_policy=RedactionPolicy()
    )
    app.include_router(router)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/hl7v2/ingest",
            content=SAMPLE_ORU,
            headers={"Content-Type": "application/hl7-v2"},
        )

    assert resp.status_code == 200
    assert not queue.empty()
    enqueued = queue.get_nowait()
    assert "MSH" in enqueued
