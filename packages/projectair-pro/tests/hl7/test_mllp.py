"""Tests for HL7v2 MLLP TCP listener (Task 8)."""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from _helpers import requires_vendor_key
from airsdk.recorder import AIRRecorder

from airsdk_pro.hl7.capture import HL7_FHIR_FEATURE
from airsdk_pro.hl7.redaction import RedactionPolicy
from airsdk_pro.license import install_license, load_license

MLLP_START = b"\x0b"
MLLP_END = b"\x1c\x0d"

SAMPLE_ORU = (
    "MSH|^~\\&|LAB|HOSP-MAIN|AI-AGENT|VINDICARA|20260511120000||ORU^R01|MSG001|P|2.5\r"
    "PID|1||MRN-0042^^^HOSP-MAIN^MR||DOE^JANE||19850315|F\r"
    "OBX|1|NM|14749-6^HbA1c^LN||8.4|%|<7.0|H|||F\r"
)


def _frame(message: str) -> bytes:
    """Wrap an HL7v2 string in MLLP framing bytes."""
    return MLLP_START + message.encode() + MLLP_END


@pytest.fixture
def licensed(
    tmp_path: Path,
    issue_token: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    token = issue_token(
        email="hl7-mllp-tests@vindicara.io",
        tier="individual",
        features=(HL7_FHIR_FEATURE,),
    )
    license_path = tmp_path / "license.json"
    install_license(token, path=license_path)
    monkeypatch.setattr(
        "airsdk_pro.gate.load_license", lambda: load_license(license_path)
    )
    return license_path


@requires_vendor_key
@pytest.mark.asyncio
async def test_mllp_accepts_framed_message(tmp_path: Path, licensed: Path) -> None:
    from airsdk_pro.hl7.mllp import MLLPListener

    listener = MLLPListener(
        host="127.0.0.1",
        port=0,
        recorder=AIRRecorder(tmp_path / "chain.jsonl"),
        redaction_policy=RedactionPolicy(),
    )
    await listener.start()
    assert listener.port > 0

    reader, writer = await asyncio.open_connection("127.0.0.1", listener.port)
    writer.write(_frame(SAMPLE_ORU))
    await writer.drain()
    response = await asyncio.wait_for(reader.read(4096), timeout=5.0)
    writer.close()
    await writer.wait_closed()
    await listener.stop()

    assert "MSA|AA" in response.decode(errors="replace")


@requires_vendor_key
@pytest.mark.asyncio
async def test_mllp_rejects_malformed_message(tmp_path: Path, licensed: Path) -> None:
    from airsdk_pro.hl7.mllp import MLLPListener

    listener = MLLPListener(
        host="127.0.0.1",
        port=0,
        recorder=AIRRecorder(tmp_path / "chain_mal.jsonl"),
        redaction_policy=RedactionPolicy(),
    )
    await listener.start()

    reader, writer = await asyncio.open_connection("127.0.0.1", listener.port)
    writer.write(_frame("NOT A VALID HL7 MESSAGE"))
    await writer.drain()
    response = await asyncio.wait_for(reader.read(4096), timeout=5.0)
    writer.close()
    await writer.wait_closed()
    await listener.stop()

    assert "MSA|AR" in response.decode(errors="replace")


@requires_vendor_key
@pytest.mark.asyncio
async def test_mllp_port_property(tmp_path: Path, licensed: Path) -> None:
    """port=0 resolves to an actual ephemeral port after start()."""
    from airsdk_pro.hl7.mllp import MLLPListener

    listener = MLLPListener(
        host="127.0.0.1",
        port=0,
        recorder=AIRRecorder(tmp_path / "chain_port.jsonl"),
    )
    await listener.start()
    port = listener.port
    await listener.stop()

    assert isinstance(port, int)
    assert 1 <= port <= 65535


@requires_vendor_key
@pytest.mark.asyncio
async def test_mllp_pipeline_queue_receives_message(
    tmp_path: Path, licensed: Path
) -> None:
    """Messages are enqueued on pipeline_queue when provided."""
    from airsdk_pro.hl7.mllp import MLLPListener

    queue: asyncio.Queue[str] = asyncio.Queue()
    listener = MLLPListener(
        host="127.0.0.1",
        port=0,
        recorder=AIRRecorder(tmp_path / "chain_q.jsonl"),
        pipeline_queue=queue,
        redaction_policy=RedactionPolicy(),
    )
    await listener.start()

    reader, writer = await asyncio.open_connection("127.0.0.1", listener.port)
    writer.write(_frame(SAMPLE_ORU))
    await writer.drain()
    await asyncio.wait_for(reader.read(4096), timeout=5.0)
    writer.close()
    await writer.wait_closed()
    await listener.stop()

    assert not queue.empty()
    enqueued = queue.get_nowait()
    assert "MSH" in enqueued


@requires_vendor_key
@pytest.mark.asyncio
async def test_mllp_multiple_messages_same_connection(
    tmp_path: Path, licensed: Path
) -> None:
    """MLLP listener handles multiple messages on the same TCP connection."""
    from airsdk_pro.hl7.mllp import MLLPListener

    listener = MLLPListener(
        host="127.0.0.1",
        port=0,
        recorder=AIRRecorder(tmp_path / "chain_multi.jsonl"),
        redaction_policy=RedactionPolicy(),
    )
    await listener.start()

    reader, writer = await asyncio.open_connection("127.0.0.1", listener.port)

    for _ in range(3):
        writer.write(_frame(SAMPLE_ORU))
        await writer.drain()
        response = await asyncio.wait_for(reader.read(4096), timeout=5.0)
        assert b"MSA|AA" in response

    writer.close()
    await writer.wait_closed()
    await listener.stop()
