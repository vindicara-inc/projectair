"""Tests for the NVIDIA NemoClaw integration."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from airsdk.agdr import load_chain, verify_chain
from airsdk.integrations.nemoclaw import (
    AIROpenClawHandler,
    instrument_nemoclaw,
)
from airsdk.recorder import AIRRecorder
from airsdk.types import VerificationStatus


class FakeOpenClawClient:
    """Minimal mock of openclaw_sdk.OpenClawClient."""

    def __init__(self) -> None:
        self.callbacks: list[Any] = []
        self.last_pipeline: str = ""
        self.last_kwargs: dict[str, Any] = {}

    def execute(self, *, pipeline: str = "", **kwargs: Any) -> dict[str, str]:
        self.last_pipeline = pipeline
        self.last_kwargs = kwargs
        return {"result": "triage_complete", "priority": "high"}

    def add_callback(self, cb: Any) -> None:
        self.callbacks.append(cb)


def test_instrument_captures_execution(tmp_path: Path) -> None:
    log = tmp_path / "chain.jsonl"
    recorder = AIRRecorder(str(log))
    client = FakeOpenClawClient()

    instrumented = instrument_nemoclaw(client, recorder)
    result = instrumented.execute(pipeline="triage", input={"mrn": "12345"})

    assert result["result"] == "triage_complete"

    records = load_chain(str(log))
    assert len(records) >= 2
    assert records[0].kind == "llm_start"
    assert "openclaw:triage" in (records[0].payload.prompt or "")
    assert records[1].kind == "llm_end"
    assert verify_chain(records).status == VerificationStatus.OK


def test_handler_tool_events(tmp_path: Path) -> None:
    log = tmp_path / "chain.jsonl"
    recorder = AIRRecorder(str(log))
    handler = AIROpenClawHandler(recorder)

    handler.on_tool_start(tool_name="ehr_query", tool_args={"mrn": "42"})
    handler.on_tool_end(tool_name="ehr_query", tool_output="HbA1c: 8.4%")

    records = load_chain(str(log))
    assert len(records) == 2
    assert records[0].kind == "tool_start"
    assert records[0].payload.tool_name == "ehr_query"
    assert records[1].kind == "tool_end"
    assert "HbA1c" in (records[1].payload.tool_output or "")
    assert verify_chain(records).status == VerificationStatus.OK


def test_handler_inference_events(tmp_path: Path) -> None:
    log = tmp_path / "chain.jsonl"
    recorder = AIRRecorder(str(log))
    handler = AIROpenClawHandler(recorder)

    handler.on_inference_start(
        model="nemotron-70b",
        messages=[{"role": "user", "content": "Summarize labs"}],
    )
    handler.on_inference_end(
        model="nemotron-70b",
        response="HbA1c elevated at 8.4%",
    )

    records = load_chain(str(log))
    assert len(records) == 2
    assert "nemotron-70b" in (records[0].payload.prompt or "")
    assert verify_chain(records).status == VerificationStatus.OK


def test_handler_sandbox_policy_event(tmp_path: Path) -> None:
    log = tmp_path / "chain.jsonl"
    recorder = AIRRecorder(str(log))
    handler = AIROpenClawHandler(recorder)

    handler.on_sandbox_policy_event(
        action="network_egress",
        resource="https://external-api.example.com",
        decision="denied",
        reason="not in allowlist",
    )

    records = load_chain(str(log))
    assert len(records) == 2
    assert records[0].kind == "tool_start"
    assert records[0].payload.tool_name == "openshell:network_egress"
    assert records[0].payload.tool_args is not None
    assert records[0].payload.tool_args["decision"] == "denied"
    assert verify_chain(records).status == VerificationStatus.OK


def test_passthrough_attributes(tmp_path: Path) -> None:
    log = tmp_path / "chain.jsonl"
    recorder = AIRRecorder(str(log))
    client = FakeOpenClawClient()
    client.some_attr = "hello"  # type: ignore[attr-defined]

    instrumented = instrument_nemoclaw(client, recorder)
    assert instrumented.some_attr == "hello"  # type: ignore[attr-defined]


def test_recorder_property(tmp_path: Path) -> None:
    log = tmp_path / "chain.jsonl"
    recorder = AIRRecorder(str(log))
    client = FakeOpenClawClient()

    instrumented = instrument_nemoclaw(client, recorder)
    assert instrumented.recorder is recorder


def test_full_clinical_workflow(tmp_path: Path) -> None:
    """Simulate a NemoClaw clinical workflow end-to-end."""
    log = tmp_path / "chain.jsonl"
    recorder = AIRRecorder(str(log))
    handler = AIROpenClawHandler(recorder)

    handler.on_execution_start(pipeline="clinical-cds", input_data={"mrn": "20260511-0042"})
    handler.on_tool_start(tool_name="ehr_query", tool_args={"mrn": "20260511-0042", "type": "labs"})
    handler.on_tool_end(tool_name="ehr_query", tool_output="HbA1c: 8.4%, Glucose: 186")
    handler.on_sandbox_policy_event(
        action="filesystem_read",
        resource="/restricted/psychiatric",
        decision="denied",
    )
    handler.on_inference_start(model="nemotron-70b", messages="Analyze patient labs...")
    handler.on_inference_end(model="nemotron-70b", response="Recommend GLP-1 agonist")
    handler.on_execution_end(pipeline="clinical-cds", output_data={"recommendation": "GLP-1"})

    records = load_chain(str(log))
    assert len(records) == 8
    result = verify_chain(records)
    assert result.status == VerificationStatus.OK
    assert result.records_verified == 8
