"""Recorder wiring: GPU_ATTESTATION lands at genesis, additively."""
from __future__ import annotations

from pathlib import Path

import pytest
from tests.attestation.conftest import make_grant

from airsdk.agdr import load_chain, verify_chain
from airsdk.attestation import FixtureNRAS, GPUAttestationConfig
from airsdk.recorder import AIRRecorder
from airsdk.types import AGDR_VERSION, StepKind, VerificationStatus


def test_attestation_record_sits_right_after_genesis(
    attested_recorder: AIRRecorder,
) -> None:
    records = load_chain(attested_recorder.log_path)
    kinds = [r.kind for r in records]
    assert kinds[:3] == [
        StepKind.DELEGATION,
        StepKind.INTENT_DECLARATION,
        StepKind.GPU_ATTESTATION,
    ]
    assert records[2].payload.attestation is not None
    assert verify_chain(records).status == VerificationStatus.OK


def test_attestation_requires_delegation(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="requires delegation="):
        AIRRecorder(
            tmp_path / "chain.jsonl",
            attestation=GPUAttestationConfig(),
            attestation_provider=FixtureNRAS(),
        )


def test_recorder_without_attestation_is_unchanged(tmp_path: Path) -> None:
    recorder = AIRRecorder(tmp_path / "plain.jsonl", delegation=make_grant())
    records = load_chain(recorder.log_path)
    assert [r.kind for r in records] == [
        StepKind.DELEGATION,
        StepKind.INTENT_DECLARATION,
    ]
    assert all(r.payload.attestation is None for r in records)


def test_v06_chains_validate_under_v07_schema(tmp_path: Path) -> None:
    """The v0.7 bump is purely additive: legacy records load and verify."""
    recorder = AIRRecorder(tmp_path / "legacy.jsonl", delegation=make_grant())
    recorder.tool_start(tool_name="x", tool_args={})
    raw = (tmp_path / "legacy.jsonl").read_text(encoding="utf-8")
    downgraded = raw.replace(f'"version":"{AGDR_VERSION}"', '"version":"0.6"')
    legacy_path = tmp_path / "v06.jsonl"
    legacy_path.write_text(downgraded, encoding="utf-8")

    records = load_chain(legacy_path)
    assert records[0].version == "0.6"
    assert verify_chain(records).status == VerificationStatus.OK
    assert all(r.payload.attestation is None for r in records)


def test_new_records_carry_v07(attested_recorder: AIRRecorder) -> None:
    records = load_chain(attested_recorder.log_path)
    assert records[0].version == "0.7"
