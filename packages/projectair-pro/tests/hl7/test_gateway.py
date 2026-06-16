"""Tests for ClinicalSidecar gateway orchestrator (Task 9)."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from _helpers import requires_vendor_key
from airsdk.recorder import AIRRecorder
from airsdk_pro.hl7.capture import HL7_FHIR_FEATURE
from airsdk_pro.hl7.gateway import ClinicalSidecar
from airsdk_pro.hl7.types import SidecarResult
from airsdk_pro.license import install_license, load_license

SAMPLE_ORU_R01 = (
    "MSH|^~\\&|LAB|HOSP-MAIN|AI-AGENT|VINDICARA|20260511120000||ORU^R01|MSG001|P|2.5\r"
    "PID|1||MRN-0042^^^HOSP-MAIN^MR~123-45-6789^^^SSA^SS||DOE^JANE||19850315|F\r"
    "OBR|1|ORD001|FIL001|14749-6^HbA1c^LN|||20260511\r"
    "OBX|1|NM|14749-6^HbA1c^LN||8.4|%|<7.0|H|||F\r"
    "OBX|2|NM|2345-7^Glucose^LN||186|mg/dL|74-106|H|||F\r"
    "OBX|3|ST|LOCAL001^Custom Test^LOCAL||Positive||||F\r"
)


@pytest.fixture
def licensed(
    tmp_path: Path,
    issue_token: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    """Install a Pro license with the HL7 FHIR feature and route the gate to it."""
    token = issue_token(
        email="gateway-tests@vindicara.io",
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
def recorder(tmp_path: Path) -> AIRRecorder:
    return AIRRecorder(log_path=tmp_path / "chain.jsonl")


# ---------------------------------------------------------------------------
# test_sidecar_processes_message
# ---------------------------------------------------------------------------


@requires_vendor_key
@pytest.mark.asyncio
async def test_sidecar_processes_message(
    licensed: Path, recorder: AIRRecorder
) -> None:
    sidecar = ClinicalSidecar(recorder)
    result = await sidecar.process(SAMPLE_ORU_R01)

    assert isinstance(result, SidecarResult)
    assert result.message_type == "ORU^R01"
    assert result.records_written == 2


# ---------------------------------------------------------------------------
# test_sidecar_processes_file
# ---------------------------------------------------------------------------


@requires_vendor_key
@pytest.mark.asyncio
async def test_sidecar_processes_file(
    licensed: Path, recorder: AIRRecorder, tmp_path: Path
) -> None:
    sample_file = tmp_path / "messages.hl7"
    sample_file.write_text(SAMPLE_ORU_R01, encoding="utf-8")

    sidecar = ClinicalSidecar(recorder)
    results = await sidecar.process_file(sample_file)

    assert len(results) == 1
    assert results[0].message_type == "ORU^R01"
    assert results[0].records_written == 2


# ---------------------------------------------------------------------------
# test_sidecar_lag_starts_at_zero
# ---------------------------------------------------------------------------


@requires_vendor_key
def test_sidecar_lag_starts_at_zero(
    tmp_path: Path,
    issue_token: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = issue_token(
        email="lag-test@vindicara.io",
        tier="individual",
        features=(HL7_FHIR_FEATURE,),
    )
    license_path = tmp_path / "license.json"
    install_license(token, path=license_path)
    monkeypatch.setattr(
        "airsdk_pro.gate.load_license", lambda: load_license(license_path)
    )

    rec = AIRRecorder(log_path=tmp_path / "chain.jsonl")
    sidecar = ClinicalSidecar(rec)

    assert sidecar.lag_seconds == 0.0
    assert sidecar.dead_letter_count == 0


# ---------------------------------------------------------------------------
# test_sidecar_dead_letters_malformed
# ---------------------------------------------------------------------------


@requires_vendor_key
@pytest.mark.asyncio
async def test_sidecar_dead_letters_malformed(
    licensed: Path, recorder: AIRRecorder
) -> None:
    sidecar = ClinicalSidecar(recorder)
    result = await sidecar.process("THIS IS NOT HL7")

    assert result.message_type == "UNKNOWN"
    assert result.records_written == 0
    assert sidecar.dead_letter_count == 1


# ---------------------------------------------------------------------------
# test_sidecar_replay_dead_letters
# ---------------------------------------------------------------------------


@requires_vendor_key
@pytest.mark.asyncio
async def test_sidecar_replay_dead_letters(
    licensed: Path, recorder: AIRRecorder
) -> None:
    sidecar = ClinicalSidecar(recorder)

    # Put a bad message into the dead-letter list
    await sidecar.process("NOT-HL7-GARBAGE")
    assert sidecar.dead_letter_count == 1

    # Replay once; message still bad so retry_count increments, stays in DLQ
    replayed = await sidecar.replay_dead_letters(max_batch=10)
    assert replayed == 0  # zero messages successfully processed
    assert sidecar.dead_letter_count == 1

    # Verify retry_count is now 1
    dl = sidecar._dead_letters  # type: ignore[attr-defined]
    assert dl[0]["retry_count"] == 1
