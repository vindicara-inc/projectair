"""Tests for HL7v2 capsule capture (Task 5)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from _helpers import requires_vendor_key
from airsdk.agdr import load_chain, verify_chain
from airsdk.recorder import AIRRecorder
from airsdk.types import StepKind, VerificationStatus

from airsdk_pro.hl7.capture import HL7_FHIR_FEATURE
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
    token = issue_token(
        email="hl7-tests@vindicara.io",
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
# test_instrument_hl7_writes_two_records
# ---------------------------------------------------------------------------


@requires_vendor_key
def test_instrument_hl7_writes_two_records(
    licensed: Path, recorder: AIRRecorder
) -> None:
    from airsdk_pro.hl7.capture import instrument_hl7

    start, end = instrument_hl7(recorder, SAMPLE_ORU_R01)

    assert start.kind == StepKind.TOOL_START
    assert end.kind == StepKind.TOOL_END
    assert start.payload.tool_name == "hl7v2_receive"


# ---------------------------------------------------------------------------
# test_chain_verifies_after_capture
# ---------------------------------------------------------------------------


@requires_vendor_key
def test_chain_verifies_after_capture(
    licensed: Path, recorder: AIRRecorder
) -> None:
    from airsdk_pro.hl7.capture import instrument_hl7

    instrument_hl7(recorder, SAMPLE_ORU_R01)

    records = load_chain(recorder.log_path)
    result = verify_chain(records)

    assert result.status == VerificationStatus.OK
    assert result.records_verified == 2


# ---------------------------------------------------------------------------
# test_capture_auto_tags_data_subject
# ---------------------------------------------------------------------------


@requires_vendor_key
def test_capture_auto_tags_data_subject(
    licensed: Path, recorder: AIRRecorder
) -> None:
    from airsdk_pro.hl7.capture import instrument_hl7

    start, _ = instrument_hl7(recorder, SAMPLE_ORU_R01)

    assert start.payload.data_subjects is not None
    assert len(start.payload.data_subjects) == 1
    subject = start.payload.data_subjects[0]
    assert subject.subject_type == "patient"
    assert subject.jurisdiction == "HIPAA"


# ---------------------------------------------------------------------------
# test_capture_includes_fhir_resources
# ---------------------------------------------------------------------------


@requires_vendor_key
def test_capture_includes_fhir_resources(
    licensed: Path, recorder: AIRRecorder
) -> None:
    from airsdk_pro.hl7.capture import instrument_hl7

    start, _ = instrument_hl7(recorder, SAMPLE_ORU_R01, map_fhir=True)

    assert start.payload.fhir_resources is not None
    assert len(start.payload.fhir_resources) > 0
    resource_types = {r.get("resourceType") for r in start.payload.fhir_resources}
    assert "Patient" in resource_types
    assert "Observation" in resource_types


# ---------------------------------------------------------------------------
# test_capture_redacts_mrn_by_default
# ---------------------------------------------------------------------------


@requires_vendor_key
def test_capture_redacts_mrn_by_default(
    licensed: Path, recorder: AIRRecorder
) -> None:
    from airsdk_pro.hl7.capture import instrument_hl7

    start, _ = instrument_hl7(recorder, SAMPLE_ORU_R01)

    # Serialize the full payload to JSON and check the raw MRN is absent
    payload_json = start.payload.model_dump_json()
    assert "MRN-0042" not in payload_json

    # The subject_id must be a BLAKE3 hash (64 hex chars), not the raw value
    assert start.payload.data_subjects is not None
    subject_id = start.payload.data_subjects[0].subject_id
    assert subject_id != "MRN-0042"
    assert len(subject_id) == 64
    # All hex characters
    assert all(c in "0123456789abcdef" for c in subject_id)
