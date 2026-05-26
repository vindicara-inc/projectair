"""End-to-end integration: raw HL7v2 -> capture -> verified chain (Task 15)."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from _helpers import requires_vendor_key
from airsdk.agdr import load_chain, verify_chain
from airsdk.recorder import AIRRecorder
from airsdk.types import VerificationStatus
from airsdk_pro.hl7.capture import HL7_FHIR_FEATURE
from airsdk_pro.hl7.redaction import PHIMode, RedactionPolicy
from airsdk_pro.license import install_license, load_license

SAMPLE_ORU_R01 = (
    "MSH|^~\\&|LAB|HOSP-MAIN|AI-AGENT|VINDICARA|20260511120000||ORU^R01|MSG001|P|2.5\r"
    "PID|1||MRN-0042^^^HOSP-MAIN^MR~123-45-6789^^^SSA^SS||DOE^JANE||19850315|F\r"
    "OBR|1|ORD001|FIL001|14749-6^HbA1c^LN|||20260511\r"
    "OBX|1|NM|14749-6^HbA1c^LN||8.4|%|<7.0|H|||F\r"
)


@requires_vendor_key
def test_full_capture_to_verified_chain(
    licensed: Path,
    recorder: AIRRecorder,
) -> None:
    """instrument_hl7 -> load_chain -> verify_chain == OK, FHIR present, MRN hashed."""
    from airsdk_pro.hl7.capture import instrument_hl7

    start, _end = instrument_hl7(recorder, SAMPLE_ORU_R01, map_fhir=True)

    records = load_chain(recorder.log_path)
    result = verify_chain(records)
    assert result.status == VerificationStatus.OK

    # FHIR resources present
    assert start.payload.fhir_resources is not None
    resource_types = {r.get("resourceType") for r in start.payload.fhir_resources}
    assert "Patient" in resource_types
    assert "Observation" in resource_types

    # MRN is hashed (64 hex chars), not the raw value
    assert start.payload.data_subjects is not None
    subject_id = start.payload.data_subjects[0].subject_id
    assert subject_id != "MRN-0042"
    assert len(subject_id) == 64
    assert all(c in "0123456789abcdef" for c in subject_id)

    # Raw MRN must not appear anywhere in the serialized payload
    payload_json = start.payload.model_dump_json()
    assert "MRN-0042" not in payload_json


@requires_vendor_key
def test_raw_mode_preserves_mrn(
    licensed: Path,
    recorder: AIRRecorder,
) -> None:
    """PHIMode.RAW -> MRN-0042 present in data_subjects.subject_id."""
    from airsdk_pro.hl7.capture import instrument_hl7

    raw_policy = RedactionPolicy(phi_mode=PHIMode.RAW)
    start, _end = instrument_hl7(recorder, SAMPLE_ORU_R01, redaction_policy=raw_policy)

    assert start.payload.data_subjects is not None
    subject_id = start.payload.data_subjects[0].subject_id
    assert subject_id == "MRN-0042"


@requires_vendor_key
def test_capture_chain_has_two_records(
    licensed: Path,
    recorder: AIRRecorder,
) -> None:
    """Each instrument_hl7 call produces exactly two records (tool_start + tool_end)."""
    from airsdk.types import StepKind
    from airsdk_pro.hl7.capture import instrument_hl7

    instrument_hl7(recorder, SAMPLE_ORU_R01)
    records = load_chain(recorder.log_path)
    assert len(records) == 2
    assert records[0].kind == StepKind.TOOL_START
    assert records[1].kind == StepKind.TOOL_END


@requires_vendor_key
def test_multiple_messages_verified_chain(
    licensed: Path,
    tmp_path: Path,
    issue_token: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Three HL7v2 messages -> 6 records, chain verifies."""
    token = issue_token(
        email="multi-msg@vindicara.io",
        tier="individual",
        features=(HL7_FHIR_FEATURE,),
    )
    lp = tmp_path / "license.json"
    install_license(token, path=lp)
    monkeypatch.setattr(
        "airsdk_pro.gate.load_license", lambda: load_license(lp)
    )

    from airsdk_pro.hl7.capture import instrument_hl7

    rec = AIRRecorder(log_path=tmp_path / "multi.jsonl")
    for i in range(3):
        msg = SAMPLE_ORU_R01.replace("MSG001", f"MSG{i:03d}")
        instrument_hl7(rec, msg)

    records = load_chain(rec.log_path)
    assert len(records) == 6
    result = verify_chain(records)
    assert result.status == VerificationStatus.OK
