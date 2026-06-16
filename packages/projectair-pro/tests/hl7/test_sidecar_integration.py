"""Full sidecar pipeline integration tests (Task 15)."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from _helpers import requires_vendor_key
from airsdk.recorder import AIRRecorder
from airsdk_pro.hl7.capture import HL7_FHIR_FEATURE
from airsdk_pro.hl7.gateway import ClinicalSidecar
from airsdk_pro.license import install_license, load_license

SAMPLE_ORU = (
    "MSH|^~\\&|LAB|HOSP-MAIN|AI-AGENT|VINDICARA|20260511120000||ORU^R01|MSG001|P|2.5\r"
    "PID|1||MRN-0042^^^HOSP-MAIN^MR~123-45-6789^^^SSA^SS||DOE^JANE||19850315|F\r"
    "OBR|1|ORD001|FIL001|14749-6^HbA1c^LN|||20260511\r"
    "OBX|1|NM|14749-6^HbA1c^LN||8.4|%|<7.0|H|||F\r"
)


@requires_vendor_key
@pytest.mark.asyncio
async def test_sidecar_full_pipeline(
    licensed: Path,
    recorder: AIRRecorder,
) -> None:
    """ClinicalSidecar.process -> message_type, records, FHIR types, hashed MRN."""
    sidecar = ClinicalSidecar(recorder)
    result = await sidecar.process(SAMPLE_ORU)

    assert result.message_type == "ORU^R01"
    assert result.records_written == 2
    assert "Patient" in result.fhir_resource_types
    assert "Observation" in result.fhir_resource_types

    # MRN must be hashed, not raw
    assert result.patient_mrn_hash is not None
    assert result.patient_mrn_hash != "MRN-0042"
    assert len(result.patient_mrn_hash) == 64


@requires_vendor_key
@pytest.mark.asyncio
async def test_sidecar_dead_letter_on_malformed(
    licensed: Path,
    recorder: AIRRecorder,
) -> None:
    """Malformed input lands in dead-letter list, result has records_written=0."""
    sidecar = ClinicalSidecar(recorder)
    result = await sidecar.process("NOT-HL7-AT-ALL")

    assert result.message_type == "UNKNOWN"
    assert result.records_written == 0
    assert sidecar.dead_letter_count == 1


@requires_vendor_key
@pytest.mark.asyncio
async def test_sidecar_process_file(
    licensed: Path,
    recorder: AIRRecorder,
    tmp_path: Path,
) -> None:
    """process_file parses all messages from a file."""
    hl7_file = tmp_path / "messages.hl7"
    hl7_file.write_text(SAMPLE_ORU, encoding="utf-8")

    sidecar = ClinicalSidecar(recorder)
    results = await sidecar.process_file(hl7_file)

    assert len(results) == 1
    assert results[0].message_type == "ORU^R01"
    assert results[0].records_written == 2


@requires_vendor_key
def test_sidecar_requires_license(
    tmp_path: Path,
    issue_token: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ClinicalSidecar.__init__ raises without a valid Pro license."""
    from airsdk_pro.gate import LicenseMissingError

    # Patch load_license to return None (no license installed)
    monkeypatch.setattr("airsdk_pro.gate.load_license", lambda: None)

    rec = AIRRecorder(log_path=tmp_path / "chain.jsonl")
    with pytest.raises((LicenseMissingError, Exception)):
        ClinicalSidecar(rec)
