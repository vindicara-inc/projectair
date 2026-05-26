"""Pydantic model validation and serialization tests for HL7v2 types (Task 16)."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from airsdk_pro.hl7.types import (
    FHIRPushResult,
    HL7v2Message,
    HL7v2ParseError,
    MSHSegment,
    OBXSegment,
    PatientIdentifier,
    SidecarResult,
)


# ---------------------------------------------------------------------------
# PatientIdentifier round-trip
# ---------------------------------------------------------------------------


def test_patient_identifier_round_trip() -> None:
    original = PatientIdentifier(
        value="MRN-0042",
        type_code="MR",
        assigning_authority="HOSP-MAIN",
    )
    dumped = original.model_dump()
    restored = PatientIdentifier.model_validate(dumped)
    assert restored.value == original.value
    assert restored.type_code == original.type_code
    assert restored.assigning_authority == original.assigning_authority


def test_patient_identifier_empty_assigning_authority() -> None:
    ident = PatientIdentifier(value="MRN-0001", type_code="MR")
    assert ident.assigning_authority == ""


def test_patient_identifier_extra_forbid() -> None:
    with pytest.raises(ValidationError):
        PatientIdentifier(
            value="MRN-0042",
            type_code="MR",
            unknown_field="should_fail",  # type: ignore[call-arg]
        )


# ---------------------------------------------------------------------------
# OBXSegment extra forbid
# ---------------------------------------------------------------------------


def test_obx_segment_extra_forbid() -> None:
    with pytest.raises(ValidationError):
        OBXSegment(
            set_id=1,
            value_type="NM",
            observation_id="TEST-1",
            extra_field="not_allowed",  # type: ignore[call-arg]
        )


def test_obx_segment_minimal() -> None:
    obx = OBXSegment(set_id=1, value_type="NM", observation_id="TEST-1")
    assert obx.value_numeric is None
    assert obx.value_string is None
    assert obx.units is None


def test_obx_segment_numeric_value() -> None:
    obx = OBXSegment(
        set_id=1,
        value_type="NM",
        observation_id="14749-6",
        value_numeric=8.4,
        units="%",
        observation_status="F",
    )
    assert obx.value_numeric == pytest.approx(8.4)
    assert obx.units == "%"
    assert obx.observation_status == "F"


# ---------------------------------------------------------------------------
# SidecarResult defaults
# ---------------------------------------------------------------------------


def test_sidecar_result_defaults() -> None:
    result = SidecarResult(message_type="ORU^R01")
    assert result.records_written == 0
    assert result.fhir_resource_types == []
    assert result.findings_count == 0
    assert result.siem_events_sent == 0
    assert result.fhir_push_success is None
    assert result.patient_mrn_hash is None
    assert result.patient_mrn is None


def test_sidecar_result_with_data() -> None:
    result = SidecarResult(
        message_type="ADT^A01",
        patient_mrn_hash="a" * 64,
        records_written=2,
        fhir_resource_types=["Patient"],
        findings_count=1,
        fhir_push_success=True,
    )
    assert result.message_type == "ADT^A01"
    assert result.patient_mrn_hash == "a" * 64
    assert result.records_written == 2
    assert "Patient" in result.fhir_resource_types


def test_sidecar_result_extra_forbid() -> None:
    with pytest.raises(ValidationError):
        SidecarResult(
            message_type="ORU^R01",
            unknown_field="oops",  # type: ignore[call-arg]
        )


# ---------------------------------------------------------------------------
# FHIRPushResult serialization round-trip
# ---------------------------------------------------------------------------


def test_fhir_push_result_serialization() -> None:
    original = FHIRPushResult(
        success=True,
        status_code=200,
        resources_created=2,
        resources_failed=0,
    )
    dumped = original.model_dump()
    restored = FHIRPushResult.model_validate(dumped)
    assert restored.success == original.success
    assert restored.status_code == original.status_code
    assert restored.resources_created == original.resources_created
    assert restored.error is None


def test_fhir_push_result_failure() -> None:
    result = FHIRPushResult(
        success=False,
        status_code=422,
        resources_created=0,
        resources_failed=1,
        error="Unprocessable Entity",
    )
    dumped = result.model_dump()
    assert dumped["success"] is False
    assert dumped["error"] == "Unprocessable Entity"
    restored = FHIRPushResult.model_validate(dumped)
    assert restored.error == "Unprocessable Entity"


def test_fhir_push_result_extra_forbid() -> None:
    with pytest.raises(ValidationError):
        FHIRPushResult(
            success=True,
            status_code=200,
            extra_field="not_allowed",  # type: ignore[call-arg]
        )


# ---------------------------------------------------------------------------
# HL7v2ParseError is an Exception
# ---------------------------------------------------------------------------


def test_hl7v2_parse_error_is_exception() -> None:
    with pytest.raises(HL7v2ParseError, match="test error"):
        raise HL7v2ParseError("test error")


# ---------------------------------------------------------------------------
# MSHSegment defaults
# ---------------------------------------------------------------------------


def test_msh_segment_defaults() -> None:
    msh = MSHSegment()
    assert msh.field_separator == "|"
    assert msh.encoding_characters == "^~\\&"
    assert msh.character_set == "ASCII"
    assert msh.sending_application == ""
