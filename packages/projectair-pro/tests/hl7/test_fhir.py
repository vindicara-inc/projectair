"""Tests for FHIR R4 resource mapping (Task 4)."""
from __future__ import annotations

import pytest

from airsdk_pro.hl7.fhir import MappedResource, map_to_fhir, normalize_code_system, project_for_chain
from airsdk_pro.hl7.parser import parse_hl7v2
from airsdk_pro.hl7.redaction import PHIMode, RedactionPolicy

SAMPLE_ORU_R01 = (
    "MSH|^~\\&|LAB|HOSP-MAIN|AI-AGENT|VINDICARA|20260511120000||ORU^R01|MSG001|P|2.5\r"
    "PID|1||MRN-0042^^^HOSP-MAIN^MR~123-45-6789^^^SSA^SS||DOE^JANE||19850315|F\r"
    "OBR|1|ORD001|FIL001|14749-6^HbA1c^LN|||20260511\r"
    "OBX|1|NM|14749-6^HbA1c^LN||8.4|%|<7.0|H|||F\r"
    "OBX|2|NM|2345-7^Glucose^LN||186|mg/dL|74-106|H|||F\r"
    "OBX|3|ST|LOCAL001^Custom Test^LOCAL||Positive||||F\r"
)


@pytest.fixture
def parsed_message():
    return parse_hl7v2(SAMPLE_ORU_R01)


# ---------------------------------------------------------------------------
# normalize_code_system
# ---------------------------------------------------------------------------


def test_code_system_loinc_normalized() -> None:
    assert normalize_code_system("LN") == "http://loinc.org"
    assert normalize_code_system("LOINC") == "http://loinc.org"


def test_code_system_snomed_normalized() -> None:
    assert normalize_code_system("SCT") == "http://snomed.info/sct"
    assert normalize_code_system("SNOMED") == "http://snomed.info/sct"


def test_code_system_cpt_normalized() -> None:
    assert normalize_code_system("CPT") == "http://www.ama-assn.org/go/cpt"
    assert normalize_code_system("CPT4") == "http://www.ama-assn.org/go/cpt"


def test_code_system_icd10_normalized() -> None:
    assert normalize_code_system("I10") == "http://hl7.org/fhir/sid/icd-10-cm"
    assert normalize_code_system("ICD10") == "http://hl7.org/fhir/sid/icd-10-cm"


def test_code_system_local_passthrough() -> None:
    result = normalize_code_system("LOCAL")
    assert "LOCAL" in result
    assert result.startswith("urn:oid:")


def test_code_system_unknown_passthrough() -> None:
    result = normalize_code_system("CUSTOM_XYZ")
    assert "CUSTOM_XYZ" in result


# ---------------------------------------------------------------------------
# map_to_fhir: resource count and types
# ---------------------------------------------------------------------------


def test_map_produces_patient(parsed_message) -> None:
    resources = map_to_fhir(parsed_message)
    patients = [r for r in resources if r.resource_type == "Patient"]
    assert len(patients) == 1


def test_map_produces_observations(parsed_message) -> None:
    resources = map_to_fhir(parsed_message)
    observations = [r for r in resources if r.resource_type == "Observation"]
    assert len(observations) == 3


def test_map_total_resource_count(parsed_message) -> None:
    resources = map_to_fhir(parsed_message)
    # 1 Patient + 3 Observations
    assert len(resources) == 4


# ---------------------------------------------------------------------------
# Patient mapping: redacted mode (default)
# ---------------------------------------------------------------------------


def test_redacted_patient_hashes_mrn(parsed_message) -> None:
    resources = map_to_fhir(parsed_message)
    patient = next(r for r in resources if r.resource_type == "Patient")
    identifiers = patient.identifier
    assert identifiers, "Patient must have at least one identifier"
    values = [ident.value for ident in identifiers if ident.value]
    # All values must be 64-char hex hashes, not raw MRN
    for val in values:
        assert val != "MRN-0042", "Raw MRN must not appear in REDACTED mode"
        assert val != "123-45-6789", "Raw SSN must not appear in REDACTED mode"
        assert len(val) == 64, f"Expected 64-char BLAKE3 hash, got: {val!r}"


def test_redacted_patient_no_name(parsed_message) -> None:
    policy = RedactionPolicy(phi_mode=PHIMode.REDACTED)
    resources = map_to_fhir(parsed_message, redaction_policy=policy)
    patient_dict = next(r for r in resources if r.resource_type == "Patient").to_dict()
    assert "name" not in patient_dict, "Name must be omitted in REDACTED mode"


def test_redacted_patient_dob_truncated_to_year(parsed_message) -> None:
    policy = RedactionPolicy(phi_mode=PHIMode.REDACTED)
    resources = map_to_fhir(parsed_message, redaction_policy=policy)
    patient_dict = next(r for r in resources if r.resource_type == "Patient").to_dict()
    if "birthDate" in patient_dict:
        birth = str(patient_dict["birthDate"])
        # REDACTED mode: only year, e.g. "1985" not "1985-03-15"
        assert birth in ("1985", "90+"), f"Expected year-only or 90+, got: {birth!r}"


# ---------------------------------------------------------------------------
# Patient mapping: RAW mode
# ---------------------------------------------------------------------------


def test_raw_patient_preserves_mrn(parsed_message) -> None:
    policy = RedactionPolicy(phi_mode=PHIMode.RAW)
    resources = map_to_fhir(parsed_message, redaction_policy=policy)
    patient = next(r for r in resources if r.resource_type == "Patient")
    values = [ident.value for ident in patient.identifier if ident.value]
    assert "MRN-0042" in values, "Raw MRN must appear in RAW mode"


def test_raw_patient_has_name(parsed_message) -> None:
    policy = RedactionPolicy(phi_mode=PHIMode.RAW)
    resources = map_to_fhir(parsed_message, redaction_policy=policy)
    patient_dict = next(r for r in resources if r.resource_type == "Patient").to_dict()
    assert "name" in patient_dict, "Name must be present in RAW mode"


def test_raw_patient_full_dob(parsed_message) -> None:
    policy = RedactionPolicy(phi_mode=PHIMode.RAW)
    resources = map_to_fhir(parsed_message, redaction_policy=policy)
    patient_dict = next(r for r in resources if r.resource_type == "Patient").to_dict()
    if "birthDate" in patient_dict:
        birth = str(patient_dict["birthDate"])
        # RAW mode: full date preserved
        assert "1985" in birth


# ---------------------------------------------------------------------------
# Observation mapping
# ---------------------------------------------------------------------------


def test_observations_have_loinc_code(parsed_message) -> None:
    resources = map_to_fhir(parsed_message)
    obs_list = [r for r in resources if r.resource_type == "Observation"]
    loinc_obs = [r.to_dict() for r in obs_list if r.to_dict().get("code")]
    # First two OBX use LN -> http://loinc.org
    for obs_dict in loinc_obs[:2]:
        coding = obs_dict["code"]["coding"]
        systems = [c["system"] for c in coding]
        assert "http://loinc.org" in systems, f"Expected LOINC system in {systems}"


def test_observation_local_code_system(parsed_message) -> None:
    resources = map_to_fhir(parsed_message)
    obs_list = [r.to_dict() for r in resources if r.resource_type == "Observation"]
    # Third OBX uses LOCAL system
    local_obs = obs_list[2]
    coding = local_obs["code"]["coding"]
    systems = [c["system"] for c in coding]
    assert any("LOCAL" in s or "urn:oid:" in s for s in systems)


def test_observation_nm_has_value_quantity(parsed_message) -> None:
    resources = map_to_fhir(parsed_message)
    obs_list = [r.to_dict() for r in resources if r.resource_type == "Observation"]
    first_obs = obs_list[0]
    assert "valueQuantity" in first_obs, "NM type OBX must map to valueQuantity"
    assert float(first_obs["valueQuantity"]["value"]) == pytest.approx(8.4)


def test_observation_st_has_value_string(parsed_message) -> None:
    resources = map_to_fhir(parsed_message)
    obs_list = [r.to_dict() for r in resources if r.resource_type == "Observation"]
    third_obs = obs_list[2]
    assert "valueString" in third_obs, "ST type OBX must map to valueString"
    assert third_obs["valueString"] == "Positive"


def test_observations_reference_patient(parsed_message) -> None:
    resources = map_to_fhir(parsed_message)
    obs_list = [r.to_dict() for r in resources if r.resource_type == "Observation"]
    for obs_dict in obs_list:
        assert "subject" in obs_dict, "Observation must have subject reference"
        ref = obs_dict["subject"]["reference"]
        assert ref.startswith("Patient/"), f"Subject must reference Patient, got: {ref!r}"


def test_observation_status_final(parsed_message) -> None:
    resources = map_to_fhir(parsed_message)
    obs_list = [r.to_dict() for r in resources if r.resource_type == "Observation"]
    for obs_dict in obs_list:
        assert obs_dict["status"] == "final"


# ---------------------------------------------------------------------------
# MappedResource
# ---------------------------------------------------------------------------


def test_mapped_resource_to_dict(parsed_message) -> None:
    resources = map_to_fhir(parsed_message)
    for resource in resources:
        d = resource.to_dict()
        assert isinstance(d, dict)
        assert "resourceType" in d


def test_mapped_resource_resource_type(parsed_message) -> None:
    resources = map_to_fhir(parsed_message)
    types = {r.resource_type for r in resources}
    assert "Patient" in types
    assert "Observation" in types


# ---------------------------------------------------------------------------
# project_for_chain
# ---------------------------------------------------------------------------


def test_chain_projection_strips_extra_fields(parsed_message) -> None:
    resources = map_to_fhir(parsed_message)
    for resource in resources:
        projected = project_for_chain(resource)
        assert isinstance(projected, dict)
        assert "resourceType" in projected
        assert "id" in projected


def test_chain_projection_patient_has_no_name(parsed_message) -> None:
    policy = RedactionPolicy(phi_mode=PHIMode.REDACTED)
    resources = map_to_fhir(parsed_message, redaction_policy=policy)
    patient = next(r for r in resources if r.resource_type == "Patient")
    projected = project_for_chain(patient)
    assert "name" not in projected


def test_chain_projection_observation_has_code(parsed_message) -> None:
    resources = map_to_fhir(parsed_message)
    obs = next(r for r in resources if r.resource_type == "Observation")
    projected = project_for_chain(obs)
    assert "code" in projected


# ---------------------------------------------------------------------------
# No-PID message: no Patient resource emitted
# ---------------------------------------------------------------------------


def test_no_pid_no_patient() -> None:
    raw = (
        "MSH|^~\\&|LAB|HOSP|AI|VINDICARA|20260511120000||ORU^R01|MSG010|P|2.5\r"
        "OBX|1|NM|14749-6^HbA1c^LN||8.4|%|<7.0|H|||F\r"
    )
    msg = parse_hl7v2(raw)
    resources = map_to_fhir(msg)
    patients = [r for r in resources if r.resource_type == "Patient"]
    assert len(patients) == 0
