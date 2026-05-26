"""Tests for HL7v2 parser wrapper (Task 3)."""
from __future__ import annotations

import pytest

from airsdk_pro.hl7.parser import parse_hl7v2
from airsdk_pro.hl7.types import HL7v2ParseError

SAMPLE_ORU_R01 = (
    "MSH|^~\\&|LAB|HOSP-MAIN|AI-AGENT|VINDICARA|20260511120000||ORU^R01|MSG001|P|2.5\r"
    "PID|1||MRN-0042^^^HOSP-MAIN^MR~123-45-6789^^^SSA^SS||DOE^JANE||19850315|F\r"
    "OBR|1|ORD001|FIL001|14749-6^HbA1c^LN|||20260511\r"
    "OBX|1|NM|14749-6^HbA1c^LN||8.4|%|<7.0|H|||F\r"
    "OBX|2|NM|2345-7^Glucose^LN||186|mg/dL|74-106|H|||F\r"
    "OBX|3|ST|LOCAL001^Custom Test^LOCAL||Positive||||F\r"
)

SAMPLE_ADT_A01 = (
    "MSH|^~\\&|ADT|HOSP-MAIN|AI|VINDICARA|20260511||ADT^A01|MSG002|P|2.5\r"
    "PID|1||MRN-0042^^^HOSP-MAIN^MR||DOE^JANE||19850315|F\r"
    "PV1|1|I|5-EAST^501^A|||DR-CHEN^CHEN^SARAH\r"
)


def test_parse_oru_r01() -> None:
    msg = parse_hl7v2(SAMPLE_ORU_R01)
    assert msg.message_type == "ORU^R01"
    assert msg.sending_facility == "HOSP-MAIN"
    assert msg.message_control_id == "MSG001"
    assert msg.pid is not None
    assert msg.pid.primary_mrn == "MRN-0042"
    assert len(msg.pid.identifiers) == 2
    assert len(msg.obx) == 3


def test_parse_oru_r01_obx_types_and_values() -> None:
    msg = parse_hl7v2(SAMPLE_ORU_R01)
    nm1 = msg.obx[0]
    assert nm1.value_type == "NM"
    assert nm1.value_numeric == pytest.approx(8.4)
    assert nm1.units == "%"

    nm2 = msg.obx[1]
    assert nm2.value_type == "NM"
    assert nm2.value_numeric == pytest.approx(186.0)

    st1 = msg.obx[2]
    assert st1.value_type == "ST"
    assert st1.value_string == "Positive"


def test_parse_adt_a01() -> None:
    msg = parse_hl7v2(SAMPLE_ADT_A01)
    assert msg.message_type == "ADT^A01"
    assert msg.pv1 is not None
    assert msg.pv1.patient_class == "I"


def test_parse_multiple_pid_identifiers() -> None:
    msg = parse_hl7v2(SAMPLE_ORU_R01)
    assert msg.pid is not None
    ids = msg.pid.identifiers
    assert len(ids) == 2

    mr = next(i for i in ids if i.type_code == "MR")
    assert mr.value == "MRN-0042"
    assert mr.assigning_authority == "HOSP-MAIN"

    ss = next(i for i in ids if i.type_code == "SS")
    assert ss.value == "123-45-6789"
    assert ss.assigning_authority == "SSA"


def test_parse_obx_code_system_local() -> None:
    msg = parse_hl7v2(SAMPLE_ORU_R01)
    local_obx = msg.obx[2]
    assert local_obx.observation_id == "LOCAL001"
    assert local_obx.observation_id_system == "LOCAL"
    assert local_obx.observation_id_text == "Custom Test"


def test_parse_z_segments_preserved() -> None:
    raw = (
        "MSH|^~\\&|ADT|HOSP-MAIN|AI|VINDICARA|20260511||ADT^A01|MSG003|P|2.5\r"
        "PID|1||MRN-0001^^^HOSP-MAIN^MR||SMITH^JOHN||19700101|M\r"
        "ZPD|CONSENT|SIGNED|20260510\r"
    )
    msg = parse_hl7v2(raw)
    assert "ZPD" in msg.z_segments
    zpd_rows = msg.z_segments["ZPD"]
    assert len(zpd_rows) == 1
    fields = zpd_rows[0]
    assert "CONSENT" in fields
    assert "SIGNED" in fields


def test_parse_variable_precision_timestamp_second() -> None:
    # 14-char timestamp: second precision
    raw = (
        "MSH|^~\\&|ADT|HOSP-MAIN|AI|VINDICARA|20260511120000||ADT^A01|MSG004|P|2.5\r"
        "PID|1||MRN-0001^^^HOSP-MAIN^MR\r"
    )
    msg = parse_hl7v2(raw)
    assert msg.timestamp_precision == "second"
    assert msg.timestamp.startswith("2026-05-11T12:00:00")


def test_parse_variable_precision_timestamp_day() -> None:
    # 8-char timestamp: day precision
    raw = (
        "MSH|^~\\&|ADT|HOSP-MAIN|AI|VINDICARA|20260511||ADT^A01|MSG005|P|2.5\r"
        "PID|1||MRN-0001^^^HOSP-MAIN^MR\r"
    )
    msg = parse_hl7v2(raw)
    assert msg.timestamp_precision == "day"
    assert msg.timestamp == "2026-05-11"


def test_parse_variable_precision_timestamp_millisecond() -> None:
    # 18-char timestamp: millisecond precision
    raw = (
        "MSH|^~\\&|ADT|HOSP-MAIN|AI|VINDICARA|20260511120000.000||ADT^A01|MSG006|P|2.5\r"
        "PID|1||MRN-0001^^^HOSP-MAIN^MR\r"
    )
    msg = parse_hl7v2(raw)
    assert msg.timestamp_precision == "millisecond"
    assert "." in msg.timestamp


def test_parse_malformed_raises() -> None:
    with pytest.raises(HL7v2ParseError):
        parse_hl7v2("THIS IS NOT HL7")


def test_parse_missing_msh_raises() -> None:
    with pytest.raises(HL7v2ParseError, match="MSH"):
        parse_hl7v2("PID|1||MRN-0001\r")


def test_parse_obx_observation_id_code() -> None:
    msg = parse_hl7v2(SAMPLE_ORU_R01)
    obx0 = msg.obx[0]
    assert obx0.observation_id == "14749-6"
    assert obx0.observation_id_text == "HbA1c"
    assert obx0.observation_id_system == "LN"


def test_parse_pid_family_given_name() -> None:
    msg = parse_hl7v2(SAMPLE_ORU_R01)
    assert msg.pid is not None
    assert msg.pid.family_name == "DOE"
    assert msg.pid.given_name == "JANE"


def test_parse_obx_set_id() -> None:
    msg = parse_hl7v2(SAMPLE_ORU_R01)
    assert msg.obx[0].set_id == 1
    assert msg.obx[1].set_id == 2
    assert msg.obx[2].set_id == 3


def test_parse_msh_fields() -> None:
    msg = parse_hl7v2(SAMPLE_ORU_R01)
    msh = msg.msh
    assert msh.sending_application == "LAB"
    assert msh.sending_facility == "HOSP-MAIN"
    assert msh.receiving_application == "AI-AGENT"
    assert msh.receiving_facility == "VINDICARA"
    assert msh.version_id == "2.5"


def test_parse_multiple_z_segments_same_type() -> None:
    raw = (
        "MSH|^~\\&|ADT|HOSP-MAIN|AI|VINDICARA|20260511||ADT^A01|MSG007|P|2.5\r"
        "PID|1||MRN-0001^^^HOSP-MAIN^MR\r"
        "ZPD|CONSENT|SIGNED|20260510\r"
        "ZPD|ALLERGIES|PENICILLIN|CONFIRMED\r"
    )
    msg = parse_hl7v2(raw)
    assert "ZPD" in msg.z_segments
    assert len(msg.z_segments["ZPD"]) == 2
