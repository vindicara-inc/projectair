"""Tests for all OBX-2 value types and code system normalization (Task 16)."""
from __future__ import annotations

import pytest

from airsdk_pro.hl7.parser import parse_hl7v2


def _make_obx_message(value_type: str, value: str, code_system: str = "LN") -> str:
    return (
        "MSH|^~\\&|LAB|HOSP|AI|V|20260511||ORU^R01|M1|P|2.5\r"
        "PID|1||MRN-0042^^^HOSP^MR||DOE^JANE||19850315|F\r"
        f"OBX|1|{value_type}|TEST-1^Test^{code_system}||{value}|units|||F\r"
    )


# ---------------------------------------------------------------------------
# NM: numeric
# ---------------------------------------------------------------------------


def test_obx_nm_value_numeric() -> None:
    msg = parse_hl7v2(_make_obx_message("NM", "8.4"))
    assert msg.obx[0].value_type == "NM"
    assert msg.obx[0].value_numeric == pytest.approx(8.4)
    assert msg.obx[0].value_string is None


def test_obx_nm_integer_value() -> None:
    msg = parse_hl7v2(_make_obx_message("NM", "186"))
    assert msg.obx[0].value_numeric == pytest.approx(186.0)


# ---------------------------------------------------------------------------
# ST: string
# ---------------------------------------------------------------------------


def test_obx_st_value_string() -> None:
    msg = parse_hl7v2(_make_obx_message("ST", "Positive"))
    assert msg.obx[0].value_type == "ST"
    assert msg.obx[0].value_string == "Positive"
    assert msg.obx[0].value_numeric is None


# ---------------------------------------------------------------------------
# TX: text data
# ---------------------------------------------------------------------------


def test_obx_tx_value_string() -> None:
    msg = parse_hl7v2(_make_obx_message("TX", "Free text note"))
    assert msg.obx[0].value_type == "TX"
    assert msg.obx[0].value_string == "Free text note"


# ---------------------------------------------------------------------------
# FT: formatted text
# ---------------------------------------------------------------------------


def test_obx_ft_value_string() -> None:
    msg = parse_hl7v2(_make_obx_message("FT", "Formatted note"))
    assert msg.obx[0].value_type == "FT"
    assert msg.obx[0].value_string == "Formatted note"


# ---------------------------------------------------------------------------
# SN: structured numeric (e.g. ">8.4")
# ---------------------------------------------------------------------------


def test_obx_sn_value_numeric() -> None:
    msg = parse_hl7v2(_make_obx_message("SN", ">8.4"))
    assert msg.obx[0].value_type == "SN"
    # SN strips comparison operator, stores as numeric when parseable
    assert msg.obx[0].value_numeric == pytest.approx(8.4)


def test_obx_sn_equals_value() -> None:
    msg = parse_hl7v2(_make_obx_message("SN", "=100"))
    assert msg.obx[0].value_numeric == pytest.approx(100.0)


# ---------------------------------------------------------------------------
# DT: date
# ---------------------------------------------------------------------------


def test_obx_dt_value_datetime() -> None:
    msg = parse_hl7v2(_make_obx_message("DT", "20260511"))
    assert msg.obx[0].value_type == "DT"
    assert msg.obx[0].value_datetime is not None
    assert "20260511" in msg.obx[0].value_datetime


# ---------------------------------------------------------------------------
# TS: timestamp
# ---------------------------------------------------------------------------


def test_obx_ts_value_datetime() -> None:
    msg = parse_hl7v2(_make_obx_message("TS", "20260511120000"))
    assert msg.obx[0].value_type == "TS"
    assert msg.obx[0].value_datetime is not None
    assert "20260511120000" in msg.obx[0].value_datetime


# ---------------------------------------------------------------------------
# CWE: coded with exceptions
# ---------------------------------------------------------------------------


def test_obx_cwe_coded_fields() -> None:
    # CWE value format: code^text^code_system
    msg = parse_hl7v2(_make_obx_message("CWE", "HbA1c^Hemoglobin A1c^SCT"))
    obx = msg.obx[0]
    assert obx.value_type == "CWE"
    assert obx.value_coded == "HbA1c"
    assert obx.value_coded_text == "Hemoglobin A1c"
    assert obx.value_coded_system == "SCT"
    assert obx.value_numeric is None
    assert obx.value_string is None


# ---------------------------------------------------------------------------
# Code system normalization
# ---------------------------------------------------------------------------


def test_code_system_loinc() -> None:
    from airsdk_pro.hl7.fhir import normalize_code_system

    assert normalize_code_system("LN") == "http://loinc.org"


def test_code_system_snomed() -> None:
    from airsdk_pro.hl7.fhir import normalize_code_system

    assert normalize_code_system("SCT") == "http://snomed.info/sct"


def test_code_system_local() -> None:
    from airsdk_pro.hl7.fhir import normalize_code_system

    result = normalize_code_system("LOCAL")
    # LOCAL systems are returned unchanged or flagged as local
    assert result is not None
    assert isinstance(result, str)


def test_obx_observation_id_system_loinc() -> None:
    msg = parse_hl7v2(_make_obx_message("NM", "8.4", code_system="LN"))
    assert msg.obx[0].observation_id_system == "LN"


def test_obx_observation_id_system_sct() -> None:
    msg = parse_hl7v2(_make_obx_message("NM", "8.4", code_system="SCT"))
    assert msg.obx[0].observation_id_system == "SCT"


def test_obx_set_id_assigned() -> None:
    msg = parse_hl7v2(_make_obx_message("NM", "42"))
    assert msg.obx[0].set_id == 1


def test_obx_units_captured() -> None:
    msg = parse_hl7v2(_make_obx_message("NM", "8.4"))
    assert msg.obx[0].units == "units"


def test_obx_observation_status_captured() -> None:
    # OBX-11 is observation_status. Fields: set_id|type|obs_id|sub_id|value|units
    #   |ref_range|abn_flags|probability|nature_of_abn|status
    raw = (
        "MSH|^~\\&|LAB|HOSP|AI|V|20260511||ORU^R01|M1|P|2.5\r"
        "PID|1||MRN-0042^^^HOSP^MR||DOE^JANE||19850315|F\r"
        "OBX|1|NM|TEST-1^Test^LN||8.4|units|<10|H|||F\r"
    )
    msg = parse_hl7v2(raw)
    assert msg.obx[0].observation_status == "F"
