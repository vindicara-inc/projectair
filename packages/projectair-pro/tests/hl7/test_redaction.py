"""Tests for airsdk_pro.hl7.redaction PHI redaction policy."""
from __future__ import annotations

import pytest

from airsdk_pro.hl7.redaction import (
    PHI_CLASS_FIELDS,
    PHIMode,
    RedactionPolicy,
    redact_dob,
    redact_identifier,
    redact_mcid,
)


# ---------------------------------------------------------------------------
# RedactionPolicy construction
# ---------------------------------------------------------------------------


class TestRedactionPolicyConstruction:
    def test_default_mode_is_redacted_with_baa(self) -> None:
        policy = RedactionPolicy(baa_acknowledged=True)
        assert policy.phi_mode == PHIMode.REDACTED
        assert policy.baa_acknowledged is True
        assert policy.allowed_fields == []

    def test_baa_false_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="baa_acknowledged must be True"):
            RedactionPolicy(baa_acknowledged=False)

    def test_baa_false_with_raw_mode_still_raises(self) -> None:
        with pytest.raises(ValueError, match="baa_acknowledged must be True"):
            RedactionPolicy(baa_acknowledged=False, phi_mode=PHIMode.RAW)

    def test_raw_mode_with_baa_succeeds(self) -> None:
        policy = RedactionPolicy(baa_acknowledged=True, phi_mode=PHIMode.RAW)
        assert policy.phi_mode == PHIMode.RAW

    def test_extra_fields_forbidden(self) -> None:
        with pytest.raises(Exception):  # pydantic ValidationError
            RedactionPolicy(baa_acknowledged=True, unknown_field="x")  # type: ignore[call-arg]

    def test_phi_fields_blocked_in_redacted_allowed_fields(self) -> None:
        with pytest.raises(ValueError, match="allowed_fields contains PHI-class fields"):
            RedactionPolicy(
                baa_acknowledged=True,
                phi_mode=PHIMode.REDACTED,
                allowed_fields=["mrn", "study_id"],
            )

    def test_phi_fields_blocked_lists_offenders(self) -> None:
        with pytest.raises(ValueError, match="mrn"):
            RedactionPolicy(
                baa_acknowledged=True,
                phi_mode=PHIMode.REDACTED,
                allowed_fields=["mrn"],
            )

    def test_non_phi_fields_allowed_in_redacted_mode(self) -> None:
        policy = RedactionPolicy(
            baa_acknowledged=True,
            phi_mode=PHIMode.REDACTED,
            allowed_fields=["study_id", "accession_number_hash"],
        )
        assert "study_id" in policy.allowed_fields

    def test_phi_fields_allowed_in_raw_mode(self) -> None:
        # In RAW mode the allowed_fields check is skipped for PHI fields
        # because the operator has explicitly opted in with phi_mode=RAW.
        policy = RedactionPolicy(
            baa_acknowledged=True,
            phi_mode=PHIMode.RAW,
            allowed_fields=["mrn", "family_name"],
        )
        assert "mrn" in policy.allowed_fields

    def test_phi_class_fields_is_frozenset(self) -> None:
        assert isinstance(PHI_CLASS_FIELDS, frozenset)
        assert "mrn" in PHI_CLASS_FIELDS
        assert "family_name" in PHI_CLASS_FIELDS
        assert "date_of_birth" in PHI_CLASS_FIELDS


# ---------------------------------------------------------------------------
# redact_identifier
# ---------------------------------------------------------------------------


class TestRedactIdentifier:
    def test_redacted_mode_returns_keyed_blake3_hex(self) -> None:
        import blake3 as _blake3

        policy = RedactionPolicy(baa_acknowledged=True, phi_mode=PHIMode.REDACTED)
        result = redact_identifier("MRN12345", policy)
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)
        # Keyed MAC, not a bare hash: must differ from the unsalted digest so a
        # short identifier cannot be brute-forced back out of the published value.
        unsalted = _blake3.blake3(b"MRN12345").hexdigest()
        assert result != unsalted

    def test_redacted_mode_is_deterministic(self) -> None:
        policy = RedactionPolicy(baa_acknowledged=True, phi_mode=PHIMode.REDACTED)
        assert redact_identifier("X", policy) == redact_identifier("X", policy)

    def test_redacted_mode_different_inputs_differ(self) -> None:
        policy = RedactionPolicy(baa_acknowledged=True, phi_mode=PHIMode.REDACTED)
        assert redact_identifier("A", policy) != redact_identifier("B", policy)

    def test_raw_mode_preserves_value(self) -> None:
        policy = RedactionPolicy(baa_acknowledged=True, phi_mode=PHIMode.RAW)
        assert redact_identifier("MRN12345", policy) == "MRN12345"

    def test_empty_string_redacted(self) -> None:
        import blake3 as _blake3

        policy = RedactionPolicy(baa_acknowledged=True, phi_mode=PHIMode.REDACTED)
        result = redact_identifier("", policy)
        assert len(result) == 64
        assert result != _blake3.blake3(b"").hexdigest()

    def test_empty_string_raw(self) -> None:
        policy = RedactionPolicy(baa_acknowledged=True, phi_mode=PHIMode.RAW)
        assert redact_identifier("", policy) == ""


# ---------------------------------------------------------------------------
# redact_dob
# ---------------------------------------------------------------------------


class TestRedactDob:
    def test_truncates_to_year_in_redacted_mode(self) -> None:
        policy = RedactionPolicy(baa_acknowledged=True, phi_mode=PHIMode.REDACTED)
        assert redact_dob("19800315", policy) == "1980"

    def test_hl7_datetime_format_truncated(self) -> None:
        policy = RedactionPolicy(baa_acknowledged=True, phi_mode=PHIMode.REDACTED)
        assert redact_dob("19651201120000", policy) == "1965"

    def test_90_plus_rule(self) -> None:
        from datetime import date

        policy = RedactionPolicy(baa_acknowledged=True, phi_mode=PHIMode.REDACTED)
        ninety_plus_year = str(date.today().year - 91)
        assert redact_dob(ninety_plus_year + "0101", policy) == "90+"

    def test_exactly_90_returns_90_plus(self) -> None:
        from datetime import date

        policy = RedactionPolicy(baa_acknowledged=True, phi_mode=PHIMode.REDACTED)
        exactly_90_year = str(date.today().year - 90)
        assert redact_dob(exactly_90_year + "0101", policy) == "90+"

    def test_89_years_old_returns_year(self) -> None:
        from datetime import date

        policy = RedactionPolicy(baa_acknowledged=True, phi_mode=PHIMode.REDACTED)
        year = str(date.today().year - 89)
        assert redact_dob(year + "0101", policy) == year

    def test_raw_mode_preserves_full_dob(self) -> None:
        policy = RedactionPolicy(baa_acknowledged=True, phi_mode=PHIMode.RAW)
        assert redact_dob("19800315", policy) == "19800315"

    def test_empty_string_returns_empty(self) -> None:
        policy = RedactionPolicy(baa_acknowledged=True, phi_mode=PHIMode.REDACTED)
        assert redact_dob("", policy) == ""

    def test_invalid_year_returns_empty(self) -> None:
        policy = RedactionPolicy(baa_acknowledged=True, phi_mode=PHIMode.REDACTED)
        assert redact_dob("XXXX0101", policy) == ""

    def test_short_string_too_short_for_year_returns_90_plus(self) -> None:
        # "198" parses to year 198 AD; current_year - 198 >= 90, so 90+.
        # The try/except only catches non-numeric input.
        policy = RedactionPolicy(baa_acknowledged=True, phi_mode=PHIMode.REDACTED)
        assert redact_dob("198", policy) == "90+"


# ---------------------------------------------------------------------------
# redact_mcid
# ---------------------------------------------------------------------------


class TestRedactMcid:
    def test_strips_8_digit_date_sequence(self) -> None:
        assert redact_mcid("MSG20250525001") == "MSGXXXXXXXX001"

    def test_no_date_in_mcid_unchanged(self) -> None:
        assert redact_mcid("MSGABC001") == "MSGABC001"

    def test_multiple_date_sequences_stripped(self) -> None:
        assert redact_mcid("20250525_20250524") == "XXXXXXXX_XXXXXXXX"

    def test_empty_string_unchanged(self) -> None:
        assert redact_mcid("") == ""

    def test_7_digit_sequence_not_stripped(self) -> None:
        # Only exactly 8 consecutive digits should be stripped
        assert redact_mcid("MSG2025052") == "MSG2025052"

    def test_9_digit_sequence_not_fully_stripped(self) -> None:
        # re.sub replaces each non-overlapping 8-digit match; a 9-digit
        # run contains one 8-digit match at the start.
        result = redact_mcid("MSG202505250")
        # The first 8 digits become XXXXXXXX, leaving the trailing digit.
        assert result == "MSGXXXXXXXX0"

    def test_unconditional_no_policy_param(self) -> None:
        # redact_mcid takes no policy param; call site never passes one.
        result = redact_mcid("CTRL20260101XY")
        assert result == "CTRLXXXXXXXXXY"
