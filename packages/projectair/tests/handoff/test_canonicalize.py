"""Tests for RFC 8785 JCS canonicalization (Section 15.11)."""
from __future__ import annotations

import datetime as _dt
from decimal import Decimal
from enum import StrEnum

import pytest

from airsdk.handoff.canonicalize import (
    canonicalize_and_hash,
    canonicalize_bytes,
    hash_bytes,
)
from airsdk.handoff.exceptions import CanonicalizationError

# Reference values locked in Section 6.6.
_REF_NULL = "blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"


class _Color(StrEnum):
    R = "red"


def test_jcs_key_order_canonicalization() -> None:
    a = {"b": 1, "a": 2, "c": {"y": True, "x": None}}
    b = {"a": 2, "c": {"x": None, "y": True}, "b": 1}
    assert canonicalize_and_hash(a) == canonicalize_and_hash(b)


def test_jcs_number_format_collapses_floats() -> None:
    # JCS shortest round-trip: 1.0 -> 1
    assert canonicalize_bytes({"d": 1.0}) == b'{"d":1}'


def test_empty_payload_no_payload_convention() -> None:
    assert canonicalize_and_hash(None) == _REF_NULL


def test_empty_payload_three_variants_are_distinct() -> None:
    no_payload = canonicalize_and_hash(None)
    empty_obj = canonicalize_and_hash({})
    empty_arr = canonicalize_and_hash([])
    assert no_payload != empty_obj
    assert no_payload != empty_arr
    assert empty_obj != empty_arr


def test_strict_input_rejects_datetime() -> None:
    with pytest.raises(CanonicalizationError, match="datetime"):
        canonicalize_and_hash({"when": _dt.datetime.now()})


def test_strict_input_rejects_bytes() -> None:
    with pytest.raises(CanonicalizationError, match="bytes"):
        canonicalize_and_hash({"k": b"\x00"})


def test_strict_input_rejects_decimal() -> None:
    with pytest.raises(CanonicalizationError, match="Decimal"):
        canonicalize_and_hash({"x": Decimal("1.5")})


def test_strict_input_rejects_enum_value() -> None:
    with pytest.raises(CanonicalizationError):
        canonicalize_and_hash({"c": _Color.R.__class__})


def test_strict_input_rejects_tuple() -> None:
    with pytest.raises(CanonicalizationError, match="tuple"):
        canonicalize_and_hash({"t": (1, 2)})


def test_strict_input_rejects_non_string_key_with_bool_label() -> None:
    # Per the strict policy, bool is checked before int so the diagnostic
    # is precise instead of saying 'int' for True/False.
    with pytest.raises(CanonicalizationError, match="bool"):
        canonicalize_and_hash({True: "x"})


def test_jsonpath_diagnostic_points_at_offending_field() -> None:
    with pytest.raises(CanonicalizationError, match=r"\$\.outer\.inner"):
        canonicalize_and_hash({"outer": {"inner": b"raw"}})


def test_hash_bytes_matches_blake3() -> None:
    out = hash_bytes(b"")
    assert out == _REF_NULL


def test_unicode_is_preserved() -> None:
    a = canonicalize_and_hash({"k": "café"})
    b = canonicalize_and_hash({"k": "café"})
    assert a == b
