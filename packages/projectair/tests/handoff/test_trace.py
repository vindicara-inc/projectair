"""W3C trace context tests (Section 5)."""
from __future__ import annotations

import pytest

from airsdk.handoff.exceptions import PTIDInvalidError, W3CTraceContextError
from airsdk.handoff.trace import (
    child_context,
    generate_ptid,
    new_root_context,
    parse_traceparent,
    reconcile_channels,
    validate_ptid,
)


def test_root_context_format() -> None:
    ctx = new_root_context()
    assert len(ctx.trace_id) == 32
    assert len(ctx.parent_id) == 16
    assert ctx.trace_id != "0" * 32
    assert ctx.parent_id != "0" * 16


def test_child_context_preserves_trace_id_generates_fresh_span() -> None:
    root = new_root_context()
    child = child_context(root)
    assert child.trace_id == root.trace_id
    assert child.parent_id != root.parent_id
    assert child.trace_flags == root.trace_flags


def test_traceparent_round_trip() -> None:
    s = "00-7f3a9b2c4d8e1f6a1234567890abcdef-00f067aa0ba902b7-01"
    ctx = parse_traceparent(s)
    assert ctx.to_traceparent() == s


@pytest.mark.parametrize(
    "bad",
    [
        "00-zzz-00f067aa0ba902b7-01",
        "00-" + "0" * 32 + "-00f067aa0ba902b7-01",
        "00-7f3a9b2c4d8e1f6a1234567890abcdef-" + "0" * 16 + "-01",
        "ff-7f3a9b2c4d8e1f6a1234567890abcdef-00f067aa0ba902b7-01",
        "no-dashes-here",
    ],
)
def test_malformed_traceparent_rejected(bad: str) -> None:
    with pytest.raises(W3CTraceContextError):
        parse_traceparent(bad)


@pytest.mark.parametrize(
    "bad", ["7F3A9B2C4D8E1F6A1234567890ABCDEF", "0" * 32, "short", "1" * 33]
)
def test_validate_ptid_rejects(bad: str) -> None:
    with pytest.raises(PTIDInvalidError):
        validate_ptid(bad)


def test_reconcile_channels_disagreement_fails_closed() -> None:
    with pytest.raises(W3CTraceContextError):
        reconcile_channels(
            jwt_air_ptid="7f3a9b2c4d8e1f6a1234567890abcdef",
            traceparent_value="00-" + "a" * 32 + "-00f067aa0ba902b7-01",
            air_parent_trace_id_header=None,
        )


def test_reconcile_channels_agreement_passes() -> None:
    ptid = "7f3a9b2c4d8e1f6a1234567890abcdef"
    tp = "00-" + ptid + "-00f067aa0ba902b7-01"
    ctx = reconcile_channels(
        jwt_air_ptid=ptid, traceparent_value=tp, air_parent_trace_id_header=None
    )
    assert ctx.trace_id == ptid


def test_ptid_uniqueness() -> None:
    seen = {generate_ptid() for _ in range(2000)}
    assert len(seen) == 2000
