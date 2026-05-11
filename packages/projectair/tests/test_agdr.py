"""AgDR signer + verifier round-trip and tamper-detection tests."""
from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from airsdk.agdr import Signer, filter_records_by_date_range, load_chain, verify_chain, verify_record
from airsdk.types import AgDRPayload, AgDRRecord, StepKind, VerificationStatus


@pytest.fixture
def signer() -> Signer:
    return Signer.generate()


def test_sign_produces_valid_record(signer: Signer) -> None:
    record = signer.sign(StepKind.LLM_START, AgDRPayload(prompt="hello"))
    assert record.kind == StepKind.LLM_START
    assert record.prev_hash == "0" * 64
    ok, reason = verify_record(record)
    assert ok, reason


def test_chain_links_records_in_order(signer: Signer) -> None:
    first = signer.sign(StepKind.LLM_START, AgDRPayload(prompt="hello"))
    second = signer.sign(StepKind.LLM_END, AgDRPayload(response="hi"))
    assert second.prev_hash == first.content_hash
    assert verify_chain([first, second]).status == VerificationStatus.OK


def test_chain_detects_payload_tamper(signer: Signer) -> None:
    first = signer.sign(StepKind.LLM_START, AgDRPayload(prompt="hello"))
    second = signer.sign(StepKind.LLM_END, AgDRPayload(response="hi"))

    # Edit the payload in-place. content_hash no longer matches.
    tampered = second.model_copy(update={"payload": AgDRPayload(response="goodbye")})

    result = verify_chain([first, tampered])
    assert result.status == VerificationStatus.TAMPERED
    assert result.failed_step_id == tampered.step_id


def test_chain_detects_broken_link() -> None:
    signer_a = Signer.generate()
    signer_b = Signer.generate()
    a = signer_a.sign(StepKind.LLM_START, AgDRPayload(prompt="hello"))
    b = signer_b.sign(StepKind.LLM_END, AgDRPayload(response="hi"))

    # b.prev_hash == "0"*64 because signer_b is fresh; it doesn't link to a.
    result = verify_chain([a, b])
    assert result.status == VerificationStatus.BROKEN_CHAIN
    assert result.failed_step_id == b.step_id


def test_load_chain_roundtrip(tmp_path: Path, signer: Signer) -> None:
    first = signer.sign(StepKind.LLM_START, AgDRPayload(prompt="hello"))
    second = signer.sign(StepKind.TOOL_START, AgDRPayload(tool_name="search", tool_args={"q": "pizza"}))

    log = tmp_path / "trace.log"
    log.write_text(
        first.model_dump_json(exclude_none=True) + "\n" + second.model_dump_json(exclude_none=True) + "\n"
    )

    loaded = load_chain(log)
    assert len(loaded) == 2
    assert loaded[0] == first
    assert loaded[1] == second
    assert verify_chain(loaded).status == VerificationStatus.OK


def test_load_chain_raises_on_malformed_line(tmp_path: Path) -> None:
    bad = tmp_path / "bad.log"
    bad.write_text("not-valid-json\n")
    with pytest.raises(ValueError, match="line 1"):
        load_chain(bad)


def test_step_id_is_uuidv7_timestamp_prefixed(signer: Signer) -> None:
    # UUIDv7 version nibble is 7. Character index 14 in an 8-4-4-4-12 layout is the version.
    record = signer.sign(StepKind.LLM_START, AgDRPayload(prompt="x"))
    assert record.step_id[14] == "7"


class TestFilterRecordsByDateRange:
    """Tests for filter_records_by_date_range."""

    @staticmethod
    def _make_record(signer: Signer, ts: str) -> AgDRRecord:
        rec = signer.sign(StepKind.LLM_START, AgDRPayload(prompt="x"))
        return rec.model_copy(update={"timestamp": ts})

    def test_no_bounds_returns_all(self, signer: Signer) -> None:
        records = [self._make_record(signer, "2026-05-07T12:00:00Z")]
        assert filter_records_by_date_range(records) is records

    def test_from_date_only(self, signer: Signer) -> None:
        r1 = self._make_record(signer, "2026-05-06T23:59:59Z")
        r2 = self._make_record(signer, "2026-05-07T00:00:00Z")
        r3 = self._make_record(signer, "2026-05-08T12:00:00Z")
        result = filter_records_by_date_range([r1, r2, r3], from_date=date(2026, 5, 7))
        assert len(result) == 2
        assert r1 not in result

    def test_to_date_only(self, signer: Signer) -> None:
        r1 = self._make_record(signer, "2026-05-07T12:00:00Z")
        r2 = self._make_record(signer, "2026-05-10T23:59:59Z")
        r3 = self._make_record(signer, "2026-05-11T00:00:01Z")
        result = filter_records_by_date_range([r1, r2, r3], to_date=date(2026, 5, 10))
        assert len(result) == 2
        assert r3 not in result

    def test_both_bounds_inclusive(self, signer: Signer) -> None:
        r1 = self._make_record(signer, "2026-05-06T12:00:00Z")
        r2 = self._make_record(signer, "2026-05-07T00:00:00Z")
        r3 = self._make_record(signer, "2026-05-09T15:30:00Z")
        r4 = self._make_record(signer, "2026-05-10T23:59:59Z")
        r5 = self._make_record(signer, "2026-05-11T00:00:00Z")
        result = filter_records_by_date_range(
            [r1, r2, r3, r4, r5], from_date=date(2026, 5, 7), to_date=date(2026, 5, 10),
        )
        assert len(result) == 3
        assert r1 not in result
        assert r5 not in result

    def test_malformed_timestamp_excluded(self, signer: Signer) -> None:
        good = self._make_record(signer, "2026-05-07T12:00:00Z")
        bad = self._make_record(signer, "not-a-date")
        result = filter_records_by_date_range([good, bad], from_date=date(2026, 5, 1))
        assert len(result) == 1

    def test_empty_records(self) -> None:
        assert filter_records_by_date_range([], from_date=date(2026, 5, 7)) == []
