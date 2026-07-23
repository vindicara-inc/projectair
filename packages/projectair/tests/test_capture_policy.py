"""Capture-time content-reference policy (PHI-vs-immutability fork).

A ``CapturePolicy`` replaces the plaintext of named payload fields with a
per-record SALTED BLAKE3 digest before signing, so PHI-bearing content never
enters the immutable, anchored chain, and the digest is neither reversible nor
correlatable. Salt + plaintext live in an erasable ReferenceVault.
"""
from __future__ import annotations

from pathlib import Path

from airsdk.agdr import load_chain, verify_chain
from airsdk.recorder import AIRRecorder
from airsdk.reference_vault import ReferenceVault
from airsdk.types import CapturePolicy, StepKind, VerificationStatus


def test_phi_safe_policy_removes_plaintext_leaves_reference(tmp_path: Path) -> None:
    recorder = AIRRecorder(log_path=tmp_path / "r.log", capture_policy=CapturePolicy.phi_safe())
    recorder.llm_start(prompt="Patient Jane Doe, MRN 12345")
    recorder.llm_end(response="Recommend PET-CT.")

    start, end = load_chain(tmp_path / "r.log")[:2]
    assert start.payload.prompt is None
    assert end.payload.response is None
    assert start.payload.content_refs is not None
    assert start.payload.content_refs["prompt"].startswith("blake3:")


def test_identical_plaintexts_get_different_refs(tmp_path: Path) -> None:
    """The core anti-correlation invariant: equal values must NOT hash equal in
    the chain, or the anchored log would leak that the same value recurred."""
    recorder = AIRRecorder(log_path=tmp_path / "r.log", capture_policy=CapturePolicy.phi_safe())
    recorder.llm_start(prompt="000-00-0000")
    recorder.llm_end(response="000-00-0000")

    start, end = load_chain(tmp_path / "r.log")[:2]
    ref_a = start.payload.content_refs["prompt"]
    ref_b = end.payload.content_refs["response"]
    assert ref_a != ref_b  # per-record salt


def test_vault_enables_verification_and_erasure(tmp_path: Path) -> None:
    vault = ReferenceVault(tmp_path / "vault.jsonl")
    recorder = AIRRecorder(
        log_path=tmp_path / "r.log",
        capture_policy=CapturePolicy.phi_safe(),
        reference_vault=vault,
    )
    recorder.llm_start(prompt="Patient Jane Doe, MRN 12345")

    ref = load_chain(tmp_path / "r.log")[0].payload.content_refs["prompt"]
    # The vault can prove the plaintext matches the chain digest.
    assert vault.verify(ref) is True
    salt, plaintext = vault.resolve(ref)  # type: ignore[misc]
    assert plaintext == "Patient Jane Doe, MRN 12345"
    assert len(salt) == 16
    # Erasure: a fresh vault with no entry cannot resolve the anchored digest.
    empty = ReferenceVault(tmp_path / "empty.jsonl")
    assert empty.resolve(ref) is None
    assert empty.verify(ref) is False


def test_vault_file_is_owner_only(tmp_path: Path) -> None:
    vault = ReferenceVault(tmp_path / "vault.jsonl")
    recorder = AIRRecorder(
        log_path=tmp_path / "r.log",
        capture_policy=CapturePolicy.phi_safe(),
        reference_vault=vault,
    )
    recorder.llm_start(prompt="secret")
    assert (vault.path.stat().st_mode & 0o777) == 0o600


def test_referenced_chain_still_verifies(tmp_path: Path) -> None:
    recorder = AIRRecorder(log_path=tmp_path / "r.log", capture_policy=CapturePolicy.phi_safe())
    recorder.llm_start(prompt="secret")
    recorder.tool_start(tool_name="db_read", tool_args={"ssn": "000-00-0000"})

    records = load_chain(tmp_path / "r.log")
    assert verify_chain(records).status is VerificationStatus.OK
    tool_rec = next(r for r in records if r.kind is StepKind.TOOL_START)
    assert tool_rec.payload.tool_args is None  # dict field referenced too
    assert "tool_args" in (tool_rec.payload.content_refs or {})


def test_no_policy_keeps_plaintext(tmp_path: Path) -> None:
    recorder = AIRRecorder(log_path=tmp_path / "r.log")  # default: no capture policy
    recorder.llm_start(prompt="hello")
    record = load_chain(tmp_path / "r.log")[0]
    assert record.payload.prompt == "hello"
    assert record.payload.content_refs is None


def test_user_intent_not_referenced_by_phi_safe(tmp_path: Path) -> None:
    """phi_safe leaves user_intent intact so ASI01 goal anchoring still works."""
    recorder = AIRRecorder(
        log_path=tmp_path / "r.log",
        user_intent="Adjudicate refund",
        capture_policy=CapturePolicy.phi_safe(),
    )
    recorder.llm_start(prompt="private")
    record = load_chain(tmp_path / "r.log")[0]
    assert record.payload.user_intent == "Adjudicate refund"
    assert record.payload.prompt is None
