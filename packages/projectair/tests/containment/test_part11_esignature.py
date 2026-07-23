"""Part 11 §11.50 e-signature meaning/manifestation (B1) and §11.10(e) /
Annex 11 §9 audit-trail review (B2)."""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from airsdk.agdr import load_chain, verify_chain
from airsdk.containment import Auth0Verifier, ChallengeNotFoundError, ContainmentPolicy, StepUpRequiredError
from airsdk.esignature import is_part11_signature, signature_manifestation
from airsdk.recorder import AIRRecorder
from airsdk.types import HumanApproval, SignatureMeaning, StepKind, VerificationStatus

if TYPE_CHECKING:
    from tests.containment.conftest import MockIdP


def _approve(tmp_path: Path, mock_idp: MockIdP, **approve_kwargs: object) -> AIRRecorder:
    verifier = Auth0Verifier(mock_idp.issuer, mock_idp.audience, jwks_uri=mock_idp.jwks_uri)
    rec = AIRRecorder(
        tmp_path / "chain.jsonl",
        containment=ContainmentPolicy(step_up_for_actions=[{"tool": "stripe_charge"}]),
        auth0_verifier=verifier,
    )
    rec.llm_start(prompt="setup")
    try:
        rec.tool_start(tool_name="stripe_charge", tool_args={"amount_cents": 9999})
        raise AssertionError("expected StepUpRequiredError")
    except StepUpRequiredError as e:
        challenge_id = e.challenge_id
    token = mock_idp.issue_token(sub="auth0|finance-lead", email="finance@example.com")
    rec.approve(challenge_id, token, **approve_kwargs)  # type: ignore[arg-type]
    return rec


# ---- B1: e-signature meaning + manifestation --------------------------------

def test_approve_records_signature_meaning(tmp_path: Path, mock_idp: MockIdP) -> None:
    _approve(tmp_path, mock_idp, signature_meaning=SignatureMeaning.REVIEW)
    approval = next(
        r.payload.human_approval
        for r in load_chain(tmp_path / "chain.jsonl")
        if r.kind is StepKind.HUMAN_APPROVAL
    )
    assert approval is not None
    assert approval.meaning is SignatureMeaning.REVIEW


def test_approve_defaults_meaning_to_approval(tmp_path: Path, mock_idp: MockIdP) -> None:
    _approve(tmp_path, mock_idp)
    approval = next(
        r.payload.human_approval
        for r in load_chain(tmp_path / "chain.jsonl")
        if r.kind is StepKind.HUMAN_APPROVAL
    )
    assert approval.meaning is SignatureMeaning.APPROVAL


def test_manifestation_and_completeness(tmp_path: Path, mock_idp: MockIdP) -> None:
    _approve(tmp_path, mock_idp, signature_meaning=SignatureMeaning.APPROVAL)
    approval = next(
        r.payload.human_approval
        for r in load_chain(tmp_path / "chain.jsonl")
        if r.kind is StepKind.HUMAN_APPROVAL
    )
    manifest = signature_manifestation(approval)
    assert "finance@example.com" in manifest  # printed name
    assert "approval" in manifest  # meaning
    assert "T" in manifest  # ISO-8601 UTC signing time
    assert "Z" in manifest
    assert is_part11_signature(approval) is True


def test_incomplete_signature_flagged() -> None:
    """An approval with no meaning is not a complete Part 11 signature."""
    approval = HumanApproval(
        challenge_id="c", decision="approve", approver_sub="auth0|x",
        issuer="https://idp", audience="aud", issued_at=1_700_000_000,
        expires_at=1_700_003_600, signed_token="jwt",  # noqa: S106  (dummy, not a secret)
    )
    assert is_part11_signature(approval) is False
    assert "meaning not recorded" in signature_manifestation(approval)


# ---- B2: audit-trail review -------------------------------------------------

def test_record_audit_review_writes_attributed_signed_record(tmp_path: Path, mock_idp: MockIdP) -> None:
    verifier = Auth0Verifier(mock_idp.issuer, mock_idp.audience, jwks_uri=mock_idp.jwks_uri)
    rec = AIRRecorder(tmp_path / "chain.jsonl", auth0_verifier=verifier)
    first = rec.llm_start(prompt="q")
    last = rec.llm_end(response="a")

    token = mock_idp.issue_token(sub="auth0|qa-reviewer", email="qa@example.com")
    review_record = rec.record_audit_review(
        token,
        reviewed_from_step=first.step_id,
        reviewed_to_step=last.step_id,
        outcome="accepted",
        notes="Quarterly trail review.",
    )
    assert review_record.kind is StepKind.AUDIT_REVIEW
    review = review_record.payload.audit_review
    assert review is not None
    assert review.reviewer_sub == "auth0|qa-reviewer"
    assert review.reviewer_email == "qa@example.com"
    assert review.reviewed_from_step == first.step_id
    assert review.reviewed_to_step == last.step_id
    assert review.outcome == "accepted"
    # The review is itself a signed, tamper-evident record in the chain.
    assert verify_chain(load_chain(tmp_path / "chain.jsonl")).status is VerificationStatus.OK


def test_audit_review_carries_reason_for_change(tmp_path: Path, mock_idp: MockIdP) -> None:
    verifier = Auth0Verifier(mock_idp.issuer, mock_idp.audience, jwks_uri=mock_idp.jwks_uri)
    rec = AIRRecorder(tmp_path / "chain.jsonl", auth0_verifier=verifier)
    step = rec.llm_start(prompt="q")
    token = mock_idp.issue_token(sub="auth0|qa", email="qa@example.com")
    review_record = rec.record_audit_review(
        token,
        reviewed_from_step=step.step_id,
        reviewed_to_step=step.step_id,
        outcome="exceptions_noted",
        reason="Corrected mislabeled tool output per CAPA-2026-014.",
    )
    assert review_record.payload.audit_review.reason == "Corrected mislabeled tool output per CAPA-2026-014."


def test_audit_review_requires_verifier(tmp_path: Path) -> None:
    rec = AIRRecorder(tmp_path / "chain.jsonl")  # no auth0_verifier
    step = rec.llm_start(prompt="q")
    with pytest.raises(ChallengeNotFoundError):
        rec.record_audit_review(
            "token", reviewed_from_step=step.step_id, reviewed_to_step=step.step_id,
        )
