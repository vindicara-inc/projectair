"""Handoff record builder + signature + content_hash tests."""
from __future__ import annotations

import pytest

from airsdk.handoff.canonicalize import canonicalize_and_hash
from airsdk.handoff.exceptions import HandoffRecordInvalidError
from airsdk.handoff.handoff_record import (
    SCHEMA_HANDOFF,
    SCHEMA_HANDOFF_ACCEPTANCE,
    AcceptanceBody,
    CapabilityTokenSummary,
    FailPolicy,
    HandoffBody,
    Originator,
    build_handoff_acceptance_record,
    build_handoff_record,
    verify_record_content_hash,
    verify_record_signature,
)
from airsdk.handoff.identity import generate_local_dev_identity
from airsdk.handoff.trace import child_context, new_root_context


def _build_pair(rekor_mode: str = "synchronous"):
    ea = generate_local_dev_identity("agent:cabinet-ea.v3", code_commit="git:ea")
    coach = generate_local_dev_identity("agent:cabinet-coach.v2", code_commit="git:coach")
    root = new_root_context()
    originator = Originator(type="user", id="user:k", auth_method="auth0_session")
    cap = CapabilityTokenSummary(
        issuer="https://vindicara.us.auth0.com/",
        jti="tok_test",
        exp=9999999999,
        scopes=["agent:cabinet-coach:invoke"],
        claims_hash=canonicalize_and_hash({"jti": "tok_test"}),
    )
    intent = "request_coaching_observation"
    intent_hash = canonicalize_and_hash(intent)
    payload_hash = canonicalize_and_hash({"req": "observe"})

    h_body = HandoffBody(
        target_agent_id=coach.agent_id,
        target_agent_identity_certificate_format=coach.fmt.value,
        target_agent_identity_certificate_hash=coach.cert_hash,
        target_agent_idp_issuer="https://cabinet-coach.us.auth0.com/",
        delegation_intent=intent,
        delegation_intent_hash=intent_hash,
        delegation_payload_hash=payload_hash,
        capability_token=cap,
        expected_response_type="coaching_observation",
        fail_policy=FailPolicy(rekor_submission_mode=rekor_mode),
    )
    h_rec = build_handoff_record(
        step_n=4, trace_context=root, originator=originator, depth=0,
        source_identity=ea, handoff_body=h_body,
        prev_hash="blake3:" + "f" * 64,
    )
    a_body = AcceptanceBody(
        source_agent_id=ea.agent_id,
        source_handoff_record_hash=h_rec["content_hash"],
        capability_token_received_jti=cap.jti,
        capability_token_validation_method="auth0_jwks_rs256",  # noqa: S106
        capability_token_validation_proof={"placeholder": True},
        delegation_intent_acknowledged=intent,
        delegation_intent_hash_acknowledged=intent_hash,
        intended_response_type="coaching_observation",
    )
    a_rec = build_handoff_acceptance_record(
        step_n=1, trace_context=child_context(root), originator=originator, depth=1,
        target_identity=coach, acceptance_body=a_body,
        prev_hash="blake3:" + "0" * 64,
        source_agent_id=ea.agent_id,
        source_handoff_record_hash=h_rec["content_hash"],
    )
    return ea, coach, h_rec, a_rec


def test_handoff_record_schema_and_signature_verify() -> None:
    ea, _, h_rec, _ = _build_pair()
    assert h_rec["schema"] == SCHEMA_HANDOFF
    verify_record_content_hash(h_rec)
    verify_record_signature(h_rec, ea.public_key)


def test_acceptance_record_schema_and_signature_verify() -> None:
    _, coach, _, a_rec = _build_pair()
    assert a_rec["schema"] == SCHEMA_HANDOFF_ACCEPTANCE
    verify_record_content_hash(a_rec)
    verify_record_signature(a_rec, coach.public_key)


def test_tampering_payload_breaks_content_hash() -> None:
    _, _, h_rec, _ = _build_pair()
    h_rec["handoff"] = dict(h_rec["handoff"])
    h_rec["handoff"]["delegation_intent"] = "evil"
    with pytest.raises(HandoffRecordInvalidError, match="content_hash mismatch"):
        verify_record_content_hash(h_rec)


def test_wrong_key_fails_signature() -> None:
    _, coach, h_rec, _ = _build_pair()
    with pytest.raises(HandoffRecordInvalidError):
        verify_record_signature(h_rec, coach.public_key)


def test_acceptance_binds_to_source_handoff_hash() -> None:
    _, _, h_rec, a_rec = _build_pair()
    assert (
        a_rec["acceptance"]["source_handoff_record_hash"] == h_rec["content_hash"]
    )
    assert (
        a_rec["trace"]["spans_received_from"]["handoff_record_hash"]
        == h_rec["content_hash"]
    )


def test_intent_hash_matches_across_pair_when_strings_match() -> None:
    _, _, h_rec, a_rec = _build_pair()
    assert (
        h_rec["handoff"]["delegation_intent_hash"]
        == a_rec["acceptance"]["delegation_intent_hash_acknowledged"]
    )


def test_intent_hash_matches_when_acceptance_redacts_string() -> None:
    """Section 6.5 rule 4: hashes match even if strings disagree (redaction)."""
    ea, coach, h_rec, _ = _build_pair()
    real_intent = "request_coaching_observation"
    intent_hash = canonicalize_and_hash(real_intent)
    a_body = AcceptanceBody(
        source_agent_id=ea.agent_id,
        source_handoff_record_hash=h_rec["content_hash"],
        capability_token_received_jti="tok_test",  # noqa: S106
        capability_token_validation_method="auth0_jwks_rs256",  # noqa: S106
        capability_token_validation_proof={},
        delegation_intent_acknowledged="REDACTED",
        delegation_intent_hash_acknowledged=intent_hash,
        intended_response_type="coaching_observation",
    )
    root = new_root_context()
    originator = Originator(type="user", id="user:k", auth_method="auth0_session")
    a_rec = build_handoff_acceptance_record(
        step_n=1, trace_context=child_context(root), originator=originator, depth=1,
        target_identity=coach, acceptance_body=a_body,
        prev_hash="blake3:" + "0" * 64,
        source_agent_id=ea.agent_id,
        source_handoff_record_hash=h_rec["content_hash"],
    )
    assert a_rec["acceptance"]["delegation_intent_hash_acknowledged"] == intent_hash
