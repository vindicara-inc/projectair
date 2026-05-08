"""Validation proof tests (Section 6.4)."""
from __future__ import annotations

import pytest

from airsdk.handoff.exceptions import ValidationProofInvalidError
from airsdk.handoff.identity import generate_local_dev_identity
from airsdk.handoff.idp.auth0 import Auth0Adapter
from airsdk.handoff.validation_proof import (
    ATTESTATION_SCHEMA,
    SUBMISSION_MODE_SYNC,
    SUBMISSION_STATE_ANCHORED,
    StubRekorBackend,
    build_validation_attestation,
    submit_validation_proof,
    verify_validation_proof,
)

PTID = "7f3a9b2c4d8e1f6a1234567890abcdef"


def _issue(adapter: Auth0Adapter):
    return adapter.issue_capability_token(
        source_agent_id="agent:cabinet-ea.v3",
        target_agent_id="agent:cabinet-coach.v2",
        target_agent_idp_issuer="https://cabinet-coach.us.auth0.com/",
        scopes=["agent:cabinet-coach:invoke"],
        parent_trace_id=PTID,
        delegation_payload_hash="blake3:" + "0" * 64,
    )


def test_attestation_schema_and_no_plaintext_identifiers(adapter: Auth0Adapter) -> None:
    cap = _issue(adapter)
    coach = generate_local_dev_identity("agent:cabinet-coach.v2")
    blob = build_validation_attestation(validating_agent=coach, capability_token=cap)
    assert blob["schema"] == ATTESTATION_SCHEMA
    plaintext_keys = [
        k
        for k, v in blob.items()
        if isinstance(v, str)
        and (
            v.startswith("agent:")
            or v.startswith("tok_")
            or v.startswith("https://")
            or "@" in v
        )
    ]
    assert plaintext_keys == [], f"hashed-identifier rule violated: {plaintext_keys}"


def test_submit_then_verify_roundtrip(adapter: Auth0Adapter) -> None:
    cap = _issue(adapter)
    coach = generate_local_dev_identity("agent:cabinet-coach.v2")
    backend = StubRekorBackend()
    proof = submit_validation_proof(
        validating_agent=coach, capability_token=cap, rekor_backend=backend
    )
    assert proof["submission_mode"] == SUBMISSION_MODE_SYNC
    assert proof["submission_state"] == SUBMISSION_STATE_ANCHORED
    assert len(backend.submissions) == 1
    verify_validation_proof(
        proof=proof, validating_agent_public_key=coach.public_key
    )


def test_blob_tamper_detected(adapter: Auth0Adapter) -> None:
    cap = _issue(adapter)
    coach = generate_local_dev_identity("agent:cabinet-coach.v2")
    proof = submit_validation_proof(
        validating_agent=coach,
        capability_token=cap,
        rekor_backend=StubRekorBackend(),
    )
    proof["validation_attestation_blob"] = dict(proof["validation_attestation_blob"])
    proof["validation_attestation_blob"]["validation_method"] = "evil"
    with pytest.raises(ValidationProofInvalidError, match="tampered"):
        verify_validation_proof(
            proof=proof, validating_agent_public_key=coach.public_key
        )


def test_wrong_identity_key_fails_signature(adapter: Auth0Adapter) -> None:
    cap = _issue(adapter)
    coach = generate_local_dev_identity("agent:cabinet-coach.v2")
    proof = submit_validation_proof(
        validating_agent=coach,
        capability_token=cap,
        rekor_backend=StubRekorBackend(),
    )
    other = generate_local_dev_identity("agent:other.v1")
    with pytest.raises(ValidationProofInvalidError):
        verify_validation_proof(
            proof=proof, validating_agent_public_key=other.public_key
        )


def test_async_mode_rejected_in_wave1(adapter: Auth0Adapter) -> None:
    cap = _issue(adapter)
    coach = generate_local_dev_identity("agent:cabinet-coach.v2")
    proof = submit_validation_proof(
        validating_agent=coach,
        capability_token=cap,
        rekor_backend=StubRekorBackend(),
    )
    proof["submission_mode"] = "asynchronous_with_retry"
    with pytest.raises(ValidationProofInvalidError, match="synchronous"):
        verify_validation_proof(
            proof=proof, validating_agent_public_key=coach.public_key
        )
