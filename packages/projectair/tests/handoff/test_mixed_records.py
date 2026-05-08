"""Mixed-record file ingestion tests.

The advisor-locked Path B says handoff records live alongside legacy v0.4
AgDR records in the same JSONL chain. The Layer 4 verifier must ignore
non-Layer-4 lines without crashing, while still verifying every Layer 4
record it finds.
"""
from __future__ import annotations

import json
from pathlib import Path

from airsdk.handoff.canonicalize import canonicalize_and_hash
from airsdk.handoff.handoff_record import (
    AcceptanceBody,
    CapabilityTokenSummary,
    FailPolicy,
    HandoffBody,
    Originator,
    build_handoff_acceptance_record,
    build_handoff_record,
)
from airsdk.handoff.identity import generate_local_dev_identity
from airsdk.handoff.idp.auth0 import Auth0Adapter
from airsdk.handoff.idp.base import AdapterRouter
from airsdk.handoff.trace import child_context, new_root_context
from airsdk.handoff.validation_proof import StubRekorBackend, submit_validation_proof
from airsdk.handoff.verifier import Chain, ChainSet, CrossAgentVerifier


def test_chain_from_path_ignores_legacy_v04_records(adapter: Auth0Adapter, tmp_path: Path) -> None:
    """Interleave a v0.4 record before and after the Layer 4 records."""
    ea = generate_local_dev_identity("agent:cabinet-ea.v3", code_commit="git:mix")
    coach = generate_local_dev_identity("agent:cabinet-coach.v2", code_commit="git:mix")
    root = new_root_context()
    originator = Originator(type="user", id="user:k", auth_method="auth0_session")

    cap = adapter.issue_capability_token(
        source_agent_id=ea.agent_id,
        target_agent_id=coach.agent_id,
        target_agent_idp_issuer="https://cabinet-coach.us.auth0.com/",
        scopes=["agent:cabinet-coach:invoke"],
        parent_trace_id=root.trace_id,
        delegation_payload_hash=canonicalize_and_hash({"req": "observe"}),
    )
    intent = "request_coaching_observation"
    intent_hash = canonicalize_and_hash(intent)
    h = build_handoff_record(
        step_n=4, trace_context=root, originator=originator, depth=0,
        source_identity=ea,
        handoff_body=HandoffBody(
            target_agent_id=coach.agent_id,
            target_agent_identity_certificate_format=coach.fmt.value,
            target_agent_identity_certificate_hash=coach.cert_hash,
            target_agent_idp_issuer="https://cabinet-coach.us.auth0.com/",
            delegation_intent=intent, delegation_intent_hash=intent_hash,
            delegation_payload_hash=canonicalize_and_hash({"req": "observe"}),
            capability_token=CapabilityTokenSummary(
                issuer=cap.issuer, jti=cap.jti, exp=cap.expires_at,
                scopes=list(cap.scopes), claims_hash=cap.claims_hash_blake3,
                raw_jwt=cap.raw_jwt,
            ),
            expected_response_type="coaching_observation",
            fail_policy=FailPolicy(rekor_submission_mode="synchronous"),
        ),
        prev_hash="blake3:" + "f" * 64,
    )
    backend = StubRekorBackend()
    proof = submit_validation_proof(
        validating_agent=coach, capability_token=cap, rekor_backend=backend
    )
    a = build_handoff_acceptance_record(
        step_n=1, trace_context=child_context(root), originator=originator, depth=1,
        target_identity=coach,
        acceptance_body=AcceptanceBody(
            source_agent_id=ea.agent_id,
            source_handoff_record_hash=h["content_hash"],
            capability_token_received_jti=cap.jti,
            capability_token_validation_method="auth0_jwks_rs256",  # noqa: S106
            capability_token_validation_proof=proof,
            delegation_intent_acknowledged=intent,
            delegation_intent_hash_acknowledged=intent_hash,
            intended_response_type="coaching_observation",
        ),
        prev_hash="blake3:" + "0" * 64,
        source_agent_id=ea.agent_id,
        source_handoff_record_hash=h["content_hash"],
    )

    legacy_before = {
        "version": "0.4",
        "kind": "tool_start",
        "step_id": "01928000-0000-0000-0000-000000000001",
        "timestamp": "2026-05-07T09:00:00Z",
        "payload": {"tool_name": "read_file", "tool_args": {"path": "./README.md"}},
        "prev_hash": "0" * 64,
        "content_hash": "ab" * 32,
        "signature": "ff" * 64,
        "signer_key": "00" * 32,
    }
    legacy_after = dict(legacy_before)
    legacy_after["step_id"] = "01928000-0000-0000-0000-000000000002"

    ea_path = tmp_path / "ea.jsonl"
    coach_path = tmp_path / "coach.jsonl"
    ea_path.write_text(
        json.dumps(legacy_before) + "\n" + json.dumps(h) + "\n" + json.dumps(legacy_after) + "\n"
    )
    coach_path.write_text(
        json.dumps(legacy_before) + "\n"
        + json.dumps(a) + "\n"
        + "\n"  # blank line, ignored
        + json.dumps(legacy_after) + "\n"
    )

    chain = Chain.from_path(ea_path)
    assert len(chain.handoff_records) == 1
    assert len(chain.acceptance_records) == 0
    assert len(chain.records) == 3  # legacy + handoff + legacy

    router = AdapterRouter()
    router.register(adapter)
    verifier = CrossAgentVerifier(adapter_router=router, rekor_backend=backend)
    verifier.register_identity(ea.cert_hash, ea.public_key)
    verifier.register_identity(coach.cert_hash, coach.public_key)
    result = verifier.verify_chain_set(
        ChainSet.from_paths([ea_path, coach_path]), parent_trace_id=root.trace_id
    )
    assert result.passed
    assert result.handoffs == 1
    assert result.acceptances == 1
