"""Eight-step cross-agent verifier tests (Section 8.2)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from airsdk.handoff.canonicalize import canonicalize_and_hash
from airsdk.handoff.exceptions import (
    ReplayAnomalyError,
    TemporalOrderingError,
)
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
from airsdk.handoff.validation_proof import (
    StubRekorBackend,
    submit_validation_proof,
)
from airsdk.handoff.verifier import (
    ChainSet,
    CrossAgentVerifier,
    verify_temporal_ordering,
)


def _stage_chain_set(adapter: Auth0Adapter, tmp_path: Path):
    ea = generate_local_dev_identity("agent:cabinet-ea.v3", code_commit="git:ea")
    coach = generate_local_dev_identity("agent:cabinet-coach.v2", code_commit="git:coach")
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
    cap_summary = CapabilityTokenSummary(
        issuer=cap.issuer, jti=cap.jti, exp=cap.expires_at,
        scopes=list(cap.scopes), claims_hash=cap.claims_hash_blake3,
    )
    intent = "request_coaching_observation"
    intent_hash = canonicalize_and_hash(intent)
    h_body = HandoffBody(
        target_agent_id=coach.agent_id,
        target_agent_identity_certificate_format=coach.fmt.value,
        target_agent_identity_certificate_hash=coach.cert_hash,
        target_agent_idp_issuer="https://cabinet-coach.us.auth0.com/",
        delegation_intent=intent,
        delegation_intent_hash=intent_hash,
        delegation_payload_hash=canonicalize_and_hash({"req": "observe"}),
        capability_token=cap_summary,
        expected_response_type="coaching_observation",
        fail_policy=FailPolicy(rekor_submission_mode="synchronous"),
    )
    h = build_handoff_record(
        step_n=4, trace_context=root, originator=originator, depth=0,
        source_identity=ea, handoff_body=h_body,
        prev_hash="blake3:" + "f" * 64,
    )
    backend = StubRekorBackend()
    proof = submit_validation_proof(
        validating_agent=coach, capability_token=cap, rekor_backend=backend
    )
    a_body = AcceptanceBody(
        source_agent_id=ea.agent_id,
        source_handoff_record_hash=h["content_hash"],
        capability_token_received_jti=cap.jti,
        capability_token_validation_method="auth0_jwks_rs256",  # noqa: S106
        capability_token_validation_proof=proof,
        delegation_intent_acknowledged=intent,
        delegation_intent_hash_acknowledged=intent_hash,
        intended_response_type="coaching_observation",
    )
    a = build_handoff_acceptance_record(
        step_n=1, trace_context=child_context(root), originator=originator, depth=1,
        target_identity=coach, acceptance_body=a_body,
        prev_hash="blake3:" + "0" * 64,
        source_agent_id=ea.agent_id,
        source_handoff_record_hash=h["content_hash"],
    )
    ea_path = tmp_path / "ea.jsonl"
    coach_path = tmp_path / "coach.jsonl"
    ea_path.write_text(json.dumps(h) + "\n")
    coach_path.write_text(json.dumps(a) + "\n")
    router = AdapterRouter()
    router.register(adapter)
    verifier = CrossAgentVerifier(adapter_router=router, rekor_backend=backend)
    verifier.register_identity(ea.cert_hash, ea.public_key)
    verifier.register_identity(coach.cert_hash, coach.public_key)
    return verifier, ea_path, coach_path, root.trace_id, ea, coach, h, a, originator, cap


def test_clean_chain_set_verifies(adapter, tmp_path) -> None:
    verifier, ea_path, coach_path, ptid, *_ = _stage_chain_set(adapter, tmp_path)
    cs = ChainSet.from_paths([ea_path, coach_path])
    result = verifier.verify_chain_set(cs, parent_trace_id=ptid)
    assert result.passed
    assert result.handoffs == 1
    assert result.acceptances == 1


def test_replay_anomaly_duplicate_acceptance_fails(adapter, tmp_path) -> None:
    verifier, ea_path, coach_path, ptid, ea, coach, h, a, originator, cap = (
        _stage_chain_set(adapter, tmp_path)
    )
    # Build a second acceptance for the SAME source handoff hash
    intent = "request_coaching_observation"
    intent_hash = canonicalize_and_hash(intent)
    a2_body = AcceptanceBody(
        source_agent_id=ea.agent_id,
        source_handoff_record_hash=h["content_hash"],
        capability_token_received_jti=cap.jti,
        capability_token_validation_method="auth0_jwks_rs256",  # noqa: S106 - method name, not a secret
        capability_token_validation_proof=a["acceptance"]["capability_token_validation_proof"],
        delegation_intent_acknowledged=intent,
        delegation_intent_hash_acknowledged=intent_hash,
        intended_response_type="coaching_observation",
    )
    from airsdk.handoff.trace import TraceContext
    ctx2 = TraceContext(
        trace_id=ptid, parent_id="ffffffffffffffff", trace_flags="01",
    )
    a2 = build_handoff_acceptance_record(
        step_n=2, trace_context=ctx2, originator=originator, depth=1,
        target_identity=coach,
        acceptance_body=a2_body,
        prev_hash="blake3:" + "0" * 64,
        source_agent_id=ea.agent_id,
        source_handoff_record_hash=h["content_hash"],
    )
    coach_path.write_text(json.dumps(a) + "\n" + json.dumps(a2) + "\n")
    cs = ChainSet.from_paths([ea_path, coach_path])
    with pytest.raises(ReplayAnomalyError):
        verifier.verify_chain_set(cs, parent_trace_id=ptid)


def test_temporal_ordering_lower_bound_within_tolerance() -> None:
    # 4-second skew within 5s tolerance: passes
    verify_temporal_ordering(
        acceptance_ts_iso="2026-05-07T10:00:00Z",
        handoff_ts_iso="2026-05-07T10:00:04Z",
        acceptance_timeout_seconds=30,
        skew_tolerance_seconds=5,
    )


def test_temporal_ordering_lower_bound_violation() -> None:
    with pytest.raises(TemporalOrderingError) as ei:
        verify_temporal_ordering(
            acceptance_ts_iso="2026-05-07T10:00:00Z",
            handoff_ts_iso="2026-05-07T10:00:07Z",
            acceptance_timeout_seconds=30,
            skew_tolerance_seconds=5,
        )
    assert ei.value.failed_bound == "lower"
    assert ei.value.actual_delta_seconds == pytest.approx(7.0)


def test_temporal_ordering_upper_bound_violation() -> None:
    with pytest.raises(TemporalOrderingError) as ei:
        verify_temporal_ordering(
            acceptance_ts_iso="2026-05-07T12:00:00Z",
            handoff_ts_iso="2026-05-07T10:00:00Z",
            acceptance_timeout_seconds=30,
            skew_tolerance_seconds=5,
        )
    assert ei.value.failed_bound == "upper"


def test_unknown_issuer_fails_routing(adapter, tmp_path) -> None:
    verifier, ea_path, coach_path, ptid, *_ = _stage_chain_set(adapter, tmp_path)
    # Replace the verifier's router with an empty one — token issuer no longer registered
    verifier.adapter_router = AdapterRouter()
    cs = ChainSet.from_paths([ea_path, coach_path])
    from airsdk.handoff.exceptions import UnregisteredIssuerError
    with pytest.raises(UnregisteredIssuerError):
        verifier.verify_chain_set(cs, parent_trace_id=ptid)
