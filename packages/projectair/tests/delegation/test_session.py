"""Tests for opening a delegated session and the recorder integration."""
from __future__ import annotations

import time
from pathlib import Path

import pytest

from airsdk.agdr import load_chain
from airsdk.delegation.session import open_delegation
from airsdk.recorder import AIRRecorder
from airsdk.types import AuthMethod, DelegationGrant, IntentSpec, StepKind
from airsdk.verification import IntentVerdict, verify_intent
from airsdk.verification.checks.delegation import check_delegation


def _grant() -> DelegationGrant:
    now = int(time.time())
    return DelegationGrant(
        delegation_id="d-1",
        agent_id="refactor-bot",
        decision="authorize",
        auth_method=AuthMethod.AUTH0,
        authorizer_sub="auth0|abc123",
        authorizer_email="clinician@hospital.org",
        issuer="https://example.us.auth0.com/",
        policy_id="eng-refactor-v2",
        policy_hash="0" * 64,
        scope=IntentSpec(
            goal="Refactor the auth module",
            allowed_tools=["read_file"],
            allowed_paths=["/repo/auth"],
        ),
        granted_at=now,
        expires_at=now + 3600,
    )


def test_open_delegation_writes_genesis_then_intent(tmp_path: Path) -> None:
    chain = tmp_path / "chain.jsonl"
    recorder = AIRRecorder(chain)
    record = open_delegation(recorder, _grant())

    records = load_chain(chain)
    assert records[0].kind == StepKind.DELEGATION
    assert records[0].step_id == record.step_id
    assert records[0].payload.delegation is not None
    assert records[0].payload.delegation.authorizer_email == "clinician@hospital.org"
    assert records[1].kind == StepKind.INTENT_DECLARATION
    assert records[1].payload.intent_spec is not None
    assert records[1].payload.intent_spec.goal == "Refactor the auth module"


def test_grant_survives_jsonl_round_trip_as_typed_model(tmp_path: Path) -> None:
    chain = tmp_path / "chain.jsonl"
    recorder = AIRRecorder(chain)
    open_delegation(recorder, _grant())

    reloaded = load_chain(chain)
    grant = reloaded[0].payload.delegation
    assert isinstance(grant, DelegationGrant)  # not a bare dict
    assert grant.policy_id == "eng-refactor-v2"


def test_constructor_delegation_argument(tmp_path: Path) -> None:
    chain = tmp_path / "chain.jsonl"
    AIRRecorder(chain, delegation=_grant())
    records = load_chain(chain)
    assert records[0].kind == StepKind.DELEGATION
    assert records[1].kind == StepKind.INTENT_DECLARATION


def test_delegation_and_intent_spec_together_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not both"):
        AIRRecorder(
            tmp_path / "chain.jsonl",
            delegation=_grant(),
            intent_spec=IntentSpec(goal="x"),
        )


def test_open_delegation_must_be_genesis(tmp_path: Path) -> None:
    recorder = AIRRecorder(tmp_path / "chain.jsonl")
    recorder.llm_start(prompt="hi")
    with pytest.raises(RuntimeError, match="first record"):
        open_delegation(recorder, _grant())


def test_covered_session_verifies_with_require_delegation(tmp_path: Path) -> None:
    chain = tmp_path / "chain.jsonl"
    recorder = AIRRecorder(chain, delegation=_grant())
    recorder.tool_start(tool_name="read_file", tool_args={"path": "/repo/auth/a.py"})
    recorder.tool_end(tool_output="ok")

    records = load_chain(chain)
    assert check_delegation(records) == []
    result = verify_intent(records, require_delegation=True)
    assert result.verdict == IntentVerdict.VERIFIED


def test_uncovered_session_fails_only_when_required(tmp_path: Path) -> None:
    chain = tmp_path / "chain.jsonl"
    recorder = AIRRecorder(chain, intent_spec=IntentSpec(goal="Refactor", allowed_tools=["read_file"]))
    recorder.tool_start(tool_name="read_file", tool_args={"path": "/work/a.py"})
    recorder.tool_end(tool_output="ok")
    records = load_chain(chain)

    # Default behavior is unchanged: no SV-AUTH penalty for a legacy chain.
    assert verify_intent(records).verdict == IntentVerdict.VERIFIED
    # Opt-in enforcement flags the uncovered agent.
    required = verify_intent(records, require_delegation=True)
    assert required.verdict == IntentVerdict.FAILED
    assert any(v.check_id == "SV-AUTH-01" for v in required.violations)
