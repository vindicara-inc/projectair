"""Test matrix for policy-driven delegation containment (AUTO / ALWAYS / NEVER).

Run:
    pytest -q tests/delegation/test_require_delegation.py
"""
from __future__ import annotations

import time
from pathlib import Path

import pytest

from airsdk.agdr import Signer, load_chain
from airsdk.containment import (
    BlockedActionError,
    Decision,
    DelegationPolicy,
    EnforcementMode,
    declares_delegation,
    evaluate_require_delegation,
    should_require_delegation,
)
from airsdk.recorder import AIRRecorder
from airsdk.types import (
    AgDRPayload,
    AgDRRecord,
    AuthMethod,
    DelegationGrant,
    IntentSpec,
    StepKind,
)
from airsdk.verification import IntentVerdict, verify_intent

NOW = int(time.time())


def _scope() -> IntentSpec:
    return IntentSpec(
        goal="adjudicate inbound claims",
        allowed_tools=["claims.read", "claims.adjudicate"],
        allowed_paths=["/phi/claims/**"],
        allowed_network=["internal-only"],
        secret_access=False,
    )


def _grant(*, decision: str = "authorize", expired: bool = False) -> DelegationGrant:
    return DelegationGrant(
        delegation_id="d1",
        agent_id="claims-bot",
        decision=decision,
        auth_method=AuthMethod.WEBAUTHN,
        authorizer_sub="webauthn:clinician-handle",
        authorizer_email="clinician@hospital.org",
        policy_id="eng-refactor-v2",
        policy_hash="b3:deadbeef",
        scope=_scope(),
        granted_at=NOW - 60,
        expires_at=(NOW - 10) if expired else (NOW + 3600),
    )


def _sign(signer: Signer, kind: StepKind, data: dict[str, object]) -> AgDRRecord:
    return signer.sign(kind=kind, payload=AgDRPayload.model_validate(data))


def legacy_chain() -> list[AgDRRecord]:
    signer = Signer.generate()
    return [
        _sign(signer, StepKind.LLM_START, {"prompt": "go", "user_intent": _scope().goal}),
        _sign(signer, StepKind.TOOL_START, {"tool_name": "claims.read"}),
    ]


def declared_covered_chain() -> list[AgDRRecord]:
    grant = _grant()
    signer = Signer.generate()
    return [
        _sign(signer, StepKind.DELEGATION, {"delegation": grant, "user_intent": grant.scope.goal}),
        _sign(signer, StepKind.INTENT_DECLARATION, {"user_intent": grant.scope.goal, "intent_spec": grant.scope}),
        _sign(signer, StepKind.TOOL_START, {"tool_name": "claims.read"}),
    ]


def declared_uncovered_chain() -> list[AgDRRecord]:
    grant = _grant(decision="deny")
    signer = Signer.generate()
    return [
        _sign(signer, StepKind.DELEGATION, {"delegation": grant, "user_intent": grant.scope.goal}),
        _sign(signer, StepKind.INTENT_DECLARATION, {"user_intent": grant.scope.goal, "intent_spec": grant.scope}),
        _sign(signer, StepKind.TOOL_START, {"tool_name": "claims.read"}),
    ]


def _sv_auth_ids(result) -> set[str]:
    return {v.check_id for v in result.violations if v.check_id.startswith("SV-AUTH")}


def test_declares_delegation_signal() -> None:
    assert declares_delegation(declared_covered_chain()) is True
    assert declares_delegation(legacy_chain()) is False
    assert should_require_delegation(legacy_chain()) is False
    assert should_require_delegation(declared_covered_chain()) is True


def test_1_legacy_auto_verified() -> None:
    result = verify_intent(legacy_chain(), _scope())
    assert result.verdict == IntentVerdict.VERIFIED
    assert _sv_auth_ids(result) == set()


def test_2_declared_covered_auto_verified() -> None:
    result = verify_intent(declared_covered_chain(), _scope())
    assert result.verdict == IntentVerdict.VERIFIED
    assert _sv_auth_ids(result) == set()


def test_3_declared_uncovered_auto_failed() -> None:
    result = verify_intent(declared_uncovered_chain(), _scope())
    assert result.verdict == IntentVerdict.FAILED
    assert "SV-AUTH-03" in _sv_auth_ids(result)


def test_4_legacy_always_failed() -> None:
    result = verify_intent(
        legacy_chain(),
        _scope(),
        delegation_policy=DelegationPolicy(mode=EnforcementMode.ALWAYS),
    )
    assert result.verdict == IntentVerdict.FAILED
    assert "SV-AUTH-01" in _sv_auth_ids(result)


def test_5_declared_uncovered_never_verified() -> None:
    result = verify_intent(
        declared_uncovered_chain(),
        _scope(),
        delegation_policy=DelegationPolicy(mode=EnforcementMode.NEVER),
    )
    assert result.verdict == IntentVerdict.VERIFIED
    assert _sv_auth_ids(result) == set()


def test_explicit_flag_overrides_policy() -> None:
    result = verify_intent(legacy_chain(), _scope(), require_delegation=True)
    assert "SV-AUTH-01" in _sv_auth_ids(result)

    result2 = verify_intent(declared_uncovered_chain(), _scope(), require_delegation=False)
    assert _sv_auth_ids(result2) == set()


def test_6_step_time_block_and_allow() -> None:
    assert evaluate_require_delegation(declared_uncovered_chain()).decision == Decision.BLOCK
    assert evaluate_require_delegation(declared_covered_chain()).decision == Decision.ALLOW
    assert evaluate_require_delegation(legacy_chain()).decision == Decision.ALLOW

    blocked = evaluate_require_delegation(
        legacy_chain(),
        policy=DelegationPolicy(mode=EnforcementMode.ALWAYS),
    )
    assert blocked.decision == Decision.BLOCK
    assert "SV-AUTH" in blocked.reason


def test_recorder_blocks_declared_uncovered_under_auto(tmp_path: Path) -> None:
    chain = tmp_path / "chain.jsonl"
    recorder = AIRRecorder(chain, delegation=_grant(decision="deny"))
    with pytest.raises(BlockedActionError, match="delegation"):
        recorder.tool_start(tool_name="claims.read")

    loaded = load_chain(chain)
    blocked_starts = [r for r in loaded if r.kind == StepKind.TOOL_START]
    assert len(blocked_starts) == 1
    assert blocked_starts[0].payload.blocked is True


def test_recorder_allows_declared_covered_under_auto(tmp_path: Path) -> None:
    chain = tmp_path / "chain.jsonl"
    recorder = AIRRecorder(chain, delegation=_grant())
    recorder.tool_start(tool_name="claims.read")
    recorder.tool_end(tool_output="ok")

    loaded = load_chain(chain)
    assert all(r.payload.blocked is not True for r in loaded if r.kind == StepKind.TOOL_START)


def test_recorder_allows_legacy_under_auto(tmp_path: Path) -> None:
    chain = tmp_path / "chain.jsonl"
    recorder = AIRRecorder(chain, intent_spec=_scope())
    recorder.tool_start(tool_name="claims.read")
    recorder.tool_end(tool_output="ok")

    assert evaluate_require_delegation(load_chain(chain)).decision == Decision.ALLOW


def test_recorder_blocks_uncovered_when_delegation_policy_always(tmp_path: Path) -> None:
    chain = tmp_path / "chain.jsonl"
    recorder = AIRRecorder(
        chain,
        intent_spec=_scope(),
        delegation_policy=DelegationPolicy(mode=EnforcementMode.ALWAYS),
    )
    with pytest.raises(BlockedActionError, match="SV-AUTH"):
        recorder.tool_start(tool_name="claims.read")

    loaded = load_chain(chain)
    assert loaded[-1].payload.blocked is True
