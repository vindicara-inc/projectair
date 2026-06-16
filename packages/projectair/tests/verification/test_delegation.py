"""Tests for SV-AUTH: delegation coverage over an AgDR chain."""
from __future__ import annotations

import time

from airsdk.agdr import Signer
from airsdk.types import (
    AgDRPayload,
    AgDRRecord,
    AuthMethod,
    DelegationGrant,
    IntentSpec,
    StepKind,
)
from airsdk.verification.checks.delegation import check_delegation


def _grant(
    *,
    decision: str = "authorize",
    authorizer_sub: str = "auth0|abc123",
    expires_in: int = 3600,
) -> DelegationGrant:
    now = int(time.time())
    return DelegationGrant(
        delegation_id="d-1",
        agent_id="refactor-bot",
        decision=decision,
        auth_method=AuthMethod.AUTH0,
        authorizer_sub=authorizer_sub,
        authorizer_email="clinician@hospital.org",
        issuer="https://example.us.auth0.com/",
        policy_id="eng-refactor-v2",
        policy_hash="0" * 64,
        scope=IntentSpec(goal="Refactor the auth module", allowed_paths=["/repo/auth"]),
        granted_at=now,
        expires_at=now + expires_in,
    )


def _sign(signer: Signer, kind: StepKind, data: dict[str, object]) -> AgDRRecord:
    return signer.sign(kind=kind, payload=AgDRPayload.model_validate(data))


def _covered_chain(grant: DelegationGrant) -> list[AgDRRecord]:
    signer = Signer.generate()
    return [
        _sign(signer, StepKind.DELEGATION, {"delegation": grant, "user_intent": grant.scope.goal}),
        _sign(signer, StepKind.INTENT_DECLARATION, {"intent_spec": grant.scope, "user_intent": grant.scope.goal}),
        _sign(signer, StepKind.TOOL_START, {"tool_name": "read_file", "tool_args": {"path": "/repo/auth/a.py"}}),
        _sign(signer, StepKind.TOOL_END, {"tool_output": "ok"}),
    ]


class TestCovered:
    def test_valid_delegation_is_covered(self) -> None:
        assert check_delegation(_covered_chain(_grant())) == []

    def test_empty_chain_returns_no_findings(self) -> None:
        assert check_delegation([]) == []

    def test_anchor_before_genesis_is_skipped(self) -> None:
        grant = _grant()
        signer = Signer.generate()
        records = [
            _sign(signer, StepKind.ANCHOR, {"anchored_chain_root": "a" * 64}),
            _sign(signer, StepKind.DELEGATION, {"delegation": grant, "user_intent": grant.scope.goal}),
            _sign(signer, StepKind.TOOL_START, {"tool_name": "read_file"}),
        ]
        assert check_delegation(records) == []


class TestUncovered:
    def test_no_delegation_genesis_is_critical(self) -> None:
        signer = Signer.generate()
        records = [
            _sign(signer, StepKind.LLM_START, {"prompt": "go"}),
            _sign(signer, StepKind.TOOL_START, {"tool_name": "read_file"}),
        ]
        violations = check_delegation(records)
        assert len(violations) == 1
        assert violations[0].check_id == "SV-AUTH-01"
        assert violations[0].severity == "critical"
        assert violations[0].step_index == 0

    def test_delegation_record_without_grant_is_critical(self) -> None:
        signer = Signer.generate()
        records = [_sign(signer, StepKind.DELEGATION, {"user_intent": "go"})]
        violations = check_delegation(records)
        assert len(violations) == 1
        assert violations[0].check_id == "SV-AUTH-02"

    def test_denied_decision_is_critical(self) -> None:
        violations = check_delegation(_covered_chain(_grant(decision="deny")))
        assert any(v.check_id == "SV-AUTH-03" for v in violations)

    def test_missing_authorizer_is_critical(self) -> None:
        violations = check_delegation(_covered_chain(_grant(authorizer_sub="")))
        assert any(v.check_id == "SV-AUTH-04" for v in violations)

    def test_action_after_expiry_is_flagged(self) -> None:
        # Grant already expired; the subsequent actions are signed "now".
        violations = check_delegation(_covered_chain(_grant(expires_in=-10)))
        expiry = [v for v in violations if v.check_id == "SV-AUTH-05"]
        assert len(expiry) == 1
        assert expiry[0].severity == "high"
