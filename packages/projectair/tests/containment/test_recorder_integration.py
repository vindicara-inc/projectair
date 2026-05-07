"""End-to-end containment tests: recorder + policy + Auth0 verifier.

These exercise the documented agent integration path: build a recorder
with a containment policy, attempt a tool, observe the block / step-up,
optionally approve via a verified Auth0 token, observe the approval +
resumption land on the chain.
"""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from airsdk.agdr import load_chain
from airsdk.containment import (
    Auth0Verifier,
    BlockedActionError,
    ChallengeNotFoundError,
    ContainmentPolicy,
    StepUpRequiredError,
)
from airsdk.containment.exceptions import ApprovalInvalidError
from airsdk.recorder import AIRRecorder
from airsdk.types import StepKind

if TYPE_CHECKING:
    from tests.containment.conftest import MockIdP


def _recorder(
    tmp: Path,
    policy: ContainmentPolicy | None = None,
    verifier: Auth0Verifier | None = None,
) -> AIRRecorder:
    log_path = tmp / "chain.jsonl"
    return AIRRecorder(log_path, containment=policy, auth0_verifier=verifier)


def test_blocked_tool_call_writes_blocked_record_and_raises(tmp_path: Path) -> None:
    rec = _recorder(tmp_path, policy=ContainmentPolicy(deny_tools=["shell_exec"]))
    rec.llm_start(prompt="setup")
    with pytest.raises(BlockedActionError, match="shell_exec"):
        rec.tool_start(tool_name="shell_exec", tool_args={"cmd": "rm -rf /"})

    records = load_chain(tmp_path / "chain.jsonl")
    blocked = [r for r in records if r.kind == StepKind.TOOL_START]
    assert len(blocked) == 1
    assert blocked[0].payload.blocked is True
    assert "shell_exec" in (blocked[0].payload.blocked_reason or "")


def test_step_up_writes_blocked_record_with_challenge_id(tmp_path: Path) -> None:
    rec = _recorder(
        tmp_path,
        policy=ContainmentPolicy(step_up_for_actions=[{"tool": "stripe_charge"}]),
    )
    rec.llm_start(prompt="setup")

    with pytest.raises(StepUpRequiredError) as exc_info:
        rec.tool_start(tool_name="stripe_charge", tool_args={"amount_cents": 9999})
    challenge_id = exc_info.value.challenge_id
    assert challenge_id

    records = load_chain(tmp_path / "chain.jsonl")
    halted = [r for r in records if r.kind == StepKind.TOOL_START]
    assert len(halted) == 1
    assert halted[0].payload.blocked is True
    assert halted[0].payload.challenge_id == challenge_id


def test_approve_with_verified_token_resumes_action(
    tmp_path: Path, mock_idp: MockIdP,
) -> None:
    verifier = Auth0Verifier(mock_idp.issuer, mock_idp.audience, jwks_uri=mock_idp.jwks_uri)
    rec = _recorder(
        tmp_path,
        policy=ContainmentPolicy(step_up_for_actions=[{"tool": "stripe_charge"}]),
        verifier=verifier,
    )
    rec.llm_start(prompt="setup")
    try:
        rec.tool_start(tool_name="stripe_charge", tool_args={"amount_cents": 9999})
        raise AssertionError("expected StepUpRequiredError")
    except StepUpRequiredError as e:
        challenge_id = e.challenge_id

    token = mock_idp.issue_token(sub="auth0|finance-lead", email="finance@example.com")
    approval_record = rec.approve(challenge_id, token)
    assert approval_record.kind == StepKind.HUMAN_APPROVAL
    assert approval_record.payload.human_approval is not None
    assert approval_record.payload.human_approval.approver_sub == "auth0|finance-lead"
    assert approval_record.payload.human_approval.approver_email == "finance@example.com"
    assert approval_record.payload.human_approval.signed_token == token

    records = load_chain(tmp_path / "chain.jsonl")
    kinds = [r.kind.value for r in records]
    # Sequence: llm_start, blocked tool_start, human_approval, resumed tool_start
    assert kinds == ["llm_start", "tool_start", "human_approval", "tool_start"]
    blocked, resumed = records[1], records[3]
    assert blocked.payload.blocked is True
    assert resumed.payload.blocked is None
    assert resumed.payload.tool_name == "stripe_charge"


def test_approve_with_forged_token_raises_and_keeps_action_halted(
    tmp_path: Path, mock_idp: MockIdP,
) -> None:
    """An attacker submitting a forged token must not drive the agent
    forward. The action stays blocked; no resumed TOOL_START is written."""
    import time as _time

    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
    )

    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attacker_pem = attacker_key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption(),
    )
    forged = jwt.encode(
        {
            "iss": mock_idp.issuer,
            "aud": mock_idp.audience,
            "sub": "auth0|forged",
            "iat": int(_time.time()),
            "exp": int(_time.time()) + 300,
        },
        attacker_pem,
        algorithm="RS256",
        headers={"kid": mock_idp.kid},
    )

    verifier = Auth0Verifier(mock_idp.issuer, mock_idp.audience, jwks_uri=mock_idp.jwks_uri)
    rec = _recorder(
        tmp_path,
        policy=ContainmentPolicy(step_up_for_actions=[{"tool": "send_email"}]),
        verifier=verifier,
    )
    rec.llm_start(prompt="setup")
    try:
        rec.tool_start(tool_name="send_email", tool_args={"to": "x@y.com"})
        raise AssertionError("expected StepUpRequiredError")
    except StepUpRequiredError as e:
        challenge_id = e.challenge_id

    with pytest.raises(ApprovalInvalidError):
        rec.approve(challenge_id, forged)

    records = load_chain(tmp_path / "chain.jsonl")
    kinds = [r.kind.value for r in records]
    # Only the original llm_start and the blocked tool_start landed; no
    # human_approval, no resumed tool_start.
    assert kinds == ["llm_start", "tool_start"]


def test_approve_with_unknown_challenge_raises(
    tmp_path: Path, mock_idp: MockIdP,
) -> None:
    verifier = Auth0Verifier(mock_idp.issuer, mock_idp.audience, jwks_uri=mock_idp.jwks_uri)
    rec = _recorder(tmp_path, policy=ContainmentPolicy(), verifier=verifier)
    token = mock_idp.issue_token()
    with pytest.raises(ChallengeNotFoundError):
        rec.approve("never-issued-challenge", token)


def test_recorder_without_policy_works_unchanged(tmp_path: Path) -> None:
    rec = _recorder(tmp_path)  # no policy, no verifier
    rec.llm_start(prompt="hi")
    rec.tool_start(tool_name="anything", tool_args={"x": 1})
    records = load_chain(tmp_path / "chain.jsonl")
    assert len(records) == 2
    assert all(r.payload.blocked is None for r in records)
