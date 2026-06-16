"""Tests for minting a DelegationGrant from a verified Auth0 passkey token."""
from __future__ import annotations

import time

import pytest

from airsdk.containment.auth0 import Auth0Claims
from airsdk.containment.exceptions import ApprovalInvalidError
from airsdk.delegation.auth0_passkey import mint_grant_from_auth0
from airsdk.types import AuthMethod, IntentSpec


class _FakeVerifier:
    """Stands in for Auth0Verifier. ``verify`` returns claims or raises."""

    def __init__(self, claims: Auth0Claims | None) -> None:
        self._claims = claims

    def verify(self, token: str) -> Auth0Claims:
        if self._claims is None:
            raise ApprovalInvalidError("forged token")
        return self._claims


def _claims() -> Auth0Claims:
    now = int(time.time())
    return Auth0Claims(
        sub="auth0|abc123",
        email="clinician@hospital.org",
        issuer="https://example.us.auth0.com/",
        audience="agent:refactor-bot",
        issued_at=now,
        expires_at=now + 300,
        jti="jti-1",
    )


def _scope() -> IntentSpec:
    return IntentSpec(goal="Refactor the auth module", allowed_paths=["/repo/auth"])


def test_valid_token_mints_grant() -> None:
    verifier = _FakeVerifier(_claims())
    grant = mint_grant_from_auth0(
        token="header.payload.sig",  # noqa: S106
        verifier=verifier,  # type: ignore[arg-type]
        agent_id="refactor-bot",
        policy_id="eng-refactor-v2",
        policy_hash="0" * 64,
        scope=_scope(),
        ttl_seconds=900,
    )
    assert grant.auth_method == AuthMethod.AUTH0
    assert grant.authorizer_sub == "auth0|abc123"
    assert grant.authorizer_email == "clinician@hospital.org"
    assert grant.issuer == "https://example.us.auth0.com/"
    assert grant.decision == "authorize"
    assert grant.scope.goal == "Refactor the auth module"
    assert grant.proof["signed_token"] == "header.payload.sig"  # noqa: S105
    assert grant.expires_at - grant.granted_at == 900


def test_forged_token_cannot_mint_grant() -> None:
    verifier = _FakeVerifier(None)
    with pytest.raises(ApprovalInvalidError):
        mint_grant_from_auth0(
            token="bad",  # noqa: S106
            verifier=verifier,  # type: ignore[arg-type]
            agent_id="refactor-bot",
            policy_id="eng-refactor-v2",
            policy_hash="0" * 64,
            scope=_scope(),
        )
