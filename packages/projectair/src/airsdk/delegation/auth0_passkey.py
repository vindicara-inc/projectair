"""Phase 1 delegation auth: reuse the shipped Auth0Verifier.

Auth0 supports passkeys as an authenticator, so a passkey login produces an
OIDC token that ``containment.Auth0Verifier`` already validates (the same
verifier the Layer 3 step-up flow uses in ``AIRRecorder.approve``). This gets
the human-binding live with zero new cryptography.

Native WebAuthn (``airsdk.delegation.webauthn``) is the next increment, for the
"biometric never leaves the device, Vindicara never stores it" guarantee.
"""
from __future__ import annotations

import time
import uuid

from airsdk.containment import Auth0Verifier
from airsdk.types import AuthMethod, DelegationGrant, IntentSpec


def mint_grant_from_auth0(
    *,
    token: str,
    verifier: Auth0Verifier,
    agent_id: str,
    policy_id: str,
    policy_hash: str,
    scope: IntentSpec,
    ttl_seconds: int = 3600,
) -> DelegationGrant:
    """Verify an Auth0 passkey token and mint a DelegationGrant.

    ``verifier.verify`` raises if the token is invalid, expired, or has the
    wrong issuer/audience, so a forged token cannot mint a grant. The original
    signed token is stored in ``proof`` for offline re-verification against the
    IdP's public JWKS.
    """
    claims = verifier.verify(token)  # raises on invalid; same path as approve()

    now = int(time.time())
    return DelegationGrant(
        delegation_id=str(uuid.uuid4()),
        agent_id=agent_id,
        decision="authorize",
        auth_method=AuthMethod.AUTH0,
        authorizer_sub=claims.sub,
        authorizer_email=claims.email,
        issuer=claims.issuer,
        credential_id=None,
        policy_id=policy_id,
        policy_hash=policy_hash,
        scope=scope,
        granted_at=now,
        expires_at=now + ttl_seconds,
        proof={
            "signed_token": token,
            "jti": claims.jti,
            "audience": claims.audience,
        },
    )
