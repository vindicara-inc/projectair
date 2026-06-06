"""Phase 2 delegation auth: native WebAuthn.

The biometric never leaves the device. Registration stores only the credential
public key; authentication verifies an assertion signature against it. This is
what lets Vindicara say truthfully that it never holds the biometric.

Built on py_webauthn (``pip install 'projectair[webauthn]'``). The functions
here are thin wrappers that (a) produce challenge options for the browser
ceremony and (b) verify the browser's response, then mint a DelegationGrant
from a verified authentication.

Credential storage (the public key, sign count, and user handle per
credential_id) is the operator's responsibility. For the MVP a small table in
the customer's own database is fine; nothing here phones home.
"""
from __future__ import annotations

import base64
import time
import uuid
from dataclasses import dataclass

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from airsdk.types import AuthMethod, DelegationGrant, IntentSpec


@dataclass
class StoredCredential:
    """What the operator persists per registered authenticator."""

    credential_id: bytes
    public_key: bytes
    sign_count: int
    user_handle: str
    user_email: str | None = None


# --- Registration (one-time, enroll a human's passkey) --------------------

def registration_options(
    *, rp_id: str, rp_name: str, user_email: str, user_handle: str | None = None
) -> tuple[str, str]:
    """Return (options_json, challenge_b64) for navigator.credentials.create.

    Persist ``challenge_b64`` against the session; you need it to verify.
    """
    handle = user_handle or str(uuid.uuid4())
    opts = generate_registration_options(
        rp_id=rp_id,
        rp_name=rp_name,
        user_name=user_email,
        user_id=handle.encode(),
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED,  # require biometric/PIN
        ),
    )
    return options_to_json(opts), _b64(opts.challenge)


def verify_registration(
    *,
    credential_json: str,
    expected_challenge_b64: str,
    rp_id: str,
    origin: str,
    user_handle: str,
    user_email: str | None = None,
) -> StoredCredential:
    """Verify a registration response; return the credential to persist."""
    verification = verify_registration_response(
        credential=credential_json,
        expected_challenge=_unb64(expected_challenge_b64),
        expected_rp_id=rp_id,
        expected_origin=origin,
        require_user_verification=True,
    )
    return StoredCredential(
        credential_id=verification.credential_id,
        public_key=verification.credential_public_key,
        sign_count=verification.sign_count,
        user_handle=user_handle,
        user_email=user_email,
    )


# --- Authentication (the authorize ceremony) ------------------------------

def authentication_options(
    *, rp_id: str, allow_credential_ids: list[bytes] | None = None
) -> tuple[str, str]:
    """Return (options_json, challenge_b64) for navigator.credentials.get."""
    allow = (
        [PublicKeyCredentialDescriptor(id=cid) for cid in allow_credential_ids]
        if allow_credential_ids
        else None
    )
    opts = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=allow,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    return options_to_json(opts), _b64(opts.challenge)


def verify_webauthn_assertion(
    *, credential_json: str, expected_challenge_b64: str, rp_id: str, origin: str, stored: StoredCredential
) -> int:
    """Verify an authentication assertion. Returns the new sign_count.

    Raises if the signature, challenge, origin, rp_id, or user-verification flag
    is wrong. Persist the returned sign_count to defend against cloned
    authenticators (a non-increasing counter is a red flag).
    """
    verification = verify_authentication_response(
        credential=credential_json,
        expected_challenge=_unb64(expected_challenge_b64),
        expected_rp_id=rp_id,
        expected_origin=origin,
        credential_public_key=stored.public_key,
        credential_current_sign_count=stored.sign_count,
        require_user_verification=True,
    )
    return verification.new_sign_count


def mint_grant_from_webauthn(
    *,
    stored: StoredCredential,
    credential_json: str,
    agent_id: str,
    policy_id: str,
    policy_hash: str,
    scope: IntentSpec,
    ttl_seconds: int = 3600,
) -> DelegationGrant:
    """Build a DelegationGrant from a verified WebAuthn authentication.

    ``credential_json`` is stored in ``proof`` so an offline verifier can
    re-check the assertion against ``stored.public_key`` with no live call.
    """
    now = int(time.time())
    return DelegationGrant(
        delegation_id=str(uuid.uuid4()),
        agent_id=agent_id,
        decision="authorize",
        auth_method=AuthMethod.WEBAUTHN,
        authorizer_sub=stored.user_handle,
        authorizer_email=stored.user_email,
        issuer=None,
        credential_id=_b64(stored.credential_id),
        policy_id=policy_id,
        policy_hash=policy_hash,
        scope=scope,
        granted_at=now,
        expires_at=now + ttl_seconds,
        proof={
            "assertion": credential_json,
            "credential_public_key_b64": _b64(stored.public_key),
        },
    )


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
