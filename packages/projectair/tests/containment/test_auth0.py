"""Auth0Verifier tests against an in-process JWKS-backed mock IdP.

These exercise the real PyJWT verification path. The only difference
from a real Auth0 tenant is the issuer URL and JWKS location; the
verifier cannot tell them apart.
"""
from __future__ import annotations

import time
from typing import TYPE_CHECKING

import jwt
import pytest

from airsdk.containment.auth0 import Auth0Verifier
from airsdk.containment.exceptions import ApprovalInvalidError

if TYPE_CHECKING:
    from tests.containment.conftest import MockIdP


def _verifier(idp: MockIdP) -> Auth0Verifier:
    return Auth0Verifier(
        issuer=idp.issuer,
        audience=idp.audience,
        jwks_uri=idp.jwks_uri,
    )


def test_verify_returns_claims_for_valid_token(mock_idp: MockIdP) -> None:
    verifier = _verifier(mock_idp)
    token = mock_idp.issue_token()
    claims = verifier.verify(token)
    assert claims.sub == "auth0|test-user"
    assert claims.email == "approver@example.com"
    assert claims.issuer == mock_idp.issuer
    assert claims.audience == mock_idp.audience
    assert claims.expires_at > claims.issued_at


def test_verify_rejects_token_for_wrong_audience(mock_idp: MockIdP) -> None:
    verifier = _verifier(mock_idp)
    bad_token = jwt.encode(
        {
            "iss": mock_idp.issuer,
            "aud": "https://other-api.example.com",
            "sub": "auth0|x",
            "iat": int(time.time()),
            "exp": int(time.time()) + 60,
        },
        mock_idp.private_pem,
        algorithm="RS256",
        headers={"kid": mock_idp.kid},
    )
    with pytest.raises(ApprovalInvalidError, match="audience"):
        verifier.verify(bad_token)


def test_verify_rejects_token_for_wrong_issuer(mock_idp: MockIdP) -> None:
    verifier = _verifier(mock_idp)
    bad_token = jwt.encode(
        {
            "iss": "https://attacker.example.com/",
            "aud": mock_idp.audience,
            "sub": "auth0|x",
            "iat": int(time.time()),
            "exp": int(time.time()) + 60,
        },
        mock_idp.private_pem,
        algorithm="RS256",
        headers={"kid": mock_idp.kid},
    )
    with pytest.raises(ApprovalInvalidError, match="issuer"):
        verifier.verify(bad_token)


def test_verify_rejects_expired_token(mock_idp: MockIdP) -> None:
    verifier = _verifier(mock_idp)
    expired = mock_idp.issue_token(ttl_seconds=-3600)
    with pytest.raises(ApprovalInvalidError, match="expired"):
        verifier.verify(expired)


def test_verify_rejects_token_signed_by_attacker_key(mock_idp: MockIdP) -> None:
    """Token claims a valid issuer/audience but is signed by a key not
    in the JWKS. Verifier must reject - this is the primary attack we
    care about."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
    )

    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attacker_pem = attacker_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    forged = jwt.encode(
        {
            "iss": mock_idp.issuer,
            "aud": mock_idp.audience,
            "sub": "auth0|forged",
            "iat": int(time.time()),
            "exp": int(time.time()) + 60,
        },
        attacker_pem,
        algorithm="RS256",
        headers={"kid": mock_idp.kid},  # claim same kid; signature is what fails
    )
    verifier = _verifier(mock_idp)
    with pytest.raises(ApprovalInvalidError):
        verifier.verify(forged)


def test_verify_rejects_token_missing_sub_claim(mock_idp: MockIdP) -> None:
    """Tokens without ``sub`` cannot identify the approver and must be
    rejected."""
    verifier = _verifier(mock_idp)
    no_sub = jwt.encode(
        {
            "iss": mock_idp.issuer,
            "aud": mock_idp.audience,
            "iat": int(time.time()),
            "exp": int(time.time()) + 60,
        },
        mock_idp.private_pem,
        algorithm="RS256",
        headers={"kid": mock_idp.kid},
    )
    with pytest.raises(ApprovalInvalidError):
        verifier.verify(no_sub)


def test_verify_rejects_garbage_input(mock_idp: MockIdP) -> None:
    verifier = _verifier(mock_idp)
    with pytest.raises(ApprovalInvalidError):
        verifier.verify("not.a.real.jwt")
