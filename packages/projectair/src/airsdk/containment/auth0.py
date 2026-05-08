"""Auth0 token verification for human-approval step-up flows.

A Layer 3 step-up halt requires a human to authenticate against the
operator's Auth0 tenant and submit the resulting access token. This
module verifies the token: signature against Auth0's published JWKS,
issuer match, audience match, expiration check. Only verified tokens
produce ``Auth0Claims``; any failure raises
``ApprovalInvalidError`` so the recorder can keep the action halted.

Why Auth0 (not "any IdP"): Auth0 ships a JWKS endpoint at a predictable
URL (``https://<tenant>/.well-known/jwks.json``), uses RS256 by default,
and includes ``email`` and ``email_verified`` claims that the chain
records as the approver identity. Other OIDC providers (Okta, Azure AD,
Google Workspace) follow the same pattern; the verifier is named for
Auth0 because that is the documented integration in v1, but the
implementation is a generic JWKS-backed JWT verifier and accepts any
issuer URL with a JWKS endpoint.

The hosted approval router and policy management surface live in the
commercial ``projectair-pro`` tier; this module is the primitive every
tier builds on.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

import jwt
from jwt import PyJWKClient

from airsdk.containment.exceptions import ApprovalInvalidError


@dataclass(frozen=True)
class Auth0Claims:
    """Verified claims extracted from a successful token verification."""

    sub: str           # user id at the IdP, e.g. "auth0|abc123"
    email: str | None  # only present when the access token was minted with the email scope
    issuer: str
    audience: str
    issued_at: int
    expires_at: int
    jti: str | None    # JWT ID, when the issuer included one for replay defense


class Auth0Verifier:
    """Verify Auth0-issued JWTs against a tenant's JWKS endpoint.

    Parameters
    ----------
    issuer:
        The tenant's issuer URL, e.g. ``https://example.us.auth0.com/``.
        Trailing slash is significant; use whatever Auth0's tenant
        settings show. Verifier rejects tokens whose ``iss`` does not
        match exactly.
    audience:
        The API identifier the access token was minted for, e.g.
        ``https://api.vindicara.io``. Verifier rejects tokens whose
        ``aud`` does not include this value.
    jwks_uri:
        Optional override for the JWKS endpoint. Defaults to
        ``<issuer>.well-known/jwks.json`` per OIDC discovery
        convention. Pass an explicit URL when running against a mock
        issuer in tests.
    leeway_seconds:
        Clock skew tolerance for ``exp``/``iat`` checks. Default 30s.
    """

    def __init__(
        self,
        issuer: str,
        audience: str,
        *,
        jwks_uri: str | None = None,
        leeway_seconds: float = 30.0,
    ) -> None:
        if not issuer.endswith("/"):
            issuer = issuer + "/"
        self._issuer = issuer
        self._audience = audience
        self._leeway = leeway_seconds
        self._jwks_client = PyJWKClient(
            jwks_uri or f"{issuer}.well-known/jwks.json",
            cache_keys=True,
        )

    @property
    def issuer(self) -> str:
        return self._issuer

    @property
    def audience(self) -> str:
        return self._audience

    def verify(self, token: str) -> Auth0Claims:
        """Verify ``token`` against the configured issuer and audience.

        Returns ``Auth0Claims`` on success. Raises
        ``ApprovalInvalidError`` for any failure: bad signature, wrong
        issuer, wrong audience, expired, malformed.
        """
        try:
            signing_key = self._jwks_client.get_signing_key_from_jwt(token).key
        except Exception as exc:
            raise ApprovalInvalidError(f"could not resolve signing key: {exc}") from exc

        try:
            claims = jwt.decode(
                token,
                signing_key,
                algorithms=["RS256", "RS384", "RS512"],
                audience=self._audience,
                issuer=self._issuer,
                leeway=self._leeway,
            )
        except jwt.ExpiredSignatureError as exc:
            raise ApprovalInvalidError("token expired") from exc
        except jwt.InvalidAudienceError as exc:
            raise ApprovalInvalidError(f"audience mismatch: {exc}") from exc
        except jwt.InvalidIssuerError as exc:
            raise ApprovalInvalidError(f"issuer mismatch: {exc}") from exc
        except jwt.InvalidSignatureError as exc:
            raise ApprovalInvalidError("signature did not verify") from exc
        except jwt.PyJWTError as exc:
            raise ApprovalInvalidError(f"token rejected: {exc}") from exc

        sub = claims.get("sub")
        if not sub:
            raise ApprovalInvalidError("token missing 'sub' claim")

        email = claims.get("email")
        if email is not None and not isinstance(email, str):
            raise ApprovalInvalidError("'email' claim must be a string when present")

        return Auth0Claims(
            sub=sub,
            email=email,
            issuer=self._issuer,
            audience=self._audience,
            issued_at=int(claims.get("iat", time.time())),
            expires_at=int(claims["exp"]),
            jti=claims.get("jti"),
        )
