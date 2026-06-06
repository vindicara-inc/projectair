"""Auth0 Bearer verification for Flightdeck console routes."""

from __future__ import annotations

import os
from dataclasses import dataclass

from airsdk.containment.auth0 import Auth0Claims, Auth0Verifier
from airsdk.containment.exceptions import ApprovalInvalidError
from fastapi import HTTPException, Request, status

_VERIFIER: Auth0Verifier | None | bool = False


@dataclass(frozen=True)
class OperatorContext:
    """Verified operator identity for console responses."""

    sub: str
    email: str | None
    name: str
    session_expires_at: int


def _resolve_verifier() -> Auth0Verifier | None:
    global _VERIFIER  # noqa: PLW0603
    if _VERIFIER is not False:
        return _VERIFIER

    domain = os.environ.get("AIR_AUTH0_DOMAIN") or os.environ.get("VINDICARA_AUTH0_DOMAIN")
    audience = os.environ.get("AIR_AUTH0_AUDIENCE") or os.environ.get("VINDICARA_AUTH0_AUDIENCE")
    issuer = os.environ.get("AIR_AUTH0_ISSUER")
    if not issuer and domain:
        issuer = f"https://{domain}/"
    if not issuer or not audience:
        _VERIFIER = None
        return None

    _VERIFIER = Auth0Verifier(issuer=issuer, audience=audience)
    return _VERIFIER


def auth0_configured() -> bool:
    return _resolve_verifier() is not None


def _claims_to_operator(claims: Auth0Claims) -> OperatorContext:
    label = claims.email or claims.sub
    if "|" in label:
        label = label.split("|", 1)[1]
    return OperatorContext(
        sub=claims.sub,
        email=claims.email,
        name=label,
        session_expires_at=claims.expires_at,
    )


def require_operator(request: Request) -> OperatorContext:
    """Validate Bearer JWT when Auth0 is configured; else allow local dev."""
    verifier = _resolve_verifier()
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header.removeprefix("Bearer ").strip()
        if not token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Empty bearer token")
        if verifier is None:
            return OperatorContext(
                sub="dev|bearer",
                email=None,
                name="Local operator",
                session_expires_at=0,
            )
        try:
            return _claims_to_operator(verifier.verify(token))
        except ApprovalInvalidError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid access token: {exc}",
            ) from exc

    if verifier is None:
        return OperatorContext(
            sub="dev|anonymous",
            email=None,
            name="Dev operator",
            session_expires_at=0,
        )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authorization required. Sign in via Auth0 and retry with a Bearer token.",
    )
