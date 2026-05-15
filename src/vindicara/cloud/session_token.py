from __future__ import annotations

import os
import time
from dataclasses import dataclass

import jwt
from jwt.exceptions import PyJWTError

_ALGORITHM = "HS256"
_ISSUER = "air-cloud"
DEFAULT_TTL_SECONDS = 900


class SessionTokenError(Exception):
    """Raised when a session token is expired, tampered, or otherwise invalid."""


@dataclass(frozen=True)
class SessionClaims:
    workspace_id: str
    role: str
    sub: str
    key_id: str


def _load_secret() -> str:
    secret = os.environ.get("VINDICARA_SESSION_SECRET")
    if not secret:
        raise RuntimeError(
            "VINDICARA_SESSION_SECRET environment variable is required but not set"
        )
    return secret


def create_session_token(
    claims: SessionClaims,
    *,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    secret: str | None = None,
) -> str:
    resolved_secret = secret if secret is not None else _load_secret()
    now = int(time.time())
    payload: dict[str, str | int] = {
        "iss": _ISSUER,
        "iat": now,
        "exp": now + ttl_seconds,
        "sub": claims.sub,
        "workspace_id": claims.workspace_id,
        "role": claims.role,
        "key_id": claims.key_id,
    }
    return jwt.encode(payload, resolved_secret, algorithm=_ALGORITHM)


def verify_session_token(token: str, *, secret: str | None = None) -> SessionClaims:
    resolved_secret = secret if secret is not None else _load_secret()
    try:
        claims = jwt.decode(
            token,
            resolved_secret,
            algorithms=[_ALGORITHM],
            issuer=_ISSUER,
            options={"require": ["exp", "iat", "iss", "sub"]},
        )
    except PyJWTError as exc:
        raise SessionTokenError(f"token verification failed: {exc}") from exc
    try:
        return SessionClaims(
            workspace_id=str(claims["workspace_id"]),
            role=str(claims["role"]),
            sub=str(claims["sub"]),
            key_id=str(claims["key_id"]),
        )
    except KeyError as exc:
        raise SessionTokenError(f"token missing required claim: {exc}") from exc


__all__ = [
    "DEFAULT_TTL_SECONDS",
    "SessionClaims",
    "SessionTokenError",
    "create_session_token",
    "verify_session_token",
]
