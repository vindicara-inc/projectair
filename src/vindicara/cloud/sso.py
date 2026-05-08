"""Enterprise SSO for AIR Cloud (OIDC, including SAML→OIDC bridges).

Per-workspace OIDC configuration: trusted issuer, expected audience,
default role for just-in-time provisioned members, optional email-domain
restriction. On a verified login, a new API key is minted for the OIDC
``(iss, sub)`` pair (or an existing key is reused), bound to the
workspace via the existing role policy.

Pure OIDC at the wire level. Customers using SAML IdPs (Okta SAML,
Azure AD SAML, JumpCloud) bridge to OIDC via Auth0 / WorkOS / their own
SAML→OIDC translator and point the workspace at the OIDC issuer the
bridge exposes. That is the same approach the existing Layer 3
containment Auth0 integration uses.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

import jwt
from jwt import PyJWKClient
from jwt.exceptions import PyJWTError

if TYPE_CHECKING:
    import httpx

DEFAULT_LEEWAY_SECONDS = 30
DEFAULT_DISCOVERY_TIMEOUT = 5.0


def _now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class SsoVerificationError(ValueError):
    """A login JWT failed verification.

    Reasons include: signature does not verify against the issuer's
    JWKS; ``iss`` / ``aud`` / ``exp`` claims do not match the workspace
    SSO config; required ``sub`` or ``email`` claim missing.
    """


class SsoConfigError(ValueError):
    """Configuration was missing or malformed before verification ran."""


@dataclass(frozen=True)
class SsoConfig:
    """Per-workspace OIDC trust configuration.

    ``allowed_email_domains`` is optional; when set, only tokens whose
    ``email`` claim is in one of the listed domains are accepted. This
    is the simplest way to bind "everyone at @acme.io can log in" to a
    workspace without provisioning each user up front.
    """

    workspace_id: str
    issuer: str
    audience: str
    default_role: str = "member"
    jwks_uri: str | None = None
    allowed_email_domains: tuple[str, ...] = field(default_factory=tuple)
    updated_at: str = field(default_factory=_now_iso)

    def resolved_jwks_uri(self) -> str:
        if self.jwks_uri:
            return self.jwks_uri
        return f"{self.issuer.rstrip('/')}/.well-known/jwks.json"


@runtime_checkable
class SsoConfigStore(Protocol):
    def put(self, config: SsoConfig) -> None: ...
    def get(self, workspace_id: str) -> SsoConfig | None: ...


class InMemorySsoConfigStore:
    """Thread-safe per-workspace SSO config store."""

    def __init__(self) -> None:
        self._items: dict[str, SsoConfig] = {}
        self._lock = threading.Lock()

    def put(self, config: SsoConfig) -> None:
        with self._lock:
            self._items[config.workspace_id] = config

    def get(self, workspace_id: str) -> SsoConfig | None:
        with self._lock:
            return self._items.get(workspace_id)


def verify_oidc_token(
    token: str,
    *,
    config: SsoConfig,
    leeway_seconds: int = DEFAULT_LEEWAY_SECONDS,
    httpx_client: httpx.Client | None = None,
    jwks_client_factory: Any = None,
) -> dict[str, Any]:
    """Verify a login JWT against the workspace's SSO config.

    Returns the verified claims dict on success; raises
    :class:`SsoVerificationError` for any signature, claim, expiry, or
    domain failure. ``httpx_client`` is unused at runtime in production
    (PyJWKClient does its own fetch); the parameter exists so test
    fixtures can swap in a stub JWKS client via
    ``jwks_client_factory``.

    ``jwks_client_factory`` defaults to whatever ``PyJWKClient`` resolves
    to at call time (looked up via this module's globals so test
    monkeypatches of ``vindicara.cloud.sso.PyJWKClient`` take effect).
    """
    del httpx_client  # reserved for future use
    if not token or not isinstance(token, str):
        raise SsoVerificationError("token must be a non-empty string")
    if not config.issuer or not config.audience:
        raise SsoConfigError("SSO config must declare issuer and audience")

    factory = jwks_client_factory if jwks_client_factory is not None else PyJWKClient
    jwks_client = factory(config.resolved_jwks_uri())
    try:
        signing_key = jwks_client.get_signing_key_from_jwt(token)
    except PyJWTError as exc:
        raise SsoVerificationError(f"could not resolve signing key: {exc}") from exc
    except Exception as exc:  # network / JWKS server errors
        raise SsoVerificationError(f"jwks fetch failed: {exc}") from exc

    try:
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256", "RS384", "RS512"],
            issuer=config.issuer,
            audience=config.audience,
            leeway=leeway_seconds,
        )
    except PyJWTError as exc:
        raise SsoVerificationError(f"token verification failed: {exc}") from exc

    if "sub" not in claims or not claims["sub"]:
        raise SsoVerificationError("token has no 'sub' claim")
    email = claims.get("email")
    if config.allowed_email_domains:
        if not isinstance(email, str) or "@" not in email:
            raise SsoVerificationError("token has no usable 'email' claim for domain check")
        domain = email.split("@", 1)[1].lower()
        if domain not in {d.lower() for d in config.allowed_email_domains}:
            raise SsoVerificationError(
                f"email domain {domain!r} is not in the workspace allowlist"
            )
    return claims


__all__ = [
    "DEFAULT_LEEWAY_SECONDS",
    "InMemorySsoConfigStore",
    "SsoConfig",
    "SsoConfigError",
    "SsoConfigStore",
    "SsoVerificationError",
    "verify_oidc_token",
]
