"""Auth0 reference IdP adapter (Section 7.3).

Wave 1 ships verification against any RS256 OIDC issuer reachable at
``{issuer}.well-known/jwks.json``. Issuance has two modes:

  - **Production mode** (``client_id`` + ``client_secret`` supplied): calls
    Auth0's ``/oauth/token`` endpoint with the M2M / Client Credentials grant.
    The four ``air_*`` claims are passed in the request body. Production
    deployments MUST have an Auth0 Action attached to the
    ``credentials-exchange`` trigger that lifts those parameters into custom
    access-token claims (see Section 7.3.1). Without the Action, Auth0
    silently strips the parameters and verification hard-fails downstream.

  - **Local-signing mode** (``signing_key_pem`` + ``signing_kid`` supplied):
    mints tokens directly with PyJWT against a local RSA key. Used for
    Wave 1 demos and tests; the in-process JWKS server stands in for Auth0.

Verification is identical in both modes: the JWT signature is validated
against the JWKS exposed at the configured issuer's well-known endpoint.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx
import jwt
from jwt.exceptions import InvalidTokenError, PyJWTError

from ..canonicalize import canonicalize_and_hash
from ..exceptions import (
    CapabilityTokenInvalidError,
    ConfigurationError,
    IdPDiscoveryError,
    RekorSubmissionError,
)
from ..handoff_record import PROTOCOL_VERSION
from .base import (
    REQUIRED_AIR_CLAIMS,
    CapabilityToken,
    IdPAdapter,
    extract_required_air_claims,
)

DEFAULT_LEEWAY_SECONDS = 30
DEFAULT_TTL_SECONDS = 90
MAX_TTL_SECONDS = 600
DEFAULT_DISCOVERY_TIMEOUT = 5.0


@dataclass(slots=True)
class Auth0Adapter(IdPAdapter):
    """Auth0 reference adapter; works against any OIDC issuer with JWKS."""

    domain: str
    audience: str
    issuer: str = ""
    jwks_uri: str = ""
    leeway_seconds: int = DEFAULT_LEEWAY_SECONDS

    # Production mode (calls Auth0 /oauth/token)
    client_id: str | None = None
    client_secret: str | None = None
    token_endpoint: str = ""

    # Local-signing mode (PyJWT against a local RSA key, for tests and demos)
    signing_key_pem: bytes | None = None
    signing_kid: str | None = None
    signing_alg: str = "RS256"

    # Construction-time fields
    _http: httpx.Client = field(default=None, repr=False)  # type: ignore[assignment]
    _jwks_cache: dict[str, dict[str, Any]] = field(default_factory=dict, repr=False)

    # Verify-only mode: no signing key and no client credentials. Issuance
    # raises ConfigurationError; verification works against the configured
    # JWKS. This is the typical deployment shape for a verifier service.
    verify_only: bool = False

    def __post_init__(self) -> None:
        if not self.issuer:
            self.issuer = f"https://{self.domain}/"
        if not self.jwks_uri:
            self.jwks_uri = f"{self.issuer}.well-known/jwks.json"
        if not self.token_endpoint:
            self.token_endpoint = f"{self.issuer}oauth/token"
        if self._http is None:
            self._http = httpx.Client(timeout=DEFAULT_DISCOVERY_TIMEOUT)

        has_local = self.signing_key_pem is not None and self.signing_kid is not None
        has_remote = self.client_id is not None and self.client_secret is not None
        if not (has_local or has_remote or self.verify_only):
            raise ConfigurationError(
                "Auth0Adapter needs (signing_key_pem + signing_kid) for "
                "local-signing mode OR (client_id + client_secret) for production "
                "mode OR verify_only=True for a pure verifier"
            )

    def handled_issuers(self) -> list[str]:
        return [self.issuer]

    def discover_metadata(self, issuer_url: str | None = None) -> dict[str, Any]:
        target = issuer_url or self.issuer
        url = f"{target.rstrip('/')}/.well-known/openid-configuration"
        try:
            resp = self._http.get(url)
            resp.raise_for_status()
            return resp.json()  # type: ignore[no-any-return]
        except (httpx.HTTPError, ValueError) as e:
            raise IdPDiscoveryError(
                f"OIDC discovery failed for {target!r}: {e}"
            ) from e

    def _fetch_jwks(self, issuer_url: str) -> dict[str, Any]:
        cached = self._jwks_cache.get(issuer_url)
        if cached is not None:
            return cached
        if issuer_url == self.issuer:
            url = self.jwks_uri
        else:
            metadata = self.discover_metadata(issuer_url)
            url = metadata.get("jwks_uri", "")
            if not url:
                raise IdPDiscoveryError(
                    f"discovery for {issuer_url!r} did not return jwks_uri"
                )
        try:
            resp = self._http.get(url)
            resp.raise_for_status()
            jwks = resp.json()
        except (httpx.HTTPError, ValueError) as e:
            raise IdPDiscoveryError(f"JWKS fetch failed: {e}") from e
        self._jwks_cache[issuer_url] = jwks
        return jwks  # type: ignore[no-any-return]

    def _signing_key_for(self, issuer_url: str, kid: str) -> Any:
        jwks = self._fetch_jwks(issuer_url)
        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                return jwt.algorithms.RSAAlgorithm.from_jwk(key)
        raise CapabilityTokenInvalidError(
            f"no JWKS entry with kid={kid!r} at issuer {issuer_url!r}",
            failure_reason="jwks_kid_not_found",
        )

    def issue_capability_token(
        self,
        *,
        source_agent_id: str,
        target_agent_id: str,
        target_agent_idp_issuer: str,
        scopes: list[str],
        parent_trace_id: str,
        delegation_payload_hash: str,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> CapabilityToken:
        if ttl_seconds <= 0 or ttl_seconds > MAX_TTL_SECONDS:
            raise ConfigurationError(
                f"capability token ttl must be 1..{MAX_TTL_SECONDS} seconds; "
                f"got {ttl_seconds}"
            )
        if self.verify_only:
            raise ConfigurationError(
                "Auth0Adapter is configured verify_only=True; cannot issue tokens"
            )
        # Production mode (real Auth0 tenant) takes precedence over local
        # signing mode when both are configured. Local signing is for unit
        # tests only; never the production path.
        if self.client_id is not None and self.client_secret is not None:
            return self._issue_via_auth0_token_endpoint(
                source_agent_id=source_agent_id,
                target_agent_id=target_agent_id,
                target_agent_idp_issuer=target_agent_idp_issuer,
                scopes=scopes,
                parent_trace_id=parent_trace_id,
                delegation_payload_hash=delegation_payload_hash,
            )
        if self.signing_key_pem is None or self.signing_kid is None:
            raise ConfigurationError(
                "Auth0Adapter has no client_id+client_secret (production mode) "
                "and no signing_key_pem+signing_kid (test mode)"
            )
        import time as _time
        now = int(_time.time())
        jti = f"tok_{parent_trace_id[:8]}_{now}_{source_agent_id}"
        claims: dict[str, Any] = {
            "iss": self.issuer,
            "sub": source_agent_id,
            "aud": target_agent_id,
            "exp": now + ttl_seconds,
            "iat": now,
            "jti": jti,
            "scope": " ".join(scopes),
            "air_ptid": parent_trace_id,
            "air_delegation_payload_hash": delegation_payload_hash,
            "air_protocol_version": PROTOCOL_VERSION,
            "air_target_idp_issuer": target_agent_idp_issuer,
        }
        try:
            raw_jwt = jwt.encode(
                claims,
                self.signing_key_pem,
                algorithm=self.signing_alg,
                headers={"kid": self.signing_kid},
            )
        except PyJWTError as e:
            raise CapabilityTokenInvalidError(
                f"local issuance failed: {e}"
            ) from e
        return self.verify_capability_token(
            raw_jwt=raw_jwt,
            expected_audience=target_agent_id,
            expected_parent_trace_id=parent_trace_id,
        )

    def _issue_via_auth0_token_endpoint(
        self,
        *,
        source_agent_id: str,
        target_agent_id: str,
        target_agent_idp_issuer: str,
        scopes: list[str],
        parent_trace_id: str,
        delegation_payload_hash: str,
    ) -> CapabilityToken:
        """Mint a capability token via Auth0's /oauth/token endpoint.

        Posts an M2M / Client Credentials grant request and passes the four
        ``air_*`` parameters in the request body. Auth0 itself strips
        unknown body parameters, so the tenant MUST have an Auth0 Action
        attached to the ``credentials-exchange`` trigger that lifts these
        into custom access-token claims (Section 7.3.1). Without the Action,
        the issued token will fail Layer 4 verification with
        ``CustomClaimMissingError`` — that is the canonical signal that
        the Action is missing or not deployed.
        """
        body = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "audience": target_agent_id,
            "grant_type": "client_credentials",
            "scope": " ".join(scopes),
            # Read by the Auth0 Action and lifted to custom claims:
            "air_ptid": parent_trace_id,
            "air_delegation_payload_hash": delegation_payload_hash,
            "air_protocol_version": PROTOCOL_VERSION,
            "air_target_idp_issuer": target_agent_idp_issuer,
            "air_source_agent_id": source_agent_id,
        }
        try:
            resp = self._http.post(
                self.token_endpoint,
                json=body,
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            payload = resp.json()
        except httpx.HTTPStatusError as e:
            raise CapabilityTokenInvalidError(
                f"Auth0 /oauth/token rejected: {e.response.status_code} "
                f"{e.response.text[:300]}"
            ) from e
        except (httpx.HTTPError, ValueError) as e:
            raise CapabilityTokenInvalidError(
                f"Auth0 /oauth/token round-trip failed: {e}"
            ) from e
        raw_jwt = payload.get("access_token")
        if not isinstance(raw_jwt, str) or not raw_jwt:
            raise CapabilityTokenInvalidError(
                f"Auth0 /oauth/token returned no access_token: keys={list(payload)}"
            )
        # Self-verify. If the Auth0 Action is missing, this raises
        # CustomClaimMissingError pointing the operator at Section 7.3.1.
        return self.verify_capability_token(
            raw_jwt=raw_jwt,
            expected_audience=target_agent_id,
            expected_parent_trace_id=parent_trace_id,
        )

    def verify_capability_token(
        self,
        *,
        raw_jwt: str,
        expected_audience: str,
        expected_parent_trace_id: str,
        accept_cross_tenant: bool = False,
    ) -> CapabilityToken:
        try:
            unverified_header = jwt.get_unverified_header(raw_jwt)
            unverified_claims = jwt.decode(
                raw_jwt, options={"verify_signature": False}
            )
        except InvalidTokenError as e:
            raise CapabilityTokenInvalidError(f"malformed JWT: {e}") from e

        kid = unverified_header.get("kid")
        if not kid:
            raise CapabilityTokenInvalidError("JWT header missing kid")
        iss = unverified_claims.get("iss")
        if not isinstance(iss, str):
            raise CapabilityTokenInvalidError("JWT missing iss claim")
        if iss != self.issuer and not accept_cross_tenant:
            raise CapabilityTokenInvalidError(
                f"cross-tenant token rejected (iss={iss!r}, accept_cross_tenant=False)"
            )
        signing_key = self._signing_key_for(iss, kid)
        try:
            claims = jwt.decode(
                raw_jwt,
                signing_key,
                algorithms=[self.signing_alg],
                audience=expected_audience,
                issuer=iss,
                leeway=self.leeway_seconds,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except InvalidTokenError as e:
            raise CapabilityTokenInvalidError(
                f"JWT verification failed: {e}",
                failure_reason="jwt_invalid",
            ) from e

        # Auth0 M2M access tokens do not expose `jti` via setCustomClaim
        # (Auth0 protects standard registered claims). When absent, derive
        # a deterministic synthetic JTI from the JWT bytes themselves so
        # source/target chain pairing still works. The synthetic JTI is
        # unique per token (BLAKE3 of the JWS) and reproducible by anyone
        # holding the same JWT.
        if "jti" not in claims:
            from blake3 import blake3 as _blake3
            claims["jti"] = "synthetic:" + _blake3(raw_jwt.encode("ascii")).hexdigest()[:32]

        air_claims = extract_required_air_claims(claims)
        if air_claims["air_ptid"] != expected_parent_trace_id:
            raise CapabilityTokenInvalidError(
                f"air_ptid mismatch: token has {air_claims['air_ptid']!r}, "
                f"expected {expected_parent_trace_id!r}",
                failure_reason="air_ptid_mismatch",
            )
        if air_claims["air_protocol_version"] != PROTOCOL_VERSION:
            raise CapabilityTokenInvalidError(
                f"air_protocol_version unsupported: "
                f"{air_claims['air_protocol_version']!r}",
                failure_reason="protocol_version_unsupported",
            )

        scope_str = claims.get("scope", "")
        scopes = scope_str.split() if isinstance(scope_str, str) else []
        return CapabilityToken(
            raw_jwt=raw_jwt,
            jti=claims["jti"],
            issuer=iss,
            subject=claims["sub"],
            audience=expected_audience,
            issued_at=int(claims["iat"]),
            expires_at=int(claims["exp"]),
            scopes=scopes,
            claims=dict(claims),
            claims_hash_blake3=canonicalize_and_hash(dict(claims)),
            air_ptid=air_claims["air_ptid"],
            air_delegation_payload_hash=air_claims["air_delegation_payload_hash"],
            air_protocol_version=air_claims["air_protocol_version"],
            air_target_idp_issuer=air_claims["air_target_idp_issuer"],
        )


__all__ = ["DEFAULT_TTL_SECONDS", "MAX_TTL_SECONDS", "Auth0Adapter"]


# Defensive import bookkeeping: kept exported so consumers can sanity-check
# they are working with the canonical claim list and not a typo'd subset.
_ = (REQUIRED_AIR_CLAIMS, RekorSubmissionError)
