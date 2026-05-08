"""Abstract IdP adapter, capability token model, and AdapterRouter.

The IdP interface is the contract every identity provider integration must
satisfy: minting and verifying capability tokens carrying the four required
``air_*`` claims (Section 7.2). Any OIDC-compliant IdP fits.

The AdapterRouter (Section 8.4) routes ``iss`` claims to the appropriate
adapter explicitly. Unregistered issuers are rejected; there is no silent
OIDC fallback to an unknown issuer, by design.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ..exceptions import (
    ConfigurationError,
    CustomClaimMissingError,
    UnregisteredIssuerError,
)

# The four custom claims every Project AIR capability token must carry,
# regardless of IdP. See Section 7.2.
REQUIRED_AIR_CLAIMS = (
    "air_ptid",
    "air_delegation_payload_hash",
    "air_protocol_version",
    "air_target_idp_issuer",
)


@dataclass(slots=True)
class CapabilityToken:
    """A verified capability token plus parsed-out claims.

    Adapters return this from both ``issue_capability_token`` (after a
    self-verification round-trip) and ``verify_capability_token``.

    ``claims_hash_blake3`` is computed via ``BLAKE3(JCS(claims))`` over the
    full claim set, suitable for the ``capability_token.claims_hash`` field
    in handoff records.
    """

    raw_jwt: str
    jti: str
    issuer: str
    subject: str
    audience: str
    issued_at: int
    expires_at: int
    scopes: list[str]
    claims: dict[str, Any]
    claims_hash_blake3: str
    air_ptid: str
    air_delegation_payload_hash: str
    air_protocol_version: str
    air_target_idp_issuer: str


def extract_required_air_claims(claims: dict[str, Any]) -> dict[str, str]:
    """Pull the four required ``air_*`` claims out, raising if any is missing.

    Per Section 15.14, missing custom claims usually indicate the IdP-side
    injector (e.g. the Auth0 Action) is misconfigured. The error names which
    claim is absent so operators can fix the injector.
    """
    out: dict[str, str] = {}
    for name in REQUIRED_AIR_CLAIMS:
        value = claims.get(name)
        if not isinstance(value, str) or value == "":
            raise CustomClaimMissingError(
                f"capability token is missing required custom claim: {name!r}. "
                f"This usually means the IdP-side claim injector "
                f"(Auth0 Action / Okta Token Hook / Entra claims-mapping policy / "
                f"SPIRE workload selectors) is missing or misconfigured. "
                f"See Section 7.3.1 / Section 15.14.",
                failure_reason=f"missing_air_claim:{name}",
            )
        out[name] = value
    return out


class IdPAdapter(ABC):
    """Abstract base for identity provider integrations (Section 7.1)."""

    @abstractmethod
    def handled_issuers(self) -> list[str]:
        """Return the OIDC issuer URLs this adapter handles.

        The AdapterRouter uses this for explicit ``iss``-to-adapter routing
        per Section 8.4. An adapter MAY claim multiple issuers (e.g. a
        single Auth0Adapter instance configured for several tenants the
        operator trusts).
        """

    @abstractmethod
    def issue_capability_token(
        self,
        *,
        source_agent_id: str,
        target_agent_id: str,
        target_agent_idp_issuer: str,
        scopes: list[str],
        parent_trace_id: str,
        delegation_payload_hash: str,
        ttl_seconds: int = 90,
    ) -> CapabilityToken:
        """Mint a short-lived, scoped capability token for an agent-to-agent call."""

    @abstractmethod
    def verify_capability_token(
        self,
        *,
        raw_jwt: str,
        expected_audience: str,
        expected_parent_trace_id: str,
        accept_cross_tenant: bool = True,
    ) -> CapabilityToken:
        """Verify a received capability token against the issuer's JWKS."""

    @abstractmethod
    def discover_metadata(self, issuer_url: str | None = None) -> dict[str, Any]:
        """Return OIDC discovery metadata for an issuer."""


@dataclass(slots=True)
class AdapterRouter:
    """Routes ``iss`` claims to the appropriate :class:`IdPAdapter`.

    Per Section 8.4, registration is explicit and unregistered issuers are
    rejected. There is no silent fallback to OIDC Discovery against an
    unknown issuer; doing so would let an attacker inject a malicious
    issuer URL and have the verifier blindly trust it.
    """

    _table: dict[str, IdPAdapter] = field(default_factory=dict)

    def register(self, adapter: IdPAdapter) -> None:
        for issuer in adapter.handled_issuers():
            if issuer in self._table:
                raise ConfigurationError(
                    f"duplicate adapter registration for issuer: {issuer!r}"
                )
            self._table[issuer] = adapter

    def route(self, iss_claim: str) -> IdPAdapter:
        adapter = self._table.get(iss_claim)
        if adapter is None:
            raise UnregisteredIssuerError(
                f"no adapter registered for issuer: {iss_claim!r}. "
                f"Register the appropriate adapter or add it to the trust store.",
                failure_reason="unregistered_issuer",
            )
        return adapter

    def issuers(self) -> list[str]:
        return sorted(self._table)


__all__ = [
    "REQUIRED_AIR_CLAIMS",
    "AdapterRouter",
    "CapabilityToken",
    "IdPAdapter",
    "extract_required_air_claims",
]
