"""Layer 4 (AgDR Handoff Protocol) exception hierarchy per Section 10 of the spec.

Every failure mode the handoff stack can produce is one of these. The verifier
contract is fail-closed: any uncaught exception MUST surface as a verification
failure and the handoff record MUST NOT be accepted.

Each exception carries optional ``failed_step_n``, ``failed_record_hash``, and
``failure_reason`` attributes so the CLI and verifier can produce precise
diagnostics. The base class accepts these as keyword arguments and exposes
them on the instance.
"""
from __future__ import annotations

from typing import Any


class HandoffError(Exception):
    """Base class for every Layer 4 handoff error."""

    def __init__(
        self,
        message: str = "",
        *,
        failed_step_n: int | None = None,
        failed_record_hash: str | None = None,
        failure_reason: str | None = None,
        **extra: Any,
    ) -> None:
        super().__init__(message)
        self.failed_step_n = failed_step_n
        self.failed_record_hash = failed_record_hash
        self.failure_reason = failure_reason or message
        self.extra: dict[str, Any] = dict(extra)


class CanonicalizationError(HandoffError):
    """RFC 8785 JCS canonicalization failed.

    Either the payload contains a non-JSON-primitive type (bytes, datetime,
    UUID, etc.) that the caller did not pre-normalize, or the underlying jcs
    library rejected the input. The message includes a JSONPath-style
    location for the offending field per Section 15.11.
    """


class PTIDInvalidError(HandoffError):
    """Parent Trace ID format is invalid (must be 32 lowercase hex)."""


class W3CTraceContextError(HandoffError):
    """W3C traceparent or tracestate is malformed or inconsistent."""


class HandoffRecordInvalidError(HandoffError):
    """A handoff record is malformed or fails integrity checks."""


class HandoffAcceptanceMissingError(HandoffError):
    """A handoff record has no matching acceptance within the policy timeout."""


class HandoffPairingError(HandoffError):
    """A handoff and acceptance exist but their fields do not match."""


class CapabilityTokenInvalidError(HandoffError):
    """A capability token failed signature, expiry, audience, or claims validation."""


class CrossTenantTrustError(HandoffError):
    """Cross-tenant handoff failed identity or OIDC discovery validation."""


class ValidationProofInvalidError(HandoffError):
    """A Rekor validation proof failed verification.

    Covers Rekor entry missing, signature wrong, payload-hash mismatch,
    timestamp outside skew, or attestation tampering.
    """


class RekorSubmissionError(HandoffError):
    """Rekor submission failed (network error, rate limit, authentication failure)."""


class IdPDiscoveryError(HandoffError):
    """OIDC discovery against the IdP failed."""


class IdPNotImplementedError(HandoffError):
    """The requested IdP adapter is not yet implemented in this version.

    Raised by the placeholder Okta, Entra, and SPIFFE adapters in v1.
    """


class UnregisteredIssuerError(HandoffError):
    """The token's iss claim has no registered IdP adapter in the AdapterRouter.

    Per Section 8.4, the verifier does not silently fall back to OIDC
    Discovery against an unknown issuer; operators must explicitly register
    adapters for every expected issuer.
    """


class CrossAgentVerificationError(HandoffError):
    """Cross-agent chain set verification failed at one of the eight steps."""


class IdentityCertificateError(HandoffError):
    """Sigstore Fulcio cert validation failed (chain broken, revoked, expired)."""


class ReplayAnomalyError(HandoffError):
    """Two or more handoff_acceptance records reference the same source_handoff_record_hash.

    Per Section 6.7, the verifier hard-fails on this and rejects the entire
    chain set; branching the causal graph or selecting "the first" acceptance
    is explicitly forbidden.
    """


class TemporalOrderingError(HandoffError):
    """Cross-agent temporal ordering check failed at the lower or upper bound.

    Per Section 8.2 step 7 and the canonical reference implementation in
    Section 15.15. Carries:
        - failed_bound: 'lower' or 'upper'
        - actual_delta_seconds: the observed clock delta
        - configured_tolerance_seconds: the configured tolerance that was
          exceeded (skew tolerance for lower bound; acceptance timeout +
          skew tolerance for upper bound)
    """

    def __init__(
        self,
        message: str = "",
        *,
        failed_bound: str | None = None,
        actual_delta_seconds: float | None = None,
        configured_tolerance_seconds: float | None = None,
        **kwargs: Any,
    ) -> None:
        if not message and failed_bound is not None:
            message = (
                f"temporal ordering failed at {failed_bound} bound: "
                f"actual delta {actual_delta_seconds}s, "
                f"tolerance {configured_tolerance_seconds}s"
            )
        super().__init__(message, **kwargs)
        self.failed_bound = failed_bound
        self.actual_delta_seconds = actual_delta_seconds
        self.configured_tolerance_seconds = configured_tolerance_seconds


class CustomClaimMissingError(HandoffError):
    """A required ``air_*`` custom claim is missing from a capability token.

    Most commonly indicates the IdP-side custom claim injector (e.g., the
    Auth0 Action attached to the M2M / Client Credentials Exchange trigger)
    is misconfigured. See Section 7.3.1 and Section 15.14.
    """


class ConfigurationError(HandoffError):
    """Static configuration of the handoff stack is invalid.

    Raised by the AdapterRouter when two adapters claim the same issuer,
    by the validation proof submitter when the Rekor mode is unrecognized,
    and by other startup-time configuration checks.
    """


__all__ = [
    "CanonicalizationError",
    "CapabilityTokenInvalidError",
    "ConfigurationError",
    "CrossAgentVerificationError",
    "CrossTenantTrustError",
    "CustomClaimMissingError",
    "HandoffAcceptanceMissingError",
    "HandoffError",
    "HandoffPairingError",
    "HandoffRecordInvalidError",
    "IdPDiscoveryError",
    "IdPNotImplementedError",
    "IdentityCertificateError",
    "PTIDInvalidError",
    "RekorSubmissionError",
    "ReplayAnomalyError",
    "TemporalOrderingError",
    "UnregisteredIssuerError",
    "ValidationProofInvalidError",
    "W3CTraceContextError",
]
