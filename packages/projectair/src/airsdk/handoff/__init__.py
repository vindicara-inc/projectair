"""Layer 4: AgDR Handoff Protocol (A2A) — cross-agent chain of custody.

Wave 1 surface (single-tenant + Rekor counter-attestation). Wave 2 lifts the
cross-tenant feature flag once Wave 1 has at least one reference deployment.

Public exports are re-exported from the submodules per the architecture in
Section 2 of the Layer 4 spec. Importing :mod:`airsdk.handoff` does not yet
do work; submodule imports are lazy so the placeholder IdP adapters do not
explode at import time.
"""
from __future__ import annotations

from .canonicalize import canonicalize_and_hash, canonicalize_bytes, hash_bytes
from .exceptions import (
    CanonicalizationError,
    CapabilityTokenInvalidError,
    ConfigurationError,
    CrossAgentVerificationError,
    CrossTenantTrustError,
    CustomClaimMissingError,
    HandoffAcceptanceMissingError,
    HandoffError,
    HandoffPairingError,
    HandoffRecordInvalidError,
    IdentityCertificateError,
    IdPDiscoveryError,
    IdPNotImplementedError,
    PTIDInvalidError,
    RekorSubmissionError,
    ReplayAnomalyError,
    TemporalOrderingError,
    UnregisteredIssuerError,
    ValidationProofInvalidError,
    W3CTraceContextError,
)

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
    "canonicalize_and_hash",
    "canonicalize_bytes",
    "hash_bytes",
]
