"""Project AIR hardware root of trust: NVIDIA NRAS GPU attestation.

Readiness: experimental (W1 of `docs/NVIDIA_INTEGRATION_SPEC.md`). Stays
experimental until one reference workload runs end to end on an NVIDIA
Confidential Computing instance.

A complete Signed Intent Capsule verifies against three independent roots:
the chain signer (what the agent did), the anchoring identity (when, via
RFC 3161 + Sigstore Rekor), and, with this subpackage, NVIDIA NRAS (where
it ran). AIR records NVIDIA's signed EAT verbatim inside the chain and
covers it under the anchored BLAKE3 root; AIR never re-signs it. The
request nonce is derived from the DELEGATION genesis record, so the token
binds to this exact authorized session (see ``evidence.derive_nonce``).

This subpackage mirrors ``airsdk.anchoring`` so the trust contract is
parallel and obvious. It is optional and additive: recorders without
``attestation=`` behave exactly as before, and AIR runs unchanged on
non-CC hardware.
"""
from __future__ import annotations

from airsdk.attestation.config import DEFAULT_NRAS_URL, GPUAttestationConfig
from airsdk.attestation.evidence import collect_evidence, derive_nonce, verify_nonce
from airsdk.attestation.fixture import FixtureNRAS
from airsdk.attestation.nras import (
    AttestationProvider,
    NRASClient,
    attest_session,
    parse_nras_response,
)
from airsdk.attestation.types import (
    AttestationError,
    AttestationVerification,
    DeviceEvidence,
    EvidenceBundle,
    EvidenceUnavailableError,
    GPUAttestation,
    NRASError,
    NRASResponseError,
    NRASResult,
    NRASUnreachableError,
)
from airsdk.attestation.verify import verify_attestation

__all__ = [
    "DEFAULT_NRAS_URL",
    "AttestationError",
    "AttestationProvider",
    "AttestationVerification",
    "DeviceEvidence",
    "EvidenceBundle",
    "EvidenceUnavailableError",
    "FixtureNRAS",
    "GPUAttestation",
    "GPUAttestationConfig",
    "NRASClient",
    "NRASError",
    "NRASResponseError",
    "NRASResult",
    "NRASUnreachableError",
    "attest_session",
    "collect_evidence",
    "derive_nonce",
    "parse_nras_response",
    "verify_attestation",
    "verify_nonce",
]
