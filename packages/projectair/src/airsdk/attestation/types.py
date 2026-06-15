"""Typed models and exceptions for the NVIDIA NRAS attestation surface.

Readiness: experimental. This module ships the W1 workstream of the
Project AIR x NVIDIA integration program (`docs/NVIDIA_INTEGRATION_SPEC.md`).
It stays experimental until one reference workload runs end to end on an
NVIDIA Confidential Computing instance.

The on-chain record shape (``GPUAttestation``) lives in ``airsdk.types``
alongside ``RFC3161Anchor`` and ``RekorAnchor`` so the AgDR schema stays in
one module; this module re-exports it and adds the request/response models
the NRAS client uses.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from airsdk.types import GPUAttestation

__all__ = [
    "AttestationError",
    "AttestationVerification",
    "DeviceEvidence",
    "EvidenceBundle",
    "EvidenceUnavailableError",
    "GPUAttestation",
    "NRASError",
    "NRASResponseError",
    "NRASResult",
    "NRASUnreachableError",
]


class AttestationError(Exception):
    """Base for all attestation-layer failures."""


class EvidenceUnavailableError(AttestationError):
    """GPU attestation evidence cannot be collected on this host.

    Raised when no CC-capable GPU or NVIDIA attestation SDK is available.
    Live evidence collection requires a Confidential Computing instance
    (W1 open decision 2.8: exact NRAS endpoint and auth model are locked
    with NVIDIA). Tests and demos use the simulated NRAS in
    ``airsdk.attestation.fixture`` instead.
    """


class NRASError(AttestationError):
    """Base for NRAS client failures."""


class NRASUnreachableError(NRASError):
    """The NRAS endpoint could not be reached."""


class NRASResponseError(NRASError):
    """NRAS responded, but the response could not be parsed or was an error."""


class DeviceEvidence(BaseModel):
    """Attestation evidence for one GPU or nvSwitch device."""

    model_config = ConfigDict(extra="forbid")

    device_id: str
    evidence_b64: str
    certificate_b64: str = ""


class EvidenceBundle(BaseModel):
    """Evidence for all devices in one attestation request, in evidence order.

    The order of ``devices`` is significant: NRAS returns per-device detached
    EAT bundles whose order matches the submitted evidence list.
    """

    model_config = ConfigDict(extra="forbid")

    gpu_arch: str
    nonce: str
    devices: list[DeviceEvidence]


class NRASResult(BaseModel):
    """Parsed NRAS attestation response.

    ``detached_eat`` is the overall attestation JWT (EAT) exactly as NRAS
    returned it; ``device_eats`` are the per-device detached EAT bundles in
    evidence order. AIR never re-signs or rewrites these tokens.
    """

    model_config = ConfigDict(extra="forbid")

    detached_eat: str
    device_eats: list[str]
    claims_version: str
    rim_matched: bool


class AttestationVerification(BaseModel):
    """Per-root status of the attestation checks over one chain.

    ``ok`` is True when every check on every GPU_ATTESTATION record passed,
    or when the chain carries no GPU_ATTESTATION records at all (legacy
    chains stay green). Failures are fatal to the attestation claim but do
    not retroactively invalidate the rest of the chain; the verifier reports
    per-root status so a buyer sees exactly which guarantees hold.
    """

    model_config = ConfigDict(extra="forbid")

    ok: bool
    mode: str  # "online" | "offline"
    records_checked: int
    checks_passed: list[str]
    failures: list[str]
