"""Evidence collection and genesis-bound nonce derivation (W1, experimental).

The nonce is the hard-to-copy detail of the hardware-rooted Signed Intent
Capsule. A valid NRAS token on its own only proves a GPU was healthy at some
moment. AIR derives the NRAS request nonce from the chain's DELEGATION
genesis record, NRAS echoes the nonce inside the signed EAT, and
verification fails closed when the EAT nonce is not recomputable from the
chain genesis. That turns "a GPU was attested somewhere" into "this exact
authorized session ran on attested hardware."

Nonce layout (32 bytes total, hex-encoded to 64 chars):

    salt = fresh_random_16
    nonce = salt || BLAKE3(genesis_content_hash_bytes || salt)[:16]

The salt travels inside the nonce itself, so an external verifier can
recompute the binding from the chain alone: split the recorded nonce, rehash
against the genesis content hash, compare in constant time. The 32-byte
total keeps the nonce inside common attestation-service nonce limits; the
maximum length NRAS accepts verbatim is a W1 open decision to lock with
NVIDIA (spec 2.8).
"""
from __future__ import annotations

import hmac
import secrets

import blake3

from airsdk.attestation.types import (
    DeviceEvidence,
    EvidenceBundle,
    EvidenceUnavailableError,
)

__all__ = ["NONCE_HEX_LENGTH", "collect_evidence", "derive_nonce", "verify_nonce"]

_SALT_BYTES = 16
_DIGEST_BYTES = 16
NONCE_HEX_LENGTH = (_SALT_BYTES + _DIGEST_BYTES) * 2


def derive_nonce(genesis_content_hash: str, *, salt: bytes | None = None) -> str:
    """Derive a freshness nonce bound to the chain's genesis record.

    ``genesis_content_hash`` is the BLAKE3 content hash (64 hex chars) of the
    DELEGATION genesis record. ``salt`` is 16 fresh random bytes; pass it
    only in tests, production callers let it default.
    """
    genesis = _genesis_bytes(genesis_content_hash)
    if salt is None:
        salt = secrets.token_bytes(_SALT_BYTES)
    if len(salt) != _SALT_BYTES:
        raise ValueError(f"salt must be {_SALT_BYTES} bytes, got {len(salt)}")
    digest = blake3.blake3(genesis + salt).digest()[:_DIGEST_BYTES]
    return (salt + digest).hex()


def verify_nonce(nonce: str, genesis_content_hash: str) -> bool:
    """Check that ``nonce`` is recomputable from ``genesis_content_hash``.

    Fails closed: any malformed input returns False. Comparison is
    constant-time.
    """
    if len(nonce) != NONCE_HEX_LENGTH:
        return False
    try:
        raw = bytes.fromhex(nonce)
        genesis = _genesis_bytes(genesis_content_hash)
    except ValueError:
        return False
    salt, recorded_digest = raw[:_SALT_BYTES], raw[_SALT_BYTES:]
    expected = blake3.blake3(genesis + salt).digest()[:_DIGEST_BYTES]
    return hmac.compare_digest(expected, recorded_digest)


def collect_evidence(nonce: str, *, gpu_arch: str = "hopper") -> EvidenceBundle:
    """Collect GPU attestation evidence on this host (nonce -> evidence bundle).

    Readiness: experimental. Requires an NVIDIA Confidential Computing
    instance with the local GPU verifier (``verifier`` from
    ``nv-local-gpu-verifier``) installed and the GPU in CC mode. Wraps
    ``verifier.cc_admin.collect_gpu_evidence_remote``, which pulls each GPU's
    attestation report and certificate chain bound to ``nonce`` and returns
    them base64-encoded in NRAS evidence-list order. On hosts without the SDK
    this raises :class:`EvidenceUnavailableError`; tests and demos drive the
    pipeline through ``airsdk.attestation.fixture.FixtureNRAS``.

    ``nonce`` is the 64-hex-char genesis-bound nonce from :func:`derive_nonce`.
    ``ppcie_mode`` is False: a single confidential GPU is not a protected-PCIe
    multi-GPU topology.
    """
    try:
        from verifier import cc_admin  # type: ignore[import-not-found]
    except ImportError as exc:
        raise EvidenceUnavailableError(
            "GPU attestation evidence collection requires an NVIDIA "
            "Confidential Computing instance with the local GPU verifier "
            "(nv-local-gpu-verifier) installed. Use "
            "airsdk.attestation.fixture.FixtureNRAS for tests and demos, or "
            "run on a CC-capable instance for live attestation."
        ) from exc

    try:
        raw_evidence = cc_admin.collect_gpu_evidence_remote(nonce, ppcie_mode=False)
    except Exception as exc:  # the SDK surfaces NVML/runtime errors untyped
        raise EvidenceUnavailableError(
            f"GPU evidence collection failed on this host: {exc}"
        ) from exc

    devices = _devices_from_raw(raw_evidence)
    if not devices:
        raise EvidenceUnavailableError("no GPU evidence was collected on this host")
    return EvidenceBundle(gpu_arch=gpu_arch, nonce=nonce, devices=devices)


def _devices_from_raw(raw_evidence: object) -> list[DeviceEvidence]:
    """Map the local GPU verifier's evidence list into typed DeviceEvidence.

    Each entry is a dict with base64 ``evidence`` and ``certificate`` fields
    (plus ``arch``); anything else fails closed with
    :class:`EvidenceUnavailableError`.
    """
    if not isinstance(raw_evidence, list):
        raise EvidenceUnavailableError(
            f"expected a list of GPU evidence, got {type(raw_evidence).__name__}"
        )
    devices: list[DeviceEvidence] = []
    for index, item in enumerate(raw_evidence):
        if not isinstance(item, dict):
            raise EvidenceUnavailableError(
                f"GPU evidence entry {index} is {type(item).__name__}, expected dict"
            )
        evidence = item.get("evidence")
        certificate = item.get("certificate", "")
        if not isinstance(evidence, str) or not evidence:
            raise EvidenceUnavailableError(
                f"GPU evidence entry {index} has no base64 'evidence' field"
            )
        devices.append(
            DeviceEvidence(
                device_id=f"gpu{index}",
                evidence_b64=evidence,
                certificate_b64=certificate if isinstance(certificate, str) else "",
            )
        )
    return devices


def _genesis_bytes(genesis_content_hash: str) -> bytes:
    if len(genesis_content_hash) != 64:
        raise ValueError(
            f"genesis_content_hash must be 64 hex chars, got {len(genesis_content_hash)}"
        )
    return bytes.fromhex(genesis_content_hash)
