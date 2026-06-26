"""Attestation binding — closing the hardware-to-application trust gap.

NVIDIA FLARE's own docs admit the seam: confidential-computing attestation proves the
*enclave/hardware is genuine* but, by itself, cannot prove *what code ran* or *what was
computed at the application layer*. Stage 5 closes it by binding three things into one
verifiable object:

    1. the ENCLAVE measurement   (proves genuine TEE + GPU — from the platform quote)
    2. the CODE measurement      (hash of the exact pipeline code that ran)
    3. the SIGNING public key     (the key every run/federation ledger is signed with)

If all three are bound and signed by the platform, then a verifier can prove: "these
signed records were produced by THIS code, running in a GENUINE confidential enclave, and
nothing was substituted." That is the end-to-end chain of trust from silicon to result.

This module SIMULATES the platform quote (a local 'platform key' stands in for the AMD
SEV-SNP / Intel TDX + NVIDIA GPU attestation). PRODUCTION verifies a real quote via the
NVIDIA Remote Attestation Service (NRAS) and the CPU vendor's attestation. The binding
logic — measurement + code + key, signed, checked against expected — is identical.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def measure_code(paths: list[str | Path]) -> str:
    """Deterministic measurement (hash) of the exact source files that ran."""
    h = hashlib.sha256()
    for p in sorted(str(x) for x in paths):
        h.update(p.encode())
        h.update(Path(p).read_bytes())
    return h.hexdigest()


@dataclass
class AttestationDocument:
    enclave_measurement: str   # genuine-TEE proof (simulated platform quote)
    code_measurement: str      # hash of the running code
    signing_pubkey: str        # the ledger signing key bound to this enclave+code
    nonce: str                 # freshness / anti-replay
    platform_pubkey: str       # platform attestation key (prod: NRAS / vendor root)
    signature: str             # platform signature over the bound fields

    def bound_body(self) -> dict[str, Any]:
        return {
            "enclave_measurement": self.enclave_measurement,
            "code_measurement": self.code_measurement,
            "signing_pubkey": self.signing_pubkey,
            "nonce": self.nonce,
        }


class SimulatedPlatform:
    """Stands in for AMD SEV-SNP / Intel TDX + NVIDIA GPU confidential computing."""

    def __init__(self) -> None:
        self._k = Ed25519PrivateKey.generate()
        self.pubkey = self._k.public_key().public_bytes_raw().hex()
        # a fixed 'genuine enclave' measurement for this simulated platform
        self.enclave_measurement = hashlib.sha256(b"SEV-SNP+TDX+NVIDIA-CC genuine enclave").hexdigest()

    def attest(self, code_measurement: str, signing_pubkey: str, nonce: str) -> AttestationDocument:
        body = {
            "enclave_measurement": self.enclave_measurement,
            "code_measurement": code_measurement,
            "signing_pubkey": signing_pubkey,
            "nonce": nonce,
        }
        digest = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
        sig = self._k.sign(bytes.fromhex(digest)).hex()
        return AttestationDocument(
            enclave_measurement=self.enclave_measurement,
            code_measurement=code_measurement,
            signing_pubkey=signing_pubkey,
            nonce=nonce,
            platform_pubkey=self.pubkey,
            signature=sig,
        )


def verify_attestation(
    doc: AttestationDocument,
    expected_enclave: str,
    expected_code: str,
    expected_signing_pubkey: str,
    trusted_platform_pubkey: str,
) -> tuple[bool, str]:
    """Verify the full chain: platform sig valid AND all three measurements as expected."""
    digest = hashlib.sha256(json.dumps(doc.bound_body(), sort_keys=True).encode()).hexdigest()
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(doc.platform_pubkey)).verify(
            bytes.fromhex(doc.signature), bytes.fromhex(digest)
        )
    except Exception:
        return False, "platform signature invalid (not a genuine attestation)"
    if doc.platform_pubkey != trusted_platform_pubkey:
        return False, "untrusted attestation platform key"
    if doc.enclave_measurement != expected_enclave:
        return False, "enclave measurement mismatch (not the expected confidential hardware)"
    if doc.code_measurement != expected_code:
        return False, "code measurement mismatch (code was modified at deploy time)"
    if doc.signing_pubkey != expected_signing_pubkey:
        return False, "signing key not bound to this enclave (records may be substituted)"
    return True, "hardware -> code -> signing-key chain intact"
