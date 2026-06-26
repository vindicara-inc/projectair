#!/usr/bin/env python3
"""Axiisium Stage 5 — confidential computing: bind the signed records to attested hardware+code.

Stages 0-4 prove WHAT was computed and by WHOSE authority (signed ledgers). Stage 5 proves
the records were produced by the EXPECTED code running inside GENUINE confidential hardware
- closing the gap NVIDIA FLARE's docs name: attestation proves the enclave is real but not
  what ran at the application layer.

    genuine TEE+GPU (enclave measurement)
            +  exact pipeline code (code measurement)
            +  the ledger signing key
            =  one platform-signed attestation document
               -> verifier proves: these signed results came from THIS code in a REAL enclave

Run:
    python stage5.py

Demonstrates the clean chain verifying, then three attacks, each caught:
  (1) code modified at deploy time   -> code measurement mismatch
  (2) signing key swapped            -> key-not-bound
  (3) forged (non-genuine) enclave   -> platform signature invalid

PRODUCTION: the simulated platform is replaced by a real AMD SEV-SNP / Intel TDX quote +
NVIDIA GPU attestation verified through the NVIDIA Remote Attestation Service (NRAS). The
binding logic is identical. See stage5/README.md.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from axiisium.confidential.attestation import (  # noqa: E402
    SimulatedPlatform,
    measure_code,
    verify_attestation,
)

BAR = "=" * 78


def main() -> None:
    print(BAR)
    print("AXIISIUM  Stage 5  -  confidential computing: hardware -> code -> key binding")
    print(BAR)

    # the exact pipeline code whose execution we attest (measure a few real source files)
    src = Path(__file__).parent / "src" / "axiisium"
    code_files = [src / "trust.py", src / "model.py", src / "fusion" / "cohort.py"]
    code_measurement = measure_code(code_files)

    # the ledger signing key (in production, generated INSIDE the enclave)
    signer = Ed25519PrivateKey.generate()
    signing_pubkey = signer.public_key().public_bytes_raw().hex()

    platform = SimulatedPlatform()
    nonce = "verifier-supplied-freshness-001"
    doc = platform.attest(code_measurement, signing_pubkey, nonce)

    print("\n  Attestation document bound:")
    print(f"    enclave measurement : {doc.enclave_measurement[:40]}...  (genuine TEE+GPU)")
    print(f"    code measurement    : {doc.code_measurement[:40]}...  (exact pipeline code)")
    print(f"    signing pubkey      : {doc.signing_pubkey[:40]}...  (the ledger key)")
    print(f"    platform key (NRAS) : {doc.platform_pubkey[:40]}...")

    # ---- clean verification ----
    ok, msg = verify_attestation(doc, platform.enclave_measurement, code_measurement,
                                 signing_pubkey, platform.pubkey)
    print(f"\n  VERIFY (clean)              : {'VALID' if ok else 'FAIL'} - {msg}")

    # ---- attack 1: code modified at deploy time ----
    tampered_code = "0" * 64
    ok1, msg1 = verify_attestation(doc, platform.enclave_measurement, tampered_code,
                                   signing_pubkey, platform.pubkey)
    print(f"  ATTACK 1 (code modified)    : {'VALID' if ok1 else 'BLOCKED'} - {msg1}")

    # ---- attack 2: signing key swapped (records substituted) ----
    other_key = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    ok2, msg2 = verify_attestation(doc, platform.enclave_measurement, code_measurement,
                                   other_key, platform.pubkey)
    print(f"  ATTACK 2 (key substituted)  : {'VALID' if ok2 else 'BLOCKED'} - {msg2}")

    # ---- attack 3: forged enclave (attacker's own platform key) ----
    rogue = SimulatedPlatform()
    forged = rogue.attest(code_measurement, signing_pubkey, nonce)
    ok3, msg3 = verify_attestation(forged, platform.enclave_measurement, code_measurement,
                                   signing_pubkey, platform.pubkey)  # trusted = real platform
    print(f"  ATTACK 3 (forged enclave)   : {'VALID' if ok3 else 'BLOCKED'} - {msg3}")

    print("\n" + BAR)
    print("Full chain of trust: NVIDIA Confidential Computing attests the silicon; Axiisium")
    print("binds the code + signing key to it. Provably private, untampered, attributable,")
    print("end to end - the complete trust contract a regulator and a pharma sponsor need.")
    print(BAR)


if __name__ == "__main__":
    main()
