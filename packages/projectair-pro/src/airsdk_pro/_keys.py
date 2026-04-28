"""Vendor public key embedded in the projectair-pro distribution.

This is the Ed25519 public key whose corresponding private key Vindicara uses
to sign license tokens. Verification is local: a token is accepted only if its
signature validates against this public key. The private key never leaves
Vindicara's infrastructure.

Replacing this constant with a different public key invalidates every license
issued against the original. The constant is therefore versioned in code and
should never be edited except as part of a deliberate, advertised key rotation.
"""
from __future__ import annotations

# Ed25519 public key (raw, 32 bytes, hex-encoded). Generated 2026-04-27.
VENDOR_LICENSE_PUBLIC_KEY_HEX: str = "e992bb1fab6aec173a89f25537ad878fda7c3b70d4cfb0cf3aec023863542249"
