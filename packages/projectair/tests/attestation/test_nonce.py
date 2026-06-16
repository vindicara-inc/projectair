"""Genesis-bound nonce derivation: the replay defense of W1."""
from __future__ import annotations

import pytest

from airsdk.attestation.evidence import NONCE_HEX_LENGTH, derive_nonce, verify_nonce

GENESIS = "ab" * 32
OTHER_GENESIS = "cd" * 32


def test_derive_and_verify_roundtrip() -> None:
    nonce = derive_nonce(GENESIS)
    assert len(nonce) == NONCE_HEX_LENGTH
    assert verify_nonce(nonce, GENESIS)


def test_nonce_is_fresh_per_call() -> None:
    assert derive_nonce(GENESIS) != derive_nonce(GENESIS)


def test_deterministic_with_fixed_salt() -> None:
    salt = bytes(range(16))
    assert derive_nonce(GENESIS, salt=salt) == derive_nonce(GENESIS, salt=salt)


def test_wrong_genesis_fails_closed() -> None:
    nonce = derive_nonce(GENESIS)
    assert not verify_nonce(nonce, OTHER_GENESIS)


def test_tampered_nonce_fails_closed() -> None:
    nonce = derive_nonce(GENESIS)
    tampered = ("0" if nonce[0] != "0" else "1") + nonce[1:]
    assert not verify_nonce(tampered, GENESIS)


@pytest.mark.parametrize(
    "bad_nonce",
    ["", "zz" * 32, "ab" * 8, "ab" * 64, "not hex at all"],
)
def test_malformed_nonce_fails_closed(bad_nonce: str) -> None:
    assert not verify_nonce(bad_nonce, GENESIS)


def test_malformed_genesis_fails_closed() -> None:
    nonce = derive_nonce(GENESIS)
    assert not verify_nonce(nonce, "short")
    assert not verify_nonce(nonce, "zz" * 32)


def test_derive_rejects_bad_inputs() -> None:
    with pytest.raises(ValueError, match="64 hex chars"):
        derive_nonce("short")
    with pytest.raises(ValueError, match="salt must be"):
        derive_nonce(GENESIS, salt=b"too short")
