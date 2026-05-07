"""Tests for the anchoring-identity key loader."""
from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from airsdk.anchoring.identity import (
    ANCHORING_KEY_ENV,
    default_key_dir,
    load_anchoring_key,
)


def _isolated_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    monkeypatch.delenv(ANCHORING_KEY_ENV, raising=False)


def _serialize_priv(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        encoding=Encoding.DER,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )


def test_load_from_env_pem(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _isolated_home(monkeypatch, tmp_path)
    priv = ec.generate_private_key(ec.SECP256R1())
    pem = priv.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    monkeypatch.setenv(ANCHORING_KEY_ENV, pem.decode())

    loaded = load_anchoring_key()
    assert isinstance(loaded, ec.EllipticCurvePrivateKey)
    assert isinstance(loaded.curve, ec.SECP256R1)
    assert _serialize_priv(loaded) == _serialize_priv(priv)


def test_env_rejects_non_pem(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _isolated_home(monkeypatch, tmp_path)
    monkeypatch.setenv(ANCHORING_KEY_ENV, "deadbeef" * 8)  # hex, not PEM
    with pytest.raises(ValueError, match="PEM-encoded"):
        load_anchoring_key()


def test_env_rejects_wrong_curve(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _isolated_home(monkeypatch, tmp_path)
    priv = ec.generate_private_key(ec.SECP384R1())
    pem = priv.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    monkeypatch.setenv(ANCHORING_KEY_ENV, pem.decode())
    with pytest.raises(ValueError, match="SECP256R1"):
        load_anchoring_key()


def test_env_rejects_ed25519(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Ed25519 keys are rejected because Rekor's hashedrekord verifier
    does not exercise Ed25519 in production; ECDSA P-256 only."""
    _isolated_home(monkeypatch, tmp_path)
    priv = Ed25519PrivateKey.generate()
    pem = priv.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    monkeypatch.setenv(ANCHORING_KEY_ENV, pem.decode())
    with pytest.raises(ValueError, match="ECDSA"):
        load_anchoring_key()


def test_generate_persists_with_0o600(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _isolated_home(monkeypatch, tmp_path)
    monkeypatch.delenv(ANCHORING_KEY_ENV, raising=False)

    key = load_anchoring_key()
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    assert isinstance(key.curve, ec.SECP256R1)

    key_path = default_key_dir() / "anchoring_key.pem"
    pub_path = default_key_dir() / "anchoring_key_pub.pem"
    assert key_path.exists()
    assert pub_path.exists()

    if os.name != "nt":
        mode = stat.S_IMODE(key_path.stat().st_mode)
        assert mode == 0o600, f"private key permissions must be 0o600, got {oct(mode)}"


def test_generate_then_load_returns_same_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    _isolated_home(monkeypatch, tmp_path)
    first = load_anchoring_key()
    second = load_anchoring_key()
    assert _serialize_priv(first) == _serialize_priv(second)
