"""Tests for the anchoring-identity key loader."""
from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
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


def test_load_from_env_pem(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _isolated_home(monkeypatch, tmp_path)
    priv = Ed25519PrivateKey.generate()
    pem = priv.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    monkeypatch.setenv(ANCHORING_KEY_ENV, pem.decode())

    loaded = load_anchoring_key()
    assert isinstance(loaded, Ed25519PrivateKey)
    # PEM round-trip: same key bytes.
    assert (
        loaded.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        == priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    )


def test_load_from_env_hex(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _isolated_home(monkeypatch, tmp_path)
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    monkeypatch.setenv(ANCHORING_KEY_ENV, seed.hex())

    loaded = load_anchoring_key()
    assert (
        loaded.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()) == seed
    )


def test_env_invalid_seed_raises(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _isolated_home(monkeypatch, tmp_path)
    monkeypatch.setenv(ANCHORING_KEY_ENV, "not-a-valid-key")
    with pytest.raises(ValueError, match="neither PEM nor hex"):
        load_anchoring_key()


def test_generate_persists_with_0o600(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _isolated_home(monkeypatch, tmp_path)
    monkeypatch.delenv(ANCHORING_KEY_ENV, raising=False)

    key = load_anchoring_key()
    assert isinstance(key, Ed25519PrivateKey)

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
    raw_a = first.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    raw_b = second.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    assert raw_a == raw_b
