"""Anchoring identity key management for OSS users.

The anchoring identity is a separate Ed25519 keypair from the chain
signer. It signs Rekor entries so a verifier can reconstruct the
binding between a chain root and its public-log entry without contacting
Vindicara.

Key resolution, in order:

1. ``AIRSDK_ANCHORING_KEY`` env var (PEM or 64-char hex), via the same
   shape ``Signer.from_env`` accepts on the chain side.
2. ``~/.config/projectair/anchoring_key.pem`` (or platform equivalent).
3. Generate a fresh keypair, persist it to the file path with mode
   0600, and return it. The public key is also written alongside in
   ``anchoring_key_pub.pem`` so the user can publish or back it up.

This is OSS behaviour. AIR Cloud / Enterprise tenants do not call this:
they use HSM-backed keys (KMS) configured at deployment time.
"""
from __future__ import annotations

import contextlib
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)

ANCHORING_KEY_ENV: str = "AIRSDK_ANCHORING_KEY"
_FILE_NAME: str = "anchoring_key.pem"
_PUB_FILE_NAME: str = "anchoring_key_pub.pem"


def default_key_dir() -> Path:
    """Platform-appropriate directory for the OSS anchoring key."""
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / "projectair"
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return Path(xdg) / "projectair"
    return Path.home() / ".config" / "projectair"


def load_anchoring_key(env_var: str = ANCHORING_KEY_ENV) -> Ed25519PrivateKey:
    """Resolve the Ed25519 anchoring identity per the documented order."""
    raw = os.environ.get(env_var)
    if raw is not None:
        return _parse_env_key(raw, env_var)

    key_path = default_key_dir() / _FILE_NAME
    if key_path.exists():
        return _load_from_path(key_path)

    return _generate_and_persist(key_path)


def _parse_env_key(raw: str, env_var: str) -> Ed25519PrivateKey:
    data = raw.strip()
    if data.startswith("-----BEGIN"):
        priv = load_pem_private_key(data.encode(), password=None)
        if not isinstance(priv, Ed25519PrivateKey):
            raise ValueError(f"{env_var} must hold an Ed25519 key, got {type(priv).__name__}")
        return priv
    try:
        seed = bytes.fromhex(data)
    except ValueError as exc:
        raise ValueError(f"{env_var} is neither PEM nor hex-encoded Ed25519 seed") from exc
    if len(seed) != 32:
        raise ValueError(f"{env_var} hex seed must decode to 32 bytes, got {len(seed)}")
    return Ed25519PrivateKey.from_private_bytes(seed)


def _load_from_path(key_path: Path) -> Ed25519PrivateKey:
    pem = key_path.read_bytes()
    priv = load_pem_private_key(pem, password=None)
    if not isinstance(priv, Ed25519PrivateKey):
        raise ValueError(
            f"anchoring key at {key_path} is not an Ed25519 key (got {type(priv).__name__})",
        )
    return priv


def _generate_and_persist(key_path: Path) -> Ed25519PrivateKey:
    key_path.parent.mkdir(parents=True, exist_ok=True)
    priv = Ed25519PrivateKey.generate()
    pem = priv.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    # Write atomically with restrictive perms before any other process can
    # observe a partial file. The 0o600 mode is critical: an attacker with
    # read access to the home directory must not be able to lift the key.
    tmp_path = key_path.with_suffix(".pem.tmp")
    fd = os.open(str(tmp_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(pem)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise
    os.replace(str(tmp_path), str(key_path))

    pub_pem = priv.public_key().public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )
    pub_path = key_path.parent / _PUB_FILE_NAME
    pub_path.write_bytes(pub_pem)
    # Windows or restrictive filesystems may reject chmod; advisory here.
    with contextlib.suppress(OSError):
        os.chmod(pub_path, 0o644)
    return priv


def public_key_path() -> Path:
    return default_key_dir() / _PUB_FILE_NAME
