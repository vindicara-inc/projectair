"""Anchoring identity key management for OSS users.

The anchoring identity is a separate ECDSA P-256 keypair from the chain
signer (which is Ed25519). It signs Rekor entries so a verifier can
reconstruct the binding between a chain root and its public-log entry
without contacting Vindicara.

Why ECDSA P-256: Sigstore's public Rekor service is built around ECDSA
P-256 with SHA-256. Ed25519 is in the Rekor schema but the production
verifier rejects Ed25519 hashedrekord entries. See ``rekor.py`` docstring
for the full story.

Key resolution, in order:

1. ``AIRSDK_ANCHORING_KEY`` env var (PEM only; raw hex form was Ed25519
   specific and is not supported for ECDSA).
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

from cryptography.hazmat.primitives.asymmetric import ec
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


def load_anchoring_key(env_var: str = ANCHORING_KEY_ENV) -> ec.EllipticCurvePrivateKey:
    """Resolve the ECDSA P-256 anchoring identity per the documented order."""
    raw = os.environ.get(env_var)
    if raw is not None:
        return _parse_env_key(raw, env_var)

    key_path = default_key_dir() / _FILE_NAME
    if key_path.exists():
        return _load_from_path(key_path)

    return _generate_and_persist(key_path)


def _parse_env_key(raw: str, env_var: str) -> ec.EllipticCurvePrivateKey:
    data = raw.strip()
    if not data.startswith("-----BEGIN"):
        raise ValueError(f"{env_var} must be a PEM-encoded ECDSA P-256 private key")
    priv = load_pem_private_key(data.encode(), password=None)
    if not isinstance(priv, ec.EllipticCurvePrivateKey):
        raise ValueError(
            f"{env_var} must hold an ECDSA private key, got {type(priv).__name__}",
        )
    if not isinstance(priv.curve, ec.SECP256R1):
        raise ValueError(
            f"{env_var} must be on curve SECP256R1 (P-256), got {priv.curve.name}",
        )
    return priv


def _load_from_path(key_path: Path) -> ec.EllipticCurvePrivateKey:
    pem = key_path.read_bytes()
    priv = load_pem_private_key(pem, password=None)
    if not isinstance(priv, ec.EllipticCurvePrivateKey):
        raise ValueError(
            f"anchoring key at {key_path} is not an ECDSA key (got {type(priv).__name__})",
        )
    if not isinstance(priv.curve, ec.SECP256R1):
        raise ValueError(
            f"anchoring key at {key_path} must be P-256, got {priv.curve.name}",
        )
    return priv


def _generate_and_persist(key_path: Path) -> ec.EllipticCurvePrivateKey:
    key_path.parent.mkdir(parents=True, exist_ok=True)
    priv = ec.generate_private_key(ec.SECP256R1())
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
