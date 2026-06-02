"""Tests for Fulcio leaf-cert chain validation (Layer 4 Wave 2, piece 2).

Builds a synthetic Fulcio-like chain (EC root -> EC intermediate -> Ed25519
leaf) with the ``cryptography`` library and exercises
``verify_fulcio_leaf`` for the happy path and each failure mode.
"""
from __future__ import annotations

import datetime as dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
    CertificatePublicKeyTypes,
)
from cryptography.x509.oid import NameOID

from airsdk.handoff.exceptions import IdentityCertificateError
from airsdk.handoff.fulcio import FulcioTrustBundle, verify_fulcio_leaf

_NOW = dt.datetime(2026, 6, 1, 12, 0, 0, tzinfo=dt.timezone.utc)
_NB = _NOW - dt.timedelta(hours=1)
_NA = _NOW + dt.timedelta(hours=1)


def _sig_hash(key: CertificateIssuerPrivateKeyTypes) -> hashes.HashAlgorithm | None:
    return None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256()


def _build_cert(
    *,
    subject_cn: str,
    issuer_cn: str,
    subject_public_key: CertificatePublicKeyTypes,
    issuer_private_key: CertificateIssuerPrivateKeyTypes,
    ca: bool,
    not_before: dt.datetime = _NB,
    not_after: dt.datetime = _NA,
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)]))
        .public_key(subject_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    return builder.sign(issuer_private_key, _sig_hash(issuer_private_key))


def _der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def _full_chain() -> tuple[FulcioTrustBundle, bytes, ed25519.Ed25519PrivateKey]:
    root_key = ec.generate_private_key(ec.SECP384R1())
    root = _build_cert(
        subject_cn="Fulcio Test Root", issuer_cn="Fulcio Test Root",
        subject_public_key=root_key.public_key(), issuer_private_key=root_key, ca=True,
    )
    inter_key = ec.generate_private_key(ec.SECP256R1())
    inter = _build_cert(
        subject_cn="Fulcio Test Intermediate", issuer_cn="Fulcio Test Root",
        subject_public_key=inter_key.public_key(), issuer_private_key=root_key, ca=True,
    )
    leaf_id = ed25519.Ed25519PrivateKey.generate()
    leaf = _build_cert(
        subject_cn="agent-1", issuer_cn="Fulcio Test Intermediate",
        subject_public_key=leaf_id.public_key(), issuer_private_key=inter_key, ca=False,
    )
    bundle = FulcioTrustBundle(roots=[_der(root)], intermediates=[_der(inter)])
    return bundle, _der(leaf), leaf_id


def test_valid_chain_returns_leaf_ed25519_key() -> None:
    bundle, leaf_der, leaf_id = _full_chain()
    returned = verify_fulcio_leaf(leaf_der, bundle, at_time=_NOW)
    raw = returned.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    expected = leaf_id.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    assert raw == expected


def test_leaf_issued_directly_by_root() -> None:
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = _build_cert(
        subject_cn="Root", issuer_cn="Root",
        subject_public_key=root_key.public_key(), issuer_private_key=root_key, ca=True,
    )
    leaf_id = ed25519.Ed25519PrivateKey.generate()
    leaf = _build_cert(
        subject_cn="agent-2", issuer_cn="Root",
        subject_public_key=leaf_id.public_key(), issuer_private_key=root_key, ca=False,
    )
    bundle = FulcioTrustBundle(roots=[_der(root)])
    assert verify_fulcio_leaf(_der(leaf), bundle, at_time=_NOW) is not None


def test_untrusted_root_rejected() -> None:
    bundle, leaf_der, _ = _full_chain()
    other_key = ec.generate_private_key(ec.SECP384R1())
    other_root = _build_cert(
        subject_cn="Other Root", issuer_cn="Other Root",
        subject_public_key=other_key.public_key(), issuer_private_key=other_key, ca=True,
    )
    tampered = FulcioTrustBundle(roots=[_der(other_root)], intermediates=bundle.intermediates)
    with pytest.raises(IdentityCertificateError, match="no trusted issuer"):
        verify_fulcio_leaf(leaf_der, tampered, at_time=_NOW)


def test_expired_leaf_rejected() -> None:
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = _build_cert(
        subject_cn="Root", issuer_cn="Root",
        subject_public_key=root_key.public_key(), issuer_private_key=root_key, ca=True,
    )
    leaf_id = ed25519.Ed25519PrivateKey.generate()
    leaf = _build_cert(
        subject_cn="agent-3", issuer_cn="Root",
        subject_public_key=leaf_id.public_key(), issuer_private_key=root_key, ca=False,
        not_before=_NOW - dt.timedelta(hours=2), not_after=_NOW - dt.timedelta(minutes=1),
    )
    bundle = FulcioTrustBundle(roots=[_der(root)])
    with pytest.raises(IdentityCertificateError, match="validity window"):
        verify_fulcio_leaf(_der(leaf), bundle, at_time=_NOW)


def test_non_ed25519_leaf_rejected() -> None:
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = _build_cert(
        subject_cn="Root", issuer_cn="Root",
        subject_public_key=root_key.public_key(), issuer_private_key=root_key, ca=True,
    )
    ec_leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = _build_cert(
        subject_cn="agent-4", issuer_cn="Root",
        subject_public_key=ec_leaf_key.public_key(), issuer_private_key=root_key, ca=False,
    )
    bundle = FulcioTrustBundle(roots=[_der(root)])
    with pytest.raises(IdentityCertificateError, match="expected Ed25519"):
        verify_fulcio_leaf(_der(leaf), bundle, at_time=_NOW)


def test_leaf_marked_ca_rejected() -> None:
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = _build_cert(
        subject_cn="Root", issuer_cn="Root",
        subject_public_key=root_key.public_key(), issuer_private_key=root_key, ca=True,
    )
    leaf_id = ed25519.Ed25519PrivateKey.generate()
    leaf = _build_cert(
        subject_cn="agent-5", issuer_cn="Root",
        subject_public_key=leaf_id.public_key(), issuer_private_key=root_key, ca=True,
    )
    bundle = FulcioTrustBundle(roots=[_der(root)])
    with pytest.raises(IdentityCertificateError, match="CA=True"):
        verify_fulcio_leaf(_der(leaf), bundle, at_time=_NOW)


def test_invalid_der_rejected() -> None:
    bundle, _, _ = _full_chain()
    with pytest.raises(IdentityCertificateError, match="not a valid DER"):
        verify_fulcio_leaf(b"not a certificate", bundle, at_time=_NOW)


def test_empty_root_bundle_rejected() -> None:
    _, leaf_der, _ = _full_chain()
    with pytest.raises(IdentityCertificateError, match="no root certificates"):
        verify_fulcio_leaf(leaf_der, FulcioTrustBundle(roots=[]), at_time=_NOW)


def test_naive_at_time_rejected() -> None:
    bundle, leaf_der, _ = _full_chain()
    with pytest.raises(IdentityCertificateError, match="timezone-aware"):
        verify_fulcio_leaf(leaf_der, bundle, at_time=dt.datetime(2026, 6, 1, 12, 0, 0))  # noqa: DTZ001
