"""Tests for Fulcio leaf-cert OIDC issuer extraction (Layer 4 Wave 2, piece 1).

``parse_fulcio_san_issuer`` reads the OIDC issuer that Sigstore Fulcio embeds
in a dedicated certificate extension (V2: DER UTF8String at
1.3.6.1.4.1.57264.1.8; V1: raw UTF-8 at 1.3.6.1.4.1.57264.1.1). Parsing is not
trust; these tests cover extraction and malformed-input handling only.
"""
from __future__ import annotations

import datetime as _dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from airsdk.handoff.exceptions import IdentityCertificateError
from airsdk.handoff.identity import parse_fulcio_san_issuer

_OID_V2 = "1.3.6.1.4.1.57264.1.8"
_OID_V1 = "1.3.6.1.4.1.57264.1.1"


def _der_utf8string(text: str) -> bytes:
    """Encode ``text`` as a short-form DER UTF8String (tag 0x0C)."""
    body = text.encode("utf-8")
    if len(body) >= 0x80:  # keep tests in short-form length
        raise ValueError("test helper only encodes short-form lengths")
    return b"\x0c" + bytes([len(body)]) + body


def _cert_with_extension(oid: str, value: bytes) -> bytes:
    """Build a self-signed DER cert carrying one opaque extension."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sigstore")])
    now = _dt.datetime(2026, 1, 1, tzinfo=_dt.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + _dt.timedelta(minutes=10))
    )
    if oid:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier(oid), value),
            critical=False,
        )
    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


def test_parses_v2_issuer_der_utf8string() -> None:
    issuer = "https://accounts.google.com"
    der = _cert_with_extension(_OID_V2, _der_utf8string(issuer))
    assert parse_fulcio_san_issuer(der) == issuer


def test_parses_v1_issuer_raw_utf8() -> None:
    issuer = "https://token.actions.githubusercontent.com"
    der = _cert_with_extension(_OID_V1, issuer.encode("utf-8"))
    assert parse_fulcio_san_issuer(der) == issuer


def test_v2_wins_when_both_present() -> None:
    v2_issuer = "https://v2.example.com"
    # Build a cert with both extensions; V2 must take precedence.
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sigstore")])
    now = _dt.datetime(2026, 1, 1, tzinfo=_dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + _dt.timedelta(minutes=10))
        .add_extension(
            x509.UnrecognizedExtension(
                x509.ObjectIdentifier(_OID_V1), b"https://v1.example.com"
            ),
            critical=False,
        )
        .add_extension(
            x509.UnrecognizedExtension(
                x509.ObjectIdentifier(_OID_V2), _der_utf8string(v2_issuer)
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    assert parse_fulcio_san_issuer(der) == v2_issuer


def test_missing_issuer_extension_raises() -> None:
    der = _cert_with_extension("", b"")  # no Fulcio issuer extension
    with pytest.raises(IdentityCertificateError, match="neither the V2"):
        parse_fulcio_san_issuer(der)


def test_invalid_der_raises() -> None:
    with pytest.raises(IdentityCertificateError, match="not a valid DER"):
        parse_fulcio_san_issuer(b"this is not a certificate")


def test_non_bytes_input_raises() -> None:
    with pytest.raises(IdentityCertificateError, match="requires bytes"):
        parse_fulcio_san_issuer("not-bytes")  # type: ignore[arg-type]
