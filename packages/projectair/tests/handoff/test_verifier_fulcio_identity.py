"""Tests for Wave 2 piece 4: Fulcio identity resolution in CrossAgentVerifier.

Exercises the behavior change (validate identity from a Fulcio cert as-of the
record's timestamp; reject LOCAL_DEV when a trust bundle is set; keep Wave 1
behavior when no bundle is configured) at the unit level, without building a
full signed handoff chain.
"""
from __future__ import annotations

import datetime as dt
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID

from airsdk.handoff.exceptions import (
    CrossAgentVerificationError,
    IdentityCertificateError,
    UnregisteredIssuerError,
)
from airsdk.handoff.fulcio import FulcioTrustBundle
from airsdk.handoff.identity import cert_hash_from_der
from airsdk.handoff.idp.base import AdapterRouter, CapabilityToken, IdPAdapter
from airsdk.handoff.verifier import CrossAgentVerifier

_TS = "2026-06-01T12:00:00Z"
_NOW = dt.datetime(2026, 6, 1, 12, 0, 0, tzinfo=dt.timezone.utc)
_NB = _NOW - dt.timedelta(hours=1)
_NA = _NOW + dt.timedelta(hours=1)
_OID_V2 = "1.3.6.1.4.1.57264.1.8"
_FULCIO = "sigstore_fulcio"
_LOCAL = "local_dev"


def _der_utf8(text: str) -> bytes:
    body = text.encode("utf-8")
    return b"\x0c" + bytes([len(body)]) + body


def _chain(
    *, issuer_value: str | None = None, nb: dt.datetime = _NB, na: dt.datetime = _NA
) -> tuple[FulcioTrustBundle, bytes, ed25519.Ed25519PrivateKey]:
    root_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root")])
    root = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NB).not_valid_after(_NA)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(root_key, hashes.SHA256())
    )
    leaf_id = ed25519.Ed25519PrivateKey.generate()
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "agent")]))
        .issuer_name(name)
        .public_key(leaf_id.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb).not_valid_after(na)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    if issuer_value is not None:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier(_OID_V2), _der_utf8(issuer_value)),
            critical=False,
        )
    leaf = builder.sign(root_key, hashes.SHA256())
    bundle = FulcioTrustBundle(roots=[root.public_bytes(serialization.Encoding.DER)])
    return bundle, leaf.public_bytes(serialization.Encoding.DER), leaf_id


def _rec(fmt: str, cert_hash: str, ts: str = _TS) -> dict[str, Any]:
    return {
        "agent": {"identity_certificate_format": fmt, "identity_certificate_hash": cert_hash},
        "ts_iso": ts,
    }


def _raw(key: ed25519.Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


class _StubAdapter(IdPAdapter):
    def handled_issuers(self) -> list[str]:
        return []

    def issue_capability_token(self, **kwargs: Any) -> CapabilityToken:
        raise NotImplementedError

    def verify_capability_token(self, **kwargs: Any) -> CapabilityToken:
        raise NotImplementedError

    def discover_metadata(self, issuer_url: str | None = None) -> dict[str, Any]:
        return {}


def test_register_fulcio_cert_returns_hash() -> None:
    bundle, leaf_der, _ = _chain()
    v = CrossAgentVerifier(adapter_router=AdapterRouter(), fulcio_trust_bundle=bundle)
    assert v.register_fulcio_cert(leaf_der) == cert_hash_from_der(leaf_der)


def test_resolve_fulcio_identity_returns_leaf_key() -> None:
    bundle, leaf_der, leaf_id = _chain()
    v = CrossAgentVerifier(adapter_router=AdapterRouter(), fulcio_trust_bundle=bundle)
    h = v.register_fulcio_cert(leaf_der)
    key = v._resolve_identity_key(_rec(_FULCIO, h))
    assert _raw(key) == _raw(leaf_id.public_key())


def test_local_dev_rejected_when_bundle_set() -> None:
    bundle, leaf_der, _ = _chain()
    v = CrossAgentVerifier(adapter_router=AdapterRouter(), fulcio_trust_bundle=bundle)
    h = v.register_fulcio_cert(leaf_der)
    with pytest.raises(CrossAgentVerificationError, match="must be Sigstore Fulcio"):
        v._resolve_identity_key(_rec(_LOCAL, h))


def test_unregistered_fulcio_cert_rejected() -> None:
    bundle, _, _ = _chain()
    v = CrossAgentVerifier(adapter_router=AdapterRouter(), fulcio_trust_bundle=bundle)
    with pytest.raises(CrossAgentVerificationError, match="no Fulcio certificate registered"):
        v._resolve_identity_key(_rec(_FULCIO, "00" * 32))


def test_cert_hash_mismatch_rejected() -> None:
    bundle, leaf_der, _ = _chain()
    v = CrossAgentVerifier(adapter_router=AdapterRouter(), fulcio_trust_bundle=bundle)
    v.fulcio_certs["deadbeef"] = leaf_der  # planted under a wrong hash
    with pytest.raises(CrossAgentVerificationError, match="does not match record cert_hash"):
        v._resolve_identity_key(_rec(_FULCIO, "deadbeef"))


def test_cert_expired_at_record_time_rejected() -> None:
    bundle, leaf_der, _ = _chain(nb=_NOW - dt.timedelta(hours=3), na=_NOW - dt.timedelta(hours=2))
    v = CrossAgentVerifier(adapter_router=AdapterRouter(), fulcio_trust_bundle=bundle)
    h = v.register_fulcio_cert(leaf_der)
    with pytest.raises(IdentityCertificateError, match="validity window"):
        v._resolve_identity_key(_rec(_FULCIO, h))  # record ts is _TS (= now), cert expired then


def test_wave1_local_dev_resolves_without_bundle() -> None:
    leaf_id = ed25519.Ed25519PrivateKey.generate()
    v = CrossAgentVerifier(adapter_router=AdapterRouter())
    v.register_identity("abc123", leaf_id.public_key())
    key = v._resolve_identity_key(_rec(_LOCAL, "abc123"))
    assert _raw(key) == _raw(leaf_id.public_key())


def test_wave1_fulcio_without_bundle_rejected() -> None:
    v = CrossAgentVerifier(adapter_router=AdapterRouter())
    with pytest.raises(CrossAgentVerificationError, match="requires a Fulcio trust bundle"):
        v._resolve_identity_key(_rec(_FULCIO, "abc123"))


def test_route_capability_issuer_strict_when_no_bundle() -> None:
    router = AdapterRouter()
    with pytest.raises(UnregisteredIssuerError):
        verifier = CrossAgentVerifier(adapter_router=router)
        verifier._route_capability_issuer("https://issuer.example/", _rec(_LOCAL, "x"))


def test_route_capability_issuer_vouched_when_bundle() -> None:
    issuer = "https://issuer.example/"
    bundle, leaf_der, _ = _chain(issuer_value=issuer)
    stub = _StubAdapter()
    router = AdapterRouter(discovery_factory=lambda _iss: stub)
    v = CrossAgentVerifier(adapter_router=router, fulcio_trust_bundle=bundle)
    h = v.register_fulcio_cert(leaf_der)
    got = v._route_capability_issuer(issuer, _rec(_FULCIO, h))
    assert got is stub
