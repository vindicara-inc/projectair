"""Tests for AdapterRouter cross-tenant resolution (Layer 4 Wave 2, piece 3).

``route_fulcio_vouched`` may resolve an unregistered issuer via an injected
OIDC-Discovery factory, but only when a Fulcio-validated cert vouches for that
exact issuer. Raw/unvouched issuers are never accepted; the strict ``route``
keeps failing closed.
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
    ConfigurationError,
    CrossTenantTrustError,
    IdentityCertificateError,
    UnregisteredIssuerError,
)
from airsdk.handoff.fulcio import FulcioTrustBundle
from airsdk.handoff.idp.base import AdapterRouter, CapabilityToken, IdPAdapter

_NOW = dt.datetime(2026, 6, 1, 12, 0, 0, tzinfo=dt.UTC)
_NB = _NOW - dt.timedelta(hours=1)
_NA = _NOW + dt.timedelta(hours=1)
_OID_V2 = "1.3.6.1.4.1.57264.1.8"
_ISSUER = "https://issuer.example/"


class _StubAdapter(IdPAdapter):
    def __init__(self, issuers: list[str] | None = None) -> None:
        self._issuers = issuers or []

    def handled_issuers(self) -> list[str]:
        return list(self._issuers)

    def issue_capability_token(self, **kwargs: Any) -> CapabilityToken:
        raise NotImplementedError

    def verify_capability_token(self, **kwargs: Any) -> CapabilityToken:
        raise NotImplementedError

    def discover_metadata(self, issuer_url: str | None = None) -> dict[str, Any]:
        return {}


def _der_utf8(text: str) -> bytes:
    body = text.encode("utf-8")
    return b"\x0c" + bytes([len(body)]) + body


def _root_and_leaf(issuer_value: str = _ISSUER) -> tuple[FulcioTrustBundle, bytes]:
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
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "agent")]))
        .issuer_name(name)
        .public_key(leaf_id.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NB).not_valid_after(_NA)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier(_OID_V2), _der_utf8(issuer_value)),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )
    bundle = FulcioTrustBundle(roots=[root.public_bytes(serialization.Encoding.DER)])
    return bundle, leaf.public_bytes(serialization.Encoding.DER)


def test_fulcio_vouched_issuer_resolved_via_factory() -> None:
    bundle, leaf_der = _root_and_leaf()
    stub = _StubAdapter()
    calls: list[str] = []

    def factory(issuer: str) -> IdPAdapter:
        calls.append(issuer)
        return stub

    router = AdapterRouter(discovery_factory=factory)
    got = router.route_fulcio_vouched(
        _ISSUER, leaf_cert_der=leaf_der, trust_bundle=bundle, at_time=_NOW
    )
    assert got is stub
    assert calls == [_ISSUER]
    # cached for subsequent strict routes
    assert router.route(_ISSUER) is stub


def test_registered_issuer_short_circuits_without_cert() -> None:
    bundle, _ = _root_and_leaf()
    registered = _StubAdapter(issuers=[_ISSUER])
    called = False

    def factory(issuer: str) -> IdPAdapter:
        nonlocal called
        called = True
        return _StubAdapter()

    router = AdapterRouter(discovery_factory=factory)
    router.register(registered)
    got = router.route_fulcio_vouched(
        _ISSUER, leaf_cert_der=b"not-even-a-cert", trust_bundle=bundle, at_time=_NOW
    )
    assert got is registered
    assert called is False


def test_issuer_mismatch_rejected() -> None:
    bundle, leaf_der = _root_and_leaf(issuer_value=_ISSUER)
    router = AdapterRouter(discovery_factory=lambda _iss: _StubAdapter())
    with pytest.raises(CrossTenantTrustError, match="vouches for issuer"):
        router.route_fulcio_vouched(
            "https://evil.example/", leaf_cert_der=leaf_der, trust_bundle=bundle, at_time=_NOW
        )


def test_untrusted_cert_rejected_before_discovery() -> None:
    _, leaf_der = _root_and_leaf()
    other_key = ec.generate_private_key(ec.SECP256R1())
    other_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Other Root")])
    other_root = (
        x509.CertificateBuilder()
        .subject_name(other_name).issuer_name(other_name)
        .public_key(other_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NB).not_valid_after(_NA)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(other_key, hashes.SHA256())
    )
    wrong_bundle = FulcioTrustBundle(roots=[other_root.public_bytes(serialization.Encoding.DER)])
    called = False

    def factory(_iss: str) -> IdPAdapter:
        nonlocal called
        called = True
        return _StubAdapter()

    router = AdapterRouter(discovery_factory=factory)
    with pytest.raises(IdentityCertificateError, match="no trusted issuer"):
        router.route_fulcio_vouched(
            _ISSUER, leaf_cert_der=leaf_der, trust_bundle=wrong_bundle, at_time=_NOW
        )
    assert called is False


def test_vouched_but_no_factory_configured() -> None:
    bundle, leaf_der = _root_and_leaf()
    router = AdapterRouter()  # no discovery_factory
    with pytest.raises(ConfigurationError, match="discovery_factory"):
        router.route_fulcio_vouched(
            _ISSUER, leaf_cert_der=leaf_der, trust_bundle=bundle, at_time=_NOW
        )


def test_strict_route_still_rejects_unregistered() -> None:
    router = AdapterRouter(discovery_factory=lambda _iss: _StubAdapter())
    with pytest.raises(UnregisteredIssuerError):
        router.route("https://issuer.example/")
