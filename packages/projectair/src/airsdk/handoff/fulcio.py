"""Layer 4 Wave 2 (piece 2): Fulcio leaf-certificate chain validation.

Given a Sigstore Fulcio leaf certificate and an operator-supplied trust bundle
(the Fulcio root, plus any intermediates), this module validates that the leaf
chains to a trusted root and returns the agent's Ed25519 signing key bound by
that certificate. That key is what the cross-agent verifier uses to check a
handoff record's signature, replacing the Wave 1 pre-registered key dictionary.

Scope and honesty: this is a Fulcio-focused minimal path validator, not a
general-purpose X.509 engine. It performs the checks enumerated on
:func:`verify_fulcio_leaf` and nothing more. The trust anchor is whatever
Fulcio root the operator supplies, fetched out of band from the Sigstore TUF
root; this module never hardcodes a root. Revocation, name constraints, and
certificate policy OIDs are out of scope (Fulcio certs are ~10-minute-lived, so
revocation is handled by expiry).
"""
from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes

from .exceptions import IdentityCertificateError

_MAX_CHAIN_DEPTH = 8


def _load(der: bytes) -> x509.Certificate:
    if not isinstance(der, (bytes, bytearray)):
        raise IdentityCertificateError(
            f"certificate must be DER bytes; got {type(der).__name__}"
        )
    try:
        return x509.load_der_x509_certificate(bytes(der))
    except ValueError as e:
        raise IdentityCertificateError(f"not a valid DER X.509 certificate: {e}") from e


def _signed_by(child: x509.Certificate, issuer_public_key: CertificatePublicKeyTypes) -> bool:
    """Return True iff ``issuer_public_key`` verifies ``child``'s signature.

    Dispatches on the issuer key type. Unsupported key types return False
    (fail closed) rather than raising, so an exotic issuer simply does not
    anchor the chain.
    """
    signature = child.signature
    tbs = child.tbs_certificate_bytes
    try:
        if isinstance(issuer_public_key, ed25519.Ed25519PublicKey):
            issuer_public_key.verify(signature, tbs)
            return True
        algorithm = child.signature_hash_algorithm
        if algorithm is None:
            return False
        if isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
            issuer_public_key.verify(signature, tbs, ec.ECDSA(algorithm))
            return True
        if isinstance(issuer_public_key, rsa.RSAPublicKey):
            issuer_public_key.verify(signature, tbs, padding.PKCS1v15(), algorithm)
            return True
    except InvalidSignature:
        return False
    return False


def _within_validity(cert: x509.Certificate, at_time: _dt.datetime) -> bool:
    return cert.not_valid_before_utc <= at_time <= cert.not_valid_after_utc


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    except x509.ExtensionNotFound:
        return False
    return bool(constraints.value.ca)


@dataclass(slots=True)
class FulcioTrustBundle:
    """Operator-supplied trust anchors for Fulcio verification.

    ``roots`` and ``intermediates`` are DER-encoded certificates. Obtain the
    current Sigstore public-good roots from the Sigstore TUF root; for private
    Fulcio deployments, supply your own CA. A bundle with no roots is rejected.
    """

    roots: list[bytes]
    intermediates: list[bytes] = field(default_factory=list)

    def load(self) -> tuple[list[x509.Certificate], list[x509.Certificate]]:
        roots = [_load(d) for d in self.roots]
        if not roots:
            raise IdentityCertificateError("trust bundle contains no root certificates")
        intermediates = [_load(d) for d in self.intermediates]
        return roots, intermediates


def _anchor_to_root(
    leaf: x509.Certificate,
    intermediates: list[x509.Certificate],
    roots: list[x509.Certificate],
    at_time: _dt.datetime,
) -> None:
    """Walk leaf -> intermediates -> trusted root, verifying each link.

    Raises :class:`IdentityCertificateError` if no chain to a trusted, valid,
    CA root can be built within :data:`_MAX_CHAIN_DEPTH` links.
    """
    current = leaf
    for _ in range(_MAX_CHAIN_DEPTH + 1):
        for root in roots:
            if current.issuer == root.subject and _signed_by(current, root.public_key()):
                if not _within_validity(root, at_time):
                    raise IdentityCertificateError("trusted root is outside its validity window")
                if not _is_ca(root):
                    raise IdentityCertificateError("trusted root does not assert BasicConstraints CA=True")
                return
        issuer_cert: x509.Certificate | None = None
        for candidate in intermediates:
            if current.issuer == candidate.subject and _signed_by(current, candidate.public_key()):
                issuer_cert = candidate
                break
        if issuer_cert is None:
            raise IdentityCertificateError(
                "no trusted issuer found for certificate subject="
                f"{current.subject.rfc4514_string()!r}"
            )
        if not _within_validity(issuer_cert, at_time):
            raise IdentityCertificateError("intermediate certificate is outside its validity window")
        if not _is_ca(issuer_cert):
            raise IdentityCertificateError(
                "intermediate certificate does not assert BasicConstraints CA=True"
            )
        current = issuer_cert
    raise IdentityCertificateError("certificate chain exceeded maximum depth")


def verify_fulcio_leaf(
    leaf_der: bytes,
    bundle: FulcioTrustBundle,
    *,
    at_time: _dt.datetime | None = None,
) -> Ed25519PublicKey:
    """Validate a Fulcio leaf certificate and return its Ed25519 public key.

    Checks performed:

    - a chain leaf -> [intermediates] -> trusted root exists, where each cert's
      issuer name equals the parent's subject AND the parent's public key
      verifies the child's signature;
    - the terminal root is present in ``bundle.roots``;
    - every certificate in the chain is within its validity window at
      ``at_time`` (default: the current UTC time);
    - intermediates and the root assert BasicConstraints CA=True, and the leaf
      does not;
    - the leaf's public key is Ed25519 (Layer 4 handoff identity is
      Ed25519-only); any other key type is rejected.

    Returns the leaf's :class:`Ed25519PublicKey`, suitable for verifying the
    handoff record signed by that agent identity.
    """
    when = at_time or _dt.datetime.now(tz=_dt.UTC)
    if when.tzinfo is None:
        raise IdentityCertificateError("at_time must be timezone-aware (UTC)")

    leaf = _load(leaf_der)
    roots, intermediates = bundle.load()

    if not _within_validity(leaf, when):
        raise IdentityCertificateError("leaf certificate is outside its validity window")
    if _is_ca(leaf):
        raise IdentityCertificateError("leaf certificate unexpectedly asserts BasicConstraints CA=True")

    _anchor_to_root(leaf, intermediates, roots, when)

    public_key = leaf.public_key()
    if not isinstance(public_key, Ed25519PublicKey):
        raise IdentityCertificateError(
            f"leaf public key is {type(public_key).__name__}, expected Ed25519 "
            "(Layer 4 handoff identity is Ed25519-only)"
        )
    return public_key


__all__ = ["FulcioTrustBundle", "verify_fulcio_leaf"]
