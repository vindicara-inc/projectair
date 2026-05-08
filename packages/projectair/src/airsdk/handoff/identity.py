"""Agent identity certificates for Layer 4 handoff records.

Wave 1 ships the ``LOCAL_DEV`` shortcut: a locally-generated Ed25519 keypair
with no real X.509 certificate, used for single-tenant demos and tests. The
identity_certificate_hash for a LOCAL_DEV identity is BLAKE3 of the raw
Ed25519 public key bytes; the chain_hash hashes a single-element JCS array
of the same.

Sigstore Fulcio (OSS path) and X.509 PEM (enterprise path) handling are
stubbed for v1 and ship in v1.5 alongside cross-tenant production support.

Per Section 6.2:
    identity_certificate_hash       = BLAKE3(JCS(<leaf_cert_der_b64>))
    identity_certificate_chain_hash = BLAKE3(JCS(<chain_array>))

The protocol layer hashes already-canonical material (DER bytes) by first
base64-encoding it into a JSON-native string, then JCS-canonicalizing the
resulting structure. This guarantees cross-language reproducibility.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
from enum import StrEnum

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonicalize import canonicalize_and_hash
from .exceptions import IdentityCertificateError


class IdentityFormat(StrEnum):
    """Identity certificate format declared on a handoff record."""

    SIGSTORE_FULCIO = "sigstore_fulcio"
    X509_PEM = "x509_pem"
    # Wave 1 demo / test shortcut. Not a production format; the verifier
    # flags chains using LOCAL_DEV identities so operators know they are
    # not anchored to a real CA root.
    LOCAL_DEV = "local_dev"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def cert_hash_from_der(der_bytes: bytes) -> str:
    """Return the canonical identity_certificate_hash for raw DER bytes.

    Per Section 6.2 the hash is BLAKE3(JCS(<base64url-no-pad>)). Wrapping
    the DER in a JCS-canonicalized JSON string gives every language the
    same hashable bytes.
    """
    if not isinstance(der_bytes, (bytes, bytearray)):
        raise IdentityCertificateError(
            f"cert_hash_from_der requires bytes; got {type(der_bytes).__name__}"
        )
    return canonicalize_and_hash(_b64url(bytes(der_bytes)))


def chain_hash_from_der_array(chain: list[bytes]) -> str:
    """Return identity_certificate_chain_hash for a leaf -> root DER list.

    The chain is encoded as a JSON array of base64url-unpadded DER strings,
    JCS-canonicalized, then BLAKE3-hashed.
    """
    if not isinstance(chain, list) or len(chain) == 0:
        raise IdentityCertificateError(
            "chain must be a non-empty list of DER bytes (leaf -> root)"
        )
    encoded = [_b64url(bytes(c)) for c in chain]
    return canonicalize_and_hash(encoded)


@dataclass(slots=True)
class AgentIdentity:
    """A signing identity bound to an agent for handoff record signing.

    For LOCAL_DEV the private/public keypair is held in process memory and
    no certificate chain exists; cert_hash hashes the raw public key bytes.
    For SIGSTORE_FULCIO and X509_PEM the leaf cert DER and chain DER list
    must be supplied at construction time.

    Production deployments rotate Fulcio certs every 10 minutes per Section
    15.13's defense-in-depth note; this class is the per-handoff snapshot,
    not a long-lived identity object.
    """

    agent_id: str
    fmt: IdentityFormat
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey
    cert_hash: str
    chain_hash: str
    code_commit: str | None = None
    leaf_cert_der: bytes | None = None
    chain_der: list[bytes] = field(default_factory=list)
    issuer_url: str | None = None  # for cross-tenant Fulcio SAN discovery

    def public_key_bytes(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign(self, message: bytes) -> bytes:
        """Sign ``message`` with the Ed25519 private key."""
        return self.private_key.sign(message)

    def to_record_block(self) -> dict[str, object]:
        """Render the ``agent`` block of a handoff record per Section 6.2."""
        block: dict[str, object] = {
            "id": self.agent_id,
            "identity_certificate_format": self.fmt.value,
            "identity_certificate_hash": self.cert_hash,
            "identity_certificate_chain_hash": self.chain_hash,
        }
        if self.code_commit is not None:
            block["code_commit"] = self.code_commit
        return block


def generate_local_dev_identity(
    agent_id: str,
    *,
    code_commit: str | None = None,
    issuer_url: str | None = None,
) -> AgentIdentity:
    """Generate a fresh LOCAL_DEV identity for tests and Wave 1 demos.

    The cert_hash hashes the raw Ed25519 public key bytes; the chain_hash
    hashes a single-element array containing the same. This format is NOT
    production-grade and the verifier flags it as such.
    """
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    pk_bytes = pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    cert_hash = cert_hash_from_der(pk_bytes)
    chain_hash = chain_hash_from_der_array([pk_bytes])
    return AgentIdentity(
        agent_id=agent_id,
        fmt=IdentityFormat.LOCAL_DEV,
        private_key=sk,
        public_key=pk,
        cert_hash=cert_hash,
        chain_hash=chain_hash,
        code_commit=code_commit,
        issuer_url=issuer_url,
    )


def parse_fulcio_san_issuer(_leaf_cert_der: bytes) -> str:
    """Extract the IdP issuer URL from a Fulcio leaf cert SAN extension.

    Wave 1 stub. Wave 2 implements URI-SAN parsing per Section 7.5; until
    then operators must supply the target IdP issuer out of band.
    """
    raise IdentityCertificateError(
        "Fulcio SAN issuer parsing is Wave 2; supply target_agent_idp_issuer "
        "out-of-band in Wave 1"
    )


__all__ = [
    "AgentIdentity",
    "IdentityFormat",
    "cert_hash_from_der",
    "chain_hash_from_der_array",
    "generate_local_dev_identity",
    "parse_fulcio_san_issuer",
]
