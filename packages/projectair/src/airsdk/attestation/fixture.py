"""Simulated NRAS for tests and demos. NOT a real attestation.

``FixtureNRAS`` plays the NVIDIA Remote Attestation Service in-process: it
signs EATs with a locally generated EC P-384 key and publishes the matching
self-signed certificate so ``air verify-public --attestation offline`` can
run the full cryptographic verification path (signature, nonce binding,
RIM verdict, device consistency) with no GPU and no network.

Every token this module produces carries the claim
``"x-nvidia-simulated": true`` so a fixture EAT can never be mistaken for
real hardware evidence. Live attestation goes through
``airsdk.attestation.nras.NRASClient`` on an NVIDIA Confidential Computing
instance (W1, experimental).
"""
from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import jwt as pyjwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from cryptography.x509.oid import NameOID

from airsdk._compat import UTC
from airsdk.attestation.types import NRASResult

__all__ = ["FIXTURE_NRAS_URL", "FixtureNRAS"]

FIXTURE_NRAS_URL = "fixture://nras.simulated.local/v3/attest/gpu"
_CLAIMS_VERSION = "fixture-3.0"


class FixtureNRAS:
    """In-process stand-in for NRAS. Satisfies ``AttestationProvider``."""

    def __init__(
        self,
        *,
        device_count: int = 1,
        rim_matched: bool = True,
        claims_version: str = _CLAIMS_VERSION,
    ) -> None:
        self._key = ec.generate_private_key(ec.SECP384R1())
        self._certificate = _self_signed_certificate(self._key)
        self._device_count = device_count
        self._rim_matched = rim_matched
        self._claims_version = claims_version

    @property
    def nras_url(self) -> str:
        return FIXTURE_NRAS_URL

    @property
    def signing_certificate_pem(self) -> bytes:
        """PEM certificate an offline verifier caches as its trust anchor."""
        return self._certificate.public_bytes(Encoding.PEM)

    @property
    def signing_key_pem(self) -> bytes:
        """PEM private key. Exposed for tests that need to forge tokens."""
        return self._key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        )

    def write_signing_certificate(self, path: str | Path) -> Path:
        """Write the trust-anchor certificate where offline verify expects it."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(self.signing_certificate_pem)
        return target

    def attest(self, *, nonce: str, gpu_arch: str) -> NRASResult:
        """Issue a simulated overall EAT plus per-device detached EATs."""
        now = datetime.now(UTC)
        base_claims: dict[str, object] = {
            "iss": FIXTURE_NRAS_URL,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(hours=1)).timestamp()),
            "eat_nonce": nonce,
            "eat_profile": self._claims_version,
            "x-nvidia-simulated": True,
            "x-nvidia-gpu-arch": gpu_arch,
        }
        overall_claims = {
            **base_claims,
            "x-nvidia-overall-att-result": self._rim_matched,
            "x-nvidia-num-devices": self._device_count,
        }
        device_eats = [
            pyjwt.encode(
                {**base_claims, "x-nvidia-device-id": f"GPU-{index}"},
                self._key,
                algorithm="ES384",
            )
            for index in range(self._device_count)
        ]
        return NRASResult(
            detached_eat=pyjwt.encode(overall_claims, self._key, algorithm="ES384"),
            device_eats=device_eats,
            claims_version=self._claims_version,
            rim_matched=self._rim_matched,
        )


def _self_signed_certificate(key: ec.EllipticCurvePrivateKey) -> x509.Certificate:
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "AIR Fixture NRAS (simulated)"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Vindicara test fixture"),
        ]
    )
    now = datetime.now(UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA384())
    )
