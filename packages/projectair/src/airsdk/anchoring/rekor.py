"""Sigstore Rekor transparency-log anchoring for Project AIR chain roots.

Submits a chain root hash plus an ECDSA P-256 signature over that hash to
a Sigstore-Rekor-compatible transparency log, parses the resulting log
entry into a verifiable record, and offers offline re-verification of the
embedded inclusion proof.

The Rekor entry type is ``hashedrekord`` (api version ``0.0.1``). The
signing identity is the operator's anchoring key, not a Fulcio-issued
X.509 cert: Rekor accepts a raw PEM public key in the ``publicKey``
field, which is what we store. Auditors can reconstruct the key path
without any Sigstore identity-issuance machinery.

Why ECDSA P-256 and not Ed25519: Sigstore (Fulcio + Rekor + cosign) is
built around ECDSA P-256 with SHA-256. Rekor's hashedrekord schema lists
Ed25519 as accepted, but the public ``rekor.sigstore.dev`` rejects
Ed25519 signatures with ``ed25519: invalid signature`` even when they
verify locally. ECDSA P-256 with SHA-256 is the path Rekor's verifier
actually exercises in production, so that is what we sign with. The
chain signer (per-step AgDR records) remains Ed25519; only the
anchoring identity is ECDSA.
"""
from __future__ import annotations

import base64
import json
import logging
import time
import urllib.error
import urllib.request
from typing import Any, Final

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from sigstore.models import TransparencyLogEntry
from sigstore.models import (  # type: ignore[attr-defined]
    verify_merkle_inclusion as _verify_merkle_inclusion,
)

from airsdk.anchoring.exceptions import (
    RekorEntryRejectedError,
    RekorProofInvalidError,
    RekorRateLimitedError,
    RekorUnreachableError,
)
from airsdk.types import RekorAnchor

# verify_merkle_inclusion is part of sigstore-python's documented public API
# but is not in ``sigstore.models.__all__``. The alias above lets typecheckers
# follow the symbol while suppressing the (false-positive) attr-defined error.
verify_merkle_inclusion = _verify_merkle_inclusion

_log = logging.getLogger(__name__)

DEFAULT_REKOR_URL: Final[str] = "https://rekor.sigstore.dev"
_HASHEDREKORD_API_VERSION: Final[str] = "0.0.1"
_HASHEDREKORD_KIND: Final[str] = "hashedrekord"
_DEFAULT_TIMEOUT: Final[float] = 10.0
_MAX_RETRIES: Final[int] = 3
_INITIAL_BACKOFF: Final[float] = 0.5


def _ecdsa_public_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.public_key().public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )


class RekorClient:
    """Submit hashes to a Rekor transparency log and verify inclusion.

    Parameters
    ----------
    rekor_url:
        Base URL of the Rekor instance. Default is the public Sigstore
        Rekor at ``rekor.sigstore.dev``. Enterprise tenants pass the URL
        of a private Trillian-backed Rekor instance.
    signing_key:
        ECDSA P-256 private key used to sign chain root hashes before
        they are submitted to Rekor. The corresponding public key is
        embedded in the entry so anyone replaying the chain can
        re-verify the signature without contacting Vindicara.
    timeout_seconds:
        Per-HTTP-request timeout. The orchestrator decides what to do on
        timeout based on its failure policy.
    """

    def __init__(
        self,
        signing_key: ec.EllipticCurvePrivateKey,
        rekor_url: str = DEFAULT_REKOR_URL,
        timeout_seconds: float = _DEFAULT_TIMEOUT,
    ) -> None:
        if not rekor_url.startswith(("http://", "https://")):
            raise ValueError(f"rekor_url must be http(s), got {rekor_url!r}")
        if not isinstance(signing_key.curve, ec.SECP256R1):
            raise ValueError(
                f"signing_key must be on curve SECP256R1 (P-256), got {signing_key.curve.name}",
            )
        self._url = rekor_url.rstrip("/")
        self._timeout = timeout_seconds
        self._signing_key = signing_key
        self._public_pem = _ecdsa_public_pem(signing_key)

    @property
    def rekor_url(self) -> str:
        return self._url

    def anchor(self, sha256_digest: bytes) -> RekorAnchor:
        """Submit a SHA-256 digest as a hashedrekord entry, return verified anchor.

        The signature is ECDSA P-256 over the **raw 32-byte SHA-256 hash**,
        using Prehashed semantics (no further hashing applied at sign time).
        This matches what ``rekor.sigstore.dev`` actually verifies against:
        the verifier decodes the hex hash field to bytes and runs ECDSA
        verification against those bytes directly, treating them as already
        the digest. Empirically confirmed by reproducing local verification
        of a known-good public-log entry.

        Using ``ec.ECDSA(hashes.SHA256())`` (without Prehashed) double-hashes
        and produces signatures Rekor rejects with "invalid signature when
        validating ASN.1 encoded signature".
        """
        if len(sha256_digest) != 32:
            raise ValueError(f"sha256 digest must be 32 bytes, got {len(sha256_digest)}")
        signature = self._signing_key.sign(sha256_digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        body = self._build_hashedrekord(sha256_digest, signature)
        response_json = self._post_with_retries(body)
        return self._anchor_from_response(response_json)

    def verify(self, anchor: RekorAnchor, expected_sha256: bytes) -> bool:
        """Re-verify a stored Rekor anchor against ``expected_sha256``."""
        if len(expected_sha256) != 32:
            raise ValueError(f"sha256 digest must be 32 bytes, got {len(expected_sha256)}")
        try:
            entry = TransparencyLogEntry._from_v1_response(anchor.inclusion_proof)
            verify_merkle_inclusion(entry)
        except Exception as exc:
            raise RekorProofInvalidError(f"Rekor inclusion proof failed: {exc}") from exc
        # Confirm the entry's body actually references our digest. The
        # canonicalized body is base64-encoded JSON of the hashedrekord.
        body_b64 = anchor.inclusion_proof.get(next(iter(anchor.inclusion_proof)), {}).get("body")
        if body_b64:
            try:
                body_dict = json.loads(base64.b64decode(body_b64))
            except (ValueError, json.JSONDecodeError) as exc:
                raise RekorProofInvalidError(f"unable to decode Rekor body: {exc}") from exc
            stored_hex = body_dict.get("spec", {}).get("data", {}).get("hash", {}).get("value", "")
            if stored_hex.lower() != expected_sha256.hex():
                raise RekorProofInvalidError(
                    f"Rekor entry hashes {stored_hex}, expected {expected_sha256.hex()}",
                )
        return True

    # -- internal -----------------------------------------------------

    def _build_hashedrekord(self, digest: bytes, signature: bytes) -> dict[str, Any]:
        return {
            "apiVersion": _HASHEDREKORD_API_VERSION,
            "kind": _HASHEDREKORD_KIND,
            "spec": {
                "signature": {
                    "content": base64.b64encode(signature).decode("ascii"),
                    "publicKey": {
                        "content": base64.b64encode(self._public_pem).decode("ascii"),
                    },
                },
                "data": {
                    "hash": {
                        "algorithm": "sha256",
                        "value": digest.hex(),
                    },
                },
            },
        }

    def _post_with_retries(self, body: dict[str, Any]) -> dict[str, Any]:
        url = f"{self._url}/api/v1/log/entries"
        payload = json.dumps(body).encode("utf-8")
        backoff = _INITIAL_BACKOFF
        last_exc: Exception | None = None
        for attempt in range(_MAX_RETRIES):
            try:
                return self._post_once(url, payload)
            except RekorRateLimitedError as exc:
                last_exc = exc
                if attempt == _MAX_RETRIES - 1:
                    raise
                time.sleep(backoff)
                backoff *= 2
            except RekorUnreachableError:
                raise
        # Defensive: should be unreachable given the loop logic above.
        raise RekorRateLimitedError(f"Rekor exhausted {_MAX_RETRIES} retries: {last_exc}")

    def _post_once(self, url: str, payload: bytes) -> dict[str, Any]:
        request = urllib.request.Request(  # noqa: S310 - URL scheme enforced at construction
            url,
            data=payload,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as raw:  # noqa: S310 - URL scheme enforced at construction
                return self._parse_response(raw.read())
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                raise RekorRateLimitedError("Rekor returned 429 (rate limited)") from exc
            try:
                detail = exc.read().decode("utf-8", errors="replace")
            except Exception:
                detail = ""
            raise RekorEntryRejectedError(
                f"Rekor rejected entry: {exc.code} {detail}",
            ) from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise RekorUnreachableError(f"Rekor {self._url} unreachable: {exc}") from exc

    def _parse_response(self, body: bytes) -> dict[str, Any]:
        try:
            data: dict[str, Any] = json.loads(body)
        except json.JSONDecodeError as exc:
            raise RekorEntryRejectedError(f"Rekor returned non-JSON body: {exc}") from exc
        if not isinstance(data, dict) or len(data) != 1:
            raise RekorEntryRejectedError(
                f"Rekor returned unexpected response shape: {list(data)[:3] if isinstance(data, dict) else type(data)}",
            )
        return data

    def _anchor_from_response(self, response: dict[str, Any]) -> RekorAnchor:
        # Validate the response is well-formed by parsing it through sigstore-python.
        try:
            entry = TransparencyLogEntry._from_v1_response(response)
            verify_merkle_inclusion(entry)
        except Exception as exc:
            raise RekorProofInvalidError(f"Rekor returned an entry that did not verify: {exc}") from exc

        uuid, payload = next(iter(response.items()))
        return RekorAnchor(
            log_index=int(payload["logIndex"]),
            uuid=uuid,
            integrated_time=int(payload["integratedTime"]),
            log_id=payload["logID"],
            inclusion_proof=response,
            rekor_url=self._url,
        )
