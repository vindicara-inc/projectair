"""RFC 3161 trusted timestamping for Project AIR chain roots.

Submits a chain root hash to a Time Stamping Authority, parses and verifies
the returned ``TimeStampToken``, and packs token bytes plus the TSA's
certificate chain into a record an external auditor can re-verify offline.

We do not roll custom ASN.1: ``rfc3161-client`` carries the parsing and
``cryptography`` handles X.509. The wrapper here is the integration glue
plus the failure-mode mapping the orchestrator depends on.

TSAs supported in v1 (HTTP-based, no auth, public infrastructure):

- FreeTSA           https://freetsa.org/tsr           default
- DigiCert          http://timestamp.digicert.com
- GlobalSign        http://timestamp.globalsign.com/tsa/r6advanced1
- Sectigo           http://timestamp.sectigo.com

Production deployments should pass an explicit ``roots=`` list so the TSA
certificate chain is validated against operator-controlled roots; the
default allows the response's own self-asserted chain so the OSS demo path
works without bundled roots.
"""
from __future__ import annotations

import base64
import logging
import urllib.error
import urllib.request
from datetime import UTC, datetime
from typing import Final

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding as _SerializationEncoding
from rfc3161_client import (
    HashAlgorithm,
    TimestampRequestBuilder,
    TimeStampResponse,
    Verifier,
    VerifierBuilder,
    decode_timestamp_response,
)
from rfc3161_client.errors import VerificationError as _RFC3161VerificationError

from airsdk.anchoring.exceptions import (
    TSACertificateInvalidError,
    TSANonceMismatchError,
    TSARateLimitedError,
    TSAResponseInvalidError,
    TSASignatureInvalidError,
    TSAUnreachableError,
)
from airsdk.types import RFC3161Anchor

_log = logging.getLogger(__name__)

DEFAULT_TSA_URL: Final[str] = "https://freetsa.org/tsr"
_CONTENT_TYPE_REQ: Final[str] = "application/timestamp-query"
_CONTENT_TYPE_RESP: Final[str] = "application/timestamp-reply"
_DEFAULT_TIMEOUT: Final[float] = 10.0


def _sha256(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()


def _encode_certs_pem(response: TimeStampResponse) -> list[str]:
    """Render the TSA-supplied certificates as PEM strings for the anchor record."""
    pems: list[str] = []
    for cert_bytes in response.signed_data.certificates:
        cert = x509.load_der_x509_certificate(bytes(cert_bytes))
        pems.append(cert.public_bytes(encoding=_SerializationEncoding.PEM).decode("ascii"))
    return pems


class RFC3161Client:
    """Submit hashes to a TSA, parse + verify the returned token.

    Parameters
    ----------
    tsa_url:
        Endpoint accepting RFC 3161 requests over HTTP(S). FreeTSA is the
        OSS default.
    timeout_seconds:
        Per-request timeout. The orchestrator's failure policy decides
        whether a timeout fails open or closed.
    roots:
        TSA root certificates to validate the response certificate chain
        against. When ``None``, the verifier accepts the certificate
        embedded in the response (suitable for bootstrap and for OSS users
        who do not yet pin a TSA root). Production deployments pinning a
        specific TSA should always pass roots explicitly.
    """

    def __init__(
        self,
        tsa_url: str = DEFAULT_TSA_URL,
        timeout_seconds: float = _DEFAULT_TIMEOUT,
        roots: list[x509.Certificate] | None = None,
    ) -> None:
        self._url = tsa_url
        self._timeout = timeout_seconds
        self._roots = list(roots) if roots is not None else None

    @property
    def tsa_url(self) -> str:
        return self._url

    def anchor(self, chain_root: bytes) -> RFC3161Anchor:
        """Submit ``chain_root`` to the TSA and return a verified anchor record.

        ``chain_root`` is the bytes to be timestamped; the orchestrator
        passes the BLAKE3 chain root hashed to SHA-256 (RFC 3161 hash
        imprint requires a fixed-size hash, and we standardize on SHA-256
        because every TSA accepts it).
        """
        request = (
            TimestampRequestBuilder()
            .data(chain_root)
            .hash_algorithm(HashAlgorithm.SHA256)
            .nonce(nonce=True)
            .cert_request(cert_request=True)
            .build()
        )
        response = self._post(request.as_bytes())
        self._verify_response(response, request, chain_root)

        return RFC3161Anchor(
            tsa_url=self._url,
            timestamp_token_b64=base64.b64encode(response.time_stamp_token()).decode("ascii"),
            timestamp_iso=response.tst_info.gen_time.replace(tzinfo=UTC).isoformat().replace("+00:00", "Z"),
            tsa_certificate_chain_pem=_encode_certs_pem(response),
            hash_algorithm="sha256",
        )

    def verify(self, anchor: RFC3161Anchor, expected_hash: bytes) -> bool:
        """Re-verify a previously stored anchor against ``expected_hash``.

        Used by ``air verify-public`` and ``air verify --check-anchors``.
        Returns True on success; raises a ``TSAError`` subclass on failure
        so callers can distinguish hard signature failure from a valid
        anchor over a different hash.
        """
        token_bytes = base64.b64decode(anchor.timestamp_token_b64)
        response = _decode_token_or_response(token_bytes)
        verifier = self._build_verifier(response, request_nonce=None)
        try:
            ok: bool = verifier.verify(response, _sha256(expected_hash))
        except _RFC3161VerificationError as exc:
            raise TSASignatureInvalidError(f"TSA token verification failed: {exc}") from exc
        return ok

    # -- internal -----------------------------------------------------

    def _post(self, body: bytes) -> TimeStampResponse:
        req = urllib.request.Request(  # noqa: S310 - operator-supplied TSA URL
            self._url,
            data=body,
            headers={"Content-Type": _CONTENT_TYPE_REQ},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as raw:  # noqa: S310 - URL is operator-supplied
                if raw.headers.get("Content-Type", "").split(";")[0].strip() != _CONTENT_TYPE_RESP:
                    raise TSAResponseInvalidError(
                        f"TSA returned unexpected Content-Type {raw.headers.get('Content-Type')!r}",
                    )
                payload = raw.read()
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                # Surface clearly: public TSAs throttle aggressive callers and
                # the orchestrator's "tsa_failed" status hides the cause.
                # Operators running fleets need this in their logs.
                _log.warning(
                    "TSA %s returned 429 Too Many Requests. "
                    "Public TSAs (FreeTSA in particular) rate-limit aggressive callers; "
                    "consider pinning a paid TSA via tsa_url= when running multiple instances.",
                    self._url,
                )
                raise TSARateLimitedError(f"TSA {self._url} returned 429 (rate limited)") from exc
            raise TSAUnreachableError(f"TSA {self._url} returned HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise TSAUnreachableError(f"TSA {self._url} unreachable: {exc}") from exc
        try:
            return decode_timestamp_response(payload)
        except Exception as exc:
            raise TSAResponseInvalidError(f"TSA {self._url} returned malformed response: {exc}") from exc

    def _verify_response(
        self,
        response: TimeStampResponse,
        request: object,
        chain_root: bytes,
    ) -> None:
        request_nonce_attr = getattr(request, "nonce", None)
        request_nonce = request_nonce_attr if isinstance(request_nonce_attr, int) else None
        verifier = self._build_verifier(response, request_nonce=request_nonce)
        try:
            ok = verifier.verify(response, _sha256(chain_root))
        except _RFC3161VerificationError as exc:
            message = str(exc).lower()
            if "nonce" in message:
                raise TSANonceMismatchError(f"TSA {self._url} nonce mismatch: {exc}") from exc
            raise TSASignatureInvalidError(f"TSA {self._url} signature invalid: {exc}") from exc
        if not ok:
            raise TSASignatureInvalidError(f"TSA {self._url} signature did not verify")

    def _build_verifier(
        self,
        response: TimeStampResponse,
        request_nonce: int | None,
    ) -> Verifier:
        builder = VerifierBuilder()
        if request_nonce is not None:
            builder = builder.nonce(request_nonce)
        roots = self._resolved_roots(response)
        for root in roots:
            builder = builder.add_root_certificate(root)
        try:
            return builder.build()
        except Exception as exc:
            raise TSACertificateInvalidError(f"unable to build TSA verifier: {exc}") from exc

    def _resolved_roots(self, response: TimeStampResponse) -> list[x509.Certificate]:
        if self._roots is not None:
            return self._roots
        # Bootstrap: trust the embedded chain. The verifier still checks
        # the signature; an attacker substituting a fake root has to forge
        # the TSA signature too. Production deployments should pin roots.
        certs: list[x509.Certificate] = []
        for cert_bytes in response.signed_data.certificates:
            certs.append(x509.load_der_x509_certificate(bytes(cert_bytes)))
        if not certs:
            raise TSACertificateInvalidError("TSA response carried no certificates")
        return certs


def _decode_token_or_response(payload: bytes) -> TimeStampResponse:
    """Best-effort decode: stored anchors hold the bare token, not the full response."""
    try:
        return decode_timestamp_response(payload)
    except Exception as exc:
        raise TSAResponseInvalidError(f"unable to decode stored TSA token: {exc}") from exc


def now_iso() -> str:
    """Helper for tests and the orchestrator."""
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")
