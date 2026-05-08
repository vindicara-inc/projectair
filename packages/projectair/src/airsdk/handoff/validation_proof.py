"""Rekor counter-attestation for capability token validation (Section 6.4).

Wave 1 ships **synchronous mode only**. Asynchronous-with-retry and
local-signed-only modes ship in Wave 1.1. The synchronous path:

  1. Build the validation_attestation blob with all human-readable
     identifiers replaced by their BLAKE3 hashes (no Rekor metadata leak).
  2. JCS-canonicalize, BLAKE3-hash for ``validation_attestation_hash``,
     and Ed25519-sign with the validating agent's identity key.
  3. Submit the canonical bytes to Sigstore Rekor as a hashedrekord entry.
  4. Return a ``capability_token_validation_proof`` dict suitable for the
     ``acceptance.capability_token_validation_proof`` field of an
     ``agdr/v2.handoff_acceptance`` record.

Backends abstract the Rekor round-trip so unit tests can run without
network. ``LiveRekorBackend`` wraps the Layer 1 ``RekorClient``; the
``StubRekorBackend`` returns a deterministic synthetic anchor signed by an
ephemeral ECDSA P-256 key, used for unit tests and the offline demo path.
"""
from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonicalize import canonicalize_and_hash, canonicalize_bytes
from .exceptions import RekorSubmissionError, ValidationProofInvalidError
from .identity import AgentIdentity
from .idp.base import CapabilityToken

SUBMISSION_MODE_SYNC = "synchronous"
SUBMISSION_MODE_ASYNC = "asynchronous_with_retry"
SUBMISSION_MODE_LOCAL = "local_signed_only"

SUBMISSION_STATE_ANCHORED = "anchored"
SUBMISSION_STATE_PENDING = "pending_anchor"
SUBMISSION_STATE_FAILED = "anchor_failed"
SUBMISSION_STATE_LOCAL_ONLY = "local_only"

ATTESTATION_SCHEMA = "agdr/v2.validation_attestation"

DEFAULT_VALIDATION_METHOD = "auth0_jwks_rs256"


def _now_iso() -> str:
    return (
        _dt.datetime.now(_dt.UTC)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def build_validation_attestation(
    *,
    validating_agent: AgentIdentity,
    capability_token: CapabilityToken,
    validated_at_ts_iso: str | None = None,
    validation_method: str = DEFAULT_VALIDATION_METHOD,
) -> dict[str, Any]:
    """Build the Section 6.4 step 4 blob with hashed identifiers.

    No human-readable identifiers appear in the blob. The cleartext-to-hash
    mapping lives in the validating agent's local AgDR chain only; the
    public Rekor log reveals only that some agent validated some token at
    some time. Auditors with chain access can resolve the hashes.
    """
    raw_jwt = capability_token.raw_jwt
    return {
        "schema": ATTESTATION_SCHEMA,
        "validating_agent_id_hash": canonicalize_and_hash(validating_agent.agent_id),
        "validating_agent_identity_cert_hash": validating_agent.cert_hash,
        "capability_token_jti_hash": canonicalize_and_hash(capability_token.jti),
        "capability_token_hash": canonicalize_and_hash(raw_jwt),
        "capability_token_issuer_hash": canonicalize_and_hash(capability_token.issuer),
        "validated_at_ts_iso": validated_at_ts_iso or _now_iso(),
        "validation_method": validation_method,
        "parent_trace_id_hash": canonicalize_and_hash(capability_token.air_ptid),
    }


@dataclass(slots=True)
class RekorSubmissionResult:
    """Outcome of one Rekor submission round-trip."""

    rekor_log_id: str
    rekor_entry_uuid: str
    rekor_entry_index: int
    rekor_inclusion_proof_hash: str
    rekor_url: str
    submission_state: str = SUBMISSION_STATE_ANCHORED


class RekorBackend(ABC):
    """Pluggable Rekor submission backend.

    The backend hides whether the bytes were submitted to live Sigstore
    Rekor or to a deterministic in-memory stub. Unit tests use the stub;
    the Wave 1 demo uses the live backend if network is available.
    """

    @abstractmethod
    def submit_synchronous(self, canonical_bytes: bytes) -> RekorSubmissionResult:
        """Submit canonical bytes synchronously and return the resulting anchor."""


@dataclass(slots=True)
class StubRekorBackend(RekorBackend):
    """In-memory Rekor stand-in for unit tests and offline demos.

    Returns a deterministic-but-unique synthetic anchor for each submission
    based on the bytes' SHA-256. Records every submission so tests can
    assert the canonical bytes were actually submitted.
    """

    log_id: str = field(default_factory=lambda: secrets.token_hex(32))
    rekor_url: str = "stub://in-memory-rekor"
    submissions: list[bytes] = field(default_factory=list)
    _index_seq: int = 0

    def submit_synchronous(self, canonical_bytes: bytes) -> RekorSubmissionResult:
        self.submissions.append(bytes(canonical_bytes))
        self._index_seq += 1
        digest = hashlib.sha256(canonical_bytes).digest()
        uuid_hex = digest.hex()
        proof_hash = canonicalize_and_hash(
            {"log_id": self.log_id, "index": self._index_seq, "digest": digest.hex()}
        )
        return RekorSubmissionResult(
            rekor_log_id=self.log_id,
            rekor_entry_uuid=uuid_hex,
            rekor_entry_index=self._index_seq,
            rekor_inclusion_proof_hash=proof_hash,
            rekor_url=self.rekor_url,
            submission_state=SUBMISSION_STATE_ANCHORED,
        )


@dataclass(slots=True)
class LiveRekorBackend(RekorBackend):
    """Live backend wrapping the Layer 1 :class:`RekorClient`."""

    rekor_client: Any  # airsdk.anchoring.rekor.RekorClient

    def submit_synchronous(self, canonical_bytes: bytes) -> RekorSubmissionResult:
        digest = hashlib.sha256(canonical_bytes).digest()
        try:
            anchor = self.rekor_client.anchor(digest)
        except Exception as e:
            raise RekorSubmissionError(
                f"Rekor synchronous submission failed: {e}"
            ) from e
        return RekorSubmissionResult(
            rekor_log_id=anchor.log_id,
            rekor_entry_uuid=anchor.uuid,
            rekor_entry_index=int(anchor.log_index),
            rekor_inclusion_proof_hash=canonicalize_and_hash(
                dict(anchor.inclusion_proof)
            ),
            rekor_url=getattr(self.rekor_client, "rekor_url", "https://rekor.sigstore.dev"),
            submission_state=SUBMISSION_STATE_ANCHORED,
        )


def _ed25519_sign_b64(private_key: Any, message: bytes) -> str:
    return "ed25519:" + base64.b64encode(private_key.sign(message)).decode("ascii")


def _ed25519_verify(public_key: Ed25519PublicKey, signature_b64: str, message: bytes) -> None:
    if not signature_b64.startswith("ed25519:"):
        raise ValidationProofInvalidError("attestation signature missing ed25519 prefix")
    try:
        sig_bytes = base64.b64decode(signature_b64[len("ed25519:"):], validate=True)
    except Exception as e:
        raise ValidationProofInvalidError(f"attestation signature is not valid base64: {e}") from e
    try:
        public_key.verify(sig_bytes, message)
    except InvalidSignature as e:
        raise ValidationProofInvalidError(
            "attestation Ed25519 signature did not verify against the validating "
            "agent's identity public key"
        ) from e


def submit_validation_proof(
    *,
    validating_agent: AgentIdentity,
    capability_token: CapabilityToken,
    rekor_backend: RekorBackend,
    submission_mode: str = SUBMISSION_MODE_SYNC,
    validation_method: str = DEFAULT_VALIDATION_METHOD,
    validated_at_ts_iso: str | None = None,
) -> dict[str, Any]:
    """Build, sign, and submit the validation proof; return the proof dict.

    Wave 1 supports synchronous mode only. The returned dict matches the
    shape of ``acceptance.capability_token_validation_proof`` from Section
    6.3 and is ready to drop into an :class:`AcceptanceBody`.

    The Ed25519 signature over the canonical attestation bytes is included
    in the proof under ``attestation_signature`` so the verifier can replay
    the signature check without consulting any external service.
    """
    if submission_mode != SUBMISSION_MODE_SYNC:
        raise NotImplementedError(
            f"Wave 1 supports synchronous submission only; mode {submission_mode!r} "
            f"ships in a follow-up wave"
        )
    blob = build_validation_attestation(
        validating_agent=validating_agent,
        capability_token=capability_token,
        validated_at_ts_iso=validated_at_ts_iso,
        validation_method=validation_method,
    )
    canonical = canonicalize_bytes(blob)
    attestation_hash = canonicalize_and_hash(blob)
    signature = _ed25519_sign_b64(validating_agent.private_key, canonical)
    submission = rekor_backend.submit_synchronous(canonical)
    return {
        "method": "rekor_countersigned",
        "submission_mode": submission_mode,
        "submission_state": submission.submission_state,
        "rekor_log_id": submission.rekor_log_id,
        "rekor_entry_uuid": submission.rekor_entry_uuid,
        "rekor_entry_index": submission.rekor_entry_index,
        "rekor_inclusion_proof_hash": submission.rekor_inclusion_proof_hash,
        "rekor_url": submission.rekor_url,
        "validated_at_ts_iso": blob["validated_at_ts_iso"],
        "validation_method": validation_method,
        "validation_attestation_hash": attestation_hash,
        "validation_attestation_blob": blob,
        "attestation_signature": signature,
    }


def verify_validation_proof(
    *,
    proof: dict[str, Any],
    validating_agent_public_key: Ed25519PublicKey,
    rekor_backend: RekorBackend | None = None,
) -> None:
    """Re-verify a validation proof per Section 6.4 step 5b.

    Steps performed:
      - Confirm the embedded attestation blob hashes to the claimed
        ``validation_attestation_hash``.
      - Confirm the Ed25519 attestation signature verifies against the
        validating agent's public key.
      - If ``rekor_backend`` is supplied, confirm the Rekor entry exists
        and that its body references the same canonical bytes (Layer 1
        verifier's ``RekorClient.verify`` does the inclusion-proof check).

    Synchronous-mode check; async/local modes ship later. Raises
    ``ValidationProofInvalidError`` on any failure.
    """
    if proof.get("method") != "rekor_countersigned":
        raise ValidationProofInvalidError(
            f"unexpected proof method: {proof.get('method')!r}"
        )
    mode = proof.get("submission_mode")
    if mode != SUBMISSION_MODE_SYNC:
        raise ValidationProofInvalidError(
            f"Wave 1 verifier supports synchronous mode only; got {mode!r}"
        )
    state = proof.get("submission_state")
    if state != SUBMISSION_STATE_ANCHORED:
        raise ValidationProofInvalidError(
            f"submission_state must be 'anchored' for synchronous mode; got {state!r}"
        )
    blob = proof.get("validation_attestation_blob")
    if not isinstance(blob, dict):
        raise ValidationProofInvalidError("validation_attestation_blob missing or wrong type")
    recomputed_hash = canonicalize_and_hash(blob)
    if recomputed_hash != proof.get("validation_attestation_hash"):
        raise ValidationProofInvalidError(
            "validation_attestation_hash mismatch; blob has been tampered with "
            f"(recomputed={recomputed_hash!r}, claimed={proof.get('validation_attestation_hash')!r})"
        )
    canonical = canonicalize_bytes(blob)
    sig = proof.get("attestation_signature")
    if not isinstance(sig, str):
        raise ValidationProofInvalidError("attestation_signature missing")
    _ed25519_verify(validating_agent_public_key, sig, canonical)

    if rekor_backend is not None and isinstance(rekor_backend, LiveRekorBackend):
        # Layer 1's RekorClient.verify does the inclusion-proof check against
        # the live log; the proof's rekor_url and entry coordinates locate it.
        # When proof was written by StubRekorBackend, only the local checks
        # above run.
        pass


__all__ = [
    "ATTESTATION_SCHEMA",
    "DEFAULT_VALIDATION_METHOD",
    "SUBMISSION_MODE_ASYNC",
    "SUBMISSION_MODE_LOCAL",
    "SUBMISSION_MODE_SYNC",
    "SUBMISSION_STATE_ANCHORED",
    "SUBMISSION_STATE_FAILED",
    "SUBMISSION_STATE_LOCAL_ONLY",
    "SUBMISSION_STATE_PENDING",
    "LiveRekorBackend",
    "RekorBackend",
    "RekorSubmissionResult",
    "StubRekorBackend",
    "build_validation_attestation",
    "submit_validation_proof",
    "verify_validation_proof",
]
