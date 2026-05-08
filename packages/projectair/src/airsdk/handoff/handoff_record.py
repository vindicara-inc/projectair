"""Handoff and handoff_acceptance record builders per Sections 6.2 / 6.3.

Layer 4 records are a parallel wire format from the v0.4 AgDRRecord types:
they carry a top-level ``schema`` string (``agdr/v2.handoff`` or
``agdr/v2.handoff_acceptance``), a ``trace`` block, an ``agent`` block, and
either a ``handoff`` or ``acceptance`` body.

Records are JSON-Lines-serializable and JCS-canonicalized for hashing. Each
record's ``content_hash`` is ``BLAKE3(JCS(record_without_content_hash_or_signatures))``;
the Ed25519 signature covers ``prev_hash || content_hash`` in keeping with
the Layer 1 chain convention.

This module produces dicts directly. The pydantic surface in ``types.py``
stays anchored at v0.4; Layer 4 verification operates on canonical dicts.
"""
from __future__ import annotations

import base64
import datetime as _dt
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonicalize import canonicalize_and_hash, canonicalize_bytes
from .exceptions import HandoffRecordInvalidError
from .identity import AgentIdentity
from .trace import TraceContext, validate_ptid

SCHEMA_HANDOFF = "agdr/v2.handoff"
SCHEMA_HANDOFF_ACCEPTANCE = "agdr/v2.handoff_acceptance"

# Wave 1 protocol version literal carried in capability tokens. Bump only
# when the wire format gains incompatible fields.
PROTOCOL_VERSION = "agdr-handoff/v1.2"

DEFAULT_ACCEPTANCE_TIMEOUT_SECONDS = 30
DEFAULT_REKOR_SUBMISSION_MODE = "synchronous"


def _now_iso() -> str:
    """RFC 3339 UTC timestamp with explicit ``Z`` suffix (Section 15.11)."""
    return (
        _dt.datetime.now(_dt.UTC)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _now_monotonic_ns() -> int:
    return time.monotonic_ns()


@dataclass(slots=True)
class Originator:
    """The root actor that initiated the workflow.

    Mapped onto the ``trace.originator`` block. Wave 1 uses ``type="user"``
    for human-initiated workflows and ``type="scheduled_job"`` for cron.
    """

    type: str
    id: str
    auth_method: str

    def to_dict(self) -> dict[str, str]:
        return {"type": self.type, "id": self.id, "auth_method": self.auth_method}


@dataclass(slots=True)
class FailPolicy:
    acceptance_timeout_seconds: int = DEFAULT_ACCEPTANCE_TIMEOUT_SECONDS
    acceptance_timeout_action: str = "fail_closed"
    rekor_submission_mode: str = DEFAULT_REKOR_SUBMISSION_MODE

    def to_dict(self) -> dict[str, Any]:
        return {
            "acceptance_timeout_seconds": int(self.acceptance_timeout_seconds),
            "acceptance_timeout_action": self.acceptance_timeout_action,
            "rekor_submission_mode": self.rekor_submission_mode,
        }


@dataclass(slots=True)
class CapabilityTokenSummary:
    """The subset of the capability token recorded in the handoff record.

    The full JWT is stored in the agent's chain elsewhere; the handoff
    record only carries metadata sufficient for pairing and verification.
    """

    issuer: str
    jti: str
    exp: int
    scopes: list[str]
    claims_hash: str
    # Optional: raw JWT for verifier step-5 re-verification. Production
    # deployments typically omit this and store the JWT in a sidecar record
    # to avoid persisting short-lived credentials. When present, the
    # verifier calls the IdP adapter for full token signature + claim
    # validation rather than relying on the claims_hash + Rekor proof alone.
    raw_jwt: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "issuer": self.issuer,
            "jti": self.jti,
            "exp": int(self.exp),
            "scopes": list(self.scopes),
            "claims_hash": self.claims_hash,
        }
        if self.raw_jwt is not None:
            out["raw_jwt"] = self.raw_jwt
        return out


@dataclass(slots=True)
class HandoffBody:
    target_agent_id: str
    target_agent_identity_certificate_format: str
    target_agent_identity_certificate_hash: str
    target_agent_idp_issuer: str
    delegation_intent: str
    delegation_intent_hash: str
    delegation_payload_hash: str
    capability_token: CapabilityTokenSummary
    expected_response_type: str
    fail_policy: FailPolicy = field(default_factory=FailPolicy)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_agent_id": self.target_agent_id,
            "target_agent_identity_certificate_format": (
                self.target_agent_identity_certificate_format
            ),
            "target_agent_identity_certificate_hash": (
                self.target_agent_identity_certificate_hash
            ),
            "target_agent_idp_issuer": self.target_agent_idp_issuer,
            "delegation_intent": self.delegation_intent,
            "delegation_intent_hash": self.delegation_intent_hash,
            "delegation_payload_hash": self.delegation_payload_hash,
            "capability_token": self.capability_token.to_dict(),
            "expected_response_type": self.expected_response_type,
            "fail_policy": self.fail_policy.to_dict(),
        }


@dataclass(slots=True)
class AcceptanceBody:
    source_agent_id: str
    source_handoff_record_hash: str
    capability_token_received_jti: str
    capability_token_validation_method: str
    capability_token_validation_proof: dict[str, Any]
    delegation_intent_acknowledged: str
    delegation_intent_hash_acknowledged: str
    intended_response_type: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_agent_id": self.source_agent_id,
            "source_handoff_record_hash": self.source_handoff_record_hash,
            "capability_token_received_jti": self.capability_token_received_jti,
            "capability_token_validation_method": (
                self.capability_token_validation_method
            ),
            "capability_token_validation_proof": dict(
                self.capability_token_validation_proof
            ),
            "delegation_intent_acknowledged": self.delegation_intent_acknowledged,
            "delegation_intent_hash_acknowledged": (
                self.delegation_intent_hash_acknowledged
            ),
            "intended_response_type": self.intended_response_type,
        }


def _trace_block(
    trace_context: TraceContext,
    originator: Originator,
    depth: int,
    spans_received_from: dict[str, str] | None,
) -> dict[str, Any]:
    validate_ptid(trace_context.trace_id)
    block: dict[str, Any] = {
        "parent_trace_id": trace_context.trace_id,
        "w3c_traceparent": trace_context.to_traceparent(),
        "w3c_tracestate": trace_context.tracestate,
        "originator": originator.to_dict(),
        "depth": int(depth),
        "spans_received_from": (
            dict(spans_received_from) if spans_received_from is not None else None
        ),
    }
    return block


def _strip_for_hash(record: dict[str, Any]) -> dict[str, Any]:
    """Return ``record`` with content_hash and signatures removed."""
    stripped = {k: v for k, v in record.items() if k not in {"content_hash", "signatures"}}
    return stripped


def compute_content_hash(record: dict[str, Any]) -> str:
    """Compute ``BLAKE3(JCS(record_without_content_hash_or_signatures))``."""
    return canonicalize_and_hash(_strip_for_hash(record))


def _sign_payload(prev_hash: str, content_hash: str, identity: AgentIdentity) -> str:
    if not isinstance(prev_hash, str) or not isinstance(content_hash, str):
        raise HandoffRecordInvalidError("prev_hash and content_hash must be str")
    message = f"{prev_hash}|{content_hash}".encode("ascii")
    sig_bytes = identity.sign(message)
    sig_b64 = base64.b64encode(sig_bytes).decode("ascii")
    return f"ed25519:{sig_b64}"


def _finalize(record: dict[str, Any], identity: AgentIdentity) -> dict[str, Any]:
    content_hash = compute_content_hash(record)
    record["content_hash"] = content_hash
    signature = _sign_payload(record["prev_hash"], content_hash, identity)
    record["signatures"] = {"ed25519": signature}
    return record


def build_handoff_record(
    *,
    step_n: int,
    trace_context: TraceContext,
    originator: Originator,
    depth: int,
    source_identity: AgentIdentity,
    handoff_body: HandoffBody,
    prev_hash: str,
    spans_received_from: dict[str, str] | None = None,
    ts_iso: str | None = None,
) -> dict[str, Any]:
    """Build, hash, and sign an ``agdr/v2.handoff`` record."""
    record: dict[str, Any] = {
        "schema": SCHEMA_HANDOFF,
        "step_n": int(step_n),
        "ts_iso": ts_iso or _now_iso(),
        "ts_monotonic": _now_monotonic_ns(),
        "trace": _trace_block(trace_context, originator, depth, spans_received_from),
        "agent": source_identity.to_record_block(),
        "handoff": handoff_body.to_dict(),
        "prev_hash": prev_hash,
    }
    return _finalize(record, source_identity)


def build_handoff_acceptance_record(
    *,
    step_n: int,
    trace_context: TraceContext,
    originator: Originator,
    depth: int,
    target_identity: AgentIdentity,
    acceptance_body: AcceptanceBody,
    prev_hash: str,
    source_agent_id: str,
    source_handoff_record_hash: str,
    ts_iso: str | None = None,
) -> dict[str, Any]:
    """Build, hash, and sign an ``agdr/v2.handoff_acceptance`` record."""
    spans_received_from = {
        "agent_id": source_agent_id,
        "handoff_record_hash": source_handoff_record_hash,
    }
    record: dict[str, Any] = {
        "schema": SCHEMA_HANDOFF_ACCEPTANCE,
        "step_n": int(step_n),
        "ts_iso": ts_iso or _now_iso(),
        "ts_monotonic": _now_monotonic_ns(),
        "trace": _trace_block(trace_context, originator, depth, spans_received_from),
        "agent": target_identity.to_record_block(),
        "acceptance": acceptance_body.to_dict(),
        "prev_hash": prev_hash,
    }
    return _finalize(record, target_identity)


def verify_record_content_hash(record: dict[str, Any]) -> None:
    """Recompute and check the record's ``content_hash``."""
    claimed = record.get("content_hash")
    if not isinstance(claimed, str):
        raise HandoffRecordInvalidError("content_hash missing or not a string")
    recomputed = compute_content_hash(record)
    if recomputed != claimed:
        raise HandoffRecordInvalidError(
            f"content_hash mismatch: claimed {claimed!r}, recomputed {recomputed!r}"
        )


def verify_record_signature(record: dict[str, Any], public_key: Ed25519PublicKey) -> None:
    """Verify the Ed25519 signature on a handoff or acceptance record."""
    sigs = record.get("signatures") or {}
    sig_field = sigs.get("ed25519")
    if not isinstance(sig_field, str) or not sig_field.startswith("ed25519:"):
        raise HandoffRecordInvalidError("missing or malformed ed25519 signature")
    try:
        sig_bytes = base64.b64decode(sig_field[len("ed25519:"):], validate=True)
    except Exception as e:
        raise HandoffRecordInvalidError(f"signature is not valid base64: {e}") from e
    prev_hash = record.get("prev_hash")
    content_hash = record.get("content_hash")
    if not isinstance(prev_hash, str) or not isinstance(content_hash, str):
        raise HandoffRecordInvalidError("prev_hash/content_hash missing")
    message = f"{prev_hash}|{content_hash}".encode("ascii")
    try:
        public_key.verify(sig_bytes, message)
    except InvalidSignature as e:
        raise HandoffRecordInvalidError("ed25519 signature verification failed") from e


def canonical_record_bytes(record: dict[str, Any]) -> bytes:
    """Return the JCS-canonical bytes of the full record (for raw signing/log)."""
    return canonicalize_bytes(record)


__all__ = [
    "DEFAULT_ACCEPTANCE_TIMEOUT_SECONDS",
    "DEFAULT_REKOR_SUBMISSION_MODE",
    "PROTOCOL_VERSION",
    "SCHEMA_HANDOFF",
    "SCHEMA_HANDOFF_ACCEPTANCE",
    "AcceptanceBody",
    "CapabilityTokenSummary",
    "FailPolicy",
    "HandoffBody",
    "Originator",
    "build_handoff_acceptance_record",
    "build_handoff_record",
    "canonical_record_bytes",
    "compute_content_hash",
    "verify_record_content_hash",
    "verify_record_signature",
]


# unused but retained for static analysis: dataclass asdict utility
_ = (asdict,)
