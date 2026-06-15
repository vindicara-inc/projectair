"""Key custody: authorized signing-key handoff and verification.

Chain integrity (``verify_chain``) proves the records are hash-linked and that
each signature is valid against the key embedded in that record. It does NOT
prove that a *change* of signing key was authorized: a key that knows the head
hash can continue the chain. ``verify_chain`` leaves that semantic question to
the detector layer (ASI07 flags a sender/key mismatch).

Key custody closes the cryptographic side of that gap. ``rotate_signer`` emits a
``KEY_TRANSITION`` record signed by the outgoing key that names the incoming
key, and ``verify_key_custody`` walks the chain enforcing that every signing-key
change was authorized by such a record signed by the prior key. An unauthorized
takeover is reported as ``UNAUTHORIZED_KEY``; chain integrity is unaffected and
remains the job of ``verify_chain``. The two checks are complementary: run both.

This answers production resilience directly: when a key is rotated or an H100
node is cycled, the chain continues without breaking custody, because the
handoff is itself a signed, in-chain, anchorable event.

Readiness: production. Additive to the AgDR record format; chains with no
``KEY_TRANSITION`` record verify unchanged as single-key custody.
"""
from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from airsdk.agdr import Signer, SigningKey, verify_record
from airsdk.types import AgDRPayload, AgDRRecord, KeyTransition, StepKind

__all__ = [
    "KeyCustodyResult",
    "KeyCustodyStatus",
    "rotate_signer",
    "verify_key_custody",
]


class KeyCustodyStatus(StrEnum):
    OK = "ok"
    UNAUTHORIZED_KEY = "unauthorized_key"  # a key change not authorized by the prior key
    INVALID_TRANSITION = "invalid_transition"  # KEY_TRANSITION malformed or its signature failed


class KeyCustodyResult(BaseModel):
    """Outcome of walking a chain for authorized-key custody."""

    model_config = ConfigDict(extra="forbid")

    status: KeyCustodyStatus
    records_verified: int
    rotations: int = 0  # count of authorized key handoffs observed
    failed_step_id: str | None = None
    reason: str | None = None


def rotate_signer(
    current: Signer,
    new_private_key: SigningKey,
    *,
    reason: str = "rotation",
) -> tuple[AgDRRecord, Signer]:
    """Emit a signed KEY_TRANSITION and return ``(transition_record, new_signer)``.

    ``current`` (the outgoing key) signs a record naming the incoming key. The
    returned ``Signer`` wraps ``new_private_key`` positioned to continue the
    chain directly from the transition record, so its first ``sign`` links
    cleanly. The transition record is the authorization a verifier checks with
    ``verify_key_custody``.
    """
    incoming = Signer(new_private_key)
    transition = current.sign(
        StepKind.KEY_TRANSITION,
        AgDRPayload(
            key_transition=KeyTransition(
                new_signer_key=incoming.public_key_hex,
                new_signature_algorithm=incoming.algorithm,
                reason=reason,
            ),
        ),
    )
    continued = Signer(new_private_key, prev_hash=current.head_hash)
    return transition, continued


def verify_key_custody(
    records: list[AgDRRecord],
    *,
    trusted_root_key: str | None = None,
) -> KeyCustodyResult:
    """Verify that every signing-key change was authorized by the prior key.

    Walks the chain tracking the currently authorized signing key. The first
    record establishes that key (trust on first use) unless ``trusted_root_key``
    is supplied, in which case the first record must already use it. A
    ``KEY_TRANSITION`` record signed by the authorized key rotates authority to
    the key it names. Any other change of signing key is ``UNAUTHORIZED_KEY``.

    This is the cryptographic complement to ``verify_chain``: integrity proves
    the records are linked and signed; custody proves the identity behind those
    signatures only ever changed with the prior key's blessing.
    """
    if not records:
        return KeyCustodyResult(status=KeyCustodyStatus.OK, records_verified=0)

    authorized_key = trusted_root_key if trusted_root_key is not None else records[0].signer_key
    rotations = 0

    for index, record in enumerate(records):
        # A signature that does not verify makes custody meaningless.
        ok, reason = verify_record(record)
        if not ok:
            failed_status = (
                KeyCustodyStatus.INVALID_TRANSITION
                if record.kind == StepKind.KEY_TRANSITION
                else KeyCustodyStatus.UNAUTHORIZED_KEY
            )
            return KeyCustodyResult(
                status=failed_status,
                records_verified=index,
                rotations=rotations,
                failed_step_id=record.step_id,
                reason=reason,
            )
        # The record must be signed by the currently authorized key.
        if record.signer_key != authorized_key:
            return KeyCustodyResult(
                status=KeyCustodyStatus.UNAUTHORIZED_KEY,
                records_verified=index,
                rotations=rotations,
                failed_step_id=record.step_id,
                reason=(
                    "signing key changed without an authorizing KEY_TRANSITION: "
                    f"expected {authorized_key}, got {record.signer_key}"
                ),
            )
        # An authorized KEY_TRANSITION rotates authority to the named key.
        if record.kind == StepKind.KEY_TRANSITION:
            transition = record.payload.key_transition
            if transition is None:
                return KeyCustodyResult(
                    status=KeyCustodyStatus.INVALID_TRANSITION,
                    records_verified=index,
                    rotations=rotations,
                    failed_step_id=record.step_id,
                    reason="KEY_TRANSITION record carries no key_transition payload",
                )
            authorized_key = transition.new_signer_key
            rotations += 1

    return KeyCustodyResult(
        status=KeyCustodyStatus.OK,
        records_verified=len(records),
        rotations=rotations,
    )
