"""Key custody: authorized rotation, multi-rotation, and forged-takeover tests.

Custody (``verify_key_custody``) is complementary to integrity
(``verify_chain``): integrity proves the records link and each signature is
valid; custody proves the signing key only ever changed with the prior key's
authorization. The forged-takeover test asserts both, to document that the two
checks are distinct and not conflated.
"""
from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from airsdk.agdr import Signer, verify_chain
from airsdk.key_custody import (
    KeyCustodyStatus,
    rotate_signer,
    verify_key_custody,
)
from airsdk.types import AgDRPayload, StepKind, VerificationStatus


def _build_base_chain(signer: Signer) -> list:
    return [
        signer.sign(StepKind.LLM_START, AgDRPayload(prompt="hello")),
        signer.sign(StepKind.LLM_END, AgDRPayload(response="hi")),
    ]


def test_empty_chain_is_ok() -> None:
    result = verify_key_custody([])
    assert result.status == KeyCustodyStatus.OK
    assert result.records_verified == 0
    assert result.rotations == 0


def test_single_key_chain_has_no_rotations() -> None:
    signer = Signer.generate()
    records = _build_base_chain(signer)
    result = verify_key_custody(records)
    assert result.status == KeyCustodyStatus.OK
    assert result.rotations == 0
    assert result.records_verified == 2


def test_authorized_rotation_passes_custody_and_chain() -> None:
    signer_a = Signer.generate()
    records = _build_base_chain(signer_a)

    transition, signer_b = rotate_signer(signer_a, Ed25519PrivateKey.generate(), reason="rotation")
    records.append(transition)
    records.append(signer_b.sign(StepKind.TOOL_START, AgDRPayload(tool_name="search")))
    records.append(signer_b.sign(StepKind.TOOL_END, AgDRPayload(tool_output="ok")))

    # Integrity holds: the chain links and every signature verifies.
    assert verify_chain(records).status == VerificationStatus.OK
    # Custody holds: the one key change was authorized by the prior key.
    custody = verify_key_custody(records)
    assert custody.status == KeyCustodyStatus.OK
    assert custody.rotations == 1
    assert custody.records_verified == len(records)


def test_multiple_rotations_chain() -> None:
    signer_a = Signer.generate()
    records = _build_base_chain(signer_a)

    transition_ab, signer_b = rotate_signer(signer_a, Ed25519PrivateKey.generate())
    records.append(transition_ab)
    records.append(signer_b.sign(StepKind.AGENT_MESSAGE, AgDRPayload(message_content="from b")))

    transition_bc, signer_c = rotate_signer(signer_b, Ed25519PrivateKey.generate(), reason="node_cycle")
    records.append(transition_bc)
    records.append(signer_c.sign(StepKind.AGENT_FINISH, AgDRPayload(final_output="done")))

    assert verify_chain(records).status == VerificationStatus.OK
    custody = verify_key_custody(records)
    assert custody.status == KeyCustodyStatus.OK
    assert custody.rotations == 2


def test_forged_takeover_flagged_by_custody_but_chain_intact() -> None:
    """A new key that knows the head hash can continue the chain. Integrity
    accepts it (links + signatures valid); custody rejects it as unauthorized."""
    signer_a = Signer.generate()
    records = _build_base_chain(signer_a)

    # Rogue key forks the chain from the current head with NO KEY_TRANSITION.
    rogue = Signer(Ed25519PrivateKey.generate(), prev_hash=signer_a.head_hash)
    forged = rogue.sign(StepKind.AGENT_MESSAGE, AgDRPayload(message_content="wire the funds"))
    records.append(forged)

    # Integrity does not catch this; that is by design (ASI07 catches it semantically).
    assert verify_chain(records).status == VerificationStatus.OK
    # Custody catches it cryptographically.
    custody = verify_key_custody(records)
    assert custody.status == KeyCustodyStatus.UNAUTHORIZED_KEY
    assert custody.failed_step_id == forged.step_id
    assert custody.rotations == 0


def test_tampered_transition_payload_is_invalid() -> None:
    signer_a = Signer.generate()
    records = _build_base_chain(signer_a)
    transition, _signer_b = rotate_signer(signer_a, Ed25519PrivateKey.generate())

    # Swap the named incoming key after signing: content_hash no longer matches.
    tampered_payload = AgDRPayload(
        key_transition=transition.payload.key_transition.model_copy(
            update={"new_signer_key": "ff" * 32},
        ),
    )
    tampered = transition.model_copy(update={"payload": tampered_payload})
    records.append(tampered)

    custody = verify_key_custody(records)
    assert custody.status == KeyCustodyStatus.INVALID_TRANSITION
    assert custody.failed_step_id == tampered.step_id


def test_transition_record_without_payload_is_invalid() -> None:
    signer = Signer.generate()
    # A KEY_TRANSITION record that names no incoming key is malformed.
    empty_transition = signer.sign(StepKind.KEY_TRANSITION, AgDRPayload())
    custody = verify_key_custody([empty_transition])
    assert custody.status == KeyCustodyStatus.INVALID_TRANSITION
    assert custody.failed_step_id == empty_transition.step_id


def test_trusted_root_key_mismatch_is_unauthorized() -> None:
    signer = Signer.generate()
    records = _build_base_chain(signer)
    result = verify_key_custody(records, trusted_root_key="ab" * 32)
    assert result.status == KeyCustodyStatus.UNAUTHORIZED_KEY
    assert result.records_verified == 0


def test_trusted_root_key_match_is_ok() -> None:
    signer = Signer.generate()
    records = _build_base_chain(signer)
    result = verify_key_custody(records, trusted_root_key=signer.public_key_hex)
    assert result.status == KeyCustodyStatus.OK
    assert result.rotations == 0
