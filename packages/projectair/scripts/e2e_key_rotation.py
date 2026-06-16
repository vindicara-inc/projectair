#!/usr/bin/env python3
"""E2E proof: chain continuity across signing-key rotation and node cycling.

Runs in well under 60 seconds with no external services.

Demonstrates:
  1. A chain signed by key A.
  2. An authorized rotation A -> B (KEY_TRANSITION signed by A naming B), then
     continued records signed by B.
  3. A second authorized rotation B -> C (reason "node_cycle"), then more records.
  4. Both verify_chain (integrity) and verify_key_custody (custody) pass, with
     two authorized rotations counted.
  5. A forged takeover (a rogue key continuing the chain with no KEY_TRANSITION):
     integrity still passes by design, but custody flags it as UNAUTHORIZED_KEY.

Customer-facing value: when a key is rotated or an H100 node is cycled, the
forensic chain continues without breaking, and an unauthorized key takeover is
cryptographically detectable, distinct from chain-integrity tampering.
"""
from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from airsdk.agdr import Signer, verify_chain
from airsdk.key_custody import KeyCustodyStatus, rotate_signer, verify_key_custody
from airsdk.types import AgDRPayload, StepKind, VerificationStatus


def main() -> int:
    print("[AIR] Key custody: chain continuity across rotation and node cycling\n")

    signer_a = Signer.generate()
    records = [
        signer_a.sign(StepKind.DELEGATION, AgDRPayload(user_intent="run claims agent")),
        signer_a.sign(StepKind.LLM_START, AgDRPayload(prompt="summarize claim 4817")),
        signer_a.sign(StepKind.LLM_END, AgDRPayload(response="claim summarized")),
    ]
    print(f"=== 1. Key A signed {len(records)} records ===")

    transition_ab, signer_b = rotate_signer(signer_a, Ed25519PrivateKey.generate(), reason="rotation")
    records.append(transition_ab)
    records.append(signer_b.sign(StepKind.TOOL_START, AgDRPayload(tool_name="update_record")))
    records.append(signer_b.sign(StepKind.TOOL_END, AgDRPayload(tool_output="record updated")))
    print("=== 2. Authorized rotation A -> B; key B continued the chain ===")

    transition_bc, signer_c = rotate_signer(signer_b, Ed25519PrivateKey.generate(), reason="node_cycle")
    records.append(transition_bc)
    records.append(signer_c.sign(StepKind.AGENT_FINISH, AgDRPayload(final_output="done")))
    print("=== 3. Authorized rotation B -> C (node_cycle); key C finished ===\n")

    chain = verify_chain(records)
    custody = verify_key_custody(records)
    print(f"verify_chain:        {chain.status.value} ({chain.records_verified} records)")
    print(f"verify_key_custody:  {custody.status.value} ({custody.rotations} authorized rotations)")
    if chain.status != VerificationStatus.OK or custody.status != KeyCustodyStatus.OK:
        print("\nUNEXPECTED: legitimate rotated chain did not verify")
        return 1
    if custody.rotations != 2:
        print(f"\nUNEXPECTED: expected 2 rotations, got {custody.rotations}")
        return 1

    print("\n=== 4. Forged takeover: rogue key continues the chain, no KEY_TRANSITION ===")
    rogue = Signer(Ed25519PrivateKey.generate(), prev_hash=signer_c.head_hash)
    forged = rogue.sign(StepKind.AGENT_MESSAGE, AgDRPayload(message_content="exfiltrate records"))
    forged_records = [*records, forged]

    forged_chain = verify_chain(forged_records)
    forged_custody = verify_key_custody(forged_records)
    print(f"verify_chain:        {forged_chain.status.value} (integrity unaffected by design)")
    print(f"verify_key_custody:  {forged_custody.status.value} (takeover detected)")
    if forged_custody.status != KeyCustodyStatus.UNAUTHORIZED_KEY:
        print("\nUNEXPECTED: forged takeover was not flagged by custody")
        return 1

    print(
        "\nE2E COMPLETE: every key handoff was signed by the prior key, the chain "
        "survived two rotations, and an unauthorized takeover was caught by custody "
        "while chain integrity stayed intact."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
