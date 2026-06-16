"""End-to-end demo of the hardware-rooted Signed Intent Capsule (W1, experimental).

Customer line: "Prove your agent ran on verified NVIDIA hardware, not just
that your logs say so."

The flow:

1. A human delegates the session (DELEGATION genesis record).
2. The recorder derives a freshness nonce from the genesis content hash,
   drives attestation, and records NVIDIA's signed EAT verbatim as a
   GPU_ATTESTATION record, right after genesis.
3. The agent does its work; an anchor record covers the whole range under
   a BLAKE3 root.
4. Verification re-checks every root independently: chain signatures, the
   genesis-bound nonce (replay defense), the EAT signature against the
   cached signing certificate, the RIM verdict, device consistency, and
   anchor coverage. Zero Vindicara API calls.

By default the NRAS role is played by an in-process simulated service
(``airsdk.attestation.fixture.FixtureNRAS``; tokens carry
``x-nvidia-simulated: true``). Run with ``--live-nras`` on an NVIDIA
Confidential Computing instance for real hardware evidence.

Run from the package root (finishes well under 60 seconds):

    PYTHONPATH=src python scripts/e2e_attestation.py
"""
from __future__ import annotations

import argparse
import sys
import tempfile
import time
from pathlib import Path

from airsdk import __version__ as air_version
from airsdk.agdr import load_chain, verify_chain
from airsdk.anchoring import AnchoringOrchestrator
from airsdk.attestation import (
    FixtureNRAS,
    GPUAttestationConfig,
    NRASClient,
    verify_attestation,
)
from airsdk.recorder import AIRRecorder
from airsdk.types import (
    AuthMethod,
    DelegationGrant,
    IntentSpec,
    StepKind,
    VerificationStatus,
)


def _section(title: str) -> None:
    print(f"\n=== {title} ===")


def _grant() -> DelegationGrant:
    # Unique per session: the attestation nonce binds to the DELEGATION
    # genesis content hash, and identical grant payloads would produce
    # identical genesis hashes across sessions.
    from uuid import uuid4

    now = int(time.time())
    return DelegationGrant(
        delegation_id=f"d-e2e-attest-{uuid4().hex}",
        agent_id="cc-reference-workload",
        auth_method=AuthMethod.WEBAUTHN,
        authorizer_sub="webauthn:operator-handle",
        authorizer_email="operator@example.org",
        policy_id="attest-e2e-v1",
        policy_hash="b3:0ddba11",
        scope=IntentSpec(goal="run the attested reference workload"),
        granted_at=now,
        expires_at=now + 3600,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--live-nras", action="store_true",
        help="Use the real NRAS (requires an NVIDIA Confidential Computing instance).",
    )
    args = parser.parse_args()
    started = time.monotonic()

    print(f"[AIR v{air_version}] W1 hardware-rooted Signed Intent Capsule (experimental)")

    with tempfile.TemporaryDirectory() as tmp:
        chain_path = Path(tmp) / "attested-chain.jsonl"
        cert_path = Path(tmp) / "nras-signing-cert.pem"

        _section("1. Attested session genesis")
        config = GPUAttestationConfig(mode="offline", cached_signing_cert_path=cert_path)
        if args.live_nras:
            provider: FixtureNRAS | NRASClient = NRASClient(config)
            print("Provider: live NRAS (Confidential Computing instance required)")
        else:
            provider = FixtureNRAS(device_count=1)
            provider.write_signing_certificate(cert_path)
            print("Provider: simulated NRAS fixture (tokens marked x-nvidia-simulated)")
        recorder = AIRRecorder(
            chain_path,
            delegation=_grant(),
            attestation=config,
            attestation_provider=provider,
        )
        genesis_records = load_chain(chain_path)
        attestation = genesis_records[2].payload.attestation
        assert attestation is not None
        print(f"DELEGATION genesis:    {genesis_records[0].step_id}")
        print(f"GPU_ATTESTATION nonce: {attestation.nonce}")
        print(f"rim_matched:           {attestation.rim_matched}")

        _section("2. Agent does its work")
        recorder.tool_start(tool_name="run_inference", tool_args={"model": "nim-llama"})
        recorder.tool_end(tool_output="inference complete")
        recorder.agent_finish(final_output="reference workload finished")
        print("3 work records emitted.")

        _section("3. Anchor the chain root")
        orchestrator = AnchoringOrchestrator(
            signer=recorder.signer, transports=recorder.transports
        )
        orchestrator.hydrate_from_chain(load_chain(chain_path))
        anchor = orchestrator.emit_anchor_now()
        assert anchor is not None
        print(f"Anchor covers {anchor.payload.anchored_step_range}")
        print("(Run with e2e_layer1.py --live-tsa --live-rekor for public anchors.)")

        _section("4. Independent verification, zero Vindicara API calls")
        records = load_chain(chain_path)
        chain_result = verify_chain(records)
        print(f"Chain signatures + links: {chain_result.status.value} "
              f"({chain_result.records_verified} records)")
        if chain_result.status != VerificationStatus.OK:
            return 1
        result = verify_attestation(records, mode="offline", config=config)
        for check in result.checks_passed:
            print(f"  attestation check OK: {check}")
        for failure in result.failures:
            print(f"  attestation check FAILED: {failure}")
        if not result.ok:
            return 1

        _section("5. Replay defense (negative case)")
        AIRRecorder(Path(tmp) / "other.jsonl", delegation=_grant())
        other_records = load_chain(Path(tmp) / "other.jsonl")
        from airsdk.agdr import Signer
        from airsdk.types import AgDRPayload

        signer = Signer.from_env()
        signer._prev_hash = other_records[-1].content_hash
        replay = signer.sign(
            kind=StepKind.GPU_ATTESTATION, payload=AgDRPayload(attestation=attestation)
        )
        replay_result = verify_attestation(
            [*other_records, replay], mode="offline", config=config
        )
        assert not replay_result.ok
        print("Stolen EAT replayed onto a different session: REJECTED (fails closed).")

    elapsed = time.monotonic() - started
    print(f"\nE2E COMPLETE in {elapsed:.1f}s: the capsule proves what ran, who "
          "authorized it, and where it ran.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
