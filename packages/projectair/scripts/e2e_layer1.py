"""End-to-end live test of Project AIR Layer 1 (RFC 3161 + Sigstore Rekor).

Records a realistic 5-step agent chain to a temp file, anchors it against
the real FreeTSA and the real public Sigstore Rekor at rekor.sigstore.dev,
captures the resulting Rekor log index, and re-verifies the embedded
inclusion proof offline.

Run from the package root:

    PYTHONPATH=src python scripts/e2e_layer1.py

This sends real bytes to public infrastructure. The Rekor entry is
permanent and globally visible. No PII is included; the entry contains
only the SHA-256 of a BLAKE3 chain root plus a single-use ECDSA P-256
public key generated at script start.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec

from airsdk import __version__ as air_version
from airsdk.agdr import load_chain, verify_chain
from airsdk.anchoring import (
    AnchoringOrchestrator,
    AnchoringPolicy,
    RekorClient,
    RFC3161Client,
)
from airsdk.recorder import AIRRecorder
from airsdk.types import VerificationStatus


def _section(title: str) -> None:
    print(f"\n=== {title} ===")


def main() -> int:
    print(f"Project AIR v{air_version} Layer 1 end-to-end live test")
    print("Targets: FreeTSA (https://freetsa.org/tsr) and Sigstore Rekor (https://rekor.sigstore.dev)")

    with tempfile.TemporaryDirectory() as tmp:
        log_path = Path(tmp) / "chain.jsonl"

        _section("1. Construct anchoring identity (per-install ECDSA P-256)")
        anchoring_key = ec.generate_private_key(ec.SECP256R1())
        print("  generated single-use ECDSA P-256 keypair for this run")

        _section("2. Construct RFC 3161 + Rekor clients pointing at real endpoints")
        rfc3161 = RFC3161Client()
        rekor = RekorClient(signing_key=anchoring_key)
        print(f"  TSA:   {rfc3161.tsa_url}")
        print(f"  Rekor: {rekor.rekor_url}")

        _section("3. Build recorder + orchestrator, attach")
        recorder = AIRRecorder(log_path, user_intent="Summarize the Q3 board memo and email it to legal.")
        orchestrator = AnchoringOrchestrator(
            signer=recorder.signer,
            transports=recorder.transports,
            rfc3161_client=rfc3161,
            rekor_client=rekor,
            policy=AnchoringPolicy(anchor_every_n_steps=999, anchor_every_n_seconds=999),
        )
        recorder.attach_orchestrator(orchestrator)
        print(f"  recorder writing to {log_path}")

        _section("4. Write 5 realistic agent steps through the recorder")
        recorder.llm_start(prompt="Read the Q3 board memo at /docs/q3.pdf and summarize the key risks.")
        recorder.tool_start(tool_name="read_file", tool_args={"path": "/docs/q3.pdf"})
        recorder.tool_end(tool_output="(48 KB markdown summary of the Q3 memo)")
        recorder.llm_end(response="Three risks identified: regulatory (EU AI Act), supply (chip shortage), churn.")
        recorder.agent_finish(final_output="Summary delivered to legal@example.com.")
        print(f"  observed {orchestrator.health().unanchored_step_count} steps in orchestrator backlog")

        _section("5. Force-emit anchor synchronously (real network)")
        anchor_record = orchestrator.emit_anchor_now()
        if anchor_record is None:
            health = orchestrator.health()
            print(f"  ANCHOR FAILED: status={health.last_anchor_status}", file=sys.stderr)
            return 1
        payload = anchor_record.payload
        print(f"  chain root (BLAKE3): {payload.anchored_chain_root}")

        _section("6. RFC 3161 trusted timestamp")
        if payload.rfc3161 is None:
            print("  RFC 3161 ANCHOR MISSING", file=sys.stderr)
            return 1
        print(f"  TSA:                {payload.rfc3161.tsa_url}")
        print(f"  Asserted time:      {payload.rfc3161.timestamp_iso}")
        print(f"  Cert chain length:  {len(payload.rfc3161.tsa_certificate_chain_pem)} cert(s)")

        _section("7. Sigstore Rekor entry")
        if payload.rekor is None:
            print("  REKOR ANCHOR MISSING", file=sys.stderr)
            return 1
        print(f"  Rekor URL:          {payload.rekor.rekor_url}")
        print(f"  Log index:          {payload.rekor.log_index}")
        print(f"  Entry UUID:         {payload.rekor.uuid}")
        print(f"  Integrated time:    {payload.rekor.integrated_time}")
        print(f"  Public verify URL:  https://search.sigstore.dev/?logIndex={payload.rekor.log_index}")

        _section("8. Re-verify the chain offline using only the embedded proofs")
        records = load_chain(log_path)
        result = verify_chain(records)
        if result.status != VerificationStatus.OK:
            print(f"  CHAIN VERIFY FAILED: {result.reason}", file=sys.stderr)
            return 1
        print(f"  signatures + chain links: OK ({result.records_verified} records)")

        chain_root_bytes = bytes.fromhex(payload.anchored_chain_root or "")
        rfc3161.verify(payload.rfc3161, chain_root_bytes)
        print("  RFC 3161 token: re-verified offline against bundled chain")

        from hashlib import sha256
        sha256_digest = sha256(chain_root_bytes).digest()
        rekor.verify(payload.rekor, sha256_digest)
        print("  Rekor inclusion proof: re-verified offline against embedded checkpoint")

        _section("9. Run `air verify-public` as a subprocess (clean env)")
        # Strip every airsdk/anchoring-related env var so this subprocess
        # really starts cold. PATH and PYTHONPATH are kept so the CLI
        # entry point is reachable from this venv.
        env = {k: v for k, v in os.environ.items() if not k.startswith(("AIRSDK_", "VINDICARA_"))}
        proc = subprocess.run(  # noqa: S603 - args are constants from this script, not user input
            [sys.executable, "-m", "projectair.cli", "verify-public", str(log_path)],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        print(proc.stdout)
        if proc.returncode != 0:
            print(f"  air verify-public FAILED (exit {proc.returncode})", file=sys.stderr)
            print(proc.stderr, file=sys.stderr)
            return 1

        _section("LAYER 1 v1 LIVE E2E PASS")
        print(f"\nPublic Rekor log index for this run:  {payload.rekor.log_index}")
        print(f"Look it up at:                        https://search.sigstore.dev/?logIndex={payload.rekor.log_index}")
        print()
        return 0


if __name__ == "__main__":
    sys.exit(main())
