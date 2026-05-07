"""End-to-end live demo of Project AIR Layer 4 Wave 1 (single-tenant handoff).

Two agents, Cabinet EA (Executive Assistant) and Cabinet Coach, hand off a
delegated task. The demo:

  1. Spawns an in-process JWKS server pretending to be Auth0.
  2. Configures an :class:`Auth0Adapter` against that mock issuer.
  3. Mints a capability token bound to the W3C trace_id (PTID), with the
     four required ``air_*`` claims (Section 7.2).
  4. EA writes a HANDOFF record to its AgDR chain, signed with its
     LOCAL_DEV identity key.
  5. Coach receives the handoff, verifies the token via the adapter,
     submits a Rekor counter-attestation with hashed identifiers
     (Section 6.4 — privacy-preserving), and writes a HANDOFF_ACCEPTANCE
     record signed with its LOCAL_DEV identity key.
  6. The :class:`CrossAgentVerifier` runs the eight-step check from
     Section 8.2 over both chains and prints PASS.

Run from the package root::

    PYTHONPATH=src python scripts/e2e_layer4.py

The default Rekor backend is the deterministic in-process
:class:`StubRekorBackend`; pass ``--live-rekor`` to submit to the public
Sigstore Rekor (requires network and an ECDSA P-256 signing key — uses
the same path as Layer 1 anchoring).
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Any

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from airsdk import __version__ as air_version
from airsdk.handoff.canonicalize import canonicalize_and_hash
from airsdk.handoff.handoff_record import (
    AcceptanceBody,
    CapabilityTokenSummary,
    FailPolicy,
    HandoffBody,
    Originator,
    build_handoff_acceptance_record,
    build_handoff_record,
)
from airsdk.handoff.identity import generate_local_dev_identity
from airsdk.handoff.idp.auth0 import Auth0Adapter
from airsdk.handoff.idp.base import AdapterRouter
from airsdk.handoff.trace import child_context, new_root_context
from airsdk.handoff.validation_proof import (
    LiveRekorBackend,
    StubRekorBackend,
    submit_validation_proof,
)
from airsdk.handoff.verifier import ChainSet, CrossAgentVerifier


def _section(title: str) -> None:
    print(f"\n=== {title} ===")


def _b64u(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@contextmanager
def _mock_idp() -> Iterator[dict[str, Any]]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    pub = priv.public_key().public_numbers()
    kid = "wave1-demo"
    body = json.dumps(
        {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": kid,
                    "n": _b64u(pub.n),
                    "e": _b64u(pub.e),
                }
            ]
        }
    ).encode("utf-8")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path.endswith("/.well-known/jwks.json"):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, *_args: Any) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    issuer = f"http://127.0.0.1:{server.server_address[1]}/"
    Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield {"issuer": issuer, "pem": pem, "kid": kid}
    finally:
        server.shutdown()
        server.server_close()


def _build_live_rekor_backend() -> LiveRekorBackend:
    from cryptography.hazmat.primitives.asymmetric import ec

    from airsdk.anchoring.rekor import RekorClient

    signing_key = ec.generate_private_key(ec.SECP256R1())
    return LiveRekorBackend(rekor_client=RekorClient(signing_key=signing_key))


def main() -> int:
    parser = argparse.ArgumentParser(description="Layer 4 Wave 1 E2E demo")
    parser.add_argument(
        "--live-rekor",
        action="store_true",
        help="Submit the validation proof to the public Sigstore Rekor.",
    )
    args = parser.parse_args()

    print(f"Project AIR v{air_version} Layer 4 Wave 1 end-to-end demo")
    print(
        "  AgDR Handoff Protocol (A2A): single-tenant cross-agent chain of custody"
    )

    rekor_backend = _build_live_rekor_backend() if args.live_rekor else StubRekorBackend()

    with _mock_idp() as idp, tempfile.TemporaryDirectory() as tmp:
        ea_path = Path(tmp) / "ea_chain.jsonl"
        coach_path = Path(tmp) / "coach_chain.jsonl"

        _section("1. Configure mock single-tenant IdP and adapter")
        adapter = Auth0Adapter(
            domain="vindicara.us.auth0.com",
            audience="agent:cabinet-coach.v2",
            issuer=idp["issuer"],
            jwks_uri=f"{idp['issuer']}.well-known/jwks.json",
            signing_key_pem=idp["pem"],
            signing_kid=idp["kid"],
        )
        print(f"  IdP issuer (mock): {idp['issuer']}")
        print("  audience         : agent:cabinet-coach.v2")

        _section("2. Generate LOCAL_DEV agent identities")
        ea = generate_local_dev_identity("agent:cabinet-ea.v3", code_commit="git:demo")
        coach = generate_local_dev_identity(
            "agent:cabinet-coach.v2",
            code_commit="git:demo",
            issuer_url="https://cabinet-coach.us.auth0.com/",
        )
        print(f"  EA   : {ea.agent_id}    cert_hash={ea.cert_hash[:32]}...")
        print(f"  Coach: {coach.agent_id} cert_hash={coach.cert_hash[:32]}...")

        _section("3. EA opens a workflow and mints a capability token")
        root = new_root_context()
        originator = Originator(
            type="user", id="user:kevin@vindicara.io", auth_method="auth0_session"
        )
        cap = adapter.issue_capability_token(
            source_agent_id=ea.agent_id,
            target_agent_id=coach.agent_id,
            target_agent_idp_issuer="https://cabinet-coach.us.auth0.com/",
            scopes=["agent:cabinet-coach:invoke", "context:user:kevin"],
            parent_trace_id=root.trace_id,
            delegation_payload_hash=canonicalize_and_hash(
                {"request": "produce coaching observation"}
            ),
        )
        print(f"  PTID (W3C trace_id): {root.trace_id}")
        print(f"  traceparent        : {root.to_traceparent()}")
        print(f"  cap token jti      : {cap.jti}")
        print(f"  air_protocol_ver   : {cap.air_protocol_version}")

        _section("4. EA writes the HANDOFF record")
        intent = "request_coaching_observation"
        intent_hash = canonicalize_and_hash(intent)
        payload_hash = canonicalize_and_hash(
            {"request": "produce coaching observation"}
        )
        handoff = build_handoff_record(
            step_n=4,
            trace_context=root,
            originator=originator,
            depth=0,
            source_identity=ea,
            handoff_body=HandoffBody(
                target_agent_id=coach.agent_id,
                target_agent_identity_certificate_format=coach.fmt.value,
                target_agent_identity_certificate_hash=coach.cert_hash,
                target_agent_idp_issuer="https://cabinet-coach.us.auth0.com/",
                delegation_intent=intent,
                delegation_intent_hash=intent_hash,
                delegation_payload_hash=payload_hash,
                capability_token=CapabilityTokenSummary(
                    issuer=cap.issuer,
                    jti=cap.jti,
                    exp=cap.expires_at,
                    scopes=list(cap.scopes),
                    claims_hash=cap.claims_hash_blake3,
                    raw_jwt=cap.raw_jwt,
                ),
                expected_response_type="coaching_observation",
                fail_policy=FailPolicy(rekor_submission_mode="synchronous"),
            ),
            prev_hash="blake3:" + "f" * 64,
        )
        ea_path.write_text(json.dumps(handoff) + "\n")
        print(f"  HANDOFF content_hash: {handoff['content_hash']}")
        print(f"  written to          : {ea_path.name}")

        _section("5. Coach verifies the cap token; submits Rekor counter-attestation")
        adapter.verify_capability_token(
            raw_jwt=cap.raw_jwt,
            expected_audience=coach.agent_id,
            expected_parent_trace_id=root.trace_id,
        )
        proof = submit_validation_proof(
            validating_agent=coach,
            capability_token=cap,
            rekor_backend=rekor_backend,
        )
        print(f"  validation method  : {proof['validation_method']}")
        print(f"  Rekor mode/state   : {proof['submission_mode']} / {proof['submission_state']}")
        print(f"  Rekor entry index  : {proof['rekor_entry_index']}")
        print(f"  Rekor entry uuid   : {proof['rekor_entry_uuid'][:32]}...")
        print(f"  attestation hash   : {proof['validation_attestation_hash']}")
        print("  attestation blob has hashed identifiers only (no topology leak)")

        _section("6. Coach writes the HANDOFF_ACCEPTANCE record")
        acceptance = build_handoff_acceptance_record(
            step_n=1,
            trace_context=child_context(root),
            originator=originator,
            depth=1,
            target_identity=coach,
            acceptance_body=AcceptanceBody(
                source_agent_id=ea.agent_id,
                source_handoff_record_hash=handoff["content_hash"],
                capability_token_received_jti=cap.jti,
                capability_token_validation_method="auth0_jwks_rs256",  # noqa: S106
                capability_token_validation_proof=proof,
                delegation_intent_acknowledged=intent,
                delegation_intent_hash_acknowledged=intent_hash,
                intended_response_type="coaching_observation",
            ),
            prev_hash="blake3:" + "0" * 64,
            source_agent_id=ea.agent_id,
            source_handoff_record_hash=handoff["content_hash"],
        )
        coach_path.write_text(json.dumps(acceptance) + "\n")
        print(f"  ACCEPTANCE content_hash: {acceptance['content_hash']}")
        print(f"  written to             : {coach_path.name}")

        _section("7. Eight-step cross-agent verification (Section 8.2)")
        router = AdapterRouter()
        router.register(adapter)
        verifier = CrossAgentVerifier(adapter_router=router, rekor_backend=rekor_backend)
        verifier.register_identity(ea.cert_hash, ea.public_key)
        verifier.register_identity(coach.cert_hash, coach.public_key)
        result = verifier.verify_chain_set(
            ChainSet.from_paths([ea_path, coach_path]),
            parent_trace_id=root.trace_id,
        )
        for flag in result.flags:
            print(f"  flag: {flag}")
        if not result.passed:
            for d in result.diagnostics:
                print(f"  fail: {d}", file=sys.stderr)
            print("VERIFICATION FAILED", file=sys.stderr)
            return 1

        _section("8. Forensic implication")
        print("  An auditor reading both chains can independently confirm:")
        print("    - the cap token was minted by Vindicara's IdP for Coach")
        print("    - Coach actually validated it (Rekor counter-attestation)")
        print("    - the Rekor entry contains zero workflow topology metadata")
        print("    - the chains share the W3C trace_id and pair cryptographically")
        print("    - no Vindicara intermediation required")

        _section("LAYER 4 WAVE 1 LIVE E2E PASS")
        return 0


if __name__ == "__main__":
    sys.exit(main())
