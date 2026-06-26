"""Multi-signer federation ledger — the moat applied across sites.

A single append-only, hash-chained log that MULTIPLE parties sign: each site signs its own
local-update records with its own key; the server signs each aggregation. This is the
cross-agent trust contract (Project AIR Layer 4) applied to federated learning, and it is
exactly what plain FedAvg / FLARE lacks: cryptographic proof of WHICH site contributed
WHAT in each round, WITHOUT the raw data ever moving, that no party can forge or alter
after the fact.

It also closes the gap NVIDIA FLARE's own docs admit: confidential computing attestation
proves the enclave is genuine but not what was computed at the application layer. Each
party signing its actual contribution into a shared chain provides that application-layer
proof, end to end.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

GENESIS = "0" * 64


class FederationLedger:
    """One chain, many signers. Each record is signed by the named party's key."""

    def __init__(self) -> None:
        self._keys: dict[str, Ed25519PrivateKey] = {}
        self.pubkeys: dict[str, str] = {}
        self.records: list[dict[str, Any]] = []

    def register(self, party_id: str) -> None:
        key = Ed25519PrivateKey.generate()
        self._keys[party_id] = key
        self.pubkeys[party_id] = key.public_key().public_bytes_raw().hex()

    def record(self, signer_id: str, kind: str, payload: dict[str, Any]) -> dict[str, Any]:
        if signer_id not in self._keys:
            raise KeyError(f"unregistered signer {signer_id!r}")
        body = {
            "ordinal": len(self.records),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "signer_id": signer_id,
            "kind": kind,
            "payload": payload,
            "prev_hash": self.records[-1]["content_hash"] if self.records else GENESIS,
        }
        content = json.dumps(body, sort_keys=True).encode()
        content_hash = hashlib.sha256(content).hexdigest()
        signature = self._keys[signer_id].sign(bytes.fromhex(content_hash)).hex()
        rec = {**body, "content_hash": content_hash, "signature": signature, "algorithm": "Ed25519"}
        self.records.append(rec)
        return rec

    @staticmethod
    def verify(records: list[dict[str, Any]], pubkeys: dict[str, str]) -> tuple[bool, str]:
        prev = GENESIS
        fields = ("ordinal", "timestamp", "signer_id", "kind", "payload", "prev_hash")
        for r in records:
            body = {k: r[k] for k in fields}
            if hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest() != r["content_hash"]:
                return False, f"content tampered at #{r['ordinal']} ({r['kind']} by {r['signer_id']})"
            if r["prev_hash"] != prev:
                return False, f"broken chain link at #{r['ordinal']}"
            signer = r["signer_id"]
            if signer not in pubkeys:
                return False, f"unknown signer {signer!r} at #{r['ordinal']}"
            try:
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkeys[signer])).verify(
                    bytes.fromhex(r["signature"]), bytes.fromhex(r["content_hash"])
                )
            except Exception:
                return False, f"invalid signature at #{r['ordinal']} (claimed signer {signer})"
            prev = r["content_hash"]
        return True, "intact"
