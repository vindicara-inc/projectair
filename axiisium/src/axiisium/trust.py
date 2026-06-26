"""Axiisium trust layer — the Vindicara/Project AIR substrate applied to model runs.

This is the moat, and it runs for real here. Every step of a training/inference run
is signed with Ed25519 at the moment it happens, hash-chained to the previous step, and
bound to a named human authority. Change one byte after the fact and verification fails.

For a regulated AML product that pharma will submit to the FDA, this is what makes a
model decision a tamper-evident, 21 CFR Part 11 / FRE 902(13)-(14)-grade record: proof
of exactly which data, code, and human produced a given prediction.

In production this is `airsdk.AIRRecorder` (BLAKE3 + Ed25519/ML-DSA-65, anchored to
Sigstore Rekor). This file is the self-contained reference so the feasibility run has
zero external dependency beyond `cryptography`.
"""
from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

GENESIS = "0" * 64


class RunLedger:
    """Signed, hash-chained ledger of one model run (train or inference)."""

    def __init__(self) -> None:
        self._key = Ed25519PrivateKey.generate()
        self.pubkey_hex = self._key.public_key().public_bytes_raw().hex()
        self.records: list[dict[str, Any]] = []

    def record(
        self,
        kind: str,
        payload: dict[str, Any],
        human_authority: str | None = None,
    ) -> dict[str, Any]:
        body = {
            "ordinal": len(self.records),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "kind": kind,
            "payload": payload,
            "human_authority": human_authority,
            "prev_hash": self.records[-1]["content_hash"] if self.records else GENESIS,
        }
        content = json.dumps(body, sort_keys=True).encode()
        content_hash = hashlib.sha256(content).hexdigest()  # BLAKE3 in production
        signature = self._key.sign(bytes.fromhex(content_hash)).hex()  # Ed25519, real
        rec = {
            **body,
            "content_hash": content_hash,
            "signature": signature,
            "algorithm": "Ed25519",
        }
        self.records.append(rec)
        return rec

    @staticmethod
    def verify(records: list[dict[str, Any]], pubkey_hex: str) -> tuple[bool, str]:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))
        prev = GENESIS
        fields = ("ordinal", "timestamp", "kind", "payload", "human_authority", "prev_hash")
        for r in records:
            body = {k: r[k] for k in fields}
            recomputed = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
            if recomputed != r["content_hash"]:
                return False, f"content tampered at record #{r['ordinal']} ({r['kind']})"
            if r["prev_hash"] != prev:
                return False, f"broken chain link at record #{r['ordinal']}"
            try:
                pub.verify(bytes.fromhex(r["signature"]), bytes.fromhex(r["content_hash"]))
            except Exception:
                return False, f"invalid signature at record #{r['ordinal']}"
            prev = r["content_hash"]
        return True, "intact"


def sha256_array(arr: Any) -> str:
    """Stable hash of a numpy array — used to bind exact data/weights into the ledger."""
    return hashlib.sha256(arr.tobytes()).hexdigest()


def tamper_copy(records: list[dict[str, Any]], ordinal: int, field: str, value: Any) -> list[dict[str, Any]]:
    """Return a deep copy with one field altered, to demonstrate tamper detection."""
    t = copy.deepcopy(records)
    t[ordinal]["payload"][field] = value
    return t
