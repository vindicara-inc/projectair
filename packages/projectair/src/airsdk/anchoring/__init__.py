"""Project AIR Layer 1: External Trust Anchor.

Anchoring binds the AgDR chain root to two independent public proofs:

- RFC 3161 trusted timestamp tokens, asserting the chain root existed
  before a known wall-clock time, signed by a Time Stamping Authority.
- Sigstore Rekor transparency log entries, asserting the chain root was
  admitted to a public, append-only, Merkle-tree-backed log at a known
  position.

Together these mean an auditor can verify the chain entirely with public
infrastructure: no Vindicara API call, no vendor cooperation, no customer
key access. The verification path is documented in ``docs/anchoring.md``
and exercised by ``air verify-public``.

This module is opt-in for v1 of the OSS package. Users who do not enable
anchoring see the same behavior as in v0.3.x and earlier.
"""
from __future__ import annotations

from airsdk.anchoring.exceptions import (
    AnchoringError,
    AnchorRequiredError,
    RekorError,
    RekorProofInvalidError,
    RekorRateLimitedError,
    RekorUnreachableError,
    TSAError,
    TSANonceMismatchError,
    TSARateLimitedError,
    TSASignatureInvalidError,
    TSAUnreachableError,
)
from airsdk.anchoring.identity import (
    ANCHORING_KEY_ENV,
    default_key_dir,
    load_anchoring_key,
    public_key_path,
)
from airsdk.anchoring.orchestrator import AnchoringOrchestrator
from airsdk.anchoring.policy import AnchoringPolicy, FailurePolicy, OrchestratorHealth
from airsdk.anchoring.rekor import RekorClient
from airsdk.anchoring.rfc3161 import RFC3161Client

__all__ = [
    "ANCHORING_KEY_ENV",
    "AnchorRequiredError",
    "AnchoringError",
    "AnchoringOrchestrator",
    "AnchoringPolicy",
    "FailurePolicy",
    "OrchestratorHealth",
    "RFC3161Client",
    "RekorClient",
    "RekorError",
    "RekorProofInvalidError",
    "RekorRateLimitedError",
    "RekorUnreachableError",
    "TSAError",
    "TSANonceMismatchError",
    "TSARateLimitedError",
    "TSASignatureInvalidError",
    "TSAUnreachableError",
    "default_key_dir",
    "load_anchoring_key",
    "public_key_path",
]
