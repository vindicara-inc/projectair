"""AgDR record types.

AgDR (AI Decision Record) is the on-disk format Project AIR writes for every agent
step; the public product term is "Signed Intent Capsule" (OWASP Top 10 for Agentic
Applications v12.6, ASI01 mitigation #5). Each record is content-hashed with
BLAKE3 and signed with Ed25519. The signature covers both the record's
content_hash AND the previous record's content_hash, producing a tamper-evident
hash chain.

Session 3 shape (v0.3, adds ANCHOR records that bind chain roots to RFC 3161
trusted timestamps and Sigstore Rekor inclusion proofs for external verifiability
without trusting Vindicara, the customer, or the agent vendor):

    {
      "version":      "0.3"
      "step_id":      UUIDv7        one per step, monotonic timestamp prefix
      "timestamp":    ISO 8601 UTC  when the step happened
      "kind":         enum          llm_start | llm_end | tool_start | tool_end
                                    | agent_finish | agent_message | anchor
      "payload":      object        kind-specific contents
      "prev_hash":    hex string    content_hash of previous record, or "0"*64 for first
      "content_hash": hex string    BLAKE3 of canonical(payload) - computed by signer
      "signature":    hex string    Ed25519(prev_hash || content_hash) - computed by signer
      "signer_key":   hex string    Ed25519 public key, for offline verification
    }

Verification walks the chain forward: for each record, recompute content_hash from
payload, assert signature verifies (prev_hash || content_hash) against signer_key,
assert this record's prev_hash equals the last record's content_hash.

Backward compatibility: 0.2 records validate under the 0.3 schema; the version
field is informational. Old chains can be loaded and verified unchanged. The 0.3
bump signals that ANCHOR records may be present; chains without ANCHOR records
remain valid 0.3 chains.
"""
from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# 64 hex chars = 256 bits. BLAKE3 default output size and Ed25519 public key size.
GENESIS_PREV_HASH = "0" * 64

AGDR_VERSION = "0.4"


class StepKind(StrEnum):
    LLM_START = "llm_start"
    LLM_END = "llm_end"
    TOOL_START = "tool_start"
    TOOL_END = "tool_end"
    AGENT_FINISH = "agent_finish"
    AGENT_MESSAGE = "agent_message"
    ANCHOR = "anchor"
    HUMAN_APPROVAL = "human_approval"


class RFC3161Anchor(BaseModel):
    """Per-anchor RFC 3161 trusted-timestamp metadata.

    The token bytes plus the certificate chain are everything an external
    verifier needs to confirm the anchored hash existed before the TSA
    issued the token, with no live TSA call required.
    """

    model_config = ConfigDict(extra="forbid")

    tsa_url: str
    timestamp_token_b64: str
    timestamp_iso: str
    tsa_certificate_chain_pem: list[str]
    hash_algorithm: str = "sha256"


class RekorAnchor(BaseModel):
    """Per-anchor Sigstore Rekor transparency-log metadata.

    log_index plus the inclusion proof let an offline verifier confirm the
    chain root was admitted to the public log at the recorded position.
    """

    model_config = ConfigDict(extra="forbid")

    log_index: int
    uuid: str
    integrated_time: int
    log_id: str
    inclusion_proof: dict[str, Any]
    rekor_url: str


class HumanApproval(BaseModel):
    """Authenticated human decision recorded as part of the chain.

    When a Layer 3 step-up rule trips, the agent halts and asks a human
    to approve. The human authenticates against an identity provider
    (Auth0 in v1; pluggable later) and submits the resulting token. The
    verifier validates the token's signature, issuer, audience, and
    expiration; the verified claims are recorded here so an auditor can
    re-verify offline using only the token plus the IdP's public JWKS.

    This binds the chain not just to "what the agent did" but to "who
    authorized what the agent did" - the consent record that makes the
    chain admissible for compliance regimes that require human oversight
    (EU AI Act Article 14, GDPR Article 22, SOC 2 access controls).
    """

    model_config = ConfigDict(extra="forbid")

    challenge_id: str
    decision: str  # "approve" | "deny"
    approver_sub: str  # IdP subject claim
    approver_email: str | None = None
    issuer: str  # IdP issuer URL
    audience: str
    token_jti: str | None = None  # JWT ID for replay defense, when present
    issued_at: int  # Unix seconds, from JWT iat claim
    expires_at: int  # Unix seconds, from JWT exp claim
    signed_token: str  # the original JWT, for offline re-verification


class AgDRPayload(BaseModel):
    """Kind-specific payload. Structured but extensible via `extra`."""

    model_config = ConfigDict(extra="allow")

    prompt: str | None = None
    response: str | None = None
    tool_name: str | None = None
    tool_args: dict[str, Any] | None = None
    tool_output: str | None = None
    user_intent: str | None = None
    final_output: str | None = None
    # Inter-agent communication fields (ASI07). Used when kind == AGENT_MESSAGE.
    source_agent_id: str | None = None
    target_agent_id: str | None = None
    message_content: str | None = None
    message_id: str | None = None
    # Anchor record fields (Layer 1). Used when kind == ANCHOR. The anchored
    # chain root is the content_hash of the most recent non-anchor record at
    # the time of anchoring; `anchored_step_range` records which step ids the
    # anchor covers so verifiers can scope inclusion claims correctly.
    anchored_chain_root: str | None = None
    anchored_step_range: dict[str, str] | None = None
    rfc3161: RFC3161Anchor | None = None
    rekor: RekorAnchor | None = None
    # Containment fields (Layer 3). Set on TOOL_START records when a
    # ContainmentPolicy rule trips. ``blocked=True`` with a populated
    # ``blocked_reason`` means the action was halted; no TOOL_END follows.
    # ``challenge_id`` is set when the policy required human approval.
    blocked: bool | None = None
    blocked_reason: str | None = None
    challenge_id: str | None = None
    # Human approval (Layer 3). Used when kind == HUMAN_APPROVAL.
    human_approval: HumanApproval | None = None


class AgDRRecord(BaseModel):
    """One signed entry in the forensic chain."""

    model_config = ConfigDict(extra="forbid")

    version: str = AGDR_VERSION
    step_id: str
    timestamp: str
    kind: StepKind
    payload: AgDRPayload
    prev_hash: str = Field(min_length=64, max_length=64)
    content_hash: str = Field(min_length=64, max_length=64)
    signature: str
    signer_key: str


class Finding(BaseModel):
    """One detection surfaced by `air trace`.

    ``detector_id`` is either an official OWASP Top 10 for Agentic Applications
    identifier (``ASI01``..``ASI10``) when the detector maps to a category in
    that public taxonomy, or an AIR-specific identifier (``AIR-01``..``AIR-NN``)
    for detectors that are not in the public taxonomy.
    """

    model_config = ConfigDict(extra="forbid")

    detector_id: str
    title: str
    severity: str
    step_id: str
    step_index: int
    description: str


class VerificationStatus(StrEnum):
    OK = "ok"
    TAMPERED = "tampered"
    BROKEN_CHAIN = "broken_chain"


class VerificationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: VerificationStatus
    records_verified: int
    failed_step_id: str | None = None
    reason: str | None = None


class ForensicReport(BaseModel):
    """The full output of `air trace`."""

    model_config = ConfigDict(extra="forbid")

    air_version: str
    report_id: str
    source_log: str
    generated_at: str
    records: int
    conversations: int
    verification: VerificationResult
    findings: list[Finding]
