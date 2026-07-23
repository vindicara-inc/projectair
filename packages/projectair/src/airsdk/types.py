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

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from airsdk._compat import StrEnum

# 64 hex chars = 256 bits. BLAKE3 default output size and Ed25519 public key size.
GENESIS_PREV_HASH = "0" * 64

AGDR_VERSION = "0.7"


class SigningAlgorithm(StrEnum):
    ED25519 = "ed25519"
    ML_DSA_65 = "ml-dsa-65"


class SignatureMeaning(StrEnum):
    """The meaning of an electronic signature (21 CFR Part 11 §11.50(a)(3)).

    A compliant e-signature manifestation must state what the signature means:
    that the signer reviewed, approved, takes responsibility for, or authored
    the record. AIR records this explicitly so a `HUMAN_APPROVAL` is a complete
    Part 11 signature, not just an authenticated click.
    """

    APPROVAL = "approval"
    REVIEW = "review"
    RESPONSIBILITY = "responsibility"
    AUTHORSHIP = "authorship"


class StepKind(StrEnum):
    LLM_START = "llm_start"
    LLM_END = "llm_end"
    TOOL_START = "tool_start"
    TOOL_END = "tool_end"
    AGENT_FINISH = "agent_finish"
    AGENT_MESSAGE = "agent_message"
    ANCHOR = "anchor"
    HUMAN_APPROVAL = "human_approval"
    AUDIT_REVIEW = "audit_review"  # Part 11 §11.10(e) / Annex 11 §9 trail review
    INTENT_DECLARATION = "intent_declaration"
    DELEGATION = "delegation"  # session-genesis human authorization
    GPU_ATTESTATION = "gpu_attestation"  # hardware root of trust, session genesis (v0.7)
    KEY_TRANSITION = "key_transition"  # signed key handoff: outgoing key authorizes incoming (key custody)


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


class GPUAttestation(BaseModel):
    """NVIDIA NRAS attestation evidence recorded into the chain (v0.7, experimental).

    AIR records NVIDIA's signed EAT verbatim. AIR does not re-sign it. The
    record's content hash covers the token, and the record falls under the
    first anchored BLAKE3 root, so tampering with the recorded attestation
    breaks chain verification. The nonce is derived from the DELEGATION
    genesis record (see ``airsdk.attestation.evidence.derive_nonce``), which
    binds "a GPU was attested" to "this exact authorized session ran on
    attested hardware."
    """

    model_config = ConfigDict(extra="forbid")

    nonce: str  # freshness nonce, derived from chain genesis
    nras_url: str  # NRAS endpoint that issued the token
    detached_eat: str  # overall attestation JWT (EAT), as returned by NRAS
    device_eats: list[str]  # per-GPU/per-nvSwitch detached EAT bundles, evidence order
    gpu_arch: str  # "hopper" | "blackwell" | "vera_rubin"
    claims_version: str  # NRAS EAT claims schema version, recorded verbatim
    rim_matched: bool  # NRAS verdict: evidence matched the Reference Integrity Manifest
    measured_at: str  # ISO 8601, when AIR collected and recorded the token
    verification_hint: str  # "nras_jwks" | "cached_rim_ocsp", how offline verify should proceed


class KeyTransition(BaseModel):
    """A signed handoff authorizing a new signing key to continue the chain.

    Emitted as a ``KEY_TRANSITION`` record signed by the OUTGOING key, whose
    payload names the INCOMING public key. The outgoing key's signature over
    the record content (which includes ``new_signer_key``) is the authorization:
    it proves the prior, already-trusted key endorsed its successor. This lets a
    chain survive key rotation or node cycling without breaking custody, and lets
    a verifier tell an authorized rotation apart from a forged takeover.

    Chain integrity (hash links, per-record signatures) is unchanged and still
    checked by ``verify_chain``. Custody (was each key change authorized by the
    prior key) is the separate concern checked by ``verify_key_custody``.
    """

    model_config = ConfigDict(extra="forbid")

    new_signer_key: str  # incoming public key, hex (raw encoding, matches AgDRRecord.signer_key)
    new_signature_algorithm: SigningAlgorithm = SigningAlgorithm.ED25519
    reason: str = "rotation"  # operator-supplied label: "rotation" | "node_cycle" | ...


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
    # 21 CFR Part 11 §11.50(a)(3): the meaning of the signature. Optional for
    # back-compat; set it (via AIRRecorder.approve(..., signature_meaning=))
    # to make the record a complete Part 11 electronic signature.
    meaning: SignatureMeaning | None = None


class AuditReview(BaseModel):
    """An IdP-verified review of a range of the forensic chain.

    21 CFR Part 11 §11.10(e) and EU Annex 11 §9 expect the audit trail to be
    reviewed. This records that a named, authenticated reviewer reviewed steps
    ``reviewed_from_step``..``reviewed_to_step`` and the outcome, as a signed,
    tamper-evident record inside the chain itself. ``reason`` carries a
    reason-for-change / reason-for-correction note where the review annotates
    or corrects a prior record (Part 11 change-control expectation).
    """

    model_config = ConfigDict(extra="forbid")

    reviewer_sub: str  # IdP subject claim of the reviewer
    reviewer_email: str | None = None
    issuer: str  # IdP issuer URL
    audience: str
    token_jti: str | None = None
    reviewed_at: int  # Unix seconds, from the reviewer token iat claim
    signed_token: str  # the reviewer's JWT, for offline re-verification
    reviewed_from_step: str  # first step_id in the reviewed range
    reviewed_to_step: str  # last step_id in the reviewed range
    outcome: str  # "accepted" | "exceptions_noted"
    notes: str | None = None
    reason: str | None = None  # reason-for-change, when the review records a correction


class EntityScope(BaseModel):
    """Dynamic scope mechanism for entity access control.

    Supports four scope types beyond static allowed_entities lists:
    facility scope (all patients at a facility/unit), roster scope
    (subscription to a FHIR patient list), and predicate scope
    (expression-based filtering on message attributes).
    """

    model_config = ConfigDict(extra="forbid")

    scope_type: str  # "static" | "facility" | "roster" | "predicate"
    facility: str | None = None
    unit: str | None = None
    time_window_hours: int | None = None
    roster_source: str | None = None
    refresh_interval_seconds: int = 300
    predicate: str | None = None

    def matches_facility(self, facility: str) -> bool:
        if self.scope_type != "facility":
            return True
        return self.facility is not None and self.facility == facility


class IntentSpec(BaseModel):
    """Structured intent declaration for structural verification.

    When attached to an INTENT_DECLARATION record, defines the scope the
    agent is authorized to operate within. The symbolic verification floor
    checks actual behavior against these constraints deterministically.
    """

    model_config = ConfigDict(extra="forbid")

    goal: str
    allowed_tools: list[str] = Field(default_factory=list)
    allowed_paths: list[str] = Field(default_factory=list)
    allowed_network: list[str] = Field(default_factory=list)
    allowed_entities: list[str] = Field(default_factory=list)
    entity_scope: EntityScope | None = None
    secret_access: bool = False
    non_goals: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_scope_exclusivity(self) -> IntentSpec:
        if self.allowed_entities and self.entity_scope:
            raise ValueError(
                "allowed_entities and entity_scope are mutually exclusive. "
                "Use allowed_entities for static lists or entity_scope for "
                "facility/roster/predicate scoping."
            )
        return self


class AuthMethod(StrEnum):
    AUTH0 = "auth0"  # OIDC token, passkey-as-authenticator inside Auth0
    WEBAUTHN = "webauthn"  # native WebAuthn, biometric stays on the device


class DelegationGrant(BaseModel):
    """A human authorizing an agent deployment, recorded as the chain genesis.

    ``HumanApproval`` binds one action to a human. ``DelegationGrant`` binds the
    whole session: who authorized this agent to run, under which policy, within
    which scope, until when. Because every later record hash-chains from this
    genesis, binding the genesis to an authenticated human binds the entire
    session.

    ``proof`` carries what an offline verifier needs to re-check the human
    authentication with no live IdP call: the Auth0 JWT, or the WebAuthn
    assertion bundle (clientDataJSON, authenticatorData, signature, and the
    credential public key).
    """

    model_config = ConfigDict(extra="forbid")

    delegation_id: str
    agent_id: str
    decision: str = "authorize"  # "authorize" | "deny"

    # Who authorized.
    auth_method: AuthMethod
    authorizer_sub: str  # IdP subject claim, or WebAuthn user handle
    authorizer_email: str | None = None
    issuer: str | None = None  # IdP issuer URL (auth0 path)
    credential_id: str | None = None  # WebAuthn credential id, b64url (webauthn path)

    # What was authorized.
    policy_id: str
    policy_hash: str  # BLAKE3 hex of the ruleset document
    scope: IntentSpec  # the authorized scope; SV enforces this exact spec

    # When.
    granted_at: int  # unix seconds
    expires_at: int  # unix seconds

    # Offline re-verification material.
    proof: dict[str, Any] = Field(default_factory=dict)


class DataAssetRef(BaseModel):
    """Reference to a data asset touched by an agent action."""

    model_config = ConfigDict(extra="forbid")

    asset_id: str
    asset_type: str
    namespace: str = ""
    sensitivity: str = ""


class DataSubjectRef(BaseModel):
    """Reference to a data subject whose data an agent action touches."""

    model_config = ConfigDict(extra="forbid")

    subject_id: str
    subject_type: str = ""
    jurisdiction: str = ""


class CapturePolicy(BaseModel):
    """Capture-time content policy for regulated / PHI-bearing chains.

    ALCOA+ "Complete" wants the content of each step recorded, but an
    immutable, externally-anchored chain must not become a permanent store
    of PHI or other data a subject can demand be erased. This policy replaces
    the plaintext of the named payload fields with a per-record **salted**
    BLAKE3 digest at the moment of capture, before signing. The salt makes the
    digest non-reversible (a low-entropy value like an SSN cannot be brute-
    forced from the digest) and non-correlatable (identical plaintexts get
    different salts, so equal values do not produce equal digests in the chain
    or in any public anchor). The salt and plaintext go to an access-controlled,
    erasable :class:`airsdk.reference_vault.ReferenceVault`, never the chain;
    pass ``reference_vault=`` to ``AIRRecorder`` to enable later verification
    and erasure. Without a vault the salt is discarded, which makes the digest
    permanently non-reversible but also unverifiable (a pure shred mode).

    This is capture-time reference, distinct from publish-time redaction:
    publish-time redaction still leaves the plaintext in the at-rest source
    record; capture-time reference never writes it to the chain at all. The
    digest is written to ``AgDRPayload.content_refs[field] = "blake3:<hex>"``.

    Tradeoff: referencing a field blinds the content-based detectors that read
    it. On a ``phi_safe`` chain, AIR-01 (prompt injection), AIR-02 (sensitive-
    data), tool-misuse, and the causal ``explain`` layer see nothing on the
    referenced fields, so "PHI-safe capture" and "full content-detector
    coverage" cannot both be claimed. This is inherent to data minimization,
    not a defect. Decision ``provenance`` is NOT referenced (model / snapshot /
    fingerprint / sampling params are not PHI), so the ALCOA+ "Accurate"
    evidence for a non-deterministic decision survives PHI mode intact.
    """

    model_config = ConfigDict(extra="forbid")

    hash_fields: frozenset[str] = frozenset()  # payload fields to reference instead of store

    @classmethod
    def phi_safe(cls) -> CapturePolicy:
        """Reference the common free-text/content fields so no plaintext (and
        thus no PHI carried in prompts, responses, or tool I/O) enters the
        signed chain. Pair with ``reference_vault=`` on the recorder to keep
        the erasable plaintext. ``user_intent`` is intentionally not referenced
        so goal anchoring (ASI01) still works; hash it too if it may carry PHI."""
        return cls(
            hash_fields=frozenset(
                {"prompt", "response", "tool_output", "tool_args", "message_content", "final_output"}
            )
        )


class LogprobsSummary(BaseModel):
    """Compact summary of the token-level probability distribution a
    non-deterministic decision was sampled from.

    A stochastic model output is drawn from a distribution; the sampled
    tokens' logprobs are the closest thing to the model "showing its work".
    Full per-token logprobs can be large, and the signed chain doubles as
    the anchoring spool, so the summary (mean / min chosen-token logprob and
    token count) is captured by default and ``full`` is opt-in for callers
    that want the complete distribution in the record.
    """

    model_config = ConfigDict(extra="forbid")

    available: bool = False  # did the provider expose logprobs at all
    mean_logprob: float | None = None  # mean chosen-token logprob (confidence proxy)
    min_logprob: float | None = None  # least-confident sampled token
    token_count: int | None = None  # number of tokens the summary covers
    full: list[dict[str, Any]] | None = None  # opt-in complete distribution, verbatim


class DecisionProvenance(BaseModel):
    """Provenance of a non-deterministic model decision.

    Captures the stochastic conditions that produced an LLM output so the
    signed record is faithful in the ALCOA+ sense (Accurate + Complete):
    which model, at what resolved snapshot and backend fingerprint, under
    what sampling parameters, and drawn from what probability distribution.

    This makes the *record* of the decision faithful and independently
    checkable. It does NOT make the decision reproducible: hosted stochastic
    inference is not bitwise reproducible even with a fixed seed (batching,
    non-deterministic kernels, MoE routing, float non-associativity, silent
    backend changes). ``system_fingerprint`` is recorded precisely so a
    silent backend change is a detectable fact rather than a hidden one.

    Every field is optional; providers expose different subsets. Attach to
    the LLM record that represents the decision (typically ``llm_end``).
    """

    model_config = ConfigDict(extra="forbid")

    provider: str | None = None  # "openai" | "anthropic" | ...
    model: str | None = None  # model id as requested, e.g. "gpt-4o"
    model_version: str | None = None  # resolved snapshot, e.g. "gpt-4o-2024-08-06"
    system_fingerprint: str | None = None  # backend-config fingerprint; a change signals a silent backend change
    # Sampling parameters: the mechanics of the non-determinism.
    temperature: float | None = None
    top_p: float | None = None
    top_k: int | None = None
    seed: int | None = None
    max_tokens: int | None = None
    stop: list[str] | None = None
    # Outcome metadata.
    finish_reason: str | None = None  # "stop" | "length" | "tool_calls" | ...
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    logprobs: LogprobsSummary | None = None


class AgDRPayload(BaseModel):
    """Kind-specific payload. Structured but extensible via `extra`."""

    model_config = ConfigDict(extra="allow")

    prompt: str | None = None
    response: str | None = None
    # Provenance of a non-deterministic model decision. Attached to LLM
    # records so the signed chain captures which model, at what snapshot and
    # fingerprint, under what sampling parameters, and from what distribution
    # the output was sampled. Additive and optional; legacy records omit it.
    provenance: DecisionProvenance | None = None
    # Capture-time content references (CapturePolicy). Maps a payload field
    # name to a ``"blake3:<hex>"`` digest of the plaintext that was NOT stored
    # in the chain. Lets a PHI-bearing deployment prove content integrity by
    # digest while keeping the plaintext out of the immutable, anchored record.
    content_refs: dict[str, str] | None = None
    tool_name: str | None = None
    tool_args: dict[str, Any] | None = None
    tool_output: str | None = None
    user_intent: str | None = None
    final_output: str | None = None
    intent_spec: IntentSpec | None = None
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
    # Audit-trail review (Part 11 §11.10(e) / Annex 11 §9). Used when
    # kind == AUDIT_REVIEW.
    audit_review: AuditReview | None = None
    # Delegation (session genesis). Used when kind == DELEGATION. Binds the
    # whole chain to the human who authorized the agent to run.
    delegation: DelegationGrant | None = None
    # Hardware root of trust (v0.7). Set when kind == GPU_ATTESTATION.
    attestation: GPUAttestation | None = None
    # Key custody. Set when kind == KEY_TRANSITION. The outgoing key signs a
    # record naming the incoming key, authorizing it to continue the chain.
    # ``verify_key_custody`` validates the handoff; ``verify_chain`` is unchanged.
    key_transition: KeyTransition | None = None
    # Data governance (v0.6). Optional tagging for data-asset lineage
    # and data-subject tracking across agent actions.
    data_assets: list[DataAssetRef] | None = None
    data_subjects: list[DataSubjectRef] | None = None
    # HL7v2 / FHIR clinical chain fields (Pro). Set by ``instrument_hl7`` when
    # capturing HL7v2 messages into the forensic chain. The parsing and mapping
    # logic lives in ``airsdk_pro.hl7``; these fields are schema stubs available
    # to any chain reader without importing the Pro package.
    hl7v2_message_type: str | None = None
    hl7v2_segments: dict[str, Any] | None = None
    fhir_resources: list[dict[str, Any]] | None = None


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
    signature_algorithm: str = SigningAlgorithm.ED25519
    # When True, the signature covers the record metadata (step_id, timestamp,
    # kind, signature_algorithm) in addition to prev_hash + content_hash, so a
    # forensic timestamp or step kind cannot be altered without breaking
    # verification. Additive and self-protecting: legacy records omit the field
    # (default False) and verify over prev_hash + content_hash exactly as
    # before; flipping the flag on a signed record invalidates its signature.
    meta_signed: bool = False


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
