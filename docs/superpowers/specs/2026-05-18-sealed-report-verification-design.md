# Sealed Report Verification Protocol

Date: 2026-05-18
Status: Draft, paste-ready
Scope: AgDR v0.6, `airsdk_pro/governance/`
References: the canonicalization spec (canonicalize, canonical_dump, canonical_dict, record_hash, merkle_leaf, merkle_root, merkle_internal, signing_bytes, canonical_timestamp); the redaction execution spec (RedactedReportStaleError, AgDRRedactionRecord); the four-pillar governance design (the DSAR, governance, and RoPA report types).

This document does not restate the canonicalization or Merkle rules. It cites them by name. Any rule that would conflict with the canonicalization spec is a bug in this document and is to be fixed here, not papered over.

---

## 0. The decisions this spec locks

1. A sealed report is itself an `AgDRRecord` of `record_type: "sealed_report"`. It is appended to a chain, participates in the chain's hash chain and Merkle tree, and is therefore tamper-evident at the same level as every other record. Reports are not side-car files.
2. Sealed reports live in a dedicated **per-tenant reports chain** named `reports.agdr`. Source data chains are referenced from sealed reports only by `ChainHeadSnapshot`. A sealed report's `prev_record_hash` linkage runs through the reports chain, never through the source chains it covers. This avoids the asymmetry of choosing one source chain to "host" the report and avoids duplicating the report across N source chains.
3. **The Merkle leaf for a sealed-report record is computed the same way as every other AgDR record**: through `canonical_dict()`, with the report's `signature` field excluded from the signing payload but included in the canonical record form once the signature has been collected. Verifiers re-derive both forms via the canonicalization spec.
4. The staleness rule from the redaction execution spec is binding: a verifier raises `RedactedReportStaleError` when any chain referenced by a `ChainHeadSnapshot` has extended past the snapshot AND any of the extension records is an `AgDRRedactionRecord`, regardless of verifier mode. Other extensions are warnings in default mode and hard errors in strict mode.
5. Re-issuance is a first-class protocol, not an operational afterthought. When a report is invalidated by a redaction in its scope, the operator regenerates against the current chain head and the new report carries an explicit `supersedes` pointer to the prior report's `record_hash`.

---

## 1. The sealed report schema

### 1.1 Envelope and payload

```python
from enum import StrEnum
from typing import Literal
from pydantic import BaseModel, ConfigDict, model_validator

class ReportType(StrEnum):
    DSAR = "dsar"
    GOVERNANCE_SUMMARY = "governance_summary"
    RTBF_ACK = "rtbf_acknowledgment"
    ROPA = "ropa"

class ChainHeadSnapshot(BaseModel):
    """Pins one source chain at the exact state the report covers."""
    model_config = ConfigDict(extra="forbid")
    chain_id: str
    head_sequence: int                          # 0-indexed sequence of last record covered
    head_record_hash: str                       # record_hash of the record at head_sequence
    merkle_root: str                            # hex of merkle_root over records 0..head_sequence

class CoverageAttestation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    data_coverage_ratio: float                  # tagged data-touching calls / total data-touching calls
    call_coverage_ratio: float                  # tagged calls / total calls
    untagged_step_ids: list[str]                # populated when data_coverage_ratio < 1.0
    mode: Literal["strict", "permissive"]
    refused_to_certify: bool                    # true iff strict + data_coverage_ratio < 1.0

class DSARRedactionDisclosure(BaseModel):
    """Required on any DSAR that returns zero accesses for a subject who
    was previously redacted. Prevents the misleading-by-omission failure."""
    model_config = ConfigDict(extra="forbid")
    redaction_id: str
    redacted_on: str                            # canonical_timestamp
    legal_basis: str                            # RedactionLegalBasis value
    request_reference: str
    officers: list[str]                         # officer_ids of the countable signatures

class SealedReportPayload(BaseModel):
    """The signed payload. Excludes the signature itself."""
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["0.6"]
    report_id: str                              # ULID, lexicographically sortable
    report_type: ReportType
    tenant_id: str
    generated_at: str                           # canonical_timestamp form
    valid_at: str                               # canonical_timestamp; equals generated_at for non-retrospective reports
    source_chain_snapshots: list[ChainHeadSnapshot]
    report_content_hash: str                    # see 1.3
    coverage_attestation: CoverageAttestation
    redaction_disclosures: list[DSARRedactionDisclosure] = []
    supersedes: str | None = None               # record_hash of the prior sealed report this re-issues, if any
    signing_key_fingerprint: str                # SHA-256 hex of the signing public key
    signing_key_version: int                    # monotonic per tenant

class SealedReportEnvelope(AgDRRecord):
    """The on-disk record. record_type is fixed; participates in the
    reports chain's hash chain and Merkle tree like any other AgDRRecord."""
    record_type: Literal["sealed_report"] = "sealed_report"
    payload: SealedReportPayload
    signature: str                              # base64 of Ed25519 signature over signing_bytes(envelope, exclude_fields={"signature"})

    def canonical_dict(self) -> dict:
        """Sorts source_chain_snapshots by chain_id (codepoint order)
        before canonicalization. Redaction disclosures are sorted by
        redaction_id. Lists with semantic order do NOT sort (e.g. the
        envelope's own positional fields)."""
        raw = canonical_dump(self)
        raw["payload"]["source_chain_snapshots"] = sorted(
            raw["payload"]["source_chain_snapshots"],
            key=lambda s: s["chain_id"],
        )
        raw["payload"]["redaction_disclosures"] = sorted(
            raw["payload"]["redaction_disclosures"],
            key=lambda d: d["redaction_id"],
        )
        return raw
```

Two list-ordering rules are enforced by the `canonical_dict()` hook so that two implementations producing the same logical report yield byte-identical canonical forms. Per the canonicalization spec (section 3.3 of that document), the sort lives on the model, not in callers.

### 1.2 The report content

The report content (DSAR rows, governance summary tables, RoPA processing records) is a separate Pydantic model not defined here. Its schema lives in the four-pillar design doc. Its only entry point into the sealed-report verification protocol is via `report_content_hash`.

### 1.3 Content hashing

The content hash is computed once, at generation time, and frozen into the payload:

```python
def report_content_hash(content: BaseModel) -> str:
    """SHA-256 of canonicalize(content.canonical_dict()), hex, lowercase.
    Uses the same canonicalization layer as every other hash in the system.
    Per the canonicalization spec, content's canonical_dict() applies any
    order-independence sorts (e.g. DSAR rows by step_id) before encoding."""
    return hashlib.sha256(
        canonicalize(content.canonical_dict())
    ).hexdigest()
```

Content models that contain order-independent collections (DSAR rows, anomaly lists) override `canonical_dict()` to apply deterministic sorts, exactly as `SealedReportEnvelope` does for snapshots and disclosures.

The content itself is persisted separately from the envelope (as a `.json` or `.jsonl` sidecar in the reports directory, or in object storage). The envelope binds to the content by hash. A verifier that has only the envelope can verify the signature and the chain snapshots but not the content. A verifier that wants to confirm "this is the report content the envelope binds to" recomputes `report_content_hash(content)` and compares.

### 1.4 Signing

```python
def sealed_report_signing_bytes(envelope: SealedReportEnvelope) -> bytes:
    """The bytes the signer signs. The signature field is EXCLUDED
    (not set empty) per the canonicalization spec section 3.1."""
    return signing_bytes(envelope, exclude_fields={"signature"})

def sign_sealed_report(
    envelope: SealedReportEnvelope,
    signer: TenantGovernanceSigner,
) -> SealedReportEnvelope:
    """Returns the envelope with the signature populated. Caller is
    responsible for setting prev_record_hash and sequence on the envelope
    before signing, since those are part of the AgDRRecord base and
    therefore part of the signing payload."""
    if envelope.payload.tenant_id != signer.tenant_id:
        raise CrossTenantSigningError(
            f"Envelope tenant_id ({envelope.payload.tenant_id}) does not "
            f"match signer tenant_id ({signer.tenant_id})."
        )
    sig_bytes = signer.ed25519_sign(sealed_report_signing_bytes(envelope))
    envelope.signature = base64.b64encode(sig_bytes).decode("ascii")
    return envelope
```

Tenant binding is enforced at the signer interface. A signer for tenant A cannot produce a valid signature for an envelope claiming tenant B because the signer rejects the mismatch before signing.

---

## 2. The per-tenant reports chain

### 2.1 Layout

Each tenant has one reports chain:

```
<tenant_root>/
  chains/
    main.agdr            # the source chain(s) of recorded agent activity
    side_chain_xyz.agdr  # additional source chains if the tenant has them
  reports/
    reports.agdr         # the per-tenant reports chain
    content/             # detached report content, named by report_id
      01H...-dsar.json
      01H...-governance.json
```

`reports.agdr` contains only `SealedReportEnvelope` records and (if you want to be strict) only `record_type: "sealed_report"`. It has its own hash chain via `prev_record_hash`. It has its own Merkle tree. Source chains reference NOTHING in the reports chain; the dependency direction is one-way (reports chain depends on source chains).

### 2.2 Sequence and prev_record_hash semantics

A `SealedReportEnvelope` follows the standard `AgDRRecord` linkage rules from the canonicalization spec. Inside `reports.agdr`:

- `sequence` is the report's 0-indexed position in `reports.agdr`.
- `prev_record_hash` is `record_hash` of the prior report in `reports.agdr`, or `""` for sequence 0.
- The envelope's `record_hash` extends the reports chain.

The `ChainHeadSnapshot` entries inside the report's payload reference SOURCE chains. They have no linkage to `reports.agdr`. A snapshot's `head_sequence` is the position within the named source chain, not within `reports.agdr`.

### 2.3 Why per-tenant, not per-source-chain

A report covering 5 source chains, persisted by appending into one of them, asymmetrically biases the chain it lives in. Persisting by appending into all 5 duplicates the record. Persisting in a separate chain decouples cleanly. The "reports chain" name and the `record_type: "sealed_report"` discriminator make filtering trivial for any tooling that wants to enumerate reports for a tenant.

---

## 3. Generation protocol

### 3.1 Inputs

- Tenant ID `T`.
- A set of source chains `{C_1, ..., C_k}` to be covered.
- The report content (DSAR rows, governance summary, etc.).
- A `TenantGovernanceSigner` for tenant `T`.
- An optional `supersedes: str | None`, the `record_hash` of a prior sealed report being re-issued (see section 6).

### 3.2 Steps

```python
def generate_sealed_report(
    tenant_id: str,
    source_chains: list[Chain],
    content: BaseModel,
    coverage: CoverageAttestation,
    redaction_disclosures: list[DSARRedactionDisclosure],
    signer: TenantGovernanceSigner,
    reports_chain: Chain,
    report_type: ReportType,
    supersedes: str | None = None,
) -> SealedReportEnvelope:

    # 1. Snapshot every source chain at its current head.
    snapshots: list[ChainHeadSnapshot] = []
    for c in source_chains:
        head = c.head_sequence                       # last record's sequence
        snapshots.append(ChainHeadSnapshot(
            chain_id=c.chain_id,
            head_sequence=head,
            head_record_hash=record_hash(c.records[head]),
            merkle_root=merkle_root(c.records[:head + 1]).hex(),
        ))

    # 2. Honor the strict-mode refusal contract. If coverage is refused,
    #    we STILL produce and sign the envelope, but `refused_to_certify`
    #    is True so verifiers must reject for action while preserving the
    #    audit-trail signature.
    now = canonical_timestamp(datetime.now(timezone.utc))

    # 3. Build the payload with the content hash but no signature yet.
    payload = SealedReportPayload(
        schema_version="0.6",
        report_id=str(ulid.new()),
        report_type=report_type,
        tenant_id=tenant_id,
        generated_at=now,
        valid_at=now,
        source_chain_snapshots=snapshots,
        report_content_hash=report_content_hash(content),
        coverage_attestation=coverage,
        redaction_disclosures=redaction_disclosures,
        supersedes=supersedes,
        signing_key_fingerprint=signer.fingerprint,
        signing_key_version=signer.version,
    )

    # 4. Construct the envelope as an AgDRRecord. prev_record_hash and
    #    sequence come from the reports chain's current head.
    envelope = SealedReportEnvelope(
        schema_version="0.6",
        record_type="sealed_report",
        sequence=reports_chain.next_sequence(),
        chain_id=reports_chain.chain_id,
        tenant_id=tenant_id,
        timestamp=now,
        prev_record_hash=(
            record_hash(reports_chain.last_record())
            if reports_chain.next_sequence() > 0
            else ""
        ),
        payload=payload,
        signature="",                                # placeholder; filled in step 5
    )

    # 5. Sign. After this call, envelope.signature is populated.
    sign_sealed_report(envelope, signer)

    # 6. Persist content (object storage / sidecar) and envelope (append
    #    to reports chain).
    reports_chain.append(envelope)
    persist_report_content(content, report_id=payload.report_id)

    return envelope
```

The order matters: snapshots are captured BEFORE the envelope itself is constructed, so they reflect source chain state at generation time and do not accidentally include the report being generated. The envelope's own `prev_record_hash` is then computed against the reports chain's current head, which is in a different chain entirely.

### 3.3 The refused-to-certify contract

When `coverage.refused_to_certify == True`, generation still proceeds. The envelope is signed and appended. A signed "refusal" record is itself audit-trail evidence: it proves that at time T, the operator attempted to generate a report and the system declined to certify due to coverage gaps. Suppressing the record would be worse than recording the refusal.

Downstream consumers (DSAR responders, governance dashboards) MUST reject a refused-to-certify envelope as an actionable artifact. The verifier surfaces this as `RefusedCertificationError` per section 8.

---

## 4. Verification protocol

The verifier consumes a `SealedReportEnvelope` plus access to the source chains and the tenant's governance key registry. It does not need the report content unless content verification is requested.

### 4.1 Algorithm

```python
def verify_sealed_report(
    envelope: SealedReportEnvelope,
    source_chains: dict[str, Chain],      # chain_id -> Chain
    key_registry: GovernanceKeyRegistry,
    mode: Literal["default", "strict"] = "default",
    content: BaseModel | None = None,     # optional, for content hash verification
) -> VerificationResult:

    # 1. Resolve the signing key. Tenant binding is checked.
    key = key_registry.lookup(
        tenant_id=envelope.payload.tenant_id,
        fingerprint=envelope.payload.signing_key_fingerprint,
    )
    if key is None:
        raise UnknownSignerError(envelope.payload.signing_key_fingerprint)
    if key.tenant_id != envelope.payload.tenant_id:
        raise CrossTenantSigningError(
            key.tenant_id, envelope.payload.tenant_id,
        )
    if not key.is_valid_at(envelope.payload.generated_at):
        raise KeyOutsideValidityWindowError(key.fingerprint, envelope.payload.generated_at)

    # 2. Verify the Ed25519 signature over signing_bytes.
    sig_bytes = base64.b64decode(envelope.signature)
    payload_bytes = sealed_report_signing_bytes(envelope)
    if not ed25519_verify(key.public_key, payload_bytes, sig_bytes):
        raise InvalidSignatureError(envelope.payload.report_id)

    # 3. Validate every source chain snapshot.
    for snap in envelope.payload.source_chain_snapshots:
        chain = source_chains.get(snap.chain_id)
        if chain is None:
            raise SnapshotChainMissingError(snap.chain_id)

        # 3a. Re-derive head_record_hash.
        if snap.head_sequence >= len(chain.records):
            raise ChainTooShortForSnapshotError(snap.chain_id, snap.head_sequence, len(chain.records))
        actual_head_hash = record_hash(chain.records[snap.head_sequence])
        if actual_head_hash != snap.head_record_hash:
            raise ChainTamperOrDriftError(
                chain_id=snap.chain_id,
                field="head_record_hash",
                expected=snap.head_record_hash,
                actual=actual_head_hash,
            )

        # 3b. Re-derive merkle_root over records 0..head_sequence inclusive.
        actual_root = merkle_root(chain.records[: snap.head_sequence + 1]).hex()
        if actual_root != snap.merkle_root:
            raise ChainTamperOrDriftError(
                chain_id=snap.chain_id,
                field="merkle_root",
                expected=snap.merkle_root,
                actual=actual_root,
            )

    # 4. Optionally validate the content hash.
    if content is not None:
        actual_content_hash = report_content_hash(content)
        if actual_content_hash != envelope.payload.report_content_hash:
            raise ReportContentTamperError(
                envelope.payload.report_id,
                envelope.payload.report_content_hash,
                actual_content_hash,
            )

    # 5. Honor refused_to_certify.
    if envelope.payload.coverage_attestation.refused_to_certify:
        raise RefusedCertificationError(
            envelope.payload.report_id,
            envelope.payload.coverage_attestation,
        )

    # 6. Staleness check (section 5).
    staleness_findings = check_staleness(envelope, source_chains, mode)

    return VerificationResult(
        envelope=envelope,
        staleness_findings=staleness_findings,
    )
```

The verifier returns successfully only if no error was raised in steps 1 through 5 and step 6 did not raise a hard staleness error. Warnings (default-mode soft staleness, see 5) flow through `VerificationResult` for the caller to act on.

### 4.2 What "verified" means

A successfully verified sealed report says, at minimum:

- The envelope was signed by a key registered to the named tenant at the time of generation.
- The source chains referenced by the snapshots have not been mutated through `head_sequence` (chain integrity).
- If content was provided, the content's canonical hash matches the binding in the envelope.
- The report was not generated as a refusal.
- No redaction has invalidated the report's scope (see section 5).

It does NOT say:

- The coverage is high enough for the customer's compliance posture (that is a policy decision the caller makes on `coverage_attestation`).
- The chain has not been extended past the snapshot (default mode tolerates extension; strict mode does not).
- Anything about chains the envelope did not reference.

---

## 5. Staleness semantics

### 5.1 The locked rule

For each source chain snapshot, after the snapshot has been validated cryptographically (section 4 step 3), the verifier inspects the chain's state PAST `head_sequence`:

```python
def check_staleness(
    envelope: SealedReportEnvelope,
    source_chains: dict[str, Chain],
    mode: Literal["default", "strict"],
) -> list[StalenessFinding]:
    findings: list[StalenessFinding] = []
    for snap in envelope.payload.source_chain_snapshots:
        chain = source_chains[snap.chain_id]
        if len(chain.records) <= snap.head_sequence + 1:
            continue   # chain has not extended

        extension = chain.records[snap.head_sequence + 1 :]
        redactions_in_extension = [
            r for r in extension if r.record_type == "redaction"
        ]

        if redactions_in_extension:
            # HARD ERROR in BOTH modes. The report's content may surface
            # data that has since been erased; re-serving it re-exposes
            # erased subjects.
            raise RedactedReportStaleError(
                report_id=envelope.payload.report_id,
                chain_id=snap.chain_id,
                snapshot_head=snap.head_sequence,
                current_head=len(chain.records) - 1,
                redaction_ids=[r.payload.redaction_id for r in redactions_in_extension],
            )

        if mode == "strict":
            raise StaleReportError(
                report_id=envelope.payload.report_id,
                chain_id=snap.chain_id,
                snapshot_head=snap.head_sequence,
                current_head=len(chain.records) - 1,
            )

        # default mode: extension without redactions is a soft warning.
        findings.append(StalenessFinding(
            chain_id=snap.chain_id,
            snapshot_head=snap.head_sequence,
            current_head=len(chain.records) - 1,
            severity="warning",
        ))

    return findings
```

### 5.2 Why redactions hard-fail in both modes

Default mode tolerates ordinary chain extension because the report still reflects valid state through `head_sequence`. A new tool call appended after the snapshot does not change the truth of "as of head_sequence, the agent's data accesses were X." The report is incomplete relative to current state, not incorrect about the state it claims to cover.

A redaction in the extension is different. A redaction represents the customer asserting "the data we previously held about subject X must be treated as never having been ours to disclose." Re-serving a sealed report that lists subject X's accesses, even if the chain through `head_sequence` cryptographically still contains them, defeats the purpose of the redaction. The hard fail in both modes is the only safe posture.

### 5.3 The overconservative cross-subject case

A report about subject Y stales when a redaction for unrelated subject X lands in the chain extension. This is overconservative: the report's claims about Y are unaffected by an erasure of X. Two valid resolutions exist:

- Conservative (locked in v0.6): all redactions in extension trigger `RedactedReportStaleError`, even cross-subject.
- Content-aware: the verifier inspects the report content to determine which subjects it covers, then triggers only if the redaction target intersects.

The conservative rule is locked because it does not require the verifier to be content-aware, which keeps the verifier simple and avoids depending on a content schema the verifier might not know how to parse. Operators regenerating reports on a cadence absorb the overconservatism without practical pain. A content-aware option is a Phase 2 consideration if the cadence proves operationally expensive.

---

## 6. Re-issuance protocol

### 6.1 When required

A report MUST be re-issued when verification of the existing report would raise `RedactedReportStaleError` against current chain state. Re-issuance is OPTIONAL when verification raises only `StaleReportError` (strict mode, no redactions) or soft `StalenessFinding` (default mode); a customer policy may require re-issuance on a cadence regardless.

### 6.2 How

Re-issuance is just `generate_sealed_report` with two specifics:

```python
def reissue_sealed_report(
    prior: SealedReportEnvelope,
    source_chains: list[Chain],
    new_content: BaseModel,
    new_coverage: CoverageAttestation,
    new_disclosures: list[DSARRedactionDisclosure],
    signer: TenantGovernanceSigner,
    reports_chain: Chain,
) -> SealedReportEnvelope:
    return generate_sealed_report(
        tenant_id=prior.payload.tenant_id,
        source_chains=source_chains,
        content=new_content,
        coverage=new_coverage,
        redaction_disclosures=new_disclosures,
        signer=signer,
        reports_chain=reports_chain,
        report_type=prior.payload.report_type,
        supersedes=record_hash(prior),
    )
```

The new envelope's `payload.supersedes` is the `record_hash` of the prior envelope. This creates an explicit, hash-linked supersession chain inside the reports chain. A reports-chain reader can reconstruct the full lineage of every report by following `supersedes` pointers.

### 6.3 What does NOT happen during re-issuance

- The prior envelope is NOT removed, mutated, or marked. Like any other AgDR record, it stays in the reports chain forever. The supersession relationship lives in the NEW envelope, not in the old one. (`AgDRRedactionRecord` cannot be used to redact a sealed-report envelope; sealed reports, like redactions, are not redactable.)
- The prior envelope continues to verify cryptographically against the chain state at its snapshot. A verifier that wants to confirm "what did we attest at time T?" can still do so. The new envelope additionally attests "and here is the corrected version as of time T'."

### 6.4 Disclosure carry-forward

When re-issuance is triggered by a redaction, the new envelope MUST include a `DSARRedactionDisclosure` for every redaction whose target subject intersects the report's content. For a DSAR being re-issued for a subject who was redacted, the new envelope's content returns zero accesses AND the disclosure makes the erasure visible. For a `GOVERNANCE_SUMMARY` or `ROPA` re-issued because an unrelated redaction landed in the chain extension, the disclosure list reflects only redactions that affected reportable content; this is the only place where the verifier's overconservatism (5.3) is exchanged for slightly more work at re-issuance time.

---

## 7. Governance key management

### 7.1 Registry layout

```
<tenant_root>/
  keys/
    governance.jsonl       # append-only registry of governance keys
```

Records:

```python
class GovernanceKeyRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    fingerprint: str                       # SHA-256 hex of public_key bytes
    version: int                           # monotonic per tenant; v_0 is the initial key
    tenant_id: str                         # immutable; binds key to tenant
    public_key: str                        # base64 of 32 raw Ed25519 public key bytes
    valid_from: str                        # canonical_timestamp
    valid_until: str | None                # null = currently active
    rotation_reason: Literal["initial", "scheduled", "compromise", "policy_update"]
    rotated_by: str                        # operator or system identity that effected the rotation
    rotation_signature: str | None         # base64 Ed25519 signature by the PREVIOUS key over signing_bytes
                                           # of this record with rotation_signature excluded.
                                           # Null only for version 0 (initial key, bootstrapped out of band).
```

`governance.jsonl` is append-only. The active key is the most recent record with `valid_until is None`. Multiple active keys are not permitted; rotation sets the prior key's `valid_until` and appends the new key as the next version.

### 7.2 Rotation chain of trust

Every key after `version: 0` is signed by the prior key. A verifier walking the registry can confirm the full lineage back to the initial key. The initial key is bootstrapped via an out-of-band ceremony documented separately; that ceremony is the only point of trust this protocol depends on.

When a verifier looks up a key by fingerprint and version, it MUST:

1. Confirm the key's `tenant_id` matches the envelope's `tenant_id`.
2. Confirm the envelope's `generated_at` falls within `[valid_from, valid_until)` of the key (or `valid_from` onward if `valid_until` is null).
3. For keys after version 0, verify the `rotation_signature` against the public key of `version - 1`.

Failure of step 3 makes the entire registry suspect. The verifier raises `KeyRegistryChainBrokenError` and rejects all reports signed by the registry until reconciled.

### 7.3 Compromise

A compromised key is rotated with `rotation_reason: "compromise"`. The verifier behavior is unchanged: signatures issued under the compromised key during its validity window still verify cryptographically. The customer's policy may dictate operational responses (regenerate every report signed by the compromised key under the new key, audit access logs, etc.). Those operational responses are not part of this protocol.

---

## 8. Error taxonomy

| Error | Cause | Verifier action |
|---|---|---|
| `UnknownSignerError` | `signing_key_fingerprint` not present in the tenant's registry | reject; escalate |
| `CrossTenantSigningError` | Key's `tenant_id` does not match envelope's `tenant_id` | reject; tampering or misconfiguration |
| `KeyOutsideValidityWindowError` | `generated_at` falls outside the key's `valid_from..valid_until` range | reject; clock skew or replay |
| `KeyRegistryChainBrokenError` | A non-initial key fails its `rotation_signature` check | reject; investigate registry |
| `InvalidSignatureError` | Ed25519 verify failed against `sealed_report_signing_bytes` | reject |
| `SnapshotChainMissingError` | A `chain_id` in snapshots cannot be located | reject; operational problem |
| `ChainTooShortForSnapshotError` | The chain on disk is shorter than `head_sequence` claims | reject; chain truncated |
| `ChainTamperOrDriftError` | Re-derived `head_record_hash` or `merkle_root` differs from snapshot | reject; chain mutated |
| `ReportContentTamperError` | Recomputed content hash differs from `report_content_hash` | reject |
| `RefusedCertificationError` | `refused_to_certify == True` | reject for action; preserve for audit |
| `RedactedReportStaleError` | Chain extension contains a redaction | reject in BOTH modes; re-issue |
| `StaleReportError` | Strict mode and chain extended without redactions | reject; re-issue or switch to default mode |
| `StalenessFinding(warning)` | Default mode and chain extended without redactions | accept with warning |

Every error carries the `report_id` and the chain_id(s) involved so operators can act without re-deriving them.

---

## 9. Conformance vectors

The v0.6 release ships sealed-report vectors alongside the canonicalization vectors. The vectors load as JSON per the canonicalization-spec format and are checked by `test_sealed_report_conformance_vectors`.

Minimum set:

1. `vector_sealed_report_minimal` -- DSAR over a single source chain at head 0, no redactions, default coverage. Asserts `signing_bytes`, `record_hash`, and `merkle_leaf` of the envelope all match expected hex.
2. `vector_sealed_report_multi_chain` -- Report covering 3 source chains. Asserts snapshot list is sorted by `chain_id` in the canonical form (per the `canonical_dict` rule).
3. `vector_sealed_report_with_disclosure` -- DSAR for a redacted subject; envelope carries one `DSARRedactionDisclosure`. Asserts disclosure list sort by `redaction_id`.
4. `vector_sealed_report_supersedes` -- A re-issued report with `supersedes` populated. Asserts the prior envelope's `record_hash` matches `supersedes`.
5. `vector_sealed_report_refused_certification` -- Envelope with `refused_to_certify=True`. Asserts signature verifies AND the verifier raises `RefusedCertificationError`.
6. `vector_sealed_report_chain_tamper` -- Snapshot present, source chain has been mutated past `head_sequence` of the snapshot's record. Asserts `ChainTamperOrDriftError` is raised at the specific field that differs.
7. `vector_sealed_report_stale_redaction` -- Source chain extended with a redaction after the snapshot. Asserts `RedactedReportStaleError` in BOTH modes.
8. `vector_sealed_report_stale_extension` -- Source chain extended with non-redaction records only. Asserts warning in default mode, `StaleReportError` in strict mode.
9. `vector_sealed_report_key_rotation` -- Envelope signed under `version: 0`, registry has `version: 1` active. Asserts envelope still verifies because `generated_at` falls in `version: 0`'s validity window.
10. `vector_sealed_report_cross_tenant` -- Envelope's `tenant_id` differs from the resolved key's `tenant_id`. Asserts `CrossTenantSigningError`.

---

## 10. What this spec does not cover

- The schemas of report content (DSAR rows, governance summaries, RoPA records). Those live in the four-pillar design doc; the sealed-report protocol only requires that `report_content_hash` is computed via the canonicalization spec's `canonical_dict` on a model that defines that hook.
- Per-subject envelope encryption. Phase 2 extends the canonicalization spec's Merkle-over-canonical-serialized-form rule into the encrypted-subject-fields regime; sealed reports verify identically across the transition because the canonicalization layer is the only thing they depend on.
- Storage paths, replication, and backup of the reports chain. Operational, not protocol.
- Signing-key custody (HSM, KMS, software keystore). Implementation-defined; the protocol only requires that `TenantGovernanceSigner.ed25519_sign` produces an Ed25519 signature under a key whose public component matches `signing_key_fingerprint` in the registry.

The single rule to carry out of this document: **a sealed report is an AgDRRecord whose canonical form, hash, and signature all go through the canonicalization spec. Verification re-derives everything from the chain plus the key registry. There are no out-of-band trust assumptions other than the initial key ceremony.**

This closes the four-document arc. Each spec now references the others by name rather than restating rules. The canonicalization spec is the floor; the redaction execution spec, the sealed-report verification spec, and the four-pillar design all sit on top of it.
