# AgDR Record-Level Canonicalization & Merkle Spec

Date: 2026-05-18
Revision: 2 (folds in the eight-item canonicalization review)
Status: Draft, paste-ready
Scope: AgDR v0.6, `airsdk` (OSS) and `airsdk_pro` (Pro)
Supersedes: revision 1 of this document.

---

## 0. Why this document exists

Three separate specs (sealed reports, redaction execution, and AgDR records
themselves) each independently described "canonicalize, then hash." Each
phrased the rules slightly differently. That divergence is an
interoperability bug: two implementations that each believe they follow their
own spec produce hashes that fail each other's verification, and the failure
only appears at the legal/SOC/insurance handoff boundary the product exists
to serve.

This document is the **single source of truth** for canonicalization and
hashing in AgDR v0.6. The sealed-report spec and the redaction spec MUST
reference the functions defined here rather than restating the rules. If a
rule needs to change, it changes here, once.

Three things are locked:

1. **One canonicalization function**, `canonicalize(obj) -> bytes`, used for
   every signed or hashed structure in the system.
2. **Every record reaches that function through its own `canonical_dict()`
   method.** Order-independent fields (signature lists) are sorted inside
   `canonical_dict()`, the one correct sort location. See section 3.
3. **The Merkle leaf is computed over the canonical serialized form of the
   record as it appears in the chain file.** v0.6: plaintext. Phase 2:
   ciphertext blobs for subject-bearing fields. The hash function and the
   leaf-construction rule are identical across versions. This keeps
   crypto-shredding non-destructive to Merkle roots. See section 4.

---

## 1. The canonicalization function

### 1.1 Definition

```python
from typing import Any
import rfc8785   # pinned; see 1.4

def canonicalize(obj: Any) -> bytes:
    """The single canonicalization function for all of AgDR v0.6.

    Accepts any JSON-compatible input (dict, list, scalar). RFC 8785 admits
    any JSON value as a canonical-form root; the type hint is `Any`
    deliberately so list-rooted inputs (possible in Phase 2) are not ruled
    out.

    Input MUST already have all None-valued dict keys removed (see
    canonical_dump / _strip_none). This function does not strip None itself;
    it assumes a clean structure and applies RFC 8785 JCS.

    Returns UTF-8 bytes, no BOM, no trailing newline.
    """
    return rfc8785.dumps(obj)


def canonical_dump(model: BaseModel, *, exclude: set[str] | None = None) -> dict:
    """Produces the clean JSON-compatible dict that `canonicalize` expects.

    - Serializes via Pydantic mode="json" so enums, datetimes, etc. become
      their wire forms.
    - Removes every dict key whose value is None, recursively.
    - Does NOT remove empty containers.
    - Does NOT drop None elements that appear inside lists (see rule 9).
    - `exclude` removes named top-level keys BEFORE serialization (used to
      drop a signature-bearing field from a signing payload).

    NOTE: most callers do not call this directly. They call the model's
    `canonical_dict()` method (section 3), which calls this and then applies
    any deterministic-ordering rules. `canonical_dump` is the unordered base.
    """
    raw = model.model_dump(mode="json", exclude=exclude or set())
    return _strip_none(raw)


def _strip_none(value: Any) -> Any:
    """Recursively removes None-valued KEYS from dicts.

    Lists preserve all elements, including None (which `canonicalize` then
    encodes as JSON null). Empty containers are preserved.
    """
    if isinstance(value, dict):
        return {k: _strip_none(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [_strip_none(v) for v in value]   # None elements pass through unchanged
    return value
```

### 1.2 The rules, stated normatively

Any implementation in any language MUST produce identical bytes by following
these rules. They are not Python-specific.

1. **Encoding.** UTF-8, no byte-order mark, no trailing newline.
2. **Object keys.** Sorted lexicographically by Unicode codepoint, per
   RFC 8785.
3. **Whitespace.** None between tokens.
4. **Numbers.** Per RFC 8785 section 3.2.2.3: integers exact, floats
   normalized to shortest round-tripping form. Integer fields MUST fit in
   53 bits of precision (the exact-integer range of an IEEE-754 double, so
   JSON consumers in any language agree). Implementations using 64-bit
   integers MUST validate at write time that no integer field exceeds
   2^53 - 1.
5. **Strings.** Escaped per RFC 8259; literal Unicode where the standard
   permits.
6. **Arrays.** Insertion order preserved. Callers that need order
   independence (e.g. signature lists) MUST sort the list inside the model's
   `canonical_dict()` override (section 3), not here.
7. **None omission applies to dict KEYS only.** A dict key whose value is
   `None` is omitted entirely. It is NOT encoded as `"key":null`. This
   applies recursively at every dict depth.
8. **Empty containers are NOT omitted.** `[]`, `{}`, and `""` are encoded as
   themselves. Only `None` triggers omission. An empty list and a missing
   key are distinguishable, and that distinction is meaningful.
9. **None inside a list is preserved.** A `None` appearing as a list
   *element* (not a dict value) is kept and encoded as JSON `null`.
   `[1, None, 2]` canonicalizes to bytes containing `[1,null,2]`, never
   `[1,2]`. Rule 7 governs dict keys only; it does not reach into lists.
10. **Timestamps.** Every timestamp string in a canonicalized structure MUST
    be in the canonical timestamp form defined in 1.5. This is enforced at
    model construction, so by the time canonicalization runs, all timestamps
    are already normalized.

Rules 7 and 9 together bound the single deviation from strict JCS: only a
dict key with a `None` value is omitted; `None` anywhere else (a list
element) encodes as `null`. Rule 8 bounds it further: emptiness is never
omission.

The reason rule 7 exists: Pydantic models carry many `Optional` fields that
default to `None`. Encoding all of them as explicit `null` would make every
hash sensitive to the mere *addition* of a new optional field, even one no
record ever populates. Omitting `None` keys means a new optional field is
invisible to existing record hashes (section 5 relies on this).

### 1.3 Forbidden shortcuts

Implementations MUST NOT use `json.dumps(..., sort_keys=True)` as a
substitute for `canonicalize`. It does not normalize floats and does not
handle Unicode escapes per RFC 8785. It agrees with `canonicalize` on simple
inputs and diverges on floats and certain strings -- the worst failure
profile: passes in testing, breaks in production. Use the pinned `rfc8785`
library only.

Implementations MUST NOT rely on Pydantic's `exclude_none=True` to perform
None-stripping for a hash input. `exclude_none` is library behavior, not a
spec, and it has subtly differed across Pydantic versions; in some versions
it also strips `None` list elements, violating rule 9. None-stripping is
performed by the spec-defined `_strip_none`. The `exclude` argument
(named-field removal) is fine; `exclude_none` is not.

### 1.4 Dependency pinning and the version-bump protocol

`rfc8785` is pinned to an exact version in both `airsdk` and `airsdk_pro`
dependency manifests. A canonicalization library is a consensus dependency:
every party that verifies must canonicalize identically.

The version-bump protocol is explicit:

- A bump is **evaluated** by vendoring the new `rfc8785` and running the
  full section 6 conformance vector suite.
- A bump that reproduces **every** vector identically is safe. It may
  proceed as an ordinary patch release.
- A bump that produces **different bytes for any vector** is a
  chain-breaking event (section 5). It MUST trigger a schema version bump
  and be released as a coordinated `airsdk` + `airsdk_pro` major release
  with a documented migration path.
- The process, in one line: vendor the new version, run conformance,
  decide. The conformance vectors are the gate; there is no other way to
  detect an output-changing bump.

### 1.5 Canonical timestamp form

RFC 3339 admits multiple valid spellings of the same instant
(`...Z`, `...000Z`, `...000000Z`, `...+00:00`). Pydantic's `mode="json"`
emits different spellings depending on whether the source `datetime` carries
microseconds. Two implementations writing the same logical instant would
otherwise produce different canonical bytes and different `record_hash`.

The canonical timestamp form is locked: exactly
`YYYY-MM-DDTHH:MM:SS.ffffffZ` -- UTC, microsecond precision, `Z` suffix,
always 27 characters.

- Lower-precision inputs are right-padded with zeros to microseconds.
- Higher-precision inputs are **truncated**, not rounded, to microseconds.
- Timezone offsets other than `Z` are **rejected at write time**.
- Naive datetimes (no timezone) are **rejected**.

```python
from datetime import datetime

def canonical_timestamp(ts: datetime | str) -> str:
    """Normalize a datetime or RFC 3339 string to the AgDR canonical form.
    Always 27 characters: YYYY-MM-DDTHH:MM:SS.ffffffZ."""
    if isinstance(ts, str):
        ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    if ts.tzinfo is None:
        raise ValueError("Naive datetime; specify UTC explicitly.")
    if ts.utcoffset().total_seconds() != 0:
        raise ValueError("Non-UTC timestamps not permitted in canonical form.")
    return ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
```

Every on-disk timestamp field MUST be normalized via `canonical_timestamp`
before it enters a model that will be canonicalized. `AgDRRecord`
(section 3.1) enforces this with a field validator, so a non-canonical
timestamp cannot survive model construction.

---

## 2. Record hashing

### 2.1 Per-record hash

```python
import hashlib

def record_hash(record: "AgDRRecord") -> str:
    """SHA-256 over the canonical serialized form of a full AgDR record.
    Hex-encoded, lowercase. Always routes through record.canonical_dict()."""
    return hashlib.sha256(canonicalize(record.canonical_dict())).hexdigest()
```

The hash covers the **entire** record including its `prev_record_hash`
field. For record `sequence > 0`, `prev_record_hash == record_hash` of the
record at `sequence - 1`. For `sequence == 0`, `prev_record_hash == ""`
(empty string, present and empty per rule 8, not `None`). This forms the
per-chain hash chain.

### 2.2 On-disk model and in-memory index model are distinct types

`record.canonical_dict()` serializes the persisted fields of the on-disk
AgDR record. It MUST NOT see indexer-populated fields (`redacted`,
`redaction_markers`, `partial_redaction_markers`, and any other
`GovernanceIndex`-side enrichment).

Implementations MUST keep on-disk record models and in-memory index models as
**distinct types**. Indexer fields MUST NOT be declared on the on-disk model.
If they share one class, `model_dump` includes them and the
"not part of the hash" intent collapses into "every caller must remember an
`exclude={...}` set" -- exactly the fragility that produces divergent
implementations.

The mandated pattern:

```python
# On-disk model: hashed, signed, persisted. The base for record_hash.
class DataAccessRecord(AgDRRecord):
    record_type: Literal["data_access"] = "data_access"
    # ... on-disk fields only ...

# In-memory model: enriched by the indexer; NEVER hashed.
class IndexedDataAccessRecord(DataAccessRecord):
    redacted: bool = False
    redaction_markers: list[str] = []
    partial_redaction_markers: list[str] = []
```

`record_hash` and `merkle_leaf` accept `AgDRRecord` (the on-disk base). An
`IndexedDataAccessRecord` reaching either is a bug. Implementations MUST
enforce this -- either at the type-system level (mypy strict; the index type
is simply not an `AgDRRecord` in the nominal hierarchy if you prefer
composition over the subclassing shown above), or with a runtime
`isinstance` / type-tag guard inside `record_hash` and `merkle_leaf` that
rejects any index type. The structural guarantee behind index-only redaction
depends on index fields being unable to enter a hash; that guarantee must be
enforced, not assumed.

(Note: the example above uses subclassing for brevity. Subclassing means
`isinstance(indexed, DataAccessRecord)` is true, so a runtime guard cannot
key on `isinstance` alone -- it must check the exact type or a type tag.
Implementations that want an `isinstance`-based guard should use composition
instead: `IndexedDataAccessRecord` *wraps* a `DataAccessRecord` rather than
extending it. Either is conformant; pick one and state it in code.)

---

## 3. The model base, the canonical-dict hook, and signing

### 3.1 `AgDRBase` and `AgDRRecord`

```python
from typing import Literal
from pydantic import BaseModel, ConfigDict, field_validator

class AgDRBase(BaseModel):
    """Base for every AgDR model (records, sealed-report payloads, etc.).
    Provides the single canonical-dict hook."""
    model_config = ConfigDict(extra="forbid")

    def canonical_dict(self) -> dict:
        """The dict that goes to `canonicalize`. Subclasses override to
        apply deterministic ordering for fields whose insertion order is not
        meaningful (e.g. signature lists). The default returns
        `canonical_dump(self)` unchanged."""
        return canonical_dump(self)


class AgDRRecord(AgDRBase):
    """The on-disk base for every AgDR record. Subclasses (tool_start,
    tool_end, llm_start, llm_end, session_init, handoff, redaction, ...) add
    type-specific fields. They MUST NOT redeclare the fields below."""
    schema_version: Literal["0.6"]
    record_type: str          # discriminator: "tool_start" | "tool_end" | ...
    sequence: int             # 0-indexed position in the chain
    chain_id: str             # the chain this record belongs to
    tenant_id: str            # required; "default" for single-tenant deployments
    timestamp: str            # canonical_timestamp form; enforced by validator below
    prev_record_hash: str     # record_hash of record[sequence-1]; "" when sequence == 0

    @field_validator("timestamp", mode="before")
    @classmethod
    def _canonical_ts(cls, v):
        return canonical_timestamp(v)
```

`AgDRRecord` is the load-bearing parent for every record subclass. Subclass
specs reference it; they do not redefine `prev_record_hash`, `sequence`,
`tenant_id`, or `timestamp` independently. Defining them once here is what
keeps the subclass specs from drifting.

### 3.2 The sort point is `canonical_dict()`, and only there

For any field whose list order is not semantically meaningful (the canonical
case: a `signatures` list), the deterministic sort lives in the model's
`canonical_dict()` override. Not in a Pydantic validator. Not inline at the
hashing call site.

```python
class AgDRRedactionRecord(AgDRRecord):
    record_type: Literal["redaction"] = "redaction"
    # ... fields, including: signatures: list[RedactionOfficerSignature] ...

    def canonical_dict(self) -> dict:
        raw = canonical_dump(self)
        raw["signatures"] = sorted(
            raw["signatures"], key=lambda s: s["officer_id"]
        )
        return raw
```

Normative statement:

> The sort point for any order-independent list is the model's
> `canonical_dict()` override. A sort applied only in a Pydantic validator
> (at construction) is insufficient: it does not survive post-construction
> mutation of the list. A sort applied only inline at a hashing call site is
> insufficient: it relies on every caller remembering. `canonical_dict()` is
> the one correct location, because `record_hash` and `merkle_leaf` both
> route through it unconditionally. A construction-time validator that also
> sorts is permitted as belt-and-suspenders, but MUST NOT be the only sort.

### 3.3 Signing payloads exclude the signature field

```python
def signing_bytes(model: AgDRBase, *, exclude_fields: set[str]) -> bytes:
    """Canonical bytes a signer signs. The signature-bearing field(s) named
    in `exclude_fields` are EXCLUDED from the payload, not set to empty.

    Routes through canonical_dump with `exclude` (NOT through the model's
    canonical_dict, because the excluded field is removed before any
    ordering rule would apply to it)."""
    return canonicalize(canonical_dump(model, exclude=exclude_fields))
```

(`exclude_fields`, renamed from the earlier `exclude_signatures`: the
argument removes the signature-*bearing field*, e.g. the whole `signatures`
list, not specific signatures from within a list.)

The signature field is **excluded entirely** from the signing payload, never
set to `[]` or `""`. Excluded and empty produce different canonical bytes
(`{"foo":1}` vs `{"foo":1,"signatures":[]}`). An implementation that empties
instead of excludes produces signatures that fail a conforming verifier. This
is normative: signature-bearing fields are EXCLUDED.

### 3.4 Multi-signer payloads sign identical bytes

When a structure carries multiple signatures:

- Every signer signs the **same** bytes:
  `signing_bytes(record, exclude_fields={"signatures"})`. Signing is
  order-independent; no signature depends on another.
- `signing_bytes` is computed **once** per structure and reused for every
  signer's verification -- not recomputed per signature.
- After all signatures are collected and placed on the record, the
  `signatures` list is sorted by `officer_id` **inside `canonical_dict()`**
  (section 3.2), so the record's own `record_hash` and Merkle leaf are
  deterministic regardless of the order signatures were gathered in.

### 3.5 Verification reconstructs by exclusion

A verifier checks a signature by reconstructing
`signing_bytes(record, exclude_fields={...})` -- omitting the signature field,
not setting it empty -- and verifying the Ed25519 signature against the
registered public key. The reconstruction MUST use the same `exclude_fields`
set the signer used. Any verifier description that says "set signatures to
`[]`" is wrong; the correct phrasing is "exclude the signatures field."

---

## 4. The Merkle tree

### 4.1 Domain separation (LOCKED)

A one-byte domain prefix is prepended before hashing, so a leaf digest can
never be reinterpreted as an internal-node digest (a known second-preimage
class of Merkle attack):

```python
LEAF_PREFIX     = b"\x00"
INTERNAL_PREFIX = b"\x01"
```

This makes `record_hash` (section 2.1: hex, no prefix, used for the linear
`prev_record_hash` chain) and the Merkle leaf digest (prefixed, raw bytes)
deliberately **different values** for the same record. They serve different
purposes -- `prev_record_hash` is the linear hash chain, the Merkle leaf is
the tree -- and keeping them distinct via the prefix is intentional, not an
inconsistency. A `ChainHeadSnapshot` carries both; the verifier checks each
on its own terms.

### 4.2 Leaf and internal-node construction

```python
def merkle_leaf(record: AgDRRecord) -> bytes:
    """A Merkle leaf: SHA-256 of LEAF_PREFIX followed by the record's
    canonical serialized form. Routes through canonical_dict()."""
    return hashlib.sha256(
        LEAF_PREFIX + canonicalize(record.canonical_dict())
    ).digest()


def merkle_internal(left: bytes, right: bytes) -> bytes:
    """An internal node: SHA-256 of INTERNAL_PREFIX followed by the raw
    concatenation of the two 32-byte child digests."""
    return hashlib.sha256(INTERNAL_PREFIX + left + right).digest()
```

The leaf is computed over the canonical serialized form of the record **as
it appears in the chain file**. This is the load-bearing sentence:

- **v0.6**: every field is plaintext. The canonical form is plaintext.
- **Phase 2**: subject-bearing fields are persisted as ciphertext blobs.
  The canonical form contains those ciphertext blobs.
- The hash function, `canonicalize`, the domain prefixes, and the
  leaf-construction rule are **identical** across versions. Only the
  *contents* of the fields differ.

### 4.3 Why this rule, and the consequence

This is the Merkle-over-canonical-serialized-form decision, locked now in
v0.6 even though Phase 2 is unbuilt, because v0.6 records are hashed today
and a later rule change would retroactively invalidate every v0.6 sealed
report.

Consequence: in Phase 2, crypto-shredding destroys a per-subject data
encryption key. That makes the plaintext of subject-bearing fields
permanently unrecoverable. It does NOT change the ciphertext blob on disk,
therefore does NOT change the canonical serialized form, therefore does NOT
change the Merkle leaf or any root over it. **Sealed reports issued before a
crypto-shred continue to verify after it.** That is the entire reason the
rule is "over canonical serialized form," not "over plaintext field values."

### 4.4 Tree construction -- reference algorithm (LOCKED)

Prose describing the odd-level rule was ambiguous for a chain of length 1.
The reference algorithm is normative; it removes the ambiguity:

```python
def merkle_root(records: list[AgDRRecord]) -> bytes:
    """Merkle root over an ordered chain of records (record 0 first).

    A single-record tree's root IS that record's leaf -- domain separation
    already applied, no duplication. Duplication of the last node applies
    ONLY inside the loop, i.e. only at a level of 2+ nodes with an odd count.
    """
    if not records:
        raise ValueError("Merkle tree over zero records is undefined")
    nodes = [merkle_leaf(r) for r in records]
    while len(nodes) > 1:
        if len(nodes) % 2 == 1:
            nodes.append(nodes[-1])          # duplicate the last node
        nodes = [
            merkle_internal(nodes[i], nodes[i + 1])
            for i in range(0, len(nodes), 2)
        ]
    return nodes[0]
```

Normative statements:

> 1. A Merkle tree over zero records is undefined. A chain always has at
>    least one record.
> 2. **A single-record tree's root is that record's leaf itself**
>    (`merkle_root([r]) == merkle_leaf(r)`). Duplication does NOT apply at a
>    level of 1. This is the explicit resolution of the prior ambiguity: the
>    root of a one-record chain is `merkle_leaf(r_0)`, NOT
>    `merkle_internal(leaf_0, leaf_0)`.
> 3. Duplication of the last node applies only at a level of 2 or more nodes
>    with an odd count, when pairing into the next level. The
>    `while len(nodes) > 1` guard enforces this: a level of 1 is the root and
>    the loop body never runs.
> 4. An internal node is `merkle_internal(left, right)` over the raw 32-byte
>    child digests, never their hex strings.

### 4.5 The hard requirement on v0.6 implementations

A v0.6 implementation that computes the leaf by hashing raw plaintext field
values directly -- bypassing the `canonical_dict` / `canonicalize` layer --
produces identical roots to a conforming implementation **in v0.6** and
**breaks in Phase 2**, where the conforming implementation hashes
ciphertext-inclusive canonical bytes and the shortcut implementation has no
canonical layer to switch.

This failure is invisible in v0.6 testing. It is caught only by an explicit
conformance test, which is **non-negotiable** for the v0.6 release:

```python
def test_merkle_leaf_goes_through_canonical_layer():
    record = make_reference_v06_record()
    expected = hashlib.sha256(
        LEAF_PREFIX + canonicalize(record.canonical_dict())
    ).digest()
    assert merkle_leaf(record) == expected
```

It is the only thing standing between a shortcut implementation and a
retroactive Phase 2 catastrophe.

---

## 5. Versioning and chain-breaking changes

`schema_version` is `"0.6"`. The canonicalization and Merkle rules are part
of the version contract.

**Chain-breaking** (MUST bump `schema_version`; the bytes a verifier
recomputes change):

- Any change to the canonicalization rules in section 1.2.
- An `rfc8785` version bump that changes output for any conformance vector
  (section 1.4).
- A change to the None-omission rule, the canonical timestamp form, the
  Merkle odd-level rule, the domain-separation prefixes, or the hash
  function.
- The Phase 2 transition to ciphertext-bearing subject fields (a schema bump
  even though the *rules* are unchanged, because field *contents* and the
  write path change).

**Not chain-breaking** (no version bump):

- Adding a new optional field that defaults to `None`. By rule 7 it is
  omitted from the canonical form, so existing record hashes are unaffected.
  This is the entire reason rule 7 exists, and it is verified by
  `vector_optional_field_addition_invariance` (section 6).
- Indexer-side changes. The index is rebuilt from scratch and is never
  hashed.

A verifier MUST refuse to verify a record or report whose `schema_version`
it does not recognize, rather than guessing. Cross-version verification is
not supported in v0.6.

Forward-compatibility note: a future v0.7 implementation MAY opt in to
reading v0.6 chains and reports. The default behavior remains
reject-on-unknown-version; v0.7 reading v0.6 is an explicit opt-in, never
implicit.

---

## 6. Conformance test vectors

The v0.6 release ships a fixed, **machine-readable** vector set so any
implementation in any language can self-check. Prose descriptions are not
sufficient -- "any implementation in any language" has operational meaning
only if the vectors are loadable inputs with expected outputs.

### 6.1 Format

```
packages/projectair/tests/canonical_vectors/
  vector_minimal_record.json
  vector_empty_containers.json
  vector_list_none_preserved.json
  ...
```

Each file:

```json
{
  "name": "vector_minimal_record",
  "schema_version": "0.6",
  "description": "Smallest valid AgDR record, all optional fields None.",
  "input": { "...": "full record as it appears in a chain file" },
  "expected": {
    "canonical_bytes_hex": "...",
    "record_hash": "...",
    "merkle_leaf_hex": "..."
  }
}
```

The conformance test in any language: load the JSON, parse `input` into the
equivalent native model, run that language's `canonicalize` / `record_hash`
/ `merkle_leaf`, hex-encode, compare to `expected`. Reproducing every vector
is the conformance bar.

### 6.2 Minimum vector set

1. `vector_minimal_record` -- smallest valid record, all optional fields
   `None`. Confirms None-key omission (rule 7).
2. `vector_empty_containers` -- explicit empty list and empty string fields.
   Confirms empty containers are NOT omitted and ARE distinguishable from
   `None` (rule 8).
3. `vector_list_none_preserved` -- a list field holding `[1, None, 2]`.
   Confirms the canonical bytes contain `[1,null,2]`, not `[1,2]` (rule 9).
4. `vector_float_normalization` -- a float that naive `json.dumps` serializes
   differently from RFC 8785. Confirms forbidden-shortcut implementations
   fail (rule 4 / section 1.3).
5. `vector_unicode_string` -- a string requiring RFC 8785 Unicode handling.
   Confirms escaping (rule 5).
6. `vector_timestamp_normalization` -- three timestamp inputs representing
   the same instant in different RFC 3339 spellings (`...Z`, `...000Z`,
   `+00:00`) all produce identical canonical bytes (section 1.5).
7. `vector_optional_field_addition_invariance` -- two records identical
   except one comes from a schema with an extra optional `None`-defaulted
   field; both produce identical canonical bytes. Catches the
   "helpfully emitting `:null`" failure (section 5).
8. `vector_redaction_signing_payload` -- an `AgDRRedactionRecord` with the
   expected `signing_bytes` (signatures field excluded) AND the expected
   `record_hash` (signatures sorted, included). Confirms section 3.
9. `vector_signature_order_independence` -- the same redaction record with
   `signatures` supplied in two different orders; both yield identical
   `record_hash`. Confirms 3.2 / 3.4.
10. `vector_merkle_single` -- a one-record chain. Asserts
    `merkle_root == merkle_leaf(record_0)`, explicitly NOT
    `merkle_internal(leaf_0, leaf_0)`. Binds the section 4.4 resolution.
11. `vector_merkle_odd` -- a three-record chain. Expected root confirms the
    duplicate-the-last odd-level rule.
12. `vector_merkle_domain_separation` -- confirms a leaf digest and an
    internal-node digest over the same underlying bytes differ (the prefixes
    are applied).

Every vector is checked by `test_conformance_vectors` in both `airsdk` and
`airsdk_pro`. A second implementation in another language is conformant if
and only if it reproduces all twelve.

---

## 7. What this spec deliberately does not cover

- The sealed-report payload schema and verification protocol. That lives in
  the sealed-report spec, which references this document for `canonicalize`,
  `signing_bytes`, `record_hash`, and the Merkle functions instead of
  restating them.
- The redaction record schema and `apply_redactions`. That lives in the
  redaction-execution spec, which references section 3 here for signature
  canonicalization.
- Per-subject envelope encryption, key management, and crypto-shred. Phase
  2. This document only locks the Merkle rule (section 4) so Phase 2 is
  buildable without retroactively breaking v0.6.

The single rule to carry out of this document: **there is one
`canonicalize`, every record reaches it through `canonical_dict()`, and the
Merkle leaf is computed over the canonical serialized form -- never over raw
field values.** Every other spec defers to that.
