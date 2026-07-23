# Part 11 / Annex 11 Controls Gap Assessment — Project AIR

**Readiness: beta. Supplier technical-controls assessment, not a validation deliverable.**

## What this is, and is not

This is a factual assessment of which **21 CFR Part 11** and **EU GMP Annex 11**
technical controls Project AIR provides, which require configuration or code, and
which are the customer's procedural responsibility. It exists so a regulated buyer
can scope a validation effort.

This is **not** validation. Validation (CSV / GAMP 5) is a process the regulated
entity executes for a **specific intended use** in **their** environment under
**their** quality management system, producing executed evidence signed by
qualified people. AIR is a component a customer validates; AIR cannot be "validated"
in the abstract, and no document here is qualification evidence. Nothing in this
file may be presented as an executed IQ/OQ/PQ or a validation summary report.

**GAMP category (indicative):** AIR SDK is a configurable product, so a deployment
is most likely **Category 4** (configured). Customer-authored detector scopes,
registries, and containment policies can push specific uses toward **Category 5**
(custom) for those parts. The customer confirms the category for their intended use.

Status legend: **Provided** (AIR supplies the control) · **Partial** (AIR supplies
part; customer configuration or additional code needed) · **Gap** (not yet in AIR;
tracked for the control-code sprint) · **Procedural** (customer or vendor process,
not a software control).

## 21 CFR Part 11 Subpart B — Electronic Records

| § | Requirement (paraphrased) | AIR control | Status |
|---|---|---|---|
| 11.10(a) | Validation; ability to discern invalid or altered records | `verify_chain` detects any altered record (BLAKE3 content hash + Ed25519/ML-DSA signature over prev_hash ‖ content_hash ‖ metadata). Tamper is cryptographically evident. System *validation* itself is the customer's. | Provided (detection) / Procedural (validation) |
| 11.10(b) | Accurate, complete copies in human-readable and electronic form for inspection | `air trace`, `air explain`, and `export_json` / `export_pdf` / `export_siem`. | Partial (add a defined "inspection copy" export profile) |
| 11.10(c) | Protection for accurate, ready retrieval over the retention period | `FileTransport` fsyncs each record; Layer 1 anchoring proves existence over time. Retention storage, backup, and archival are customer infrastructure. | Partial |
| 11.10(d) | Limit system access to authorized individuals | Layer 3 authority checks (IdP-verified) gate step-up actions. There is no role-based access model for read/verify/export. | Gap (RBAC + unique-user attribution) |
| 11.10(e) | Secure, computer-generated, time-stamped audit trail; changes do not obscure prior records; retained for review | **Core strength.** The chain *is* a computer-generated, per-record-timestamped, append-only audit trail; append-only means a change never obscures prior entries; Layer 1 (RFC 3161 + Sigstore Rekor) supplies trusted, non-repudiable time; the trail verifies offline. Missing: an explicit **reason-for-change** on operator-initiated modifications and a **trail-review** attestation record. | Partial (strong; two gaps) |
| 11.10(f) | Operational checks enforcing permitted step sequencing | `prev_hash` chain enforces immutable ordering; containment policy gates tool actions. | Partial |
| 11.10(g) | Authority checks: only authorized individuals use the system, sign, access | Layer 3 IdP-verified approval binds an authorized human to a halted action. No general authority/role model. | Partial → Gap (RBAC) |
| 11.10(h) | Device checks validating the source of data input | Agent registry (Zero-Trust identity) + GPU attestation (hardware root of trust, experimental) establish input source. | Partial |
| 11.10(i) | Personnel education, training, experience | — | Procedural |
| 11.10(j) | Written accountability policy for signature use | — | Procedural |
| 11.10(k) | Controls over systems documentation and change control | Vendor SDLC + customer document control. | Procedural (feeds supplier qualification) |
| 11.30 | Open-system additional controls (encryption, digital signatures) | Ed25519 / ML-DSA-65 signatures and BLAKE3 hashing protect record authenticity and integrity end to end. | Provided |
| 11.50 | Signature manifestation: printed name, date/time, and **meaning** of the signature | `HUMAN_APPROVAL` records the verified signer (`approver_sub` / `approver_email`), signing time (`issued_at`), and the decision. It does **not** carry the §11.50 **meaning** (review / approval / responsibility / authorship) or a defined human-readable manifestation. | Gap (control-code sprint, item B1) |
| 11.70 | Signature/record linking to prevent copy or transfer to falsify | `HUMAN_APPROVAL` is a record inside the signed chain, bound by `prev_hash` to the exact halted action; it cannot be excised or moved without breaking verification. | Provided |

## 21 CFR Part 11 Subpart C — Electronic Signatures

| § | Requirement | AIR control | Status |
|---|---|---|---|
| 11.100 | Each signature unique to one individual; identity verified before assignment | Identity is asserted by the customer's IdP (OIDC); AIR records the verified claims. Uniqueness and identity-proofing are the IdP's responsibility. | Partial (IdP-dependent) |
| 11.200 | Signature components and controls (e.g., two distinct components; genuine-owner controls) | The authentication ceremony (factors, re-auth on a series) is performed by the IdP; AIR verifies and records the resulting token. AIR does not itself enforce the two-component ceremony. | Partial (IdP-dependent) |
| 11.300 | Controls over ID codes / passwords | IdP + customer procedure. | Procedural |

## EU Annex 11 (condensed; overlaps Part 11 above)

| Clause | Theme | AIR posture |
|---|---|---|
| 1 | Risk management | Customer performs; AIR provides the risk-relevant controls below. |
| 3 | Suppliers / service providers | Supplier-qualification packet (SDLC, test evidence, change control) — separate deliverable D. |
| 4 | Validation | Customer's, for intended use. AIR supplies validatability. |
| 5 | Data (accuracy checks) | Chain integrity + decision provenance (model, snapshot, fingerprint, sampling params) evidence data faithfulness. |
| 7.1 / 8 | Data storage, printouts, audit trail | See 11.10(b)/(c)/(e). Audit trail is a core strength. |
| 9 | Audit trail review | **Gap:** trail-review attestation record (control-code sprint, item B2). |
| 10 | Change and configuration management | Customer process + vendor change control. |
| 12 | Security | Signatures, hashing, IdP-gated authority; RBAC is the gap. |
| 14 | Electronic signature | See 11.50 / 11.70 / Subpart C. |
| 17 | Archiving | Customer infrastructure; anchoring supports long-term integrity proof. |

## Summary

**Genuine strengths (lead with these).** The audit trail is the standout: computer-
generated, per-record timestamped, cryptographically tamper-evident, append-only so
changes never obscure prior records, given trusted time by an independent public log,
and verifiable offline with no vendor call. That is a stronger §11.10(e) / Annex 11
audit-trail story than most COTS systems. Record-integrity detection (11.10(a)),
signature-record linking (11.70), and open-system cryptographic protection (11.30)
are provided today. Decision provenance strengthens Annex 11 clause 5 data-accuracy
evidence for non-deterministic model steps.

**Ranked gaps for the control-code sprint (B):**
1. **B1 — Part 11 §11.50 e-signature semantics.** Add signature **meaning** and a
   defined manifestation to `HUMAN_APPROVAL`. Highest value, cleanly scoped, builds
   on existing Layer 3. *Closes 11.50; completes the 11.70 story.*
2. **B2 — Audit-trail review + reason-for-change.** A reviewer-attestation record over
   a step range (Annex 11 §9, 11.10(e)) and an optional reason-for-change on operator
   modifications.
3. **B3 — RBAC + unique-user attribution.** A role/authority model for read / verify /
   export / approve (11.10(d),(g), 11.300). Largest effort; recommended as a follow-on,
   not folded into B1/B2.

**Customer / organizational (not buildable by the vendor as a control):** the QMS
(SOPs, CAPA, change control, training records), executed qualification, intended-use
definition, periodic review, and third-party certifications (SOC 2, ISO 9001 / 13485)
that require real audits.

**Bottom line.** AIR is close to being straightforwardly validatable for its audit-
trail and record-integrity role. B1 and B2 close the clearest technical gaps; RBAC
(B3) and the accelerator templates (C) follow. None of this is validation; it is what
makes a customer's validation fast and defensible.
