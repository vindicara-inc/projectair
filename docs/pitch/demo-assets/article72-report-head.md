# EU AI Act Article 72 Post-Market Monitoring Report

**System:** Sales Assistant v2
**System ID:** `sales-agent-v2`
**Provider / Operator:** Acme Corp
**Reporting period:** 2026-Q2
**Report generated:** 2026-04-23T06:56:17.784212Z
**Source log:** `/private/tmp/air-demo/air-demo.log`
**Project AIR version:** 0.3.0

> **INFORMATIONAL TEMPLATE, NOT LEGAL ADVICE.** This report is a populated template generated from a Project AIR signed forensic chain. It is intended as a starting point for Article 72 post-market monitoring evidence, not a filed compliance artefact. The provider must review the contents, adapt them to their high-risk AI system context, incorporate deployer-contributed data per Article 72(2), have a qualified person execute the attestation, and consult counsel qualified in the applicable jurisdiction before relying on this document as evidence of Article 72 compliance or for any filing under Article 73 (reporting of serious incidents).

---

## 1. Executive Summary

This report documents the post-market monitoring activity for the above-identified high-risk AI system over the stated reporting period, collected from a signed Intent Capsule chain produced by Project AIR (BLAKE3 content hashing + Ed25519 signatures + forward hash chain). See `vindicara.io/admissibility` for the cryptographic architecture and its mapping to evidentiary frameworks.

- **Records analysed:** 47
- **Conversations / sessions:** 1
- **Observed time range:** 2026-04-23T06:46:58.038887Z to 2026-04-23T06:46:58.042765Z (UTC)
- **Chain integrity:** OK
- **Records cryptographically verified:** 47
- **Unique signing keys observed:** 2
- **Total findings:** 33
- **Findings of critical severity:** 12
- **Findings of high severity:** 18
- **Findings of medium severity:** 3

---

## 2. System Identification (Article 11 Annex IV)

| Field | Value |
|---|---|
| System identifier | `sales-agent-v2` |
| System name | Sales Assistant v2 |
| Provider / Operator | Acme Corp |
| Monitoring period | 2026-Q2 |
| Monitoring system | Project AIR signed Intent Capsule chain (AgDR format v0.2) |
| Log file (chain source) | `/private/tmp/air-demo/air-demo.log` |
| Signing keys (Ed25519 public keys, hex) | `4843c9f0d47e82da...`, `7ea9ab2f2307a6d2...` |

---

## 3. Monitoring Methodology

Every agent action (LLM call, tool invocation, inter-agent message, final output) produces an append-only signed record. Each record is content-hashed with BLAKE3 and signed with Ed25519 (RFC 8032); the signature binds the record to the previous record's hash, producing a forward-chained audit log in which any alteration, insertion, deletion, or reordering is detected deterministically by replay. The open-source verifier `air trace` reproduces the verification offline using only the log file and the signer's public key. Detector coverage spans the OWASP Top 10 for Agentic Applications (10 of 10 in v0.3.0), three OWASP Top 10 for LLM Applications categories (prompt injection, sensitive data exposure, unrestricted resource consumption), and one AIR-native chain-integrity check.

---

## 4. Chain-Integrity Attestation

- **Verification status:** `ok`
- **Records verified:** 47

The chain verified cleanly. Every record's BLAKE3 content hash was recomputed from its canonicalised payload and matched; every record's Ed25519 signature verified against its declared public key; and every record's `prev_hash` matched the previous record's content hash. The forensic chain is tamper-evident and has not been altered since production.

---

## 5. Detector Findings Summary

| Detector | Count |
|---|---|
| `AIR-01` | 1 |
| `AIR-02` | 1 |
| `AIR-03` | 1 |
| `AIR-04` | 1 |
| `ASI01` | 3 |
| `ASI02` | 1 |
| `ASI03` | 7 |
| `ASI04` | 1 |
| `ASI05` | 2 |
| `ASI06` | 1 |
| `ASI07` | 5 |
| `ASI08` | 1 |
| `ASI09` | 1 |
| `ASI10` | 7 |

---

## 6. Serious-Incident Candidates (Article 73 cross-reference)

Under Article 3(49), a 'serious incident' is an incident or malfunctioning of an AI system that directly or indirectly leads to death or serious health harm, irreversible disruption of critical infrastructure, infringement of fundamental-rights obligations, or serious harm to property or the environment. Article 73 requires providers to report such incidents to the market surveillance authority within the deadlines set out in Article 73(2)-(4).

**The findings below are candidates for Article 73 classification, not automatic serious incidents.** Severity 'critical' indicates a high-risk pattern detected in the chain; the provider must assess each finding against the Article 3(49) criteria to determine whether it constitutes a serious incident, a malfunction, or a detected-and-mitigated deviation.

| Step | Timestamp (UTC) | Detector | Severity | Description |
|---|---|---|---|---|
| 39 | 2026-04-23T06:46:58.042151Z | ASI02 | critical | Tool `shell_exec` invoked with arguments matching pattern: shell metacharacters. |
| 8 | 2026-04-23T06:46:58.039786Z | ASI03 | critical | Agent `sales-agent-v1` (tier 1) invoked tool `admin_delete_records`, which requires tier 3. Privilege escalation via delegated task (OWASP ASI03 example #3). |
| 17 | 2026-04-23T06:46:58.040509Z | ASI03 | critical | Agent `sales-agent-v1` (tier 1) invoked tool `wire_transfer`, which requires tier 3. Privilege escalation via delegated task (OWASP ASI03 example #3). |
| 39 | 2026-04-23T06:46:58.042151Z | ASI03 | critical | Agent `sales-agent-v1` (tier 1) invoked tool `shell_exec`, which requires tier 3. Privilege escalation via delegated task (OWASP ASI03 example #3). |
| 11 | 2026-04-23T06:46:58.040011Z | AIR-02 | critical | Sensitive pattern `AWS access key` detected in tool_end.tool_output. Review for unintended credential or PII leakage. |
| 14 | 2026-04-23T06:46:58.040288Z | ASI05 | critical | Tool `python_eval` matches the `python/code eval` execution-semantics pattern. Verify the tool runs in a sandboxed, least-privilege environment and that its inputs are validated (OWASP ASI05 mitigation #3/#4/#5). |
| 42 | 2026-04-23T06:46:58.042454Z | ASI07 | critical | Agent `alpha` previously signed with key 4843c9f0d47e82da..., but this message is signed with 7ea9ab2f2307a6d2... Possible A2A descriptor forgery or agent impersonation (OWASP ASI07 example #5). |
| 43 | 2026-04-23T06:46:58.042532Z | ASI07 | critical | Agent `alpha` previously signed with key 4843c9f0d47e82da..., but this message is signed with 7ea9ab2f2307a6d2... Possible A2A descriptor forgery or agent impersonation (OWASP ASI07 example #5). |
| 44 | 2026-04-23T06:46:58.042611Z | ASI07 | critical | Agent `alpha` previously signed with key 4843c9f0d47e82da..., but this message is signed with 7ea9ab2f2307a6d2... Possible A2A descriptor forgery or agent impersonation (OWASP ASI07 example #5). |
| 45 | 2026-04-23T06:46:58.042688Z | ASI07 | critical | Agent `alpha` previously signed with key 4843c9f0d47e82da..., but this message is signed with 7ea9ab2f2307a6d2... Possible A2A descriptor forgery or agent impersonation (OWASP ASI07 example #5). |
| 46 | 2026-04-23T06:46:58.042765Z | ASI07 | critical | Agent `alpha` previously signed with key 4843c9f0d47e82da..., but this message is signed with 7ea9ab2f2307a6d2... Possible A2A descriptor forgery or agent impersonation (OWASP ASI07 example #5). |
