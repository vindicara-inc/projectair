"""Prose content blocks for the NIST AI RMF report generator.

Separated from ``report_nist_rmf.py`` so the generator stays under the
300-line file limit. These strings are framework-precise; edit with care.

Source: NIST AI 100-1, "Artificial Intelligence Risk Management Framework
(AI RMF 1.0)", January 2023, and the NIST AI RMF Generative AI Profile
(NIST AI 600-1), July 2024. Subcategory identifiers used here follow the
public taxonomy unchanged.
"""
from __future__ import annotations

DISCLAIMER = (
    "**INFORMATIONAL TEMPLATE, NOT LEGAL OR AUDIT ADVICE.** This report is "
    "a populated template generated from a Project AIR signed forensic "
    "chain. It is intended as a starting point for an organization's NIST "
    "AI RMF implementation evidence package, not a NIST-blessed compliance "
    "artefact (NIST does not certify or attest to AI RMF conformance). The "
    "organization must review the contents, adapt them to its AI risk "
    "management context, fill in the GOVERN and MAP sections that depend "
    "on organizational policy and stakeholder input, have a qualified "
    "person execute the attestation, and consult counsel and qualified "
    "auditors before relying on this document for any regulatory, "
    "contractual, or insurance-bearing purpose."
)

METHODOLOGY = (
    "Project AIR records every agent action (LLM call, tool invocation, "
    "inter-agent message, final output, anchor, human approval) as an "
    "append-only signed record. Each record is content-hashed with BLAKE3 "
    "and signed with Ed25519 (RFC 8032); the signature binds the record to "
    "the previous record's hash, producing a forward-chained audit log in "
    "which any alteration, insertion, deletion, or reordering is detected "
    "deterministically by replay. The open-source verifier `air trace` "
    "reproduces the verification offline using only the log file and the "
    "signer's public key. Detector coverage spans the OWASP Top 10 for "
    "Agentic Applications (10 of 10), three OWASP Top 10 for LLM "
    "Applications categories (prompt injection, sensitive data exposure, "
    "unrestricted resource consumption), and one AIR-native chain-integrity "
    "check. The methodology supplies measurable, reproducible evidence to "
    "the AI RMF MEASURE function and feeds GOVERN, MAP, and MANAGE."
)

CHAIN_OK_STATEMENT = (
    "The chain verified cleanly. Every record's BLAKE3 content hash was "
    "recomputed from its canonicalised payload and matched; every record's "
    "Ed25519 signature verified against its declared public key; and every "
    "record's `prev_hash` matched the previous record's content hash. The "
    "forensic chain is tamper-evident and has not been altered since "
    "production. This evidence supports MEASURE 2.7 (security and "
    "resilience) and MEASURE 2.8 (transparency and accountability)."
)

CHAIN_FAIL_STATEMENT = (
    "**Chain verification did not complete successfully.** The log is "
    "either tampered, truncated, or malformed. Investigate before relying "
    "on the records below as evidence. Preserve the original log file for "
    "forensic analysis. A failed chain weakens MEASURE 2.7, MEASURE 2.8, "
    "and MANAGE 4.1 evidence; document the root cause and remediation "
    "before re-running the assessment."
)

GOVERN_PREAMBLE = (
    "The GOVERN function establishes a culture of risk management. Project "
    "AIR provides operational evidence that monitoring infrastructure "
    "exists, runs, and is auditable; the organisational policies, "
    "accountability structures, and workforce decisions that surround it "
    "remain the organisation's responsibility. The subcategories below are "
    "the ones to which AIR's signed-chain evidence directly contributes. "
    "Other GOVERN subcategories require organisational documentation "
    "outside the chain."
)

MAP_PREAMBLE = (
    "The MAP function categorises AI risks in context. AIR's evidence "
    "contributes a runtime view of how the system actually behaves: which "
    "tools were invoked, which inter-agent messages were exchanged, where "
    "the chain anchored to external timestamping, where human approvals "
    "interrupted automated action. Operators should pair this runtime view "
    "with the system-design and stakeholder-impact analyses that complete "
    "the MAP function."
)

MEASURE_PREAMBLE = (
    "The MEASURE function analyses, assesses, benchmarks, and monitors AI "
    "risks. This is where AIR contributes the most evidence: 14 detectors "
    "produce structured findings classified by the OWASP Agentic and LLM "
    "taxonomies; the signed chain provides the audit trail; the verifier "
    "supplies cryptographic attestation that the measurements are "
    "tamper-evident and reproducible offline. The findings tables in this "
    "section feed MEASURE 1, MEASURE 2.7, MEASURE 2.8, and MEASURE 3."
)

MANAGE_PREAMBLE = (
    "The MANAGE function allocates risk-treatment resources. AIR surfaces "
    "the high-priority findings (critical and high severity) that "
    "MANAGE 1.3 requires the organisation to develop responses for. The "
    "corrective-actions table below is the operator-completed record of "
    "those responses. AIR runs continuously in deployment, satisfying "
    "MANAGE 4.1's requirement that post-deployment monitoring plans be "
    "implemented and not merely planned."
)

SUMMARY_PARAGRAPH = (
    "This report documents AI risk-management evidence for the "
    "above-identified system over the stated reporting period, collected "
    "from a signed Intent Capsule chain produced by Project AIR (BLAKE3 "
    "content hashing + Ed25519 signatures + forward hash chain). The "
    "evidence is structured against the four functions of the NIST AI "
    "Risk Management Framework (NIST AI 100-1): GOVERN, MAP, MEASURE, "
    "MANAGE. See `vindicara.io/admissibility` for the cryptographic "
    "architecture and its mapping to evidentiary frameworks."
)

CORRECTIVE_ACTIONS_PREAMBLE = (
    "Under MANAGE 1.3, responses to risks deemed high priority by mapping "
    "or measurement must be developed, planned, and documented. For each "
    "critical- and high-severity finding above, document the corrective "
    "action the operator has taken or plans to take. Examples: tightening "
    "an agent's permitted_tools list, rotating a compromised signing key, "
    "updating a behavioural-scope policy to catch a bypass pattern, "
    "pausing the system pending a fix. Closed actions feed MANAGE 4 risk "
    "treatments; open actions feed MANAGE 2 strategy."
)

ATTESTATION_PARAGRAPH = (
    "I, the undersigned qualified person for the above-identified "
    "operator, attest that the AI risk-management evidence summarised in "
    "this report was collected from the Project AIR signed Intent Capsule "
    "chain identified above in the regular course of the operator's "
    "operation of the AI system, that the chain verified cleanly using "
    "the open-source Project AIR verifier (`air trace`, v{air_version}), "
    "and that the findings, subcategory crosswalk, and corrective actions "
    "recorded above are a true and correct record of the system's "
    "AI RMF-aligned post-deployment monitoring activity for the reporting "
    "period."
)

# (subcategory_id, what_air_supplies, evidence_pointer)
# Pointer is a Markdown anchor reference into this same document so the
# crosswalk reads as a single navigable artefact.
SUBCATEGORY_CROSSWALK: tuple[tuple[str, str, str], ...] = (
    (
        "GOVERN 1.5",
        "Ongoing monitoring substrate exists and runs.",
        "Section 5 (Methodology) and Section 8 (Chain integrity)",
    ),
    (
        "GOVERN 4.2",
        "Risks and potential impacts of the AI system are documented.",
        "Section 9 (Detector findings)",
    ),
    (
        "MAP 5.1",
        "Likelihood and magnitude of impact, derived from runtime severity rollup.",
        "Section 6 (Severity rollup)",
    ),
    (
        "MEASURE 1",
        "Methods and metrics applied: 14 detectors, OWASP taxonomy.",
        "Section 5 (Methodology)",
    ),
    (
        "MEASURE 2.7",
        "AI system security and resilience evidence: detector coverage + chain integrity.",
        "Sections 8 and 9",
    ),
    (
        "MEASURE 2.8",
        "Transparency and accountability: signed, verifiable evidence trail.",
        "Section 8 (Chain integrity attestation)",
    ),
    (
        "MEASURE 3",
        "Tracking AI risks over time: append-only chain across reporting periods.",
        "Section 5 (Methodology)",
    ),
    (
        "MANAGE 1.3",
        "Responses to high-priority risks documented for each critical and high finding.",
        "Section 11 (Corrective actions)",
    ),
    (
        "MANAGE 4.1",
        "Post-deployment monitoring plan is implemented and producing evidence.",
        "Sections 5, 8, 9 (this report itself is the artefact)",
    ),
)
