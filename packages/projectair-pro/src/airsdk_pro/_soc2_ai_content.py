"""Prose content blocks for the SOC 2 AI report generator.

Separated from ``report_soc2_ai.py`` so the generator stays under the
300-line file limit. These strings reference the AICPA Trust Services
Criteria (TSC) 2017 with 2022 revisions, and the AICPA SOC 2 + AI
considerations guidance (2024). Subcategory identifiers used here
(CC1.x, CC2.x, ..., PI1.x) follow the AICPA TSC taxonomy unchanged.

A SOC 2 report is issued by an independent CPA after a Type I or Type II
examination; this module produces evidence material an auditor can
incorporate into that examination, not a SOC 2 report itself. The
disclaimer below is explicit about that distinction.
"""
from __future__ import annotations

DISCLAIMER = (
    "**INFORMATIONAL TEMPLATE, NOT A SOC 2 REPORT AND NOT LEGAL OR AUDIT "
    "ADVICE.** A SOC 2 report can only be issued by an independent CPA "
    "firm following a SOC 2 Type I or Type II examination conducted under "
    "AICPA AT-C 105 / 205. This document is auditor-input evidence "
    "generated from a Project AIR signed forensic chain; the service "
    "organisation must review the contents, fill in the controls, "
    "policies, and management-assertion language that the chain cannot "
    "produce on its own, supply the evidence to a qualified CPA, and "
    "consult counsel before relying on this document for any audit, "
    "regulatory, customer-due-diligence, or contractual purpose."
)

METHODOLOGY = (
    "Project AIR records every agent action (LLM call, tool invocation, "
    "inter-agent message, final output, anchor, human approval) as an "
    "append-only signed record. Each record is content-hashed with BLAKE3 "
    "and signed with Ed25519 (RFC 8032); the signature binds the record "
    "to the previous record's hash, producing a forward-chained audit log "
    "in which any alteration, insertion, deletion, or reordering is "
    "detected deterministically by replay. The open-source verifier "
    "`air trace` reproduces the verification offline using only the log "
    "file and the signer's public key. The detector taxonomy spans the "
    "OWASP Top 10 for Agentic Applications (10 of 10), three OWASP Top 10 "
    "for LLM Applications categories, and one AIR-native chain-integrity "
    "check. The methodology supplies measurable, reproducible evidence to "
    "the AICPA Common Criteria (Security) and to the Processing Integrity "
    "category for organisations that include them in scope."
)

CHAIN_OK_STATEMENT = (
    "The chain verified cleanly. Every record's BLAKE3 content hash was "
    "recomputed from its canonicalised payload and matched; every "
    "record's Ed25519 signature verified against its declared public "
    "key; and every record's `prev_hash` matched the previous record's "
    "content hash. The forensic chain is tamper-evident and has not been "
    "altered since production. This evidence supports CC7 (System "
    "Operations) and CC8 (Change Management) by demonstrating that "
    "agent-system events are recorded immutably and that any alteration "
    "is detectable."
)

CHAIN_FAIL_STATEMENT = (
    "**Chain verification did not complete successfully.** The log is "
    "either tampered, truncated, or malformed. Investigate before "
    "relying on the records below as evidence. Preserve the original log "
    "file for forensic analysis. A failed chain weakens CC7 and CC8 "
    "control evidence and is itself a security incident under CC7.4 "
    "(detected security events). Document the root cause and remediation "
    "before the auditor relies on this period's evidence."
)

SECURITY_PREAMBLE = (
    "The Common Criteria (Security) cover the 'security' principle that "
    "the system is protected against unauthorised access, use, or "
    "modification. Project AIR's evidence speaks directly to a subset of "
    "these criteria; other Common Criteria require organisational "
    "documentation outside the runtime chain (governance, risk "
    "management, vendor management, change-control procedures, employee "
    "training records). The subcategories below are the ones to which "
    "the signed-chain evidence directly contributes."
)

PROCESSING_INTEGRITY_PREAMBLE = (
    "The Processing Integrity criteria address whether the system "
    "achieves its objective in a complete, valid, accurate, timely, and "
    "authorised manner. For an AI system, AIR's evidence supplies the "
    "'authorised' axis (Zero-Trust agent-registry enforcement) and the "
    "'complete and accurate processing' axis (every step of the agent's "
    "execution captured in a tamper-evident chain). The findings tables "
    "in section 9 are the empirical record of where the system met or "
    "departed from those criteria during the reporting period."
)

INCIDENT_PREAMBLE = (
    "Under CC7.4, the entity must respond to identified security events "
    "to prevent further security incidents. Critical- and high-severity "
    "detector findings are candidate security events that require the "
    "service organisation's response. The corrective-actions table below "
    "is the operator-completed record of those responses; closed "
    "actions feed the auditor's CC7.5 evidence (recovery from identified "
    "security incidents)."
)

SUMMARY_PARAGRAPH = (
    "This report documents AI-system control evidence for the "
    "above-identified system over the stated reporting period, collected "
    "from a signed Intent Capsule chain produced by Project AIR (BLAKE3 "
    "content hashing + Ed25519 signatures + forward hash chain). The "
    "evidence is structured against the AICPA Trust Services Criteria "
    "in scope: Common Criteria (Security) and, where elected, "
    "Processing Integrity. See `vindicara.io/admissibility` for the "
    "cryptographic architecture and its mapping to evidentiary "
    "frameworks."
)

CORRECTIVE_ACTIONS_PREAMBLE = (
    "Under CC7.4 and CC7.5, the entity must respond to identified "
    "security events and recover from identified incidents. For each "
    "critical- and high-severity finding above, document the corrective "
    "action the service organisation has taken or plans to take. "
    "Examples: rotating a compromised signing key, tightening an agent's "
    "permitted_tools list, updating a behavioural-scope policy, pausing "
    "the system pending a fix, communicating with affected customers."
)

ATTESTATION_PARAGRAPH = (
    "I, the undersigned authorised representative of the service "
    "organisation identified above, attest that the AI-system control "
    "evidence summarised in this report was collected from the Project "
    "AIR signed Intent Capsule chain identified above in the regular "
    "course of the entity's operation of the AI system, that the chain "
    "verified cleanly using the open-source Project AIR verifier "
    "(`air trace`, v{air_version}), and that the findings, criteria "
    "crosswalk, and corrective actions recorded above are a true and "
    "correct record of the entity's AI-system control activity for the "
    "reporting period."
)

# (criterion_id, what_air_supplies, evidence_pointer)
TSC_CROSSWALK: tuple[tuple[str, str, str], ...] = (
    (
        "CC2.1",
        "Internal communication of relevant information: signed event records of every agent action.",
        "Section 5 (Methodology) and Section 9 (Findings)",
    ),
    (
        "CC4.1",
        "Ongoing evaluation of internal control: continuous detector coverage during operation.",
        "Section 9 (Detector findings)",
    ),
    (
        "CC4.2",
        "Communication of internal-control deficiencies: detector findings flagged by severity.",
        "Section 9 and Section 11 (Corrective actions)",
    ),
    (
        "CC6.1",
        "Logical access controls: Zero-Trust agent-registry enforcement (ASI03/ASI10).",
        "Section 7 (Security evidence)",
    ),
    (
        "CC6.6",
        "Restriction of access on logical assets: declared `permitted_tools` and behavioural scope.",
        "Section 7 (Security evidence)",
    ),
    (
        "CC7.2",
        "Monitoring of system components for anomalies: AIR detector taxonomy.",
        "Section 5 (Methodology) and Section 9 (Findings)",
    ),
    (
        "CC7.3",
        "Evaluation of security events: severity classification and detector identifiers.",
        "Section 6 (Severity rollup)",
    ),
    (
        "CC7.4",
        "Response to identified security events: corrective-actions table.",
        "Section 11 (Corrective actions)",
    ),
    (
        "CC7.5",
        "Recovery from identified security incidents: closed corrective actions.",
        "Section 11 (Corrective actions)",
    ),
    (
        "CC8.1",
        "Authorised changes are tested and approved: human-approval records on the chain (Layer 3).",
        "Section 7 (Security evidence)",
    ),
    (
        "CC9.1",
        "Identification, selection, and development of risk-mitigation activities: detector ASI taxonomy.",
        "Section 5 (Methodology)",
    ),
    (
        "PI1.4",
        "Implementation of policies and procedures over system inputs: agent-registry enforcement at runtime.",
        "Section 8 (Processing Integrity evidence)",
    ),
    (
        "PI1.5",
        "Implementation of policies and procedures over system processing: tamper-evident chain.",
        "Sections 7 and 8",
    ),
)
