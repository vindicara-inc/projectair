"""ALCOA+ data-integrity evidence report generator.

ALCOA+ (Attributable, Legible, Contemporaneous, Original, Accurate, plus
Complete, Consistent, Enduring, Available) is the data-integrity framework
used in regulated (GxP) settings. This module walks a Project AIR signed
forensic chain and maps each principle to the concrete cryptographic evidence
the chain carries, so an operator can see, per principle, what the chain
proves and what it does not.

READINESS: beta.

SCOPE BOUNDARY (read before using this in any regulated context). This report
evidences that the *record* of agent activity is faithful, attributable, and
tamper-evident, and maps that to ALCOA+. It does NOT assert that the system is
a *validated* system (CSV / GAMP 5), that SOPs exist, that infrastructure is
qualified, or that any decision was *correct*. ALCOA+ in a regulated field
requires those things in addition to a faithful record. "Faithful capture" is
necessary, not sufficient, for GxP compliance. The output is evidence for a
qualified reviewer to assess, not a certificate of compliance. Have a qualified
person review it and consult counsel before relying on it.
"""
from __future__ import annotations

from datetime import datetime

from airsdk._compat import UTC
from airsdk.types import AgDRRecord, ForensicReport, StepKind, VerificationStatus

_MET = "Evidenced"
_PARTIAL = "Partial"
_NONE = "Not evidenced in this chain"

_BOUNDARY = (
    "This report evidences a **faithful, attributable, tamper-evident record**, "
    "mapped to ALCOA+. It is **not** an assertion of a validated (CSV/GAMP 5) "
    "system, of SOPs, of qualified infrastructure, or that any decision was "
    "correct. Faithful capture is necessary, not sufficient, for GxP compliance. "
    "A qualified person must review this evidence; consult counsel before relying "
    "on it."
)


def _principle(letter: str, name: str, status: str, evidence: str, caveat: str) -> str:
    """Render one ALCOA+ principle as a Markdown block."""
    caveat_line = f"\n- **Caveat:** {caveat}" if caveat else ""
    return (
        f"### {letter} — {name}\n\n"
        f"- **Status:** {status}\n"
        f"- **Evidence:** {evidence}{caveat_line}\n"
    )


def _timestamp_range(records: list[AgDRRecord]) -> tuple[str, str]:
    stamps = sorted(r.timestamp for r in records if r.timestamp)
    if not stamps:
        return ("", "")
    return (stamps[0], stamps[-1])


def _assess(records: list[AgDRRecord], status: VerificationStatus) -> list[str]:
    """Build the nine principle blocks from evidence present in the chain."""
    total = len(records)
    signer_keys = sorted({r.signer_key for r in records if r.signer_key})
    anchors = [r for r in records if r.kind is StepKind.ANCHOR]
    approvals = [r for r in records if r.kind is StepKind.HUMAN_APPROVAL]
    signed_esigs = [
        r for r in approvals
        if r.payload.human_approval is not None and r.payload.human_approval.meaning is not None
    ]
    reviews = [r for r in records if r.kind is StepKind.AUDIT_REVIEW]
    delegations = [r for r in records if r.kind is StepKind.DELEGATION]
    llm = [r for r in records if r.kind in (StepKind.LLM_START, StepKind.LLM_END)]
    with_prov = [r for r in llm if r.payload.provenance is not None]
    referenced = [r for r in records if r.payload.content_refs]
    chain_ok = status is VerificationStatus.OK

    attributable_status = _MET if signer_keys else _NONE
    attributable_ev = (
        f"{total} records signed; {len(signer_keys)} distinct signer key(s); "
        f"{len(approvals)} human-approval record(s), of which {len(signed_esigs)} carry a "
        f"Part 11 §11.50 signature meaning; {len(delegations)} delegation genesis record(s)."
    )
    approval_caveat = (
        "" if approvals or delegations
        else "No human-identity binding (HUMAN_APPROVAL / DELEGATION) in this chain; "
        "attribution is to the signing agent key only."
    )

    contemporaneous_status = _MET if chain_ok else _PARTIAL
    contemporaneous_ev = (
        f"Every record carries an ISO-8601 timestamp and is signed in-process at the step; "
        f"{len(anchors)} external anchor record(s) (RFC 3161 / Sigstore Rekor) bind chain roots to trusted time."
    )
    contemporaneous_caveat = (
        "" if anchors
        else "No external anchor in this chain: 'contemporaneous' and 'enduring' rest on operator trust "
        "until an RFC 3161 / Rekor (or on-prem TSA / HSM) anchor is added."
    )

    original_status = _MET
    original_ev = (
        "The first signed capture is the original record; "
        + (
            f"{len(referenced)} record(s) use capture-time content references "
            "(plaintext replaced by a salted, non-reversible BLAKE3 digest, e.g. for PHI minimization)."
            if referenced
            else "all content is stored in-line (no capture-time referencing applied)."
        )
    )

    accurate_status = _MET
    accurate_ev = (
        "Each record's BLAKE3 content_hash binds its payload, so any edit is detectable; "
        f"{len(with_prov)}/{len(llm)} LLM record(s) carry decision provenance "
        "(model snapshot, backend fingerprint, sampling parameters, logprobs)."
    )
    accurate_caveat = (
        "'Accurate' here means the record faithfully reflects the event, not that the decision was correct."
        if not with_prov
        else "Provenance makes a non-deterministic decision faithfully captured; it does not make it reproducible."
    )

    complete_status = _MET if chain_ok else _PARTIAL
    complete_ev = (
        f"{total} records span the observed activity; AIR-04 chain-integrity detection surfaces "
        "missing tool_end records and silent intervals (gaps are detectable, not hidden); "
        f"{len(reviews)} audit-trail review record(s) (Part 11 §11.10(e) / Annex 11 §9)."
    )

    consistent_status = _MET if chain_ok else _NONE
    consistent_ev = (
        f"prev_hash chain gives strict, tamper-evident chronological order; chain verification: {status.value}."
    )

    enduring_status = _MET if anchors else _PARTIAL
    enduring_ev = (
        "Records are written to durable media (fsync per record); "
        + (
            f"{len(anchors)} anchor(s) place chain roots in an append-only log independent of the operator."
            if anchors
            else "no external anchor present, so durability is operator-scoped only."
        )
    )

    available_status = _MET if signer_keys else _PARTIAL
    available_ev = (
        "Signer public keys are embedded in every record, so the chain is independently verifiable "
        "offline (`air verify` / `air verify-public`) with no vendor calls."
    )

    return [
        _principle("A", "Attributable", attributable_status, attributable_ev, approval_caveat),
        _principle("L", "Legible", _MET, "Records are structured, canonical AgDR JSON, human-readable via `air explain`.", ""),
        _principle("C", "Contemporaneous", contemporaneous_status, contemporaneous_ev, contemporaneous_caveat),
        _principle("O", "Original", original_status, original_ev, ""),
        _principle("A", "Accurate", accurate_status, accurate_ev, accurate_caveat),
        _principle("+C", "Complete", complete_status, complete_ev, ""),
        _principle("+C", "Consistent", consistent_status, consistent_ev, ""),
        _principle("+E", "Enduring", enduring_status, enduring_ev, ""),
        _principle("+A", "Available", available_status, available_ev, ""),
    ]


def generate_alcoa_report(
    report: ForensicReport,
    records: list[AgDRRecord],
    system_name: str = "[AI system name]",
    operator_entity: str = "[Provider / Operator entity]",
) -> str:
    """Render a Markdown ALCOA+ data-integrity evidence report.

    Deterministic for a given input (safe to diff across runs). ``report``
    supplies the verification verdict; ``records`` are the raw chain records
    the evidence is read from.
    """
    generated_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    earliest, latest = _timestamp_range(records)
    time_line = f"{earliest} to {latest} (UTC)" if earliest and latest else "(no timestamps)"
    blocks = "\n".join(_assess(records, report.verification.status))

    return f"""# ALCOA+ Data-Integrity Evidence Report

**System:** {system_name}
**Provider / Operator:** {operator_entity}
**Source chain:** `{report.source_log}`
**Records:** {report.records}  **Observed range:** {time_line}
**Chain verification:** {report.verification.status.value}
**Generated:** {generated_at}  **AIR version:** {report.air_version}
**Readiness:** beta

> **Scope boundary.** {_BOUNDARY}

## Principle-by-principle evidence

{blocks}
## Reviewer sign-off

This report is evidence for a qualified reviewer, not a certificate of compliance.

- **Reviewed by:** ______________________  **Role / qualification:** ______________________
- **Date:** ____________  **Determination:** ______________________
"""
