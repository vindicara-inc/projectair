"""NIST AI RMF (NIST AI 100-1) risk-management report generator.

Takes a ``ForensicReport`` produced by ``air trace`` plus the underlying
chain and emits a Markdown report structured against the four AI RMF
functions: GOVERN, MAP, MEASURE, MANAGE. The output is a populated
template, not a NIST-blessed compliance artefact (NIST does not certify
AI RMF conformance). The operator must review, adapt, and have a
qualified person sign the attestation before the report is usable as
evidence in any audit, regulatory, or insurance context.

Gated behind the ``report-nist-ai-rmf`` Pro feature flag.

Prose blocks live in ``_nist_rmf_content.py`` to keep this module under
the 300-line file limit.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import UTC, datetime

from airsdk.types import AgDRRecord, Finding, ForensicReport, VerificationStatus

from airsdk_pro._nist_rmf_content import (
    ATTESTATION_PARAGRAPH,
    CHAIN_FAIL_STATEMENT,
    CHAIN_OK_STATEMENT,
    CORRECTIVE_ACTIONS_PREAMBLE,
    DISCLAIMER,
    GOVERN_PREAMBLE,
    MANAGE_PREAMBLE,
    MAP_PREAMBLE,
    MEASURE_PREAMBLE,
    METHODOLOGY,
    SUBCATEGORY_CROSSWALK,
    SUMMARY_PARAGRAPH,
)
from airsdk_pro.gate import requires_pro

NIST_RMF_FEATURE = "report-nist-ai-rmf"
SEVERITY_ORDER = ("critical", "high", "medium", "low")


def _timestamp_range(records: list[AgDRRecord]) -> tuple[str, str]:
    timestamps = [r.timestamp for r in records if r.timestamp]
    if not timestamps:
        return ("", "")
    return (min(timestamps), max(timestamps))


def _unique_signer_keys(records: list[AgDRRecord]) -> list[str]:
    return sorted({r.signer_key for r in records if r.signer_key})


def _findings_by_severity(findings: list[Finding]) -> dict[str, list[Finding]]:
    buckets: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        buckets[finding.severity].append(finding)
    return buckets


def _format_finding_row(finding: Finding, record: AgDRRecord | None) -> str:
    timestamp = record.timestamp if record is not None else ""
    desc = finding.description.replace("|", "\\|").replace("\n", " ")
    return (
        f"| {finding.step_index} | {timestamp} | {finding.detector_id} | "
        f"{finding.severity} | {desc} |"
    )


def _render_findings_table(
    findings: list[Finding],
    records_by_id: dict[str, AgDRRecord],
    empty_message: str,
) -> str:
    if not findings:
        return empty_message
    rows = [
        "| Step | Timestamp (UTC) | Detector | Severity | Description |",
        "|---|---|---|---|---|",
    ]
    rows.extend(_format_finding_row(f, records_by_id.get(f.step_id)) for f in findings)
    return "\n".join(rows)


def _render_severity_rollup(severities: dict[str, list[Finding]]) -> str:
    lines: list[str] = []
    for severity in SEVERITY_ORDER:
        count = len(severities.get(severity, []))
        if count:
            lines.append(f"- **Findings of {severity} severity:** {count}")
    return "\n".join(lines)


def _render_detector_table(counts: Counter[str]) -> str:
    if not counts:
        return "No findings surfaced during this reporting period."
    rows = ["| Detector | Count |", "|---|---|"]
    rows.extend(f"| `{code}` | {counts[code]} |" for code in sorted(counts))
    return "\n".join(rows)


def _render_crosswalk_table() -> str:
    rows = ["| AI RMF subcategory | Project AIR evidence | Pointer |", "|---|---|---|"]
    for subcat, supplies, pointer in SUBCATEGORY_CROSSWALK:
        rows.append(f"| {subcat} | {supplies} | {pointer} |")
    return "\n".join(rows)


@requires_pro(feature=NIST_RMF_FEATURE)
def generate_nist_rmf_report(
    report: ForensicReport,
    records: list[AgDRRecord],
    system_id: str,
    system_name: str = "[AI system name]",
    operator_entity: str = "[Operator entity]",
    monitoring_period: str = "[reporting period, e.g. 2026-Q3]",
    rmf_profile: str = "AI RMF 1.0 (NIST AI 100-1)",
) -> str:
    """Render a Markdown NIST AI RMF risk-management report.

    The output is deterministic for a given input; safe to diff across
    runs, regenerate whenever the chain changes. Gated behind a Pro
    license with the ``report-nist-ai-rmf`` feature flag; calling without
    a valid license raises a ``LicenseError`` subclass.
    """
    generated_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    earliest, latest = _timestamp_range(records)
    severities = _findings_by_severity(report.findings)
    detector_counts = Counter(f.detector_id for f in report.findings)
    signer_keys = _unique_signer_keys(records)
    verification = report.verification
    records_by_id = {r.step_id: r for r in records}

    chain_statement = (
        CHAIN_OK_STATEMENT
        if verification.status == VerificationStatus.OK
        else CHAIN_FAIL_STATEMENT
    )
    failure_row = (
        f"\n- **Failure step_id:** `{verification.failed_step_id}`"
        if verification.failed_step_id else ""
    )
    reason_row = f"\n- **Reason:** {verification.reason}" if verification.reason else ""
    time_range_line = (
        f"- **Observed time range:** {earliest} to {latest} (UTC)\n"
        if earliest and latest else ""
    )
    severity_rollup = _render_severity_rollup(severities)
    severity_rollup_block = f"\n{severity_rollup}" if severity_rollup else ""
    signer_display = (
        ", ".join(f"`{k[:16]}...`" for k in signer_keys) if signer_keys else "(none)"
    )
    critical_table = _render_findings_table(
        severities.get("critical", []), records_by_id,
        "No critical-severity findings in this reporting period.",
    )
    high_table = _render_findings_table(
        severities.get("high", []), records_by_id,
        "No high-severity findings in this reporting period.",
    )
    full_table = _render_findings_table(
        report.findings, records_by_id, "No findings in this reporting period."
    )
    detector_table = _render_detector_table(detector_counts)
    crosswalk_table = _render_crosswalk_table()
    attestation = ATTESTATION_PARAGRAPH.format(air_version=report.air_version)

    return f"""# NIST AI RMF Risk-Management Report

**System:** {system_name}
**System ID:** `{system_id}`
**Operator:** {operator_entity}
**Reporting period:** {monitoring_period}
**RMF profile:** {rmf_profile}
**Report generated:** {generated_at}
**Source log:** `{report.source_log}`
**Project AIR version:** {report.air_version}

> {DISCLAIMER}

---

## 1. Executive Summary

{SUMMARY_PARAGRAPH}

- **Records analysed:** {report.records}
- **Conversations / sessions:** {report.conversations}
{time_range_line}- **Chain integrity:** {verification.status.value.upper()}
- **Records cryptographically verified:** {verification.records_verified}
- **Unique signing keys observed:** {len(signer_keys)}
- **Total findings:** {len(report.findings)}{severity_rollup_block}

---

## 2. System Identification

| Field | Value |
|---|---|
| System identifier | `{system_id}` |
| System name | {system_name} |
| Operator | {operator_entity} |
| Monitoring period | {monitoring_period} |
| RMF profile | {rmf_profile} |
| Monitoring system | Project AIR signed Intent Capsule chain |
| Log file (chain source) | `{report.source_log}` |
| Signing keys (Ed25519 public keys, hex) | {signer_display} |

---

## 3. AI RMF Subcategory Crosswalk

The table below maps Project AIR's signed-chain evidence onto the NIST AI
RMF subcategories it directly supports. Other subcategories require
organisational evidence outside the runtime chain (policies,
stakeholder-impact analyses, workforce decisions, vendor-management
records); the operator is responsible for those.

{crosswalk_table}

---

## 4. GOVERN Function Evidence

{GOVERN_PREAMBLE}

- **GOVERN 1.5 (Ongoing monitoring):** Project AIR is the monitoring
  substrate. Records are produced continuously during agent execution
  and aggregated into the chain referenced above. The chain in this
  report covers {report.records} records over the period {earliest} to
  {latest} (UTC).
- **GOVERN 4.2 (Risk documentation):** Detector findings constitute
  documented risks. Section 9 lists every finding produced for the
  reporting period.

---

## 5. Methodology

{METHODOLOGY}

---

## 6. MAP Function Evidence

{MAP_PREAMBLE}

- **Severity rollup (MAP 5.1 input):**

{severity_rollup or "_No findings; severity rollup is empty for this period._"}

- **Detector / risk-category coverage:**

{detector_table}

---

## 7. MEASURE Function Evidence

{MEASURE_PREAMBLE}

---

## 8. Chain-Integrity Attestation (MEASURE 2.7, 2.8)

- **Verification status:** `{verification.status.value}`
- **Records verified:** {verification.records_verified}{failure_row}{reason_row}

{chain_statement}

---

## 9. Detector Findings (MEASURE 1, MEASURE 3)

### 9.1 Critical-severity findings

{critical_table}

### 9.2 High-severity findings

{high_table}

---

## 10. MANAGE Function Evidence

{MANAGE_PREAMBLE}

---

## 11. Corrective Actions (MANAGE 1.3, MANAGE 4)

{CORRECTIVE_ACTIONS_PREAMBLE}

| Finding (step, detector) | Action taken | Owner | Status | Completion date |
|---|---|---|---|---|
| [step_index] [detector_id] | [description] | [owner] | [open/in progress/closed] | [date] |

---

## 12. Attestation

{attestation}

| Field | Value |
|---|---|
| Name | [Full name] |
| Title | [Role, e.g. CISO / AI Risk Officer / Compliance Lead] |
| Entity | [Operator entity] |
| Date | [YYYY-MM-DD] |
| Signature | [signature] |

---

## Appendix A: Full Finding List

{full_table}
"""


__all__ = ["NIST_RMF_FEATURE", "generate_nist_rmf_report"]
