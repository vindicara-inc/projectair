"""SOC 2 AI evidence-template generator.

Takes a ``ForensicReport`` produced by ``air trace`` plus the underlying
chain and emits a Markdown evidence template structured against the
AICPA Trust Services Criteria (TSC) in scope: Common Criteria (Security)
and, where the engagement elects it, Processing Integrity. The output
is auditor-input evidence material, not a SOC 2 report (only an
independent CPA can issue one). The disclaimer is explicit on this.

Gated behind the ``report-soc2-ai`` Pro feature flag.

Prose blocks live in ``_soc2_ai_content.py`` to keep this module under
the 300-line file limit.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import UTC, datetime

from airsdk.types import AgDRRecord, Finding, ForensicReport, VerificationStatus

from airsdk_pro._soc2_ai_content import (
    ATTESTATION_PARAGRAPH,
    CHAIN_FAIL_STATEMENT,
    CHAIN_OK_STATEMENT,
    CORRECTIVE_ACTIONS_PREAMBLE,
    DISCLAIMER,
    INCIDENT_PREAMBLE,
    METHODOLOGY,
    PROCESSING_INTEGRITY_PREAMBLE,
    SECURITY_PREAMBLE,
    SUMMARY_PARAGRAPH,
    TSC_CROSSWALK,
)
from airsdk_pro.gate import requires_pro

SOC2_AI_FEATURE = "report-soc2-ai"
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
    rows = ["| AICPA TSC criterion | Project AIR evidence | Pointer |", "|---|---|---|"]
    for criterion, supplies, pointer in TSC_CROSSWALK:
        rows.append(f"| {criterion} | {supplies} | {pointer} |")
    return "\n".join(rows)


@requires_pro(feature=SOC2_AI_FEATURE)
def generate_soc2_ai_report(
    report: ForensicReport,
    records: list[AgDRRecord],
    system_id: str,
    service_organisation: str = "[Service organisation]",
    system_name: str = "[AI system name]",
    monitoring_period: str = "[reporting period, e.g. 2026-Q3]",
    in_scope_categories: tuple[str, ...] = ("Security", "Processing Integrity"),
) -> str:
    """Render a Markdown SOC 2 AI evidence template.

    The output is deterministic for a given input; safe to diff across
    runs, regenerate whenever the chain changes. Gated behind a Pro
    license with the ``report-soc2-ai`` feature flag; calling without a
    valid license raises a ``LicenseError`` subclass.

    The output is *evidence material* for a CPA-led SOC 2 examination,
    not a SOC 2 report itself. Only an independent CPA firm can issue
    a SOC 2 report.
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
    scope_display = ", ".join(in_scope_categories) if in_scope_categories else "(none)"

    return f"""# SOC 2 AI System Control Evidence

**Service organisation:** {service_organisation}
**System:** {system_name}
**System ID:** `{system_id}`
**Reporting period:** {monitoring_period}
**TSC categories in scope:** {scope_display}
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
| Service organisation | {service_organisation} |
| Monitoring period | {monitoring_period} |
| TSC categories in scope | {scope_display} |
| Monitoring system | Project AIR signed Intent Capsule chain |
| Log file (chain source) | `{report.source_log}` |
| Signing keys (Ed25519 public keys, hex) | {signer_display} |

---

## 3. Trust Services Criteria Crosswalk

The table below maps Project AIR's signed-chain evidence onto the AICPA
Trust Services Criteria it directly supports. Other criteria require
service-organisation evidence outside the runtime chain (governance
policies, vendor management, employee training, change-control
procedures, business-continuity testing); the entity is responsible for
those, and the CPA examiner will request them separately.

{crosswalk_table}

---

## 4. Methodology

{METHODOLOGY}

---

## 5. Severity Rollup (CC7.3)

{severity_rollup or "_No findings; severity rollup is empty for this period._"}

---

## 6. Detector Coverage (CC7.2, CC9.1)

{detector_table}

---

## 7. Common Criteria (Security) Evidence

{SECURITY_PREAMBLE}

- **CC6.1 (Logical access controls):** Zero-Trust agent-registry
  enforcement ensures every agent action is checked against a declared
  identity and permitted-tool set before execution. Findings under
  ASI03 (Identity & Privilege Abuse) and ASI10 (Rogue Agents) record
  attempted violations.
- **CC6.6 (Restriction of access):** Behavioural-scope declarations
  bound each agent's allowed actions; findings record violations.
- **CC7.2 (Monitoring for anomalies):** {len(detector_counts)} distinct
  detector categories produced findings in this period.
- **CC8.1 (Authorised changes):** Human-approval records (Layer 3) on
  the chain provide auditor-verifiable evidence that step-up flows
  occurred when policy required.

---

## 8. Processing Integrity Evidence

{PROCESSING_INTEGRITY_PREAMBLE}

- **PI1.4 (Authorised inputs):** Agent registry checks every action's
  authorisation against the operator's declared scope before
  execution.
- **PI1.5 (Authorised processing):** The signed forensic chain records
  every step of the system's processing in a tamper-evident form,
  enabling the auditor to confirm processing integrity by replay.

---

## 9. Detector Findings (CC4.1, CC7.2, CC7.3)

### 9.1 Critical-severity findings

{critical_table}

### 9.2 High-severity findings

{high_table}

---

## 10. Chain-Integrity Attestation (CC7, CC8)

- **Verification status:** `{verification.status.value}`
- **Records verified:** {verification.records_verified}{failure_row}{reason_row}

{chain_statement}

---

## 11. Corrective Actions (CC7.4, CC7.5)

{INCIDENT_PREAMBLE}

{CORRECTIVE_ACTIONS_PREAMBLE}

| Finding (step, detector) | Action taken | Owner | Status | Completion date |
|---|---|---|---|---|
| [step_index] [detector_id] | [description] | [owner] | [open/in progress/closed] | [date] |

---

## 12. Management's Statement and Attestation

{attestation}

| Field | Value |
|---|---|
| Name | [Full name] |
| Title | [Role, e.g. CISO / Head of Engineering / VP Compliance] |
| Service organisation | {service_organisation} |
| Date | [YYYY-MM-DD] |
| Signature | [signature] |

---

## Appendix A: Full Finding List

{full_table}
"""


__all__ = ["SOC2_AI_FEATURE", "generate_soc2_ai_report"]
