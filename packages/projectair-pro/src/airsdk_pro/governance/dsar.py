"""DSAR (Data Subject Access Request) report generator."""
from __future__ import annotations

from datetime import UTC, datetime

from airsdk.types import DataSubjectRef

from airsdk_pro.governance.query import query_by_subject
from airsdk_pro.governance.types import GovernanceIndex, SubjectAccessReport

_JURISDICTION_NOTES: dict[str, str] = {
    "HIPAA": "Subject has right to accounting of disclosures per 45 CFR 164.528.",
    "GDPR": "Subject has right of access per Article 15 of the GDPR.",
    "CCPA": "Consumer has right to know per California Civil Code Section 1798.100.",
}


def generate_dsar(
    index: GovernanceIndex,
    subject_id: str,
    subject_type: str = "",
    jurisdiction: str = "",
    chains_searched: int = 1,
) -> SubjectAccessReport:
    """Generate a DSAR report for a specific data subject."""
    accesses = query_by_subject(index, subject_id)
    notes = _JURISDICTION_NOTES.get(jurisdiction, "No jurisdiction-specific notes.")

    return SubjectAccessReport(
        subject=DataSubjectRef(
            subject_id=subject_id,
            subject_type=subject_type,
            jurisdiction=jurisdiction,
        ),
        generated_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        total_accesses=len(accesses),
        accesses=accesses,
        chains_searched=chains_searched,
        jurisdiction_notes=notes,
    )


def render_dsar_markdown(report: SubjectAccessReport) -> str:
    """Render a DSAR report as human-readable Markdown."""
    lines: list[str] = []
    lines.append("# Data Subject Access Report")
    lines.append("")
    lines.append(f"**Subject ID:** {report.subject.subject_id}")
    if report.subject.subject_type:
        lines.append(f"**Subject Type:** {report.subject.subject_type}")
    if report.subject.jurisdiction:
        lines.append(f"**Jurisdiction:** {report.subject.jurisdiction}")
    lines.append(f"**Generated:** {report.generated_at}")
    lines.append(f"**Chains Searched:** {report.chains_searched}")
    lines.append(f"**Total Accesses Found:** {report.total_accesses}")
    lines.append("")

    if report.accesses:
        lines.append("## Access Records")
        lines.append("")
        lines.append("| Timestamp | Tool | Access Type | Assets | Policy |")
        lines.append("|---|---|---|---|---|")
        for access in report.accesses:
            asset_names = ", ".join(a.asset_id for a in access.data_assets)
            lines.append(
                f"| {access.timestamp} | {access.tool_name} "
                f"| {access.access_type} | {asset_names} "
                f"| {access.policy_decision or 'n/a'} |"
            )
        lines.append("")
    else:
        lines.append("No accesses found for this data subject.")
        lines.append("")

    lines.append("## Jurisdiction Notes")
    lines.append("")
    lines.append(report.jurisdiction_notes)
    lines.append("")

    return "\n".join(lines)
