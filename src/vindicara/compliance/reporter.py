"""Compliance report generator."""

import uuid
from datetime import UTC, datetime

import structlog

from vindicara.compliance.collector import EvidenceCollector
from vindicara.compliance.frameworks import get_framework
from vindicara.compliance.models import (
    ComplianceFramework,
    ComplianceReport,
    ControlEvidence,
    ControlStatus,
    EvidenceType,
)

logger = structlog.get_logger()


class ComplianceReporter:
    """Generates compliance reports by mapping evidence to framework controls."""

    def __init__(self, collector: EvidenceCollector) -> None:
        self._collector = collector

    def generate(
        self,
        framework: ComplianceFramework,
        system_id: str,
        period: str = "",
    ) -> ComplianceReport:
        """Generate a compliance report for the given framework and period."""
        fw = get_framework(framework)
        evidence = self._collector.collect(system_id=system_id, period=period)

        controls: list[ControlEvidence] = []
        met_count = 0
        partial_count = 0
        not_met_count = 0

        for control_def in fw.controls:
            total_evidence = 0
            found_types: list[EvidenceType] = []
            last_ts = ""

            for req_type in control_def.required_evidence_types:
                type_events = evidence.get(req_type, [])
                if type_events:
                    found_types.append(req_type)
                    total_evidence += len(type_events)
                    for evt in type_events:
                        evt_ts = datetime.fromtimestamp(
                            evt.timestamp, tz=UTC
                        ).isoformat()
                        if evt_ts > last_ts:
                            last_ts = evt_ts

            status = _compute_status(
                required_types=control_def.required_evidence_types,
                found_types=found_types,
                total_evidence=total_evidence,
                min_count=control_def.min_evidence_count,
            )

            if status == ControlStatus.MET:
                met_count += 1
            elif status == ControlStatus.PARTIAL:
                partial_count += 1
            else:
                not_met_count += 1

            summary = _build_summary(
                control_def.control_name, status, total_evidence
            )

            controls.append(
                ControlEvidence(
                    control_id=control_def.control_id,
                    control_name=control_def.control_name,
                    status=status,
                    evidence_count=total_evidence,
                    evidence_types=found_types,
                    summary=summary,
                    last_evidence_at=last_ts,
                )
            )

        total = len(fw.controls)
        coverage = _compute_coverage(met_count, partial_count, total)

        report = ComplianceReport(
            report_id=f"rpt_{uuid.uuid4().hex[:12]}",
            framework=framework,
            system_id=system_id,
            period=period,
            generated_at=datetime.now(UTC).isoformat(),
            total_controls=total,
            met_controls=met_count,
            partial_controls=partial_count,
            not_met_controls=not_met_count,
            coverage_pct=round(coverage, 1),
            controls=controls,
            summary=f"{fw.name}: {met_count}/{total} controls met, {coverage:.1f}% coverage",
        )

        logger.info(
            "compliance.report.generated",
            framework=framework.value,
            system_id=system_id,
            coverage_pct=report.coverage_pct,
        )
        return report


def _compute_status(
    required_types: list[EvidenceType],
    found_types: list[EvidenceType],
    total_evidence: int,
    min_count: int,
) -> ControlStatus:
    """Determine control status based on evidence."""
    if not found_types:
        return ControlStatus.NOT_MET

    all_types_present = all(rt in found_types for rt in required_types)

    if all_types_present and total_evidence >= min_count:
        return ControlStatus.MET

    return ControlStatus.PARTIAL


def _build_summary(
    control_name: str,
    status: ControlStatus,
    evidence_count: int,
) -> str:
    """Build a human-readable summary for a control."""
    if status == ControlStatus.MET:
        return f"{control_name}: fully satisfied with {evidence_count} evidence items"
    if status == ControlStatus.PARTIAL:
        return f"{control_name}: partially satisfied with {evidence_count} evidence items"
    return f"{control_name}: no evidence collected"


def _compute_coverage(
    met: int, partial: int, total: int
) -> float:
    """Compute coverage percentage. Partial controls count as half."""
    if total == 0:
        return 0.0
    return (met + 0.5 * partial) / total * 100.0
