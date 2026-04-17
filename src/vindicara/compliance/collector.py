"""Evidence collector: aggregates audit events into compliance evidence."""

import time
from datetime import UTC, datetime

import structlog

from vindicara.audit.logger import AuditEvent
from vindicara.compliance.models import EvidenceType
from vindicara.config.constants import (
    AUDIT_EVENT_AGENT_ACTION,
    AUDIT_EVENT_AGENT_SUSPENDED,
    AUDIT_EVENT_GUARD,
    AUDIT_EVENT_MCP_SCAN,
    AUDIT_EVENT_POLICY_CREATE,
    AUDIT_EVENT_POLICY_UPDATE,
)

logger = structlog.get_logger()

EVENT_TYPE_MAP: dict[str, EvidenceType] = {
    AUDIT_EVENT_GUARD: EvidenceType.GUARD_EVALUATION,
    AUDIT_EVENT_POLICY_CREATE: EvidenceType.POLICY_CHANGE,
    AUDIT_EVENT_POLICY_UPDATE: EvidenceType.POLICY_CHANGE,
    AUDIT_EVENT_AGENT_ACTION: EvidenceType.AGENT_ACTION,
    AUDIT_EVENT_AGENT_SUSPENDED: EvidenceType.AGENT_SUSPENSION,
    AUDIT_EVENT_MCP_SCAN: EvidenceType.MCP_SCAN,
}

QUARTER_MONTHS: dict[str, tuple[int, int]] = {
    "Q1": (1, 3),
    "Q2": (4, 6),
    "Q3": (7, 9),
    "Q4": (10, 12),
}


def _parse_period(period: str) -> tuple[float, float]:
    """Parse a period string like '2026-Q1' into start/end timestamps."""
    if not period:
        return 0.0, time.time()

    parts = period.split("-")
    if len(parts) == 2 and parts[1] in QUARTER_MONTHS:
        year = int(parts[0])
        start_month, end_month = QUARTER_MONTHS[parts[1]]
        start = datetime(year, start_month, 1, tzinfo=UTC)
        end = datetime(year + 1, 1, 1, tzinfo=UTC) if end_month == 12 else datetime(year, end_month + 1, 1, tzinfo=UTC)
        return start.timestamp(), end.timestamp()

    return 0.0, time.time()


class EvidenceCollector:
    """Collects and categorizes audit events as compliance evidence."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    def record(self, event: AuditEvent) -> None:
        """Record an audit event for compliance evidence."""
        self._events.append(event)

    def collect(
        self,
        system_id: str,
        period: str = "",
    ) -> dict[EvidenceType, list[AuditEvent]]:
        """Collect evidence grouped by type for a given period."""
        start_time, end_time = _parse_period(period)

        result: dict[EvidenceType, list[AuditEvent]] = {et: [] for et in EvidenceType}

        for event in self._events:
            if event.timestamp < start_time or event.timestamp > end_time:
                continue

            evidence_type = EVENT_TYPE_MAP.get(event.event_type)
            if evidence_type is not None:
                result[evidence_type].append(event)

        total = sum(len(v) for v in result.values())
        logger.info(
            "compliance.evidence.collected",
            system_id=system_id,
            period=period,
            total_events=total,
        )
        return result
