"""PagerDuty Events API v2 alert helper."""
from __future__ import annotations

import httpx
from airsdk.types import Finding, ForensicReport

from airsdk_pro.alerts.types import (
    DEFAULT_MIN_SEVERITY,
    DEFAULT_TIMEOUT_SECONDS,
    INCIDENT_WORKFLOWS_FEATURE,
    AlertConfigError,
    AlertPushError,
    AlertResult,
    filter_findings,
)
from airsdk_pro.gate import requires_pro

TARGET = "pagerduty"
EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"
DEFAULT_SOURCE = "vindicara-air"
DEFAULT_COMPONENT = "ai-agent"
DEFAULT_GROUP = "agent-security"
DEFAULT_CLASS = "owasp-asi"

# AIR severity → PagerDuty Events v2 severity. PagerDuty accepts
# critical / error / warning / info.
PD_SEVERITY_MAP = {
    "critical": "critical",
    "high": "error",
    "medium": "warning",
    "low": "info",
}


@requires_pro(feature=INCIDENT_WORKFLOWS_FEATURE)
def alert_to_pagerduty(
    report: ForensicReport,
    *,
    integration_key: str,
    source: str = DEFAULT_SOURCE,
    component: str = DEFAULT_COMPONENT,
    group: str = DEFAULT_GROUP,
    pd_class: str = DEFAULT_CLASS,
    min_severity: str = DEFAULT_MIN_SEVERITY,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    client: httpx.Client | None = None,
) -> AlertResult:
    """Send one ``trigger`` event per qualifying finding to PagerDuty Events v2.

    Each finding becomes its own incident. The ``dedup_key`` is set to
    a stable function of report id + finding step id so re-running the
    push for the same report does not reopen-then-reopen incidents:
    PagerDuty deduplicates and updates the existing incident instead.

    AIR severity is mapped onto PagerDuty's four-level severity:
    critical → critical, high → error, medium → warning, low → info.

    Raises ``AlertConfigError`` for missing config and ``AlertPushError``
    for non-2xx responses.
    """
    if not integration_key:
        raise AlertConfigError("PagerDuty integration_key is required")
    qualifying = filter_findings(report.findings, min_severity)
    if not qualifying:
        return AlertResult(target=TARGET, findings_alerted=0, http_status=200, endpoint=EVENTS_URL)

    owns_client = client is None
    http = client or httpx.Client(timeout=timeout)
    last_status = 200
    try:
        for finding in qualifying:
            payload = _build_payload(
                report=report,
                finding=finding,
                integration_key=integration_key,
                source=source,
                component=component,
                group=group,
                pd_class=pd_class,
            )
            response = http.post(EVENTS_URL, json=payload)
            if response.status_code >= 300:
                raise AlertPushError(TARGET, response.status_code, response.text)
            last_status = response.status_code
    finally:
        if owns_client:
            http.close()

    return AlertResult(
        target=TARGET,
        findings_alerted=len(qualifying),
        http_status=last_status,
        endpoint=EVENTS_URL,
    )


def _build_payload(
    *,
    report: ForensicReport,
    finding: Finding,
    integration_key: str,
    source: str,
    component: str,
    group: str,
    pd_class: str,
) -> dict[str, object]:
    pd_severity = PD_SEVERITY_MAP.get(finding.severity, "warning")
    dedup_key = f"vindicara-air:{report.report_id}:{finding.step_id}:{finding.detector_id}"
    return {
        "routing_key": integration_key,
        "event_action": "trigger",
        "dedup_key": dedup_key,
        "payload": {
            "summary": f"{finding.detector_id} {finding.title} (severity: {finding.severity})",
            "source": source,
            "severity": pd_severity,
            "component": component,
            "group": group,
            "class": pd_class,
            "custom_details": {
                "detector_id": finding.detector_id,
                "step_id": finding.step_id,
                "step_index": finding.step_index,
                "description": finding.description,
                "chain_status": report.verification.status.value,
                "records_verified": report.verification.records_verified,
                "source_log": report.source_log,
                "air_version": report.air_version,
            },
        },
    }
