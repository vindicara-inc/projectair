"""Shared types for the incident-alerting hooks."""
from __future__ import annotations

from dataclasses import dataclass

from airsdk.types import Finding

INCIDENT_WORKFLOWS_FEATURE = "incident-workflows"
"""License feature flag the alerting hooks gate on."""

DEFAULT_TIMEOUT_SECONDS = 10.0
"""Default network timeout for alerting HTTPS calls."""

DEFAULT_MIN_SEVERITY = "high"
"""Default threshold: only ``high`` and ``critical`` findings raise alerts."""

SEVERITY_ORDER: tuple[str, ...] = ("low", "medium", "high", "critical")


def severity_rank(severity: str) -> int:
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return -1


def filter_findings(findings: list[Finding], min_severity: str) -> list[Finding]:
    threshold = severity_rank(min_severity)
    if threshold < 0:
        raise AlertConfigError(
            f"min_severity {min_severity!r} not one of {SEVERITY_ORDER}"
        )
    return [f for f in findings if severity_rank(f.severity) >= threshold]


class AlertConfigError(ValueError):
    """Configuration was missing or malformed before the request was sent."""


class AlertPushError(RuntimeError):
    """The destination returned an error response."""

    def __init__(self, target: str, status_code: int, body: str) -> None:
        self.target = target
        self.status_code = status_code
        self.body = body
        super().__init__(
            f"{target} alert failed with HTTP {status_code}: {body[:200]}"
        )


@dataclass(frozen=True)
class AlertResult:
    """Outcome of a successful alert delivery.

    Attributes
    ----------
    target:
        ``"slack"`` / ``"pagerduty"`` / ``"webhook"``.
    findings_alerted:
        Number of findings that produced an alert (i.e., findings above
        ``min_severity``). Zero means no alert was sent because nothing
        crossed the threshold.
    http_status:
        HTTP status returned by the destination, or 200 when the alert
        was a no-op.
    endpoint:
        Description of where the alert landed.
    """

    target: str
    findings_alerted: int
    http_status: int
    endpoint: str
