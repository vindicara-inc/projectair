"""Shared finding → event conversion used by every SIEM helper.

The SIEM-specific modules wrap the events with vendor framing
(Datadog ``ddsource``, Splunk ``sourcetype``, etc.) but the underlying
fact list is the same for every vendor.
"""
from __future__ import annotations

from typing import Any

from airsdk.types import ForensicReport

SEVERITY_ORDER: tuple[str, ...] = ("low", "medium", "high", "critical")


def _severity_rank(severity: str) -> int:
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return -1


def findings_above(report: ForensicReport, min_severity: str | None) -> list[dict[str, Any]]:
    """Return a list of structured event dicts above ``min_severity``.

    Each event is a flat dict suitable for direct JSON serialisation by
    the vendor-specific helpers. The fields are deliberately stable: SIEM
    rules customers write against ``vindicara.detector_id`` and
    ``vindicara.severity`` should keep working across releases.
    """
    if min_severity is None:
        threshold = -1
    else:
        threshold = _severity_rank(min_severity)
        if threshold < 0:
            raise ValueError(
                f"min_severity {min_severity!r} not one of {SEVERITY_ORDER}"
            )

    events: list[dict[str, Any]] = []
    for finding in report.findings:
        if _severity_rank(finding.severity) < threshold:
            continue
        events.append(_event_from_finding(report, finding))
    return events


def _event_from_finding(report: ForensicReport, finding: Any) -> dict[str, Any]:
    """Build a single SIEM-shape event from a Finding + the parent report."""
    return {
        "vendor": "vindicara",
        "product": "projectair",
        "air_version": report.air_version,
        "report_id": report.report_id,
        "source_log": report.source_log,
        "vindicara": {
            "detector_id": finding.detector_id,
            "title": finding.title,
            "severity": finding.severity,
            "step_id": finding.step_id,
            "step_index": finding.step_index,
            "description": finding.description,
            "chain_status": report.verification.status.value,
            "records_verified": report.verification.records_verified,
        },
    }
