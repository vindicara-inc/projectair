"""Slack Incoming Webhook alert helper."""
from __future__ import annotations

from collections.abc import Sequence
from typing import Any

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

TARGET = "slack"

SEVERITY_EMOJI = {
    "critical": ":rotating_light:",
    "high": ":warning:",
    "medium": ":information_source:",
    "low": ":mag:",
}


@requires_pro(feature=INCIDENT_WORKFLOWS_FEATURE)
def alert_to_slack(
    report: ForensicReport,
    *,
    webhook_url: str,
    channel: str | None = None,
    min_severity: str = DEFAULT_MIN_SEVERITY,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    client: httpx.Client | None = None,
) -> AlertResult:
    """POST a single summary message with all qualifying findings to a Slack Incoming Webhook.

    The Slack incoming-webhook URL is itself the credential, so callers
    should treat ``webhook_url`` as a secret. Slack does not support
    overriding the destination channel from a default-channel webhook
    in newer apps, but ``channel`` is included for legacy webhooks that
    still honour it.

    Raises ``AlertConfigError`` for missing config and ``AlertPushError``
    for non-2xx responses.
    """
    if not webhook_url:
        raise AlertConfigError("Slack webhook_url is required")
    qualifying = filter_findings(report.findings, min_severity)
    if not qualifying:
        return AlertResult(target=TARGET, findings_alerted=0, http_status=200, endpoint=webhook_url)

    blocks = _build_blocks(report, qualifying)
    payload: dict[str, Any] = {"text": _summary_text(report, qualifying), "blocks": blocks}
    if channel:
        payload["channel"] = channel

    owns_client = client is None
    http = client or httpx.Client(timeout=timeout)
    try:
        response = http.post(webhook_url, json=payload)
    finally:
        if owns_client:
            http.close()

    if response.status_code >= 300:
        raise AlertPushError(TARGET, response.status_code, response.text)
    return AlertResult(
        target=TARGET,
        findings_alerted=len(qualifying),
        http_status=response.status_code,
        endpoint=webhook_url,
    )


def _summary_text(report: ForensicReport, qualifying: Sequence[Finding]) -> str:
    return (
        f"Project AIR: {len(qualifying)} finding(s) above threshold in "
        f"{report.records} records (chain: {report.verification.status.value})"
    )


def _build_blocks(report: ForensicReport, qualifying: Sequence[Finding]) -> list[dict[str, Any]]:
    header: dict[str, Any] = {
        "type": "header",
        "text": {
            "type": "plain_text",
            "text": f"Project AIR alert - {len(qualifying)} finding(s)",
        },
    }
    chain_line: dict[str, Any] = {
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": (
                f"*Chain:* `{report.verification.status.value}` "
                f"({report.verification.records_verified} of {report.records} records verified) "
                f"\n*Source:* `{report.source_log}`"
            ),
        },
    }
    finding_lines: list[dict[str, Any]] = []
    for f in qualifying:
        emoji = SEVERITY_EMOJI.get(f.severity, "")
        finding_lines.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"{emoji} *{f.detector_id}* {f.title} "
                        f"(severity: `{f.severity}`, step: {f.step_index})"
                        f"\n{f.description}"
                    ),
                },
            }
        )
    return [header, chain_line, *finding_lines]
