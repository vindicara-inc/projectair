"""Slack Incoming Webhook push helper."""
from __future__ import annotations

from typing import Any

import httpx
from airsdk.types import ForensicReport

from airsdk_pro.gate import requires_pro
from airsdk_pro.siem._events import findings_above
from airsdk_pro.siem.types import (
    DEFAULT_TIMEOUT_SECONDS,
    SIEM_INTEGRATIONS_FEATURE,
    SiemConfigError,
    SiemPushError,
    SiemPushResult,
)

VENDOR = "slack"

SEVERITY_EMOJI: dict[str, str] = {
    "critical": "\U0001f534",
    "high": "\U0001f7e0",
    "medium": "\U0001f7e1",
    "low": "⚪",
}


@requires_pro(feature=SIEM_INTEGRATIONS_FEATURE)
def push_to_slack(
    report: ForensicReport,
    *,
    webhook_url: str,
    channel: str | None = None,
    username: str = "Vindicara AIR",
    min_severity: str | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    client: httpx.Client | None = None,
) -> SiemPushResult:
    """POST findings to a Slack Incoming Webhook as a Block Kit message.

    Each call sends one message containing all findings above
    ``min_severity``. The webhook URL is the only credential; it never
    leaves the customer's process.

    Raises ``SiemConfigError`` for missing config and ``SiemPushError``
    for non-2xx responses.
    """
    if not webhook_url:
        raise SiemConfigError("Slack webhook_url is required")
    if not webhook_url.startswith("https://hooks.slack.com/"):
        raise SiemConfigError(
            "webhook_url must start with https://hooks.slack.com/"
        )

    events = findings_above(report, min_severity)
    if not events:
        return SiemPushResult(
            vendor=VENDOR, events_sent=0, http_status=200, endpoint=""
        )

    payload = _build_payload(
        events, report=report, channel=channel, username=username
    )

    owns_client = client is None
    http = client or httpx.Client(timeout=timeout)
    try:
        response = http.post(
            webhook_url,
            json=payload,
            headers={"Content-Type": "application/json"},
        )
    finally:
        if owns_client:
            http.close()

    if response.status_code >= 300:
        raise SiemPushError(VENDOR, response.status_code, response.text)
    return SiemPushResult(
        vendor=VENDOR,
        events_sent=len(events),
        http_status=response.status_code,
        endpoint=webhook_url,
    )


def _build_payload(
    events: list[dict[str, Any]],
    *,
    report: ForensicReport,
    channel: str | None,
    username: str,
) -> dict[str, Any]:
    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"AIR Alert: {len(events)} finding{'s' if len(events) != 1 else ''} detected",
            },
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": (
                        f"*Report* `{report.report_id}` | "
                        f"*Chain* `{report.verification.status.value}` | "
                        f"*Records* {report.verification.records_verified}"
                    ),
                },
            ],
        },
        {"type": "divider"},
    ]

    for event in events:
        v: dict[str, Any] = event["vindicara"]
        emoji = SEVERITY_EMOJI.get(v["severity"], "❓")
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"{emoji} *{v['detector_id']}* | `{v['severity']}`\n"
                        f"{v['title']}\n"
                        f"_{v['description']}_"
                    ),
                },
            }
        )

    payload: dict[str, Any] = {"blocks": blocks, "username": username}
    if channel is not None:
        payload["channel"] = channel
    return payload
