"""Incident workflow / alerting hooks (Pro).

Thin HTTPS push helpers that take a Project AIR ``ForensicReport`` and
deliver high-severity findings to incident-response destinations the
**customer** owns. The helpers are decoupled from the SIEM push
helpers in ``airsdk_pro.siem``: SIEM push is for log aggregation and
detection rules, alerting is for waking someone up at 3am.

Destinations covered:

- **Slack** Incoming Webhook (``alert_to_slack``)
- **PagerDuty** Events API v2 (``alert_to_pagerduty``)
- Generic HTTPS webhook (``alert_to_webhook``)

Each function is gated behind the ``incident-workflows`` Pro feature
flag. None of the helpers route through Vindicara; every push goes
directly from the customer's process to the customer's destination.
"""
from __future__ import annotations

from airsdk_pro.alerts.pagerduty import alert_to_pagerduty
from airsdk_pro.alerts.slack import alert_to_slack
from airsdk_pro.alerts.types import (
    INCIDENT_WORKFLOWS_FEATURE,
    AlertConfigError,
    AlertPushError,
    AlertResult,
)
from airsdk_pro.alerts.webhook import alert_to_webhook

__all__ = [
    "INCIDENT_WORKFLOWS_FEATURE",
    "AlertConfigError",
    "AlertPushError",
    "AlertResult",
    "alert_to_pagerduty",
    "alert_to_slack",
    "alert_to_webhook",
]
