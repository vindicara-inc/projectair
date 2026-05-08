"""Datadog Logs API v2 push helper."""
from __future__ import annotations

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

DEFAULT_DATADOG_SITE = "datadoghq.com"
"""Default Datadog site. Override for EU (``datadoghq.eu``), US3 (``us3.datadoghq.com``), etc."""

VENDOR = "datadog"
DEFAULT_SOURCE = "vindicara-air"
DEFAULT_SERVICE = "vindicara-air"


@requires_pro(feature=SIEM_INTEGRATIONS_FEATURE)
def push_to_datadog(
    report: ForensicReport,
    *,
    api_key: str,
    site: str = DEFAULT_DATADOG_SITE,
    source: str = DEFAULT_SOURCE,
    service: str = DEFAULT_SERVICE,
    tags: tuple[str, ...] = (),
    min_severity: str | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    client: httpx.Client | None = None,
) -> SiemPushResult:
    """POST findings to Datadog's Logs API v2 endpoint for the configured site.

    Each finding becomes one log entry. The endpoint is
    ``https://http-intake.logs.<site>/api/v2/logs``; authentication is
    via the ``DD-API-KEY`` header. The customer's API key never leaves
    their process, and the request goes directly from the customer to
    Datadog (Vindicara is not in the data path).

    Raises ``SiemConfigError`` for missing config and ``SiemPushError``
    for non-2xx responses.
    """
    if not api_key:
        raise SiemConfigError("Datadog api_key is required")
    if not site:
        raise SiemConfigError("Datadog site is required")

    events = findings_above(report, min_severity)
    if not events:
        return SiemPushResult(vendor=VENDOR, events_sent=0, http_status=200, endpoint="")

    url = f"https://http-intake.logs.{site}/api/v2/logs"
    payload = [_to_datadog_entry(event, source=source, service=service, tags=tags) for event in events]
    headers = {
        "DD-API-KEY": api_key,
        "Content-Type": "application/json",
    }

    owns_client = client is None
    http = client or httpx.Client(timeout=timeout)
    try:
        response = http.post(url, json=payload, headers=headers)
    finally:
        if owns_client:
            http.close()

    if response.status_code >= 300:
        raise SiemPushError(VENDOR, response.status_code, response.text)
    return SiemPushResult(
        vendor=VENDOR,
        events_sent=len(events),
        http_status=response.status_code,
        endpoint=url,
    )


def _to_datadog_entry(
    event: dict[str, object],
    *,
    source: str,
    service: str,
    tags: tuple[str, ...],
) -> dict[str, object]:
    detector_id = event["vindicara"]["detector_id"]  # type: ignore[index]
    severity = event["vindicara"]["severity"]  # type: ignore[index]
    base_tags = [
        f"detector_id:{detector_id}",
        f"severity:{severity}",
        f"air_version:{event['air_version']}",
    ]
    base_tags.extend(tags)
    return {
        "ddsource": source,
        "service": service,
        "ddtags": ",".join(base_tags),
        "message": f"{detector_id} {event['vindicara']['title']}",  # type: ignore[index]
        **event,
    }
