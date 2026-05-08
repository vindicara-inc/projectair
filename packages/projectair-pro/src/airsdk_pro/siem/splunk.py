"""Splunk HTTP Event Collector (HEC) push helper."""
from __future__ import annotations

import json

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

VENDOR = "splunk_hec"
DEFAULT_SOURCETYPE = "vindicara_air:finding"
DEFAULT_SOURCE = "vindicara-air"


@requires_pro(feature=SIEM_INTEGRATIONS_FEATURE)
def push_to_splunk_hec(
    report: ForensicReport,
    *,
    hec_url: str,
    hec_token: str,
    sourcetype: str = DEFAULT_SOURCETYPE,
    source: str = DEFAULT_SOURCE,
    index: str | None = None,
    min_severity: str | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    client: httpx.Client | None = None,
) -> SiemPushResult:
    """POST findings to a Splunk HTTP Event Collector endpoint.

    ``hec_url`` is the full HEC endpoint, including the ``/services/collector``
    path (e.g. ``https://hec.splunkcloud.com:8088/services/collector``).
    Authentication is via the ``Authorization: Splunk <token>`` header.
    The HEC payload format is "concatenated JSON" -- one event per
    ``{"event": ..., "sourcetype": ..., ...}`` object, NOT a JSON array;
    this helper constructs that format correctly.

    Raises ``SiemConfigError`` for missing config and ``SiemPushError``
    for non-2xx responses.
    """
    if not hec_url:
        raise SiemConfigError("Splunk hec_url is required")
    if not hec_token:
        raise SiemConfigError("Splunk hec_token is required")

    events = findings_above(report, min_severity)
    if not events:
        return SiemPushResult(vendor=VENDOR, events_sent=0, http_status=200, endpoint="")

    body_parts: list[str] = []
    for event in events:
        envelope: dict[str, object] = {
            "event": event,
            "sourcetype": sourcetype,
            "source": source,
        }
        if index:
            envelope["index"] = index
        body_parts.append(json.dumps(envelope))
    body = "\n".join(body_parts)

    headers = {
        "Authorization": f"Splunk {hec_token}",
        "Content-Type": "application/json",
    }

    owns_client = client is None
    http = client or httpx.Client(timeout=timeout)
    try:
        response = http.post(hec_url, content=body, headers=headers)
    finally:
        if owns_client:
            http.close()

    if response.status_code >= 300:
        raise SiemPushError(VENDOR, response.status_code, response.text)
    return SiemPushResult(
        vendor=VENDOR,
        events_sent=len(events),
        http_status=response.status_code,
        endpoint=hec_url,
    )
