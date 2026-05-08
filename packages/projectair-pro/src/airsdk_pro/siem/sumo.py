"""Sumo Logic Hosted HTTP Source push helper."""
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

VENDOR = "sumo"


@requires_pro(feature=SIEM_INTEGRATIONS_FEATURE)
def push_to_sumo(
    report: ForensicReport,
    *,
    http_source_url: str,
    category: str | None = None,
    host: str | None = None,
    name: str | None = None,
    min_severity: str | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    client: httpx.Client | None = None,
) -> SiemPushResult:
    """POST findings to a Sumo Logic Hosted HTTP Source.

    ``http_source_url`` is the full source URL Sumo issues for the
    collector (e.g. ``https://endpoint.collection.sumologic.com/receiver/v1/http/<token>``);
    the URL itself is the credential, so callers should treat it like a
    secret. The body is newline-delimited JSON, one finding per line --
    Sumo's preferred format for structured logs.

    The optional headers ``X-Sumo-Category``, ``X-Sumo-Host``, and
    ``X-Sumo-Name`` map onto Sumo's metadata fields when set.

    Raises ``SiemConfigError`` for missing config and ``SiemPushError``
    for non-2xx responses.
    """
    if not http_source_url:
        raise SiemConfigError("Sumo http_source_url is required")

    events = findings_above(report, min_severity)
    if not events:
        return SiemPushResult(vendor=VENDOR, events_sent=0, http_status=200, endpoint="")

    body = "\n".join(json.dumps(event) for event in events)
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if category:
        headers["X-Sumo-Category"] = category
    if host:
        headers["X-Sumo-Host"] = host
    if name:
        headers["X-Sumo-Name"] = name

    owns_client = client is None
    http = client or httpx.Client(timeout=timeout)
    try:
        response = http.post(http_source_url, content=body, headers=headers)
    finally:
        if owns_client:
            http.close()

    if response.status_code >= 300:
        raise SiemPushError(VENDOR, response.status_code, response.text)
    return SiemPushResult(
        vendor=VENDOR,
        events_sent=len(events),
        http_status=response.status_code,
        endpoint=http_source_url,
    )
