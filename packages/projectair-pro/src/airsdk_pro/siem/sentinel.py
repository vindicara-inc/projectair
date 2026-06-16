"""Microsoft Sentinel push helper (Azure Log Analytics Data Collector API).

Uses the Log Analytics Data Collector API, which is the documented path
for getting custom logs into a Sentinel workspace. Authentication is
HMAC-SHA256 over a canonical string with the workspace shared key; this
module does the canonicalization and signing locally so the workspace
key never leaves the customer's process.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import UTC, datetime

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

VENDOR = "sentinel"
DEFAULT_LOG_TYPE = "VindicaraAIR"
API_VERSION = "2016-04-01"
SIGNING_METHOD = "POST"
CONTENT_TYPE = "application/json"
RESOURCE_PATH = "/api/logs"


@requires_pro(feature=SIEM_INTEGRATIONS_FEATURE)
def push_to_sentinel(
    report: ForensicReport,
    *,
    workspace_id: str,
    shared_key: str,
    log_type: str = DEFAULT_LOG_TYPE,
    min_severity: str | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    client: httpx.Client | None = None,
    now: datetime | None = None,
) -> SiemPushResult:
    """POST findings to a Microsoft Sentinel workspace via the Log Analytics Data Collector API.

    ``workspace_id`` is the GUID-shaped Log Analytics workspace ID;
    ``shared_key`` is the base64-encoded primary or secondary shared
    key (from "Agents management" in the Azure portal). The endpoint
    URL is derived as
    ``https://<workspace_id>.ods.opinsights.azure.com/api/logs?api-version=2016-04-01``.

    ``log_type`` becomes the custom-log table suffix (Sentinel appends
    ``_CL``). Default is ``VindicaraAIR`` so findings land in
    ``VindicaraAIR_CL``.

    The ``now`` parameter is for tests; production callers leave it None
    and the helper uses ``datetime.now(timezone.utc)``.

    Raises ``SiemConfigError`` for missing config and ``SiemPushError``
    for non-2xx responses.
    """
    if not workspace_id:
        raise SiemConfigError("Sentinel workspace_id is required")
    if not shared_key:
        raise SiemConfigError("Sentinel shared_key is required")
    if not log_type:
        raise SiemConfigError("Sentinel log_type is required")

    events = findings_above(report, min_severity)
    if not events:
        return SiemPushResult(vendor=VENDOR, events_sent=0, http_status=200, endpoint="")

    body = json.dumps(events).encode("utf-8")
    timestamp = (now or datetime.now(UTC)).strftime("%a, %d %b %Y %H:%M:%S GMT")
    signature = _build_signature(
        method=SIGNING_METHOD,
        content_length=len(body),
        content_type=CONTENT_TYPE,
        date=timestamp,
        resource=RESOURCE_PATH,
        shared_key=shared_key,
    )

    url = f"https://{workspace_id}.ods.opinsights.azure.com/api/logs?api-version={API_VERSION}"
    headers = {
        "Content-Type": CONTENT_TYPE,
        "Authorization": f"SharedKey {workspace_id}:{signature}",
        "Log-Type": log_type,
        "x-ms-date": timestamp,
        "time-generated-field": "",
    }

    owns_client = client is None
    http = client or httpx.Client(timeout=timeout)
    try:
        response = http.post(url, content=body, headers=headers)
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


def _build_signature(
    *,
    method: str,
    content_length: int,
    content_type: str,
    date: str,
    resource: str,
    shared_key: str,
) -> str:
    """Build the SharedKey authorization signature for the Data Collector API.

    Canonical string format (Microsoft documentation):
        ``"<method>\\n<content-length>\\n<content-type>\\nx-ms-date:<date>\\n<resource>"``

    The shared key is base64-decoded, used as the HMAC-SHA256 key over
    that canonical string, and the resulting digest is base64-encoded.
    """
    try:
        decoded_key = base64.b64decode(shared_key)
    except (ValueError, TypeError) as exc:
        raise SiemConfigError(f"Sentinel shared_key is not valid base64: {exc}") from exc
    canonical = (
        f"{method}\n{content_length}\n{content_type}\nx-ms-date:{date}\n{resource}"
    ).encode()
    digest = hmac.new(decoded_key, canonical, hashlib.sha256).digest()
    return base64.b64encode(digest).decode("ascii")
