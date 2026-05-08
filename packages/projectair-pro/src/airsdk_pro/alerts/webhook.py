"""Generic alert-to-webhook helper.

Distinct from ``airsdk_pro.cloud.push_chain_to_webhook``: that one
delivers the **full chain** as JSONL for archival; this one delivers a
**summary alert** payload (qualifying findings + chain status) for an
incident-response receiver. A customer can configure both side-by-side
without conflict.
"""
from __future__ import annotations

import hashlib
import hmac
import json

import httpx
from airsdk.types import ForensicReport

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

TARGET = "webhook"
SIGNATURE_HEADER = "X-Vindicara-Alert-Signature"
"""HMAC-SHA256 signature header. Format: ``sha256=<lowercase hex digest>``."""


@requires_pro(feature=INCIDENT_WORKFLOWS_FEATURE)
def alert_to_webhook(
    report: ForensicReport,
    *,
    url: str,
    secret: str | None = None,
    extra_headers: dict[str, str] | None = None,
    min_severity: str = DEFAULT_MIN_SEVERITY,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    client: httpx.Client | None = None,
) -> AlertResult:
    """POST a JSON alert summary to a customer-owned HTTPS webhook.

    Body shape::

        {
          "vendor": "vindicara",
          "kind": "alert",
          "report_id": "...",
          "source_log": "...",
          "air_version": "...",
          "chain_status": "ok|tampered|broken_chain",
          "records_verified": <int>,
          "min_severity": "high",
          "findings": [
            {"detector_id": "...", "title": "...", "severity": "...",
             "step_id": "...", "step_index": <int>, "description": "..."},
            ...
          ]
        }

    When ``secret`` is set, the helper signs the body with HMAC-SHA256
    and sends the digest as ``X-Vindicara-Alert-Signature: sha256=<hex>``.
    Same envelope pattern as the cloud-client webhook helper, distinct
    header name so receivers can route alerts and chain-archive pushes
    separately.

    Raises ``AlertConfigError`` for missing config and ``AlertPushError``
    for non-2xx responses.
    """
    if not url:
        raise AlertConfigError("webhook url is required")
    qualifying = filter_findings(report.findings, min_severity)
    if not qualifying:
        return AlertResult(target=TARGET, findings_alerted=0, http_status=200, endpoint=url)

    payload = {
        "vendor": "vindicara",
        "kind": "alert",
        "report_id": report.report_id,
        "source_log": report.source_log,
        "air_version": report.air_version,
        "chain_status": report.verification.status.value,
        "records_verified": report.verification.records_verified,
        "min_severity": min_severity,
        "findings": [
            {
                "detector_id": f.detector_id,
                "title": f.title,
                "severity": f.severity,
                "step_id": f.step_id,
                "step_index": f.step_index,
                "description": f.description,
            }
            for f in qualifying
        ],
    }
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if extra_headers:
        for key, value in extra_headers.items():
            normalised = key.lower()
            if normalised in {"content-type", SIGNATURE_HEADER.lower()}:
                raise AlertConfigError(
                    f"extra_headers may not override {key!r}; the helper sets it."
                )
            headers[key] = value
    if secret:
        digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
        headers[SIGNATURE_HEADER] = f"sha256={digest}"

    owns_client = client is None
    http = client or httpx.Client(timeout=timeout)
    try:
        response = http.post(url, content=body, headers=headers)
    finally:
        if owns_client:
            http.close()

    if response.status_code >= 300:
        raise AlertPushError(TARGET, response.status_code, response.text)
    return AlertResult(
        target=TARGET,
        findings_alerted=len(qualifying),
        http_status=response.status_code,
        endpoint=url,
    )
