"""Push a signed Intent Capsule chain to a customer-owned HTTPS webhook."""
from __future__ import annotations

import hashlib
import hmac
import json

import httpx
from airsdk.types import AgDRRecord

from airsdk_pro.cloud.types import (
    AIR_CLOUD_CLIENT_FEATURE,
    DEFAULT_TIMEOUT_SECONDS,
    CloudConfigError,
    CloudPushError,
    CloudPushResult,
)
from airsdk_pro.gate import requires_pro

TARGET = "webhook"
SIGNATURE_HEADER = "X-Vindicara-Signature"
"""HMAC-SHA256 signature header name. Format: ``sha256=<lowercase hex digest>``."""


@requires_pro(feature=AIR_CLOUD_CLIENT_FEATURE)
def push_chain_to_webhook(
    records: list[AgDRRecord],
    *,
    url: str,
    secret: str | None = None,
    extra_headers: dict[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    client: httpx.Client | None = None,
) -> CloudPushResult:
    """POST a JSONL representation of ``records`` to ``url``.

    The body is newline-delimited JSON: one record per line, in chain
    order. Every record's existing BLAKE3 hash and Ed25519 signature
    survive the round-trip; the receiver can re-verify the chain
    offline using the same OSS verifier (`air trace`).

    When ``secret`` is set, the helper computes
    ``HMAC-SHA256(secret, body)`` and sends it as
    ``X-Vindicara-Signature: sha256=<hex>``. The receiver should
    independently compute the same HMAC and reject any request whose
    header does not match. This is the same pattern GitHub, Stripe, and
    Slack use for their outgoing webhooks; it makes the webhook
    endpoint safe to expose on the public internet without requiring
    the receiver to terminate mTLS.

    ``extra_headers`` is for routing / metadata only (e.g. tenant
    routing). It must not include ``Content-Type`` or the signature
    header, which the helper sets itself.

    Raises ``CloudConfigError`` for missing config and ``CloudPushError``
    for non-2xx responses.
    """
    if not url:
        raise CloudConfigError("webhook url is required")
    if not records:
        return CloudPushResult(target=TARGET, records_sent=0, bytes_sent=0, endpoint=url)

    body = _serialize_chain(records)
    headers: dict[str, str] = {"Content-Type": "application/x-ndjson"}
    if extra_headers:
        for key, value in extra_headers.items():
            normalised = key.lower()
            if normalised in {"content-type", SIGNATURE_HEADER.lower()}:
                raise CloudConfigError(
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
        raise CloudPushError(TARGET, response.status_code, response.text)
    return CloudPushResult(
        target=TARGET,
        records_sent=len(records),
        bytes_sent=len(body),
        endpoint=url,
    )


def _serialize_chain(records: list[AgDRRecord]) -> bytes:
    lines = [json.dumps(record.model_dump(mode="json"), separators=(",", ":")) for record in records]
    return ("\n".join(lines) + "\n").encode("utf-8")
