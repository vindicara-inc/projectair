"""Push a signed Intent Capsule chain to the hosted Vindicara AIR Cloud ingest service.

Wraps the W3.7 ``POST /v1/capsules/bulk`` endpoint behind a thin
helper. ``push_chain_to_air_cloud(records, *, base_url, api_key)``
sends every record in a single newline-delimited JSON request and
returns a :class:`CloudPushResult` shaped like the other cloud
destinations. Authentication is the workspace's API key, sent as the
``X-API-Key`` header.

The endpoint accepts already-signed records and verifies each
signature server-side before persisting; tampered records are
rejected with HTTP 422.
"""
from __future__ import annotations

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

TARGET = "air_cloud"
DEFAULT_BASE_URL = "https://cloud.vindicara.io"
INGEST_PATH = "/v1/capsules/bulk"


@requires_pro(feature=AIR_CLOUD_CLIENT_FEATURE)
def push_chain_to_air_cloud(
    records: list[AgDRRecord],
    *,
    api_key: str,
    base_url: str = DEFAULT_BASE_URL,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    client: httpx.Client | None = None,
) -> CloudPushResult:
    """POST a chain of records to the hosted AIR Cloud bulk ingest endpoint.

    ``api_key`` is the workspace's API key (``air_<32 hex>``); it is
    sent as ``X-API-Key`` and authenticates the bearer as the workspace.
    ``base_url`` is the cloud service base URL; defaults to the public
    ``https://cloud.vindicara.io`` deployment.

    Raises ``CloudConfigError`` for missing config and ``CloudPushError``
    for non-2xx responses.
    """
    if not api_key:
        raise CloudConfigError("AIR Cloud api_key is required")
    if not base_url:
        raise CloudConfigError("AIR Cloud base_url is required")

    if not records:
        return CloudPushResult(
            target=TARGET,
            records_sent=0,
            bytes_sent=0,
            endpoint=f"{base_url}{INGEST_PATH}",
        )

    body = _serialize_chain(records)
    url = f"{base_url.rstrip('/')}{INGEST_PATH}"
    headers = {
        "Content-Type": "application/x-ndjson",
        "X-API-Key": api_key,
    }

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


__all__ = ["DEFAULT_BASE_URL", "INGEST_PATH", "push_chain_to_air_cloud"]
