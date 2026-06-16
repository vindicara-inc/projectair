"""Push a signed Intent Capsule chain to a customer-owned S3 bucket.

``boto3`` is an optional dependency (install ``projectair-pro[s3]``).
When it is not importable this module's ``push_chain_to_s3`` raises a
clean ``CloudConfigError`` directing the caller to the install command,
instead of an ImportError at import time.
"""
from __future__ import annotations

import json
from typing import Any

from airsdk.types import AgDRRecord

from airsdk_pro.cloud.types import (
    AIR_CLOUD_CLIENT_FEATURE,
    CloudConfigError,
    CloudPushResult,
)
from airsdk_pro.gate import requires_pro

TARGET = "s3"
DEFAULT_CONTENT_TYPE = "application/x-ndjson"


@requires_pro(feature=AIR_CLOUD_CLIENT_FEATURE)
def push_chain_to_s3(
    records: list[AgDRRecord],
    *,
    bucket: str,
    key: str,
    region: str | None = None,
    content_type: str = DEFAULT_CONTENT_TYPE,
    sse: str | None = "AES256",
    metadata: dict[str, str] | None = None,
    client: Any = None,
) -> CloudPushResult:
    """Upload ``records`` as a JSONL object to ``s3://bucket/key``.

    Server-side encryption defaults to ``AES256``; pass ``sse=None``
    only if your bucket policy explicitly forbids SSE on PutObject.
    ``metadata`` is for tenant / system-id breadcrumbs the customer's
    indexing pipeline cares about; do not put secrets in it (S3 object
    metadata is plaintext at rest from the IAM caller's perspective).

    Pass ``client`` to use a pre-built ``boto3.client('s3')``; otherwise
    one is constructed against the default credential chain.

    Raises ``CloudConfigError`` for missing config or missing boto3.
    """
    if not bucket:
        raise CloudConfigError("S3 bucket is required")
    if not key:
        raise CloudConfigError("S3 key is required")
    if not records:
        return CloudPushResult(
            target=TARGET, records_sent=0, bytes_sent=0, endpoint=f"s3://{bucket}/{key}"
        )

    s3 = client or _build_default_client(region=region)
    body = _serialize_chain(records)

    put_kwargs: dict[str, Any] = {
        "Bucket": bucket,
        "Key": key,
        "Body": body,
        "ContentType": content_type,
    }
    if sse:
        put_kwargs["ServerSideEncryption"] = sse
    if metadata:
        put_kwargs["Metadata"] = metadata

    s3.put_object(**put_kwargs)
    return CloudPushResult(
        target=TARGET,
        records_sent=len(records),
        bytes_sent=len(body),
        endpoint=f"s3://{bucket}/{key}",
    )


def _build_default_client(*, region: str | None) -> Any:
    try:
        import boto3
    except ImportError as exc:
        raise CloudConfigError(
            "S3 push requires boto3. Install projectair-pro with the S3 extra: "
            "pip install 'projectair-pro[s3]'"
        ) from exc
    if region:
        return boto3.client("s3", region_name=region)
    return boto3.client("s3")


def _serialize_chain(records: list[AgDRRecord]) -> bytes:
    lines = [json.dumps(record.model_dump(mode="json"), separators=(",", ":")) for record in records]
    return ("\n".join(lines) + "\n").encode("utf-8")
