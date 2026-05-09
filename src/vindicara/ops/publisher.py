"""Publish anchored ops chains to a public-read S3 bucket as redacted JSONL.

Designed to run as a cron Lambda on a 30-60 second cadence. Scans DDB for
chains where every record has ``anchored=True`` and at least one record
has ``published=False``; for each such chain, redacts every record via
:mod:`vindicara.ops.redaction`, writes the chain to S3 at
``ops-chain/<chain_id>.jsonl``, updates ``manifest.json`` with the latest
log index, and marks the records ``published=True`` in DDB.

The published JSONL never carries the original Ed25519 signature on each
record; the redacted payload is no longer the bytes the signature covered.
The Sigstore Rekor anchor over the chain root is what verifiers check.
"""
from __future__ import annotations

import json
import logging
import os
from typing import TYPE_CHECKING, Final

from vindicara.ops.redaction import redact_record

if TYPE_CHECKING:
    from mypy_boto3_dynamodb.service_resource import Table
    from mypy_boto3_s3.service_resource import Bucket


_log = logging.getLogger(__name__)

CHAIN_PREFIX: Final[str] = "ops-chain"
MANIFEST_KEY: Final[str] = f"{CHAIN_PREFIX}/manifest.json"
MAX_CHAINS_PER_INVOCATION: Final[int] = 100


def scan_publishable_chains(table: Table) -> dict[str, list[dict[str, object]]]:
    """Return ``{chain_id: [items in ord order]}`` for chains ready to publish.

    A chain is publishable when every record in it is anchored and at
    least one record has ``published=False``. We over-fetch (every
    anchored unpublished item) and then filter, because DDB cannot
    express the cross-record predicate "every record in this chain is
    anchored" directly.
    """
    chains: dict[str, list[dict[str, object]]] = {}
    response = table.scan(
        FilterExpression="anchored = :true AND published = :false",
        ExpressionAttributeValues={":true": True, ":false": False},
    )
    for item in response.get("Items", []):
        chain_id = str(item["chain_id"])
        chains.setdefault(chain_id, []).append(dict(item))

    while "LastEvaluatedKey" in response:
        response = table.scan(
            FilterExpression="anchored = :true AND published = :false",
            ExpressionAttributeValues={":true": True, ":false": False},
            ExclusiveStartKey=response["LastEvaluatedKey"],
        )
        for item in response.get("Items", []):
            chain_id = str(item["chain_id"])
            chains.setdefault(chain_id, []).append(dict(item))

    for chain_id, items in chains.items():
        items.sort(key=lambda i: str(i["ord"]))
        chains[chain_id] = items
    return chains


def render_chain_jsonl(chain_id: str, items: list[dict[str, object]]) -> str:
    """Redact each record and emit one JSONL string for the whole chain."""
    lines: list[str] = []
    for item in items:
        record = json.loads(str(item["record_json"]))
        record["ord"] = item["ord"]
        record["chain_id"] = chain_id
        if "rekor_log_index" in item:
            record["rekor_log_index"] = item["rekor_log_index"]
        redacted = redact_record(record)
        lines.append(json.dumps(redacted, sort_keys=True, separators=(",", ":"), default=str))
    return "\n".join(lines) + "\n"


def publish_chain(bucket: Bucket, chain_id: str, items: list[dict[str, object]]) -> str:
    """Write one chain's JSONL to S3 and return the object key."""
    body = render_chain_jsonl(chain_id, items).encode("utf-8")
    key = f"{CHAIN_PREFIX}/{chain_id}.jsonl"
    bucket.put_object(
        Key=key,
        Body=body,
        ContentType="application/x-ndjson",
        CacheControl="public, max-age=60",
    )
    _log.info(
        "vindicara.ops.publisher.published",
        extra={"chain_id": chain_id, "key": key, "records": len(items)},
    )
    return key


def update_manifest(bucket: Bucket, latest_log_index: int) -> None:
    """Write a tiny manifest the public verify page reads."""
    manifest = {
        "latest_rekor_log_index": int(latest_log_index),
        "rekor_url": f"https://search.sigstore.dev/?logIndex={int(latest_log_index)}",
        "chain_prefix": CHAIN_PREFIX,
    }
    bucket.put_object(
        Key=MANIFEST_KEY,
        Body=json.dumps(manifest, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8"),
        ContentType="application/json",
        CacheControl="public, max-age=30",
    )


def mark_chain_published(table: Table, items: list[dict[str, object]]) -> None:
    """Flip ``published=True`` on every record of a chain."""
    with table.batch_writer() as batch:
        for item in items:
            updated = dict(item)
            updated["published"] = True
            batch.put_item(Item=updated)


def run_once(table: Table, bucket: Bucket) -> int:
    """Publish every anchored-but-unpublished chain. Returns the count."""
    chains = scan_publishable_chains(table)
    published_count = 0
    latest_log_index: int | None = None
    for chain_id, items in chains.items():
        if published_count >= MAX_CHAINS_PER_INVOCATION:
            _log.info(
                "vindicara.ops.publisher.cap_reached",
                extra={"cap": MAX_CHAINS_PER_INVOCATION, "remaining": len(chains) - published_count},
            )
            break
        try:
            publish_chain(bucket, chain_id, items)
            mark_chain_published(table, items)
            published_count += 1
            for item in items:
                idx = item.get("rekor_log_index")
                if idx is not None and (latest_log_index is None or int(idx) > latest_log_index):
                    latest_log_index = int(idx)
        except Exception as exc:
            _log.warning(
                "vindicara.ops.publisher.publish_failed chain_id=%s error=%s",
                chain_id,
                exc,
            )

    if latest_log_index is not None:
        try:
            update_manifest(bucket, latest_log_index)
        except Exception as exc:
            _log.warning("vindicara.ops.publisher.manifest_failed", extra={"error": str(exc)})
    return published_count


def lambda_handler(event: dict[str, object], context: object) -> dict[str, int]:
    """Cron-Lambda entry point. Reads table + bucket from environment."""
    del event, context
    import boto3

    table_name = os.environ["VINDICARA_OPS_CHAIN_TABLE"]
    bucket_name = os.environ["VINDICARA_OPS_CHAIN_BUCKET"]
    region = os.environ.get("AWS_REGION", "us-west-2")

    dynamodb = boto3.resource("dynamodb", region_name=region)
    s3 = boto3.resource("s3", region_name=region)
    table = dynamodb.Table(table_name)
    bucket = s3.Bucket(bucket_name)

    published = run_once(table, bucket)
    return {"published": published}
