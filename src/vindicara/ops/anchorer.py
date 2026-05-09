"""Anchor complete-but-unanchored ops chains to Sigstore Rekor.

Designed to run as a cron Lambda on a 30-60 second cadence. The trade-off
between cadence and latency-to-anchor is just a CDK config change.

Anchoring policy:

- A chain is *complete* when the most recent record in it is older than
  :data:`COMPLETION_QUIET_SECONDS`. We do not require a special terminal
  record kind: each chain corresponds to a single Lambda invocation
  (partition key is the Lambda request id), and a Lambda that has not
  emitted in 5 seconds is reliably done.
- A chain is *unanchored* when its last record's ``anchored`` flag is
  ``False``. We only check the last record because the anchorer marks
  every record of a chain in one batch_write at the end; this avoids
  partial-anchor states.
- The anchored root is the BLAKE3 ``content_hash`` of the last record in
  the chain, encoded to bytes and then SHA-256'd. This matches what
  :mod:`airsdk.anchoring.orchestrator` does for customer chains, so
  ``air verify-public`` walks Vindicara's published chain identically to
  any customer's.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from typing import TYPE_CHECKING, Final

from airsdk.anchoring.identity import load_anchoring_key
from airsdk.anchoring.rekor import RekorClient

if TYPE_CHECKING:
    from airsdk.types import RekorAnchor
    from mypy_boto3_dynamodb.service_resource import Table


_log = logging.getLogger(__name__)

COMPLETION_QUIET_SECONDS: Final[int] = 5
"""A chain is treated as complete when its most recent record is older
than this many seconds. Below this we wait, on the assumption that the
Lambda is still running."""

MAX_CHAINS_PER_INVOCATION: Final[int] = 50
"""Soft cap on the number of chains anchored per cron invocation. Limits
the worst-case Lambda duration if a backlog accumulates."""


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _epoch_from_iso(timestamp: str) -> float:
    """Parse the ISO-8601 timestamp on each record into seconds since epoch."""
    from datetime import datetime
    return datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()


def scan_unanchored_chains(table: Table) -> dict[str, list[dict[str, object]]]:
    """Return ``{chain_id: [items in ord order]}`` for chains with any unanchored records.

    DynamoDB Scan is fine at our volume; if traffic grows the table can
    later carry a GSI on ``anchored`` and we switch to Query. Until then,
    Scan is simpler.
    """
    chains: dict[str, list[dict[str, object]]] = {}
    response = table.scan(
        FilterExpression="anchored = :false",
        ExpressionAttributeValues={":false": False},
    )
    for item in response.get("Items", []):
        chain_id = str(item["chain_id"])
        chains.setdefault(chain_id, []).append(dict(item))

    while "LastEvaluatedKey" in response:
        response = table.scan(
            FilterExpression="anchored = :false",
            ExpressionAttributeValues={":false": False},
            ExclusiveStartKey=response["LastEvaluatedKey"],
        )
        for item in response.get("Items", []):
            chain_id = str(item["chain_id"])
            chains.setdefault(chain_id, []).append(dict(item))

    for chain_id, items in chains.items():
        items.sort(key=lambda i: str(i["ord"]))
        chains[chain_id] = items
    return chains


def chain_is_complete(items: list[dict[str, object]], now_epoch: float) -> bool:
    """A chain is complete when the most recent record is quiet for COMPLETION_QUIET_SECONDS."""
    if not items:
        return False
    last_ts = _epoch_from_iso(str(items[-1]["timestamp"]))
    return (now_epoch - last_ts) >= COMPLETION_QUIET_SECONDS


def anchor_chain(
    rekor: RekorClient,
    chain_id: str,
    items: list[dict[str, object]],
) -> RekorAnchor:
    """Anchor one complete chain to Rekor and return the resulting anchor."""
    last_record_json = json.loads(str(items[-1]["record_json"]))
    chain_root_hex = str(last_record_json["content_hash"])
    chain_root_bytes = bytes.fromhex(chain_root_hex)
    rekor_digest = _sha256(chain_root_bytes)
    anchor = rekor.anchor(rekor_digest)
    _log.info(
        "vindicara.ops.anchorer.anchored",
        extra={
            "chain_id": chain_id,
            "rekor_log_index": anchor.log_index,
            "records": len(items),
        },
    )
    return anchor


def mark_chain_anchored(
    table: Table,
    chain_id: str,
    items: list[dict[str, object]],
    anchor: RekorAnchor,
) -> None:
    """Mark every record of a chain as anchored in one batch."""
    with table.batch_writer() as batch:
        for item in items:
            updated = dict(item)
            updated["anchored"] = True
            updated["rekor_log_index"] = anchor.log_index
            batch.put_item(Item=updated)
    _log.info(
        "vindicara.ops.anchorer.marked_anchored",
        extra={"chain_id": chain_id, "records": len(items)},
    )


def run_once(table: Table, rekor: RekorClient) -> int:
    """Anchor every complete-but-unanchored chain. Returns the count anchored."""
    now_epoch = time.time()
    chains = scan_unanchored_chains(table)
    anchored_count = 0
    for chain_id, items in chains.items():
        if anchored_count >= MAX_CHAINS_PER_INVOCATION:
            _log.info(
                "vindicara.ops.anchorer.cap_reached",
                extra={"cap": MAX_CHAINS_PER_INVOCATION, "remaining": len(chains) - anchored_count},
            )
            break
        if not chain_is_complete(items, now_epoch):
            continue
        try:
            anchor = anchor_chain(rekor, chain_id, items)
            mark_chain_anchored(table, chain_id, items, anchor)
            anchored_count += 1
        except Exception as exc:
            _log.warning(
                "vindicara.ops.anchorer.anchor_failed",
                extra={"chain_id": chain_id, "error": str(exc)},
            )
    return anchored_count


def _hydrate_anchoring_key_from_secret(region: str) -> None:
    """If VINDICARA_ANCHORING_KEY_SECRET_ARN is set, fetch the secret value
    and stage it as AIRSDK_ANCHORING_KEY so load_anchoring_key picks it up.

    No-op when the env var is unset, which keeps local dev working with a
    file-system key at ``~/.config/projectair/anchoring_key.pem``.
    """
    secret_arn = os.environ.get("VINDICARA_ANCHORING_KEY_SECRET_ARN")
    if not secret_arn:
        return
    if os.environ.get("AIRSDK_ANCHORING_KEY"):
        return
    import boto3

    client = boto3.client("secretsmanager", region_name=region)
    response = client.get_secret_value(SecretId=secret_arn)
    secret_string = response.get("SecretString", "")
    if not secret_string:
        raise RuntimeError(f"secret {secret_arn} has no SecretString")
    os.environ["AIRSDK_ANCHORING_KEY"] = secret_string


def lambda_handler(event: dict[str, object], context: object) -> dict[str, int]:
    """Cron-Lambda entry point. Reads table name + Rekor URL from environment."""
    del event, context
    import boto3

    table_name = os.environ["VINDICARA_OPS_CHAIN_TABLE"]
    rekor_url = os.environ.get("VINDICARA_REKOR_URL", "https://rekor.sigstore.dev")
    region = os.environ.get("AWS_REGION", "us-west-2")

    _hydrate_anchoring_key_from_secret(region)

    dynamodb = boto3.resource("dynamodb", region_name=region)
    table = dynamodb.Table(table_name)
    signing_key = load_anchoring_key()
    rekor = RekorClient(signing_key=signing_key, rekor_url=rekor_url)

    anchored = run_once(table, rekor)
    return {"anchored": anchored}
