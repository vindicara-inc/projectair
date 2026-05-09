"""Tests for ``vindicara.ops.publisher``."""
from __future__ import annotations

import json
from decimal import Decimal
from typing import Any

import pytest

from vindicara.ops.publisher import (
    CHAIN_PREFIX,
    MANIFEST_KEY,
    publish_chain,
    render_chain_jsonl,
    run_once,
    scan_publishable_chains,
    update_manifest,
)


class FakeBatchWriter:
    def __init__(self, table: FakeTable) -> None:
        self._table = table

    def __enter__(self) -> FakeBatchWriter:
        return self

    def __exit__(self, *args: Any) -> None:
        del args

    def put_item(self, *, Item: dict[str, Any]) -> None:  # noqa: N803 - boto3 API parity
        for idx, existing in enumerate(self._table.items):
            if existing["chain_id"] == Item["chain_id"] and existing["ord"] == Item["ord"]:
                self._table.items[idx] = Item
                return
        self._table.items.append(Item)


class FakeTable:
    def __init__(self) -> None:
        self.items: list[dict[str, Any]] = []

    def scan(
        self,
        *,
        FilterExpression: str = "",  # noqa: N803
        ExpressionAttributeValues: dict[str, Any] | None = None,  # noqa: N803
        ExclusiveStartKey: dict[str, Any] | None = None,  # noqa: N803
    ) -> dict[str, Any]:
        del FilterExpression, ExclusiveStartKey
        values = ExpressionAttributeValues or {}
        target_anchored = values.get(":true", True)
        target_published = values.get(":false", False)
        matches = [
            item
            for item in self.items
            if item["anchored"] == target_anchored and item["published"] == target_published
        ]
        return {"Items": matches}

    def batch_writer(self) -> FakeBatchWriter:
        return FakeBatchWriter(self)


class FakeBucket:
    def __init__(self) -> None:
        self.objects: dict[str, dict[str, Any]] = {}
        self.fail_next: Exception | None = None

    def put_object(
        self,
        *,
        Key: str,  # noqa: N803
        Body: bytes,  # noqa: N803
        ContentType: str = "",  # noqa: N803
        CacheControl: str = "",  # noqa: N803
    ) -> None:
        if self.fail_next is not None:
            exc = self.fail_next
            self.fail_next = None
            raise exc
        self.objects[Key] = {
            "Body": Body,
            "ContentType": ContentType,
            "CacheControl": CacheControl,
        }


def _make_record_json(content_hash: str, prev_hash: str = "0" * 64, kind: str = "tool_start") -> str:
    return json.dumps({
        "version": "0.4",
        "step_id": f"step-{content_hash[:6]}",
        "timestamp": "2026-05-08T15:00:00Z",
        "kind": kind,
        "payload": {"tool_name": "vindicara.api.request"},
        "prev_hash": prev_hash,
        "content_hash": content_hash,
        "signature": "sig",
        "signer_key": "pk",
    })


def _add_chain(
    table: FakeTable,
    chain_id: str,
    *,
    count: int = 2,
    anchored: bool = True,
    published: bool = False,
    rekor_log_index: int = 1_000_000,
) -> None:
    last_hash = "0" * 64
    for ord_idx in range(count):
        new_hash = f"{ord_idx + 1:02x}" + "00" * 31
        table.items.append({
            "chain_id": chain_id,
            "ord": f"{ord_idx:06d}",
            "step_id": f"step-{ord_idx}",
            "kind": "tool_start" if ord_idx % 2 == 0 else "tool_end",
            "timestamp": "2026-05-08T15:00:00Z",
            "record_json": _make_record_json(new_hash, last_hash),
            "anchored": anchored,
            "published": published,
            "rekor_log_index": rekor_log_index,
        })
        last_hash = new_hash


def test_scan_returns_only_anchored_unpublished() -> None:
    table = FakeTable()
    _add_chain(table, "ready", anchored=True, published=False)
    _add_chain(table, "already", anchored=True, published=True)
    _add_chain(table, "stale", anchored=False, published=False)

    chains = scan_publishable_chains(table)  # type: ignore[arg-type]

    assert "ready" in chains
    assert "already" not in chains
    assert "stale" not in chains


def test_render_chain_jsonl_emits_one_line_per_record_with_redaction() -> None:
    table = FakeTable()
    _add_chain(table, "chain-A", count=3)
    items = scan_publishable_chains(table)["chain-A"]  # type: ignore[arg-type]

    rendered = render_chain_jsonl("chain-A", items)

    lines = rendered.strip().split("\n")
    assert len(lines) == 3
    for line in lines:
        record = json.loads(line)
        assert record["chain_id"] == "chain-A"
        assert record["rekor_log_index"] == 1_000_000
        assert "signature" not in record
        assert record["payload"]["tool_name"].startswith("blake3:")


def test_publish_chain_writes_to_expected_s3_key() -> None:
    table = FakeTable()
    _add_chain(table, "chain-A", count=2)
    items = scan_publishable_chains(table)["chain-A"]  # type: ignore[arg-type]
    bucket = FakeBucket()

    key = publish_chain(bucket, "chain-A", items)  # type: ignore[arg-type]

    assert key == f"{CHAIN_PREFIX}/chain-A.jsonl"
    assert key in bucket.objects
    assert bucket.objects[key]["ContentType"] == "application/x-ndjson"
    body_text = bucket.objects[key]["Body"].decode()
    lines = [line for line in body_text.split("\n") if line]
    assert len(lines) == 2


def test_update_manifest_writes_latest_log_index() -> None:
    bucket = FakeBucket()
    update_manifest(bucket, latest_log_index=1_465_403_522)  # type: ignore[arg-type]

    assert MANIFEST_KEY in bucket.objects
    body = json.loads(bucket.objects[MANIFEST_KEY]["Body"])
    assert body["latest_rekor_log_index"] == 1_465_403_522
    assert "1465403522" in body["rekor_url"]


def test_run_once_publishes_marks_and_updates_manifest() -> None:
    table = FakeTable()
    _add_chain(table, "chain-A", count=2, rekor_log_index=999)
    _add_chain(table, "chain-B", count=2, rekor_log_index=1001)
    bucket = FakeBucket()

    published = run_once(table, bucket)  # type: ignore[arg-type]

    assert published == 2
    assert all(item["published"] for item in table.items)
    assert f"{CHAIN_PREFIX}/chain-A.jsonl" in bucket.objects
    assert f"{CHAIN_PREFIX}/chain-B.jsonl" in bucket.objects
    manifest = json.loads(bucket.objects[MANIFEST_KEY]["Body"])
    assert manifest["latest_rekor_log_index"] == 1001


def test_run_once_with_no_chains_does_nothing() -> None:
    table = FakeTable()
    bucket = FakeBucket()
    assert run_once(table, bucket) == 0  # type: ignore[arg-type]
    assert MANIFEST_KEY not in bucket.objects


def test_publish_failure_does_not_mark_published() -> None:
    table = FakeTable()
    _add_chain(table, "chain-A", count=2)
    bucket = FakeBucket()
    bucket.fail_next = RuntimeError("simulated S3 outage")

    run_once(table, bucket)  # type: ignore[arg-type]

    assert all(not item["published"] for item in table.items)


@pytest.mark.parametrize("record_count", [1, 5, 50])
def test_render_jsonl_handles_various_chain_lengths(record_count: int) -> None:
    table = FakeTable()
    _add_chain(table, "chain", count=record_count)
    items = scan_publishable_chains(table)["chain"]  # type: ignore[arg-type]
    rendered = render_chain_jsonl("chain", items)
    lines = [line for line in rendered.split("\n") if line]
    assert len(lines) == record_count


def test_render_jsonl_survives_decimal_from_dynamodb() -> None:
    """DynamoDB returns numbers as ``Decimal``. ``json.dumps`` must not crash."""
    table = FakeTable()
    _add_chain(table, "chain", count=2, rekor_log_index=Decimal(1_500_000_000))  # type: ignore[arg-type]
    items = scan_publishable_chains(table)["chain"]  # type: ignore[arg-type]
    rendered = render_chain_jsonl("chain", items)
    lines = [line for line in rendered.split("\n") if line]
    assert len(lines) == 2
    parsed = json.loads(lines[0])
    assert "rekor_log_index" in parsed
