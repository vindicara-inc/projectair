"""Local end-to-end smoke test for the Vindicara ops chain.

Runs the full pipeline against in-memory fakes for DDB, S3, and Rekor:

  AIRRecorder ──► DDBTransport ──► [FakeTable]
                                       │
                                       ▼
                                  anchorer.run_once
                                       │
                                       ▼
                                  publisher.run_once
                                       │
                                       ▼
                                  [FakeBucket published JSONL]

This is the smoke test we run before each CDK deploy. The deployed
pipeline is then exercised by driving real synthetic traffic through
the API Lambda; that's a separate scripts/soak_ops_chain.py that lives
once the stack is deployed.
"""
from __future__ import annotations

import json
import sys
import time
from datetime import UTC, datetime, timedelta
from typing import Any

from vindicara.ops.anchorer import COMPLETION_QUIET_SECONDS
from vindicara.ops.anchorer import run_once as anchor_run_once
from vindicara.ops.publisher import CHAIN_PREFIX, MANIFEST_KEY
from vindicara.ops.publisher import run_once as publish_run_once
from vindicara.ops.recorder import request_chain


class FakeBatchWriter:
    def __init__(self, table: FakeTable) -> None:
        self._table = table

    def __enter__(self) -> FakeBatchWriter:
        return self

    def __exit__(self, *args: Any) -> None:
        del args

    def put_item(self, *, Item: dict[str, Any]) -> None:  # noqa: N803
        for idx, existing in enumerate(self._table.items):
            if existing["chain_id"] == Item["chain_id"] and existing["ord"] == Item["ord"]:
                self._table.items[idx] = Item
                return
        self._table.items.append(Item)


class FakeTable:
    def __init__(self) -> None:
        self.items: list[dict[str, Any]] = []

    def put_item(self, *, Item: dict[str, Any], **kwargs: Any) -> None:  # noqa: N803
        del kwargs
        self.items.append(Item)

    def scan(
        self,
        *,
        FilterExpression: str = "",  # noqa: N803
        ExpressionAttributeValues: dict[str, Any] | None = None,  # noqa: N803
        ExclusiveStartKey: dict[str, Any] | None = None,  # noqa: N803
    ) -> dict[str, Any]:
        del FilterExpression, ExclusiveStartKey
        values = ExpressionAttributeValues or {}
        target_anchored = values.get(":true", values.get(":false", False))
        target_published = values.get(":false", False)
        if ":true" in values and ":false" in values:
            matches = [
                item
                for item in self.items
                if item.get("anchored") == target_anchored and item.get("published") == target_published
            ]
        else:
            matches = [item for item in self.items if item.get("anchored") == target_published]
        return {"Items": matches}

    def batch_writer(self) -> FakeBatchWriter:
        return FakeBatchWriter(self)


class FakeBucket:
    def __init__(self) -> None:
        self.objects: dict[str, dict[str, Any]] = {}

    def put_object(self, *, Key: str, Body: bytes, **kwargs: Any) -> None:  # noqa: N803
        self.objects[Key] = {"Body": Body, **kwargs}


class FakeAnchor:
    def __init__(self, log_index: int) -> None:
        self.log_index = log_index


class FakeRekor:
    def __init__(self) -> None:
        self.next_index = 1_500_000_000
        self.calls = 0

    def anchor(self, digest: bytes) -> FakeAnchor:
        del digest
        self.calls += 1
        result = FakeAnchor(log_index=self.next_index)
        self.next_index += 1
        return result


def _stale_now() -> str:
    return (datetime.now(UTC) - timedelta(seconds=COMPLETION_QUIET_SECONDS + 5)).isoformat().replace("+00:00", "Z")


def _emit_one_request(table: FakeTable, chain_id: str) -> None:
    with request_chain(chain_id=chain_id, table=table) as ops:  # type: ignore[arg-type]
        ops.api_request(
            method="GET",
            path_template="/health",
            status_code=200,
            duration_ms=12,
            auth_token="Bearer SHOULD-NOT-LEAK",  # noqa: S106 - test fixture
        )


def _stale_timestamps_in_table(table: FakeTable) -> None:
    """Backdate the records so the anchorer treats them as complete."""
    stale = _stale_now()
    for item in table.items:
        item["timestamp"] = stale


def main() -> int:
    table = FakeTable()
    bucket = FakeBucket()
    rekor = FakeRekor()

    print("[e2e] emitting 3 synthetic API requests")
    _emit_one_request(table, "lambda-req-A")
    _emit_one_request(table, "lambda-req-B")
    _emit_one_request(table, "lambda-req-C")
    assert len(table.items) == 6, f"expected 6 records, got {len(table.items)}"
    print(f"[e2e] DDB has {len(table.items)} records across 3 chains")

    print("[e2e] backdating timestamps so anchorer treats chains as complete")
    _stale_timestamps_in_table(table)

    print("[e2e] running anchorer")
    anchored = anchor_run_once(table, rekor)  # type: ignore[arg-type]
    assert anchored == 3, f"expected 3 anchored chains, got {anchored}"
    assert all(item["anchored"] for item in table.items), "all records should be anchored"
    print(f"[e2e] anchorer anchored {anchored} chains; rekor called {rekor.calls} times")

    print("[e2e] running publisher")
    published = publish_run_once(table, bucket)  # type: ignore[arg-type]
    assert published == 3, f"expected 3 published chains, got {published}"
    assert all(item["published"] for item in table.items), "all records should be published"
    print(f"[e2e] publisher published {published} chains")

    print("[e2e] verifying published JSONL bodies")
    for chain_id in ("lambda-req-A", "lambda-req-B", "lambda-req-C"):
        key = f"{CHAIN_PREFIX}/{chain_id}.jsonl"
        assert key in bucket.objects, f"missing published chain: {key}"
        body = bucket.objects[key]["Body"].decode()
        lines = [json.loads(line) for line in body.split("\n") if line]
        assert len(lines) == 2, f"chain {chain_id} should have 2 records, got {len(lines)}"
        for line in lines:
            assert line["chain_id"] == chain_id
            assert "rekor_log_index" in line
            assert "signature" not in line, "signature should be stripped from public chain"
            payload = line.get("payload", {})
            for key_name, value in payload.items():
                if key_name in ("method", "path_template", "status_code", "duration_ms"):
                    assert not (isinstance(value, str) and value.startswith("blake3:")), \
                        f"{key_name} should be cleartext"
                else:
                    if isinstance(value, str):
                        assert value.startswith("blake3:") or key_name in {
                            "method",
                            "path_template",
                        }, f"non-whitelisted field {key_name} should be redacted: {value!r}"
        if any("Bearer" in line for line in body.split("\n")):
            print(f"[e2e] FAIL: 'Bearer' substring found in published JSONL of {chain_id}")
            return 1
    print("[e2e] no auth_token leaked into the published JSONL ✓")

    print("[e2e] verifying manifest")
    assert MANIFEST_KEY in bucket.objects
    manifest = json.loads(bucket.objects[MANIFEST_KEY]["Body"])
    print(f"[e2e] manifest: {manifest}")
    assert manifest["latest_rekor_log_index"] >= 1_500_000_000

    print("[e2e] PASS")
    return 0


if __name__ == "__main__":
    start = time.monotonic()
    code = main()
    elapsed = time.monotonic() - start
    print(f"[e2e] elapsed {elapsed:.2f}s")
    sys.exit(code)
