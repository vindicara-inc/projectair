"""Tests for ``vindicara.ops.anchorer``.

Uses a fake DynamoDB Table and a fake RekorClient. The anchorer's only
real responsibility (besides scanning) is composing two existing,
well-tested pieces: ``RekorClient.anchor`` and ``Table.batch_writer``.
The interesting branches to cover are completion-detection, the
unanchored filter, and the anchored-flag write-back.
"""
from __future__ import annotations

import json
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from vindicara.ops.anchorer import (
    COMPLETION_QUIET_SECONDS,
    chain_is_complete,
    mark_chain_anchored,
    run_once,
    scan_unanchored_chains,
)


class FakeAnchor:
    """Minimal stand-in for airsdk.types.RekorAnchor."""

    def __init__(self, log_index: int) -> None:
        self.log_index = log_index


class FakeRekor:
    def __init__(self) -> None:
        self.anchored_digests: list[bytes] = []
        self.next_index = 1_000_000
        self.fail_next: Exception | None = None

    def anchor(self, digest: bytes) -> FakeAnchor:
        if self.fail_next is not None:
            exc = self.fail_next
            self.fail_next = None
            raise exc
        self.anchored_digests.append(digest)
        anchor = FakeAnchor(log_index=self.next_index)
        self.next_index += 1
        return anchor


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
        FilterExpression: str = "",  # noqa: N803 - boto3 API parity
        ExpressionAttributeValues: dict[str, Any] | None = None,  # noqa: N803
        ExclusiveStartKey: dict[str, Any] | None = None,  # noqa: N803
    ) -> dict[str, Any]:
        del FilterExpression, ExclusiveStartKey
        values = ExpressionAttributeValues or {}
        target_anchored = values.get(":false", False)
        matches = [item for item in self.items if item["anchored"] == target_anchored]
        return {"Items": matches}

    def batch_writer(self) -> FakeBatchWriter:
        return FakeBatchWriter(self)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _stale_iso() -> str:
    return (datetime.now(UTC) - timedelta(seconds=COMPLETION_QUIET_SECONDS + 5)).isoformat().replace("+00:00", "Z")


def _make_record_json(content_hash: str = "ab" * 32, prev_hash: str = "0" * 64) -> str:
    return json.dumps({
        "version": "0.4",
        "step_id": str(uuid.uuid4()),
        "timestamp": _now_iso(),
        "kind": "tool_start",
        "payload": {},
        "prev_hash": prev_hash,
        "content_hash": content_hash,
        "signature": "sig",
        "signer_key": "pk",
    })


def _add_chain(table: FakeTable, chain_id: str, count: int = 2, *, anchored: bool = False, stale: bool = True) -> None:
    last_hash = "0" * 64
    for ord_idx in range(count):
        new_hash = f"{ord_idx + 1:02x}" + "00" * 31
        table.items.append({
            "chain_id": chain_id,
            "ord": f"{ord_idx:06d}",
            "step_id": f"step-{ord_idx}",
            "kind": "tool_start" if ord_idx % 2 == 0 else "tool_end",
            "timestamp": _stale_iso() if stale else _now_iso(),
            "record_json": _make_record_json(content_hash=new_hash, prev_hash=last_hash),
            "anchored": anchored,
            "published": False,
        })
        last_hash = new_hash


def test_scan_unanchored_chains_returns_only_unanchored() -> None:
    table = FakeTable()
    _add_chain(table, "chain-A", count=3, anchored=False)
    _add_chain(table, "chain-B", count=2, anchored=True)

    chains = scan_unanchored_chains(table)  # type: ignore[arg-type]

    assert "chain-A" in chains
    assert "chain-B" not in chains
    assert [item["ord"] for item in chains["chain-A"]] == ["000000", "000001", "000002"]


def test_chain_is_complete_when_quiet_window_elapsed() -> None:
    table = FakeTable()
    _add_chain(table, "stale", count=1, stale=True)
    _add_chain(table, "fresh", count=1, stale=False)

    chains = scan_unanchored_chains(table)  # type: ignore[arg-type]
    now = time.time()

    assert chain_is_complete(chains["stale"], now)
    assert not chain_is_complete(chains["fresh"], now)


def test_run_once_anchors_only_complete_chains() -> None:
    table = FakeTable()
    _add_chain(table, "stale", count=2, stale=True)
    _add_chain(table, "fresh", count=2, stale=False)
    rekor = FakeRekor()

    anchored = run_once(table, rekor)  # type: ignore[arg-type]

    assert anchored == 1
    assert len(rekor.anchored_digests) == 1
    stale_items = [item for item in table.items if item["chain_id"] == "stale"]
    fresh_items = [item for item in table.items if item["chain_id"] == "fresh"]
    assert all(item["anchored"] for item in stale_items)
    assert not any(item["anchored"] for item in fresh_items)
    assert all(item["rekor_log_index"] == 1_000_000 for item in stale_items)


def test_anchor_failure_does_not_mark_anchored() -> None:
    table = FakeTable()
    _add_chain(table, "stale", count=2, stale=True)
    rekor = FakeRekor()
    rekor.fail_next = RuntimeError("simulated rekor outage")

    anchored = run_once(table, rekor)  # type: ignore[arg-type]

    assert anchored == 0
    assert all(not item["anchored"] for item in table.items)


def test_mark_chain_anchored_writes_log_index_to_every_record() -> None:
    table = FakeTable()
    _add_chain(table, "chain", count=4, stale=True)
    items = scan_unanchored_chains(table)["chain"]  # type: ignore[arg-type]
    anchor = FakeAnchor(log_index=42)

    mark_chain_anchored(table, "chain", items, anchor)  # type: ignore[arg-type]

    assert all(item["anchored"] for item in table.items)
    assert all(item["rekor_log_index"] == 42 for item in table.items)


def test_runs_with_no_chains_succeeds() -> None:
    table = FakeTable()
    rekor = FakeRekor()
    assert run_once(table, rekor) == 0  # type: ignore[arg-type]


def test_chain_is_complete_with_empty_items() -> None:
    assert not chain_is_complete([], time.time())


@pytest.mark.parametrize("count", [0, 1, 5, 20])
def test_run_once_handles_various_chain_sizes(count: int) -> None:
    table = FakeTable()
    if count > 0:
        _add_chain(table, "chain", count=count, stale=True)
    rekor = FakeRekor()

    anchored = run_once(table, rekor)  # type: ignore[arg-type]

    expected = 1 if count > 0 else 0
    assert anchored == expected
