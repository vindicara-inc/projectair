"""Tests for ``vindicara.ops.ddb_transport.DDBTransport``."""
from __future__ import annotations

from typing import Any

import pytest
from airsdk.recorder import AIRRecorder

from vindicara.ops.ddb_transport import ORD_WIDTH, DDBTransport, FailureMode


class FakeTable:
    """In-memory DynamoDB Table stand-in. Only implements put_item with the
    subset of features ``DDBTransport`` uses: an item dict and a
    ``ConditionExpression`` that asserts the (chain_id, ord) primary key
    does not already exist."""

    def __init__(self) -> None:
        self.items: list[dict[str, Any]] = []
        self.fail_next: Exception | None = None

    def put_item(
        self,
        *,
        Item: dict[str, Any],  # noqa: N803 - matches boto3's PascalCase API
        ConditionExpression: str | None = None,  # noqa: N803
        ExpressionAttributeNames: dict[str, str] | None = None,  # noqa: N803
    ) -> None:
        del ConditionExpression, ExpressionAttributeNames
        if self.fail_next is not None:
            exc = self.fail_next
            self.fail_next = None
            raise exc
        for existing in self.items:
            if existing["chain_id"] == Item["chain_id"] and existing["ord"] == Item["ord"]:
                raise RuntimeError("ConditionalCheckFailedException-equivalent")
        self.items.append(Item)


@pytest.fixture
def fake_table() -> FakeTable:
    return FakeTable()


def test_chain_id_required(fake_table: FakeTable) -> None:
    with pytest.raises(ValueError, match="chain_id must be a non-empty string"):
        DDBTransport(table=fake_table, chain_id="")  # type: ignore[arg-type]


def test_emit_writes_item_with_padded_ord(fake_table: FakeTable, tmp_path: Any) -> None:
    transport = DDBTransport(table=fake_table, chain_id="test-chain")  # type: ignore[arg-type]
    recorder = AIRRecorder(log_path=tmp_path / "chain.jsonl", transports=[transport])

    recorder.tool_start(tool_name="vindicara.api.request", tool_args={"method": "GET", "path": "/health"})

    assert len(fake_table.items) == 1
    item = fake_table.items[0]
    assert item["chain_id"] == "test-chain"
    assert item["ord"] == "0".zfill(ORD_WIDTH)
    assert item["kind"] == "tool_start"
    assert item["anchored"] is False
    assert item["published"] is False
    assert "record_json" in item


def test_emit_increments_ord_per_record(fake_table: FakeTable, tmp_path: Any) -> None:
    transport = DDBTransport(table=fake_table, chain_id="test-chain")  # type: ignore[arg-type]
    recorder = AIRRecorder(log_path=tmp_path / "chain.jsonl", transports=[transport])

    recorder.tool_start(tool_name="vindicara.api.request", tool_args={"path": "/a"})
    recorder.tool_end(tool_name="vindicara.api.request", tool_output="ok")
    recorder.tool_start(tool_name="vindicara.api.request", tool_args={"path": "/b"})

    assert [item["ord"] for item in fake_table.items] == [
        "0".zfill(ORD_WIDTH),
        "1".zfill(ORD_WIDTH),
        "2".zfill(ORD_WIDTH),
    ]
    assert transport.ord == 3


def test_emit_soft_failure_logs_and_continues(
    fake_table: FakeTable,
    tmp_path: Any,
    caplog: pytest.LogCaptureFixture,
) -> None:
    transport = DDBTransport(
        table=fake_table,  # type: ignore[arg-type]
        chain_id="test-chain",
        failure_mode=FailureMode.SOFT,
    )
    recorder = AIRRecorder(log_path=tmp_path / "chain.jsonl", transports=[transport])

    fake_table.fail_next = RuntimeError("simulated DDB outage")
    recorder.tool_start(tool_name="vindicara.api.request", tool_args={"path": "/a"})
    recorder.tool_end(tool_name="vindicara.api.request", tool_output="ok")

    assert any("put_item_failed" in rec.message for rec in caplog.records)
    assert len(fake_table.items) == 1
    assert fake_table.items[0]["ord"] == "1".zfill(ORD_WIDTH)


def test_emit_hard_failure_raises(fake_table: FakeTable, tmp_path: Any) -> None:
    transport = DDBTransport(
        table=fake_table,  # type: ignore[arg-type]
        chain_id="test-chain",
        failure_mode=FailureMode.HARD,
    )
    recorder = AIRRecorder(log_path=tmp_path / "chain.jsonl", transports=[transport])

    fake_table.fail_next = RuntimeError("simulated DDB outage")
    with pytest.raises(RuntimeError, match="simulated DDB outage"):
        recorder.tool_start(tool_name="vindicara.api.request", tool_args={"path": "/a"})


def test_drain_is_noop(fake_table: FakeTable) -> None:
    transport = DDBTransport(table=fake_table, chain_id="test-chain")  # type: ignore[arg-type]
    transport.drain(timeout=5.0)
    assert fake_table.items == []
