"""Tests for ``vindicara.ops.recorder``."""
from __future__ import annotations

import json
from typing import Any

import pytest

from vindicara.ops.ddb_transport import DDBTransport, FailureMode
from vindicara.ops.recorder import OpsRecorder, open_recorder, request_chain
from vindicara.ops.schema import OpsKind


class FakeTable:
    def __init__(self) -> None:
        self.items: list[dict[str, Any]] = []

    def put_item(
        self,
        *,
        Item: dict[str, Any],  # noqa: N803 - boto3 API parity
        ConditionExpression: str | None = None,  # noqa: N803
        ExpressionAttributeNames: dict[str, str] | None = None,  # noqa: N803
    ) -> None:
        del ConditionExpression, ExpressionAttributeNames
        self.items.append(Item)


def test_open_recorder_uses_ddb_transport() -> None:
    table = FakeTable()
    recorder = open_recorder(chain_id="chain-A", table=table)  # type: ignore[arg-type]

    assert len(recorder.transports) == 1
    transport = recorder.transports[0]
    assert isinstance(transport, DDBTransport)
    assert transport.chain_id == "chain-A"


def test_open_recorder_emits_into_table() -> None:
    table = FakeTable()
    recorder = open_recorder(chain_id="chain-A", table=table)  # type: ignore[arg-type]

    recorder.tool_start(tool_name="vindicara.api.request", tool_args={"path": "/health"})
    recorder.tool_end(tool_output="ok")

    assert len(table.items) == 2
    assert all(item["chain_id"] == "chain-A" for item in table.items)


def test_request_chain_yields_ops_recorder() -> None:
    table = FakeTable()
    with request_chain(chain_id="chain-A", table=table) as ops:  # type: ignore[arg-type]
        assert isinstance(ops, OpsRecorder)
        ops.recorder.tool_start(tool_name="vindicara.api.request", tool_args={"path": "/health"})

    assert len(table.items) == 1


def _emit_then_raise(ops: OpsRecorder) -> None:
    ops.recorder.tool_start(tool_name="vindicara.api.request", tool_args={"path": "/health"})
    raise ValueError("boom")


def test_request_chain_propagates_exceptions() -> None:
    table = FakeTable()
    with (
        pytest.raises(ValueError, match="boom"),
        request_chain(chain_id="chain-A", table=table) as ops,  # type: ignore[arg-type]
    ):
        _emit_then_raise(ops)
    assert len(table.items) == 1


def test_open_recorder_passes_failure_mode() -> None:
    table = FakeTable()
    recorder = open_recorder(chain_id="chain-A", table=table, failure_mode=FailureMode.HARD)  # type: ignore[arg-type]
    transport = recorder.transports[0]
    assert isinstance(transport, DDBTransport)


def test_ops_recorder_api_request_emits_pair_with_tool_name() -> None:
    table = FakeTable()
    with request_chain(chain_id="chain-A", table=table) as ops:  # type: ignore[arg-type]
        ops.api_request(method="GET", path_template="/health", status_code=200, duration_ms=42.0)

    assert len(table.items) == 2
    start_record = json.loads(table.items[0]["record_json"])
    end_record = json.loads(table.items[1]["record_json"])
    assert start_record["payload"]["tool_name"] == OpsKind.API_REQUEST.value
    assert end_record["payload"]["tool_name"] == OpsKind.API_REQUEST.value
    assert end_record["payload"]["status_code"] == 200
    assert end_record["payload"]["duration_ms"] == 42.0


def test_ops_recorder_auth_event_emits_pair() -> None:
    table = FakeTable()
    with request_chain(chain_id="dashboard:sess-1", table=table) as ops:  # type: ignore[arg-type]
        ops.auth_event(OpsKind.DASHBOARD_LOGIN, outcome="success", duration_ms=15.0)

    assert len(table.items) == 2
    end_record = json.loads(table.items[1]["record_json"])
    assert end_record["payload"]["tool_name"] == OpsKind.DASHBOARD_LOGIN.value
    assert end_record["payload"]["outcome"] == "success"


def test_ops_recorder_time_request_computes_duration() -> None:
    table = FakeTable()
    with (
        request_chain(chain_id="chain-A", table=table) as ops,  # type: ignore[arg-type]
        ops.time_request(method="POST", path_template="/v1/guard") as bag,
    ):
        bag["status_code"] = 200

    assert len(table.items) == 2
    end_record = json.loads(table.items[1]["record_json"])
    assert end_record["payload"]["status_code"] == 200
    assert end_record["payload"]["duration_ms"] >= 0.0
    assert end_record["payload"]["tool_name"] == OpsKind.API_REQUEST.value
