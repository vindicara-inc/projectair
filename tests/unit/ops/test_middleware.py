"""Tests for ``vindicara.api.middleware.ops_chain.OpsChainMiddleware``."""
from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from starlette.requests import Request  # noqa: TC002 - runtime needed by FastAPI for DI

from vindicara.api.middleware.ops_chain import OpsChainMiddleware


class FakeTable:
    def __init__(self) -> None:
        self.items: list[dict[str, Any]] = []

    def put_item(
        self,
        *,
        Item: dict[str, Any],  # noqa: N803
        ConditionExpression: str | None = None,  # noqa: N803
        ExpressionAttributeNames: dict[str, str] | None = None,  # noqa: N803
    ) -> None:
        del ConditionExpression, ExpressionAttributeNames
        self.items.append(Item)


def _build_app(table: FakeTable | None) -> FastAPI:
    app = FastAPI()

    @app.get("/echo")
    async def echo() -> dict[str, str]:
        return {"ok": "yes"}

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/ops_state")
    async def ops_state(request: Request) -> dict[str, str]:
        ops = getattr(request.state, "ops", None)
        return {"has_ops": "yes" if ops is not None else "no"}

    middleware = OpsChainMiddleware(app=app)
    middleware._table = table  # type: ignore[assignment] - injection for tests
    app.add_middleware(OpsChainMiddleware)
    app.middleware_stack = None
    app.user_middleware = []
    app.add_middleware(_StaticTableMiddleware, table=table)
    return app


class _StaticTableMiddleware(OpsChainMiddleware):
    """Test variant of OpsChainMiddleware that takes a table directly."""

    def __init__(self, app: object, table: FakeTable | None) -> None:
        super().__init__(app)
        self._table = table  # type: ignore[assignment]


@pytest.mark.asyncio
async def test_middleware_records_request_into_chain() -> None:
    table = FakeTable()
    app = _build_app(table)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/echo")

    assert response.status_code == 200
    assert len(table.items) == 2
    start_record = json.loads(table.items[0]["record_json"])
    end_record = json.loads(table.items[1]["record_json"])
    assert start_record["payload"]["method"] == "GET"
    assert start_record["payload"]["path_template"] == "/echo"
    assert end_record["payload"]["status_code"] == 200
    assert "duration_ms" in end_record["payload"]


@pytest.mark.asyncio
async def test_middleware_skips_health_path() -> None:
    table = FakeTable()
    app = _build_app(table)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/health")

    assert response.status_code == 200
    assert table.items == []


@pytest.mark.asyncio
async def test_middleware_no_op_when_table_unavailable() -> None:
    app = _build_app(table=None)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/echo")

    assert response.status_code == 200


@pytest.mark.asyncio
async def test_middleware_attaches_ops_to_request_state() -> None:
    table = FakeTable()
    app = _build_app(table)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/ops_state")

    assert response.status_code == 200
    assert response.json() == {"has_ops": "yes"}
