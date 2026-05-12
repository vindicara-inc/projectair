"""SSE endpoint for real-time capsule streaming.

Clients open ``GET /v1/capsules/stream`` with their API key. The
connection stays open; each new capsule ingested into the workspace
is pushed as an SSE ``data:`` frame containing the AgDRRecord JSON.

A keepalive comment is sent every 15 seconds to prevent proxy
timeouts. The connection closes when the client disconnects.
"""
from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from fastapi import APIRouter, Request
from starlette.responses import StreamingResponse

from vindicara.cloud.roles import Capability, require

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

router = APIRouter(prefix="/v1", tags=["stream"])

KEEPALIVE_SECONDS = 15


async def _event_stream(
    request: Request,
    workspace_id: str,
) -> AsyncGenerator[str, None]:
    bus = request.app.state.capsule_event_bus
    sub = bus.subscribe(workspace_id)
    try:
        while True:
            if await request.is_disconnected():
                break
            try:
                event = await asyncio.wait_for(
                    sub.queue.get(),
                    timeout=KEEPALIVE_SECONDS,
                )
            except TimeoutError:
                yield ": keepalive\n\n"
                continue

            if event is None:
                break

            record_json = event.record.model_dump_json(exclude_none=True)
            yield f"data: {record_json}\n\n"
    finally:
        bus.unsubscribe(sub)


@router.get("/capsules/stream")
async def stream_capsules(request: Request) -> StreamingResponse:
    """Stream capsules as Server-Sent Events."""
    require(request, Capability.READ_CAPSULES)
    workspace_id: str = request.state.workspace_id
    return StreamingResponse(
        _event_stream(request, workspace_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
