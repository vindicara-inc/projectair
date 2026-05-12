"""In-process pub/sub for capsule events.

When a capsule is appended to the store, the ingest route publishes it
here. SSE subscribers for the matching workspace receive the event in
real time. Each subscriber gets its own asyncio.Queue so slow readers
do not block ingest.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from airsdk.types import AgDRRecord

_log = logging.getLogger(__name__)


@dataclass(frozen=True)
class CapsuleEvent:
    workspace_id: str
    record: AgDRRecord


@dataclass
class _Subscriber:
    workspace_id: str
    queue: asyncio.Queue[CapsuleEvent | None] = field(
        default_factory=lambda: asyncio.Queue(maxsize=1000),
    )


class CapsuleEventBus:
    """Workspace-scoped fan-out for capsule events."""

    def __init__(self) -> None:
        self._subscribers: list[_Subscriber] = []

    def subscribe(self, workspace_id: str) -> _Subscriber:
        sub = _Subscriber(workspace_id=workspace_id)
        self._subscribers.append(sub)
        return sub

    def unsubscribe(self, sub: _Subscriber) -> None:
        with contextlib.suppress(ValueError):
            self._subscribers.remove(sub)

    def publish(self, event: CapsuleEvent) -> None:
        for sub in self._subscribers:
            if sub.workspace_id != event.workspace_id:
                continue
            try:
                sub.queue.put_nowait(event)
            except asyncio.QueueFull:
                _log.warning(
                    "cloud.event_bus.subscriber_queue_full",
                    extra={"workspace_id": event.workspace_id},
                )
