"""Behavioral baseline generation and event storage."""

import math
from collections import defaultdict
from datetime import UTC, datetime

import structlog

from vindicara.monitor.models import Baseline, BehaviorEvent, MetricBaseline

logger = structlog.get_logger()

BUCKET_MINUTES = 5


class BaselineStore:
    """In-memory store for agent behavior events. DynamoDB backend in future."""

    def __init__(self) -> None:
        self._events: dict[str, list[BehaviorEvent]] = defaultdict(list)

    def record(self, event: BehaviorEvent) -> BehaviorEvent:
        """Record a behavior event for an agent."""
        if not event.timestamp:
            event = event.model_copy(update={"timestamp": datetime.now(UTC).isoformat()})
        self._events[event.agent_id].append(event)
        logger.info(
            "monitor.event.recorded",
            agent_id=event.agent_id,
            tool=event.tool,
        )
        return event

    def get_events(self, agent_id: str, window_minutes: int = 60) -> list[BehaviorEvent]:
        """Get events for agent within the time window."""
        cutoff = datetime.now(UTC).timestamp() - (window_minutes * 60)
        result: list[BehaviorEvent] = []
        for event in self._events.get(agent_id, []):
            if not event.timestamp:
                continue
            try:
                ts = datetime.fromisoformat(event.timestamp).timestamp()
            except ValueError:
                continue
            if ts >= cutoff:
                result.append(event)
        return result

    def compute_baseline(self, agent_id: str, window_minutes: int = 60) -> Baseline:
        """Compute statistical baseline from recorded events."""
        events = self.get_events(agent_id, window_minutes)

        if not events:
            return Baseline(
                agent_id=agent_id,
                window_minutes=window_minutes,
                created_at=datetime.now(UTC).isoformat(),
                event_count=0,
            )

        buckets = _bucket_events(events, BUCKET_MINUTES)
        num_buckets = max(len(buckets), 1)

        call_counts = [float(len(b)) for b in buckets.values()]
        unique_tools_counts = [float(len({e.tool for e in b})) for b in buckets.values()]
        unique_scopes_counts = [float(len({e.data_scope for e in b if e.data_scope})) for b in buckets.values()]

        now = datetime.now(UTC).isoformat()
        metrics = [
            MetricBaseline(
                metric_name="tool_call_count",
                mean=_mean(call_counts),
                stddev=_stddev(call_counts),
                sample_count=num_buckets,
                last_updated=now,
            ),
            MetricBaseline(
                metric_name="unique_tools",
                mean=_mean(unique_tools_counts),
                stddev=_stddev(unique_tools_counts),
                sample_count=num_buckets,
                last_updated=now,
            ),
            MetricBaseline(
                metric_name="unique_scopes",
                mean=_mean(unique_scopes_counts),
                stddev=_stddev(unique_scopes_counts),
                sample_count=num_buckets,
                last_updated=now,
            ),
        ]

        return Baseline(
            agent_id=agent_id,
            metrics=metrics,
            window_minutes=window_minutes,
            created_at=now,
            event_count=len(events),
        )


def _bucket_events(events: list[BehaviorEvent], bucket_minutes: int) -> dict[int, list[BehaviorEvent]]:
    """Group events into time buckets."""
    buckets: dict[int, list[BehaviorEvent]] = defaultdict(list)
    for event in events:
        try:
            ts = datetime.fromisoformat(event.timestamp).timestamp()
        except ValueError:
            continue
        bucket_key = int(ts // (bucket_minutes * 60))
        buckets[bucket_key].append(event)
    return buckets


def _mean(values: list[float]) -> float:
    """Compute arithmetic mean."""
    if not values:
        return 0.0
    return round(sum(values) / len(values), 2)


def _stddev(values: list[float]) -> float:
    """Compute sample standard deviation. Returns 1.0 if fewer than 2 samples."""
    if len(values) < 2:
        return 1.0
    avg = sum(values) / len(values)
    variance = sum((v - avg) ** 2 for v in values) / (len(values) - 1)
    return round(math.sqrt(variance), 2)
