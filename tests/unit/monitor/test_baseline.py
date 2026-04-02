"""Tests for baseline store."""

from datetime import UTC, datetime

from vindicara.monitor.baseline import BaselineStore
from vindicara.monitor.models import BehaviorEvent


class TestBaselineStore:
    def test_record_event(self) -> None:
        store = BaselineStore()
        event = BehaviorEvent(agent_id="a1", tool="crm_read")
        recorded = store.record(event)
        assert recorded.agent_id == "a1"
        assert recorded.timestamp != ""

    def test_record_preserves_timestamp(self) -> None:
        store = BaselineStore()
        ts = "2026-04-01T12:00:00+00:00"
        event = BehaviorEvent(agent_id="a1", tool="crm_read", timestamp=ts)
        recorded = store.record(event)
        assert recorded.timestamp == ts

    def test_get_events_empty(self) -> None:
        store = BaselineStore()
        events = store.get_events("nonexistent")
        assert events == []

    def test_get_events_returns_recent(self) -> None:
        store = BaselineStore()
        now = datetime.now(UTC).isoformat()
        store.record(BehaviorEvent(agent_id="a1", tool="crm_read", timestamp=now))
        store.record(BehaviorEvent(agent_id="a1", tool="email_send", timestamp=now))
        events = store.get_events("a1", window_minutes=60)
        assert len(events) == 2

    def test_get_events_filters_old(self) -> None:
        store = BaselineStore()
        old = "2020-01-01T00:00:00+00:00"
        now = datetime.now(UTC).isoformat()
        store.record(BehaviorEvent(agent_id="a1", tool="old_tool", timestamp=old))
        store.record(BehaviorEvent(agent_id="a1", tool="new_tool", timestamp=now))
        events = store.get_events("a1", window_minutes=60)
        assert len(events) == 1
        assert events[0].tool == "new_tool"

    def test_compute_baseline_no_events(self) -> None:
        store = BaselineStore()
        baseline = store.compute_baseline("a1")
        assert baseline.event_count == 0
        assert baseline.metrics == []

    def test_compute_baseline_with_events(self) -> None:
        store = BaselineStore()
        now = datetime.now(UTC).isoformat()
        for _ in range(5):
            store.record(BehaviorEvent(agent_id="a1", tool="crm_read", timestamp=now))
        store.record(BehaviorEvent(agent_id="a1", tool="email_send", timestamp=now))

        baseline = store.compute_baseline("a1")
        assert baseline.event_count == 6
        assert len(baseline.metrics) == 3
        metric_names = {m.metric_name for m in baseline.metrics}
        assert "tool_call_count" in metric_names
        assert "unique_tools" in metric_names
        assert "unique_scopes" in metric_names
