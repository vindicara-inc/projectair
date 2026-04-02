"""Tests for drift detection."""

from datetime import UTC, datetime

from vindicara.monitor.baseline import BaselineStore
from vindicara.monitor.drift import DriftDetector
from vindicara.monitor.models import BehaviorEvent


class TestDriftDetector:
    def test_no_baseline_no_drift(self) -> None:
        store = BaselineStore()
        detector = DriftDetector(store)
        score = detector.check_drift("a1")
        assert score.score == 0.0
        assert score.alerts == []

    def test_normal_behavior_low_drift(self) -> None:
        store = BaselineStore()
        now = datetime.now(UTC).isoformat()
        for _ in range(10):
            store.record(BehaviorEvent(agent_id="a1", tool="crm_read", timestamp=now))

        detector = DriftDetector(store)
        score = detector.check_drift("a1")
        assert score.score < 0.5
        assert score.baseline_event_count == 10

    def test_high_frequency_drift(self) -> None:
        store = BaselineStore()
        now = datetime.now(UTC).isoformat()

        for _ in range(3):
            store.record(BehaviorEvent(agent_id="a1", tool="crm_read", timestamp=now))

        for _ in range(50):
            store.record(BehaviorEvent(agent_id="a1", tool="crm_read", timestamp=now))

        detector = DriftDetector(store)
        score = detector.check_drift("a1")
        assert score.agent_id == "a1"
        assert score.checked_at != ""

    def test_new_tools_detected(self) -> None:
        store = BaselineStore()
        now = datetime.now(UTC).isoformat()
        store.record(BehaviorEvent(agent_id="a1", tool="crm_read", timestamp=now))
        store.record(BehaviorEvent(agent_id="a1", tool="admin_delete", timestamp=now))
        store.record(BehaviorEvent(agent_id="a1", tool="db_drop", timestamp=now))
        store.record(BehaviorEvent(agent_id="a1", tool="file_write", timestamp=now))

        detector = DriftDetector(store)
        score = detector.check_drift("a1")
        assert score.current_event_count > 0

    def test_drift_score_bounded(self) -> None:
        store = BaselineStore()
        now = datetime.now(UTC).isoformat()
        for _ in range(100):
            store.record(BehaviorEvent(agent_id="a1", tool="crm_read", timestamp=now))

        detector = DriftDetector(store)
        score = detector.check_drift("a1")
        assert 0.0 <= score.score <= 1.0
