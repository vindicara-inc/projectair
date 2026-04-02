"""Tests for monitor models."""

from vindicara.monitor.models import (
    BehaviorEvent,
    BreakerConfig,
    BreakerStatus,
    DriftAlert,
    DriftCategory,
    DriftScore,
    RecordEventRequest,
    SetBreakerRequest,
)


class TestBehaviorEvent:
    def test_create(self) -> None:
        event = BehaviorEvent(agent_id="a1", tool="crm_read")
        assert event.agent_id == "a1"
        assert event.tool == "crm_read"
        assert event.timestamp == ""
        assert event.data_scope == ""

    def test_with_metadata(self) -> None:
        event = BehaviorEvent(
            agent_id="a1",
            tool="crm_read",
            data_scope="accounts.sales",
            metadata={"source": "api"},
        )
        assert event.data_scope == "accounts.sales"
        assert event.metadata["source"] == "api"


class TestDriftScore:
    def test_defaults(self) -> None:
        score = DriftScore(agent_id="a1")
        assert score.score == 0.0
        assert score.alerts == []

    def test_with_alerts(self) -> None:
        alert = DriftAlert(
            category=DriftCategory.FREQUENCY,
            metric="tool_call_count",
            baseline_value=5.0,
            current_value=25.0,
            deviation=3.5,
            message="High frequency",
        )
        score = DriftScore(agent_id="a1", score=0.875, alerts=[alert])
        assert len(score.alerts) == 1
        assert score.alerts[0].category == DriftCategory.FREQUENCY


class TestBreakerConfig:
    def test_defaults(self) -> None:
        config = BreakerConfig(agent_id="a1")
        assert config.threshold == 0.8
        assert config.auto_suspend is True
        assert config.enabled is True

    def test_custom(self) -> None:
        config = BreakerConfig(
            agent_id="a1", threshold=0.5, auto_suspend=False
        )
        assert config.threshold == 0.5
        assert config.auto_suspend is False


class TestBreakerStatus:
    def test_create(self) -> None:
        config = BreakerConfig(agent_id="a1")
        status = BreakerStatus(agent_id="a1", config=config)
        assert status.tripped is False
        assert status.current_drift == 0.0


class TestRequestModels:
    def test_record_event_request(self) -> None:
        req = RecordEventRequest(agent_id="a1", tool="crm_read")
        assert req.agent_id == "a1"

    def test_set_breaker_request(self) -> None:
        req = SetBreakerRequest(agent_id="a1", threshold=0.9)
        assert req.threshold == 0.9
