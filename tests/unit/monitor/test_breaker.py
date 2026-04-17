"""Tests for circuit breaker."""

from datetime import UTC, datetime

from vindicara.identity.registry import AgentRegistry
from vindicara.monitor.baseline import BaselineStore
from vindicara.monitor.breaker import CircuitBreaker
from vindicara.monitor.drift import DriftDetector
from vindicara.monitor.models import BehaviorEvent, BreakerConfig


class TestCircuitBreaker:
    def _make_breaker(self) -> tuple[CircuitBreaker, BaselineStore, AgentRegistry]:
        store = BaselineStore()
        detector = DriftDetector(store)
        registry = AgentRegistry()
        breaker = CircuitBreaker(detector, registry)
        return breaker, store, registry

    def test_set_config(self) -> None:
        breaker, _, _ = self._make_breaker()
        config = BreakerConfig(agent_id="a1", threshold=0.7)
        result = breaker.set_config(config)
        assert result.threshold == 0.7

    def test_get_config(self) -> None:
        breaker, _, _ = self._make_breaker()
        config = BreakerConfig(agent_id="a1")
        breaker.set_config(config)
        retrieved = breaker.get_config("a1")
        assert retrieved is not None
        assert retrieved.agent_id == "a1"

    def test_get_config_missing(self) -> None:
        breaker, _, _ = self._make_breaker()
        assert breaker.get_config("nonexistent") is None

    def test_check_no_config_returns_disabled(self) -> None:
        breaker, _, registry = self._make_breaker()
        registry.register(name="test-bot")
        status = breaker.check("a1")
        assert status.config.enabled is False
        assert status.tripped is False

    def test_check_below_threshold_not_tripped(self) -> None:
        breaker, _store, registry = self._make_breaker()
        agent = registry.register(name="test-bot")

        config = BreakerConfig(agent_id=agent.agent_id, threshold=0.9)
        breaker.set_config(config)

        status = breaker.check(agent.agent_id)
        assert status.tripped is False

    def test_check_disabled_breaker_not_tripped(self) -> None:
        breaker, _, registry = self._make_breaker()
        agent = registry.register(name="test-bot")

        config = BreakerConfig(agent_id=agent.agent_id, enabled=False, threshold=0.0)
        breaker.set_config(config)

        status = breaker.check(agent.agent_id)
        assert status.tripped is False

    def test_breaker_status_has_drift_score(self) -> None:
        breaker, store, registry = self._make_breaker()
        agent = registry.register(name="test-bot")
        now = datetime.now(UTC).isoformat()
        store.record(BehaviorEvent(agent_id=agent.agent_id, tool="crm_read", timestamp=now))

        config = BreakerConfig(agent_id=agent.agent_id)
        breaker.set_config(config)

        status = breaker.check(agent.agent_id)
        assert status.current_drift >= 0.0
        assert status.last_checked != ""
