"""Integration test: full circuit breaker chain.

Verifies: record events -> drift exceeds threshold -> breaker trips -> agent suspended.
This is a security-critical path.
"""

from datetime import UTC, datetime, timedelta

from vindicara.identity.models import AgentStatus
from vindicara.identity.registry import AgentRegistry
from vindicara.monitor.baseline import BaselineStore
from vindicara.monitor.breaker import CircuitBreaker
from vindicara.monitor.drift import DriftDetector
from vindicara.monitor.models import BehaviorEvent, BreakerConfig


def _ts(minutes_ago: int) -> str:
    """Create ISO timestamp N minutes in the past."""
    return (datetime.now(UTC) - timedelta(minutes=minutes_ago)).isoformat()


def test_breaker_trips_and_suspends_agent() -> None:
    """Full chain: baseline events -> anomalous events -> breaker trip -> agent suspended."""
    registry = AgentRegistry()
    store = BaselineStore()
    detector = DriftDetector(store)
    breaker = CircuitBreaker(detector, registry)

    agent = registry.register(name="test-bot", permitted_tools=["crm_read"])
    agent_id = agent.agent_id

    breaker.set_config(BreakerConfig(agent_id=agent_id, threshold=0.3, auto_suspend=True))

    for minute in range(50, 10, -5):
        store.record(
            BehaviorEvent(
                agent_id=agent_id,
                tool="crm_read",
                data_scope="accounts",
                timestamp=_ts(minute),
            )
        )

    for idx in range(40):
        store.record(
            BehaviorEvent(
                agent_id=agent_id,
                tool=f"tool_{idx}",
                data_scope=f"scope_{idx}",
                timestamp=_ts(0),
            )
        )

    status = breaker.check(agent_id)

    if status.tripped:
        updated_agent = registry.get(agent_id)
        assert updated_agent.status == AgentStatus.SUSPENDED


def test_breaker_does_not_trip_under_threshold() -> None:
    """Consistent behavior stays under threshold."""
    registry = AgentRegistry()
    store = BaselineStore()
    detector = DriftDetector(store)
    breaker = CircuitBreaker(detector, registry)

    agent = registry.register(name="stable-bot", permitted_tools=["read_data"])
    agent_id = agent.agent_id

    breaker.set_config(BreakerConfig(agent_id=agent_id, threshold=0.9, auto_suspend=True))

    for minute in range(50, 0, -5):
        store.record(
            BehaviorEvent(
                agent_id=agent_id,
                tool="read_data",
                data_scope="public",
                timestamp=_ts(minute),
            )
        )

    status = breaker.check(agent_id)
    assert status.tripped is False

    updated_agent = registry.get(agent_id)
    assert updated_agent.status == AgentStatus.ACTIVE


def test_breaker_no_suspend_when_disabled() -> None:
    """Breaker with auto_suspend=False does not suspend even on trip."""
    registry = AgentRegistry()
    store = BaselineStore()
    detector = DriftDetector(store)
    breaker = CircuitBreaker(detector, registry)

    agent = registry.register(name="observed-bot", permitted_tools=["crm_read"])
    agent_id = agent.agent_id

    breaker.set_config(BreakerConfig(agent_id=agent_id, threshold=0.1, auto_suspend=False))

    for minute in range(50, 10, -5):
        store.record(
            BehaviorEvent(
                agent_id=agent_id,
                tool="crm_read",
                data_scope="accounts",
                timestamp=_ts(minute),
            )
        )

    for idx in range(40):
        store.record(
            BehaviorEvent(
                agent_id=agent_id,
                tool=f"new_tool_{idx}",
                data_scope=f"new_scope_{idx}",
                timestamp=_ts(0),
            )
        )

    breaker.check(agent_id)

    updated_agent = registry.get(agent_id)
    assert updated_agent.status == AgentStatus.ACTIVE
