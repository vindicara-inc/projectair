"""Circuit breaker: auto-suspends agents when drift exceeds threshold."""

from datetime import UTC, datetime

import structlog

from vindicara.identity.registry import AgentRegistry
from vindicara.monitor.drift import DriftDetector
from vindicara.monitor.models import BreakerConfig, BreakerStatus

logger = structlog.get_logger()


class CircuitBreaker:
    """Monitors drift and auto-suspends agents that exceed thresholds."""

    def __init__(
        self, detector: DriftDetector, registry: AgentRegistry
    ) -> None:
        self._detector = detector
        self._registry = registry
        self._configs: dict[str, BreakerConfig] = {}

    def set_config(self, config: BreakerConfig) -> BreakerConfig:
        """Configure a circuit breaker for an agent."""
        self._configs[config.agent_id] = config
        logger.info(
            "monitor.breaker.configured",
            agent_id=config.agent_id,
            threshold=config.threshold,
            auto_suspend=config.auto_suspend,
        )
        return config

    def get_config(self, agent_id: str) -> BreakerConfig | None:
        """Get circuit breaker config for an agent."""
        return self._configs.get(agent_id)

    def check(self, agent_id: str) -> BreakerStatus:
        """Check circuit breaker status. May trigger auto-suspension."""
        config = self._configs.get(agent_id)
        if config is None:
            config = BreakerConfig(agent_id=agent_id, enabled=False)

        drift = self._detector.check_drift(
            agent_id, config.window_minutes
        )
        tripped = config.enabled and drift.score >= config.threshold

        if tripped and config.auto_suspend:
            self._registry.suspend(
                agent_id, reason=config.suspend_reason
            )
            logger.warning(
                "monitor.breaker.tripped",
                agent_id=agent_id,
                drift_score=drift.score,
                threshold=config.threshold,
            )

        return BreakerStatus(
            agent_id=agent_id,
            config=config,
            current_drift=drift.score,
            tripped=tripped,
            last_checked=datetime.now(UTC).isoformat(),
        )
