"""Behavioral drift detection models."""

from enum import StrEnum

from pydantic import BaseModel, Field


class DriftCategory(StrEnum):
    FREQUENCY = "frequency"
    SCOPE = "scope"
    PATTERN = "pattern"


class BehaviorEvent(BaseModel):
    """A recorded agent behavior event."""

    agent_id: str
    tool: str
    timestamp: str = ""
    data_scope: str = ""
    metadata: dict[str, str] = Field(default_factory=dict)


class MetricBaseline(BaseModel):
    """Statistical baseline for a single metric."""

    metric_name: str
    mean: float = 0.0
    stddev: float = 0.0
    sample_count: int = 0
    last_updated: str = ""


class Baseline(BaseModel):
    """Behavioral baseline for an agent."""

    agent_id: str
    metrics: list[MetricBaseline] = Field(default_factory=list)
    window_minutes: int = 60
    created_at: str = ""
    event_count: int = 0


class DriftAlert(BaseModel):
    """Alert for a specific metric that deviated from baseline."""

    category: DriftCategory
    metric: str
    baseline_value: float
    current_value: float
    deviation: float
    message: str = ""


class DriftScore(BaseModel):
    """Overall drift assessment for an agent."""

    agent_id: str
    score: float = 0.0
    alerts: list[DriftAlert] = Field(default_factory=list)
    checked_at: str = ""
    baseline_event_count: int = 0
    current_event_count: int = 0


class BreakerConfig(BaseModel):
    """Circuit breaker configuration for an agent."""

    agent_id: str
    threshold: float = 0.8
    window_minutes: int = 60
    enabled: bool = True
    auto_suspend: bool = True
    suspend_reason: str = "Behavioral drift exceeded threshold"


class BreakerStatus(BaseModel):
    """Current circuit breaker status."""

    agent_id: str
    config: BreakerConfig
    current_drift: float = 0.0
    tripped: bool = False
    last_checked: str = ""


class RecordEventRequest(BaseModel):
    """Request to record a behavior event."""

    agent_id: str
    tool: str
    data_scope: str = ""
    metadata: dict[str, str] = Field(default_factory=dict)


class SetBreakerRequest(BaseModel):
    """Request to configure a circuit breaker."""

    agent_id: str
    threshold: float = 0.8
    window_minutes: int = 60
    auto_suspend: bool = True
