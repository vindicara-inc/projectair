"""Behavioral drift detection endpoints."""

import structlog
from fastapi import APIRouter, Depends

from vindicara.api.deps import (
    get_baseline_store,
    get_circuit_breaker,
    get_drift_detector,
)
from vindicara.monitor.baseline import BaselineStore
from vindicara.monitor.breaker import CircuitBreaker
from vindicara.monitor.drift import DriftDetector
from vindicara.monitor.models import (
    BehaviorEvent,
    BreakerConfig,
    BreakerStatus,
    DriftScore,
    RecordEventRequest,
    SetBreakerRequest,
)

logger = structlog.get_logger()

router = APIRouter(prefix="/v1")


@router.post("/monitor/events", response_model=BehaviorEvent)
async def record_event(
    request: RecordEventRequest,
    store: BaselineStore = Depends(get_baseline_store),
) -> BehaviorEvent:
    """Record a behavior event for an agent."""
    event = BehaviorEvent(
        agent_id=request.agent_id,
        tool=request.tool,
        data_scope=request.data_scope,
        metadata=request.metadata,
    )
    return store.record(event)


@router.get("/monitor/drift/{agent_id}", response_model=DriftScore)
async def get_drift(
    agent_id: str,
    window_minutes: int = 60,
    detector: DriftDetector = Depends(get_drift_detector),
) -> DriftScore:
    """Get drift score for an agent."""
    return detector.check_drift(agent_id, window_minutes)


@router.post("/monitor/breakers", response_model=BreakerConfig)
async def set_breaker(
    request: SetBreakerRequest,
    breaker: CircuitBreaker = Depends(get_circuit_breaker),
) -> BreakerConfig:
    """Configure a circuit breaker for an agent."""
    config = BreakerConfig(
        agent_id=request.agent_id,
        threshold=request.threshold,
        window_minutes=request.window_minutes,
        auto_suspend=request.auto_suspend,
    )
    return breaker.set_config(config)


@router.get("/monitor/breakers/{agent_id}", response_model=BreakerStatus)
async def check_breaker(
    agent_id: str,
    breaker: CircuitBreaker = Depends(get_circuit_breaker),
) -> BreakerStatus:
    """Check circuit breaker status for an agent."""
    return breaker.check(agent_id)
