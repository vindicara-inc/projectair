"""Drift detection: compares live behavior against baseline."""

from datetime import UTC, datetime

import structlog

from vindicara.monitor.baseline import BaselineStore
from vindicara.monitor.models import (
    DriftAlert,
    DriftCategory,
    DriftScore,
)

logger = structlog.get_logger()

CURRENT_WINDOW_MINUTES = 5
ALERT_THRESHOLD_STDDEVS = 2.0
MAX_Z_FOR_NORMALIZATION = 4.0

METRIC_CATEGORY_MAP: dict[str, DriftCategory] = {
    "tool_call_count": DriftCategory.FREQUENCY,
    "unique_tools": DriftCategory.PATTERN,
    "unique_scopes": DriftCategory.SCOPE,
}


class DriftDetector:
    """Compares current agent behavior to baseline and scores drift."""

    def __init__(self, store: BaselineStore) -> None:
        self._store = store

    def check_drift(
        self, agent_id: str, window_minutes: int = 60
    ) -> DriftScore:
        """Compute drift score for an agent."""
        baseline = self._store.compute_baseline(agent_id, window_minutes)

        if baseline.event_count == 0:
            return DriftScore(
                agent_id=agent_id,
                score=0.0,
                checked_at=datetime.now(UTC).isoformat(),
            )

        current_events = self._store.get_events(
            agent_id, window_minutes=CURRENT_WINDOW_MINUTES
        )

        current_metrics = _compute_current_metrics(current_events)
        alerts: list[DriftAlert] = []
        z_scores: list[float] = []

        for metric in baseline.metrics:
            current_val = current_metrics.get(metric.metric_name, 0.0)
            stddev = metric.stddev if metric.stddev > 0 else 1.0
            z = abs(current_val - metric.mean) / stddev
            z_scores.append(z)

            if z > ALERT_THRESHOLD_STDDEVS:
                category = METRIC_CATEGORY_MAP.get(
                    metric.metric_name, DriftCategory.PATTERN
                )
                alerts.append(
                    DriftAlert(
                        category=category,
                        metric=metric.metric_name,
                        baseline_value=round(metric.mean, 2),
                        current_value=current_val,
                        deviation=round(z, 2),
                        message=(
                            f"{metric.metric_name}: {current_val} vs "
                            f"baseline {metric.mean:.1f} "
                            f"({z:.1f} standard deviations)"
                        ),
                    )
                )

        max_z = max(z_scores) if z_scores else 0.0
        score = min(1.0, max_z / MAX_Z_FOR_NORMALIZATION)

        logger.info(
            "monitor.drift.checked",
            agent_id=agent_id,
            score=round(score, 3),
            alert_count=len(alerts),
        )

        return DriftScore(
            agent_id=agent_id,
            score=round(score, 3),
            alerts=alerts,
            checked_at=datetime.now(UTC).isoformat(),
            baseline_event_count=baseline.event_count,
            current_event_count=len(current_events),
        )


def _compute_current_metrics(
    events: list,
) -> dict[str, float]:
    """Compute current metric values from recent events."""
    return {
        "tool_call_count": float(len(events)),
        "unique_tools": float(len({e.tool for e in events})),
        "unique_scopes": float(
            len({e.data_scope for e in events if e.data_scope})
        ),
    }
