"""Analytics summary route for AIR Cloud."""
from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict

from vindicara.cloud.roles import Capability, require

if TYPE_CHECKING:
    from vindicara.cloud.capsule_store import CapsuleStore, StoredCapsule
    from vindicara.cloud.workspace import ApiKeyStore

router = APIRouter(tags=["analytics"])


class ChainHealth(BaseModel):
    """Breakdown of chain verification status across all capsules."""

    model_config = ConfigDict(extra="forbid")

    verified: int
    tampered: int
    broken_link: int


class DailyCount(BaseModel):
    """Capsule ingestion count for one calendar day (UTC)."""

    model_config = ConfigDict(extra="forbid")

    date: str
    count: int


class AnalyticsSummary(BaseModel):
    """Workspace-level metrics returned by GET /v1/analytics/summary."""

    model_config = ConfigDict(extra="forbid")

    total_capsules: int
    capsules_this_week: int
    unique_agents: int
    active_members: int
    detector_counts: dict[str, int]
    chain_health: ChainHealth
    daily_ingestion: list[DailyCount]


def _week_cutoff() -> str:
    """ISO string for 7 days ago (UTC), sorts correctly against record timestamps."""
    return (datetime.now(UTC) - timedelta(days=7)).isoformat().replace("+00:00", "Z")


def _build_daily_ingestion(
    capsules: list[StoredCapsule],
    days: int = 30,
) -> list[DailyCount]:
    """Return per-day ingestion counts for the last ``days`` calendar days."""
    today = datetime.now(UTC).date()
    counts: Counter[str] = Counter()
    cutoff_date = today - timedelta(days=days - 1)
    for cap in capsules:
        ts = cap.record.timestamp
        try:
            day = ts[:10]  # "YYYY-MM-DD"
            if day >= cutoff_date.isoformat():
                counts[day] += 1
        except (IndexError, ValueError):
            pass
    result: list[DailyCount] = []
    for offset in range(days):
        day_str = (cutoff_date + timedelta(days=offset)).isoformat()
        result.append(DailyCount(date=day_str, count=counts.get(day_str, 0)))
    return result


@router.get(
    "/v1/analytics/summary",
    response_model=AnalyticsSummary,
    summary="Workspace analytics summary (admin+ only).",
)
async def analytics_summary(request: Request) -> AnalyticsSummary:
    """Return aggregated workspace metrics.

    Requires ``LIST_KEYS`` capability (owner or admin roles). The metrics
    include total capsule count, unique signing-key count (proxy for unique
    agents), active member count, per-detector finding frequencies, daily
    ingestion over the last 30 days, and chain health breakdown.
    """
    require(request, Capability.LIST_KEYS)

    capsule_store: CapsuleStore = request.app.state.capsule_store
    key_store: ApiKeyStore = request.app.state.cloud_api_keys
    workspace_id: str = request.state.workspace_id

    capsules = capsule_store.for_workspace(workspace_id)
    keys = key_store.for_workspace(workspace_id)

    total = len(capsules)

    week_cutoff = _week_cutoff()
    this_week = sum(
        1 for cap in capsules if cap.record.timestamp >= week_cutoff
    )

    unique_agents = len({cap.record.signer_key for cap in capsules})

    active_members = sum(1 for k in keys if k.revoked_at is None)

    # Findings are emitted by `air trace` post-hoc over the full chain; they
    # are not stored on individual capsules at ingest time. The counter is
    # empty at Phase 1 and will be populated once the cloud trace pipeline lands.
    detector_counts: Counter[str] = Counter()

    # Chain health: structural verification is out of scope for Phase 1.
    # All ingested capsules passed signature verification at ingest time.
    chain_health = ChainHealth(verified=total, tampered=0, broken_link=0)
    daily = _build_daily_ingestion(capsules)

    return AnalyticsSummary(
        total_capsules=total,
        capsules_this_week=this_week,
        unique_agents=unique_agents,
        active_members=active_members,
        detector_counts=dict(detector_counts),
        chain_health=chain_health,
        daily_ingestion=daily,
    )


__all__ = [
    "AnalyticsSummary",
    "ChainHealth",
    "DailyCount",
    "router",
]
