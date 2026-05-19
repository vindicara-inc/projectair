"""Query engine over a GovernanceIndex."""
from __future__ import annotations

from datetime import datetime

from airsdk_pro.governance.types import DataAccessRecord, GovernanceIndex


def query_by_subject(index: GovernanceIndex, subject_id: str) -> list[DataAccessRecord]:
    positions = index.by_subject.get(subject_id, [])
    return [index.accesses[p] for p in positions]


def query_by_asset(index: GovernanceIndex, asset_id: str) -> list[DataAccessRecord]:
    positions = index.by_asset.get(asset_id, [])
    return [index.accesses[p] for p in positions]


def query_by_agent(index: GovernanceIndex, agent_id: str) -> list[DataAccessRecord]:
    positions = index.by_agent.get(agent_id, [])
    return [index.accesses[p] for p in positions]


def query_by_time_range(
    index: GovernanceIndex,
    from_dt: datetime | None = None,
    to_dt: datetime | None = None,
) -> list[DataAccessRecord]:
    if from_dt is None and to_dt is None:
        return list(index.accesses)
    results: list[DataAccessRecord] = []
    for access in index.accesses:
        ts = access.timestamp
        normalized = ts.replace("Z", "+00:00") if ts.endswith("Z") else ts
        try:
            record_dt = datetime.fromisoformat(normalized)
        except (ValueError, TypeError):
            continue
        if from_dt is not None and record_dt < from_dt:
            continue
        if to_dt is not None and record_dt > to_dt:
            continue
        results.append(access)
    return results


def query(
    index: GovernanceIndex,
    *,
    subject_id: str | None = None,
    asset_id: str | None = None,
    agent_id: str | None = None,
    from_dt: datetime | None = None,
    to_dt: datetime | None = None,
) -> list[DataAccessRecord]:
    """Compound query: intersects results from all provided filters."""
    result_sets: list[set[int]] = []

    if subject_id is not None:
        result_sets.append(set(index.by_subject.get(subject_id, [])))
    if asset_id is not None:
        result_sets.append(set(index.by_asset.get(asset_id, [])))
    if agent_id is not None:
        result_sets.append(set(index.by_agent.get(agent_id, [])))

    if result_sets:
        positions = result_sets[0]
        for s in result_sets[1:]:
            positions = positions & s
    else:
        positions = set(range(len(index.accesses)))

    candidates = [index.accesses[p] for p in sorted(positions)]

    if from_dt is None and to_dt is None:
        return candidates

    filtered: list[DataAccessRecord] = []
    for access in candidates:
        ts = access.timestamp
        normalized = ts.replace("Z", "+00:00") if ts.endswith("Z") else ts
        try:
            record_dt = datetime.fromisoformat(normalized)
        except (ValueError, TypeError):
            continue
        if from_dt is not None and record_dt < from_dt:
            continue
        if to_dt is not None and record_dt > to_dt:
            continue
        filtered.append(access)
    return filtered
