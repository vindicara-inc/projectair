"""Findings surface: the ``see vs. do`` boundary made concrete.

- ``GET /v1/findings`` runs the 16 detectors over the workspace's ingested
  capsules and returns the real findings. **Every tier, including free.** This is
  the AUDIT floor: you always see the truth about your own agent.
- ``POST /v1/findings/{finding_id}/act`` records an action on a finding. Guarded
  by :func:`require_action`: a free-tier workspace gets a 402 with an upgrade
  prompt; paid tiers record the action. This is the door handle you pay for.

Findings are computed on read from the stored capsules rather than precomputed on
ingest, so a chain and its findings can never drift out of sync.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

from airsdk.detections import run_detectors
from airsdk.types import Finding  # noqa: TC002 - runtime use: pydantic model field, not just an annotation
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from vindicara.cloud.capabilities import can_act, require_action, resolve_tier

if TYPE_CHECKING:
    from vindicara.cloud.capsule_store import CapsuleStore

router = APIRouter(tags=["findings"])


class FindingActionRecord(BaseModel):
    workspace_id: str
    finding_id: str
    intent: str


class FindingActionStore:
    """In-memory record of actions taken on findings.

    Follows the same convention as the capsule / workspace stores: an in-memory
    implementation ships first; a DynamoDB-backed one lands when the acting
    tiers need durable action history. Only paid tiers ever reach this store
    (the route gate blocks free), so its contents are always billable actions.
    """

    def __init__(self) -> None:
        self._items: list[FindingActionRecord] = []
        self._lock = threading.Lock()

    def record(self, *, workspace_id: str, finding_id: str, intent: str) -> None:
        with self._lock:
            self._items.append(
                FindingActionRecord(workspace_id=workspace_id, finding_id=finding_id, intent=intent)
            )

    def for_workspace(self, workspace_id: str) -> list[FindingActionRecord]:
        with self._lock:
            return [a for a in self._items if a.workspace_id == workspace_id]


class FindingsPage(BaseModel):
    workspace_id: str
    tier: str
    can_act: bool
    count: int
    findings: list[Finding]


class FindingActionBody(BaseModel):
    intent: str = Field(min_length=1)


def _workspace_findings(request: Request, workspace_id: str) -> list[Finding]:
    store: CapsuleStore = request.app.state.capsule_store
    records = [c.record for c in store.for_workspace(workspace_id)]
    return run_detectors(records)


@router.get("/v1/findings")
async def list_findings(request: Request) -> FindingsPage:
    """Return the real findings for the calling workspace. Open to every tier."""
    workspace_id: str = request.state.workspace_id
    tier = resolve_tier(request)
    findings = _workspace_findings(request, workspace_id)
    return FindingsPage(
        workspace_id=workspace_id,
        tier=tier,
        can_act=can_act(tier),
        count=len(findings),
        findings=findings,
    )


@router.post(
    "/v1/findings/{finding_id}/act",
    status_code=204,
    dependencies=[Depends(require_action("act_on_finding"))],
)
async def act_on_finding(finding_id: str, body: FindingActionBody, request: Request) -> None:
    """Record an action on a finding. Free tier is blocked by the gate above."""
    store: FindingActionStore | None = getattr(request.app.state, "finding_actions", None)
    if store is not None:
        store.record(
            workspace_id=request.state.workspace_id,
            finding_id=finding_id,
            intent=body.intent,
        )


__all__ = ["FindingActionStore", "FindingsPage", "router"]
