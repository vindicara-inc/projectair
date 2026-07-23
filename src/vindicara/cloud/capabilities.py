"""Tier capabilities: the single ``see vs. do`` rule for AIR Cloud.

The product model in one line: **free sees everything, does nothing.** Every
finding from every detector is visible on every tier; only paid tiers can *act*
on them (resolve, contain, anchor, export, retain). This module is the one place
that rule lives, so every action endpoint enforces the same boundary.

``require_action`` is a FastAPI dependency: attach it to any endpoint that
changes state or produces a kept/provable artifact, and a free-tier caller gets
a 402 with an upgrade prompt instead of the mutation. View endpoints attach
nothing and stay open to all tiers.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import HTTPException, Request, status

if TYPE_CHECKING:
    from collections.abc import Callable

    from vindicara.cloud.workspace import Workspace, WorkspaceStore

FREE = "free"
PRO = "pro"
TEAM = "team"
ENTERPRISE = "enterprise"

#: Tiers whose users may take actions. Free is deliberately excluded.
ACTING_TIERS = frozenset({PRO, TEAM, ENTERPRISE})

UPGRADE_URL = "https://vindicara.io/pricing"


def can_act(tier: str) -> bool:
    """True if ``tier`` may take actions (not read-only). Free is read-only."""
    return tier in ACTING_TIERS


def upgrade_detail(action: str) -> dict[str, str]:
    """The 402 body a free-tier caller receives when it attempts an action."""
    return {
        "error": "action_requires_upgrade",
        "action": action,
        "message": (
            f"Your workspace is on the free tier, which is read-only. "
            f"'{action}' requires Pro or above. Upgrade to act on findings, "
            f"anchor, export, and keep your history."
        ),
        "upgrade_url": UPGRADE_URL,
    }


def resolve_tier(request: Request) -> str:
    """Resolve the calling workspace's tier from the request.

    The auth middleware set ``request.state.workspace_id`` from the API key /
    session. Fail closed: an unknown or missing workspace resolves to free
    (read-only), never to an acting tier.
    """
    workspace_id: str | None = getattr(request.state, "workspace_id", None)
    store: WorkspaceStore | None = getattr(request.app.state, "cloud_workspaces", None)
    if workspace_id is None or store is None:
        return FREE
    workspace: Workspace | None = store.get(workspace_id)
    return workspace.tier if workspace is not None else FREE


def require_action(action: str) -> Callable[[Request], None]:
    """Build a dependency that blocks free-tier callers from an action.

    Usage::

        @router.post("/v1/findings/{finding_id}/act",
                     dependencies=[Depends(require_action("act_on_finding"))])
    """

    def _dependency(request: Request) -> None:
        if not can_act(resolve_tier(request)):
            raise HTTPException(
                status_code=status.HTTP_402_PAYMENT_REQUIRED,
                detail=upgrade_detail(action),
            )

    return _dependency


__all__ = [
    "ACTING_TIERS",
    "ENTERPRISE",
    "FREE",
    "PRO",
    "TEAM",
    "UPGRADE_URL",
    "can_act",
    "require_action",
    "resolve_tier",
    "upgrade_detail",
]
