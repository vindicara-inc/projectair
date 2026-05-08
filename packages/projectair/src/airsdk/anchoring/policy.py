"""Policy and health dataclasses for the anchoring orchestrator.

Split out from ``orchestrator.py`` to keep that module under the
project's 300-line ceiling.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class AnchoringPolicy:
    """When to emit an anchor.

    Default: every 100 steps OR every 10 seconds, whichever fires first.
    """

    anchor_every_n_steps: int = 100
    anchor_every_n_seconds: float = 10.0
    rfc3161_enabled: bool = True
    rekor_enabled: bool = True


@dataclass(frozen=True)
class FailurePolicy:
    """What to do when the anchoring pipeline is unhealthy.

    ``on_anchor_failure`` is the default. Specific actions can be forced
    fail-closed via ``fail_closed_for_actions`` even when the default is
    fail-open. ``max_unanchored_steps`` and ``max_unanchored_seconds``
    promote fail-open into fail-closed when the backlog grows past the
    operator's tolerance.
    """

    on_anchor_failure: str = "fail_open"
    fail_closed_for_actions: list[dict[str, object]] = field(default_factory=list)
    max_unanchored_steps: int = 500
    max_unanchored_seconds: float = 300.0


@dataclass
class OrchestratorHealth:
    """Snapshot of anchoring pipeline health for /metrics and CLI status."""

    unanchored_step_count: int
    seconds_since_last_anchor: float
    last_anchor_status: str
    next_anchor_due_seconds: float
