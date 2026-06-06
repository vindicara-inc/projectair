"""SV-AUTH: every agent session must open with a valid human delegation.

No agent is autonomous. A chain whose genesis is not a valid, unexpired
DELEGATION record signed by an authenticated human is an "uncovered agent": it
ran with no traceable human on the hook. This is the deterministic embodiment
of the thesis. It does not judge intent; it checks for the presence and
validity of delegated authority, the same way the other SV checks operate
symbolically over the chain.

Wired into ``verifier.py`` alongside the other checks:
    violations.extend(check_delegation(records))
"""
from __future__ import annotations

from datetime import datetime

from airsdk.types import AgDRRecord, StepKind
from airsdk.verification.types import Violation

# Anchor records may precede the genesis; skip them when locating the root.
_SKIP_BEFORE_GENESIS = frozenset({StepKind.ANCHOR})


def check_delegation(records: list[AgDRRecord]) -> list[Violation]:
    """Return SV-AUTH violations for a chain lacking valid delegated authority."""
    if not records:
        return []

    violations: list[Violation] = []

    genesis_idx = next(
        (i for i, r in enumerate(records) if r.kind not in _SKIP_BEFORE_GENESIS),
        None,
    )
    if genesis_idx is None:
        return []
    genesis = records[genesis_idx]

    if genesis.kind != StepKind.DELEGATION:
        return [
            Violation(
                check_id="SV-AUTH-01",
                title="Uncovered agent: no human delegation at session start",
                severity="critical",
                step_index=genesis_idx,
                step_id=genesis.step_id,
                evidence=f"genesis record kind={genesis.kind.value}",
                expected="session opens with a DELEGATION record",
                actual="agent ran with no traceable authorizing human",
            )
        ]

    grant = genesis.payload.delegation
    if grant is None:
        return [
            Violation(
                check_id="SV-AUTH-02",
                title="Malformed delegation: DELEGATION record carries no grant",
                severity="critical",
                step_index=genesis_idx,
                step_id=genesis.step_id,
                evidence="payload.delegation is empty",
                expected="a populated DelegationGrant",
                actual="empty",
            )
        ]

    if grant.decision != "authorize":
        violations.append(
            Violation(
                check_id="SV-AUTH-03",
                title="Agent ran under a denied delegation",
                severity="critical",
                step_index=genesis_idx,
                step_id=genesis.step_id,
                evidence=f"decision={grant.decision}",
                expected="decision=authorize",
                actual=f"decision={grant.decision}",
            )
        )

    if not grant.authorizer_sub:
        violations.append(
            Violation(
                check_id="SV-AUTH-04",
                title="Delegation has no authenticated human",
                severity="critical",
                step_index=genesis_idx,
                step_id=genesis.step_id,
                evidence="authorizer_sub is empty",
                expected="an authenticated subject",
                actual="none",
            )
        )

    expires_at = grant.expires_at
    if expires_at:
        for i in range(genesis_idx + 1, len(records)):
            r = records[i]
            ts = _epoch(r.timestamp)
            if ts is not None and ts > expires_at:
                violations.append(
                    Violation(
                        check_id="SV-AUTH-05",
                        title="Agent acted after its delegation expired",
                        severity="high",
                        step_index=i,
                        step_id=r.step_id,
                        evidence=f"action at {r.timestamp}; grant expired at epoch {expires_at}",
                        expected="all actions before delegation expiry",
                        actual="action after expiry",
                    )
                )
                break  # one report per session is enough

    return violations


def _epoch(timestamp_iso: str) -> int | None:
    try:
        return int(datetime.fromisoformat(timestamp_iso.replace("Z", "+00:00")).timestamp())
    except (ValueError, AttributeError):
        return None
