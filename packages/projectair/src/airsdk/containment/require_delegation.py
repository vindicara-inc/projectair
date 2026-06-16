"""SV-AUTH containment rule: policy-driven delegation enforcement.

Builds directly on what Cursor shipped:

  - ``verify_intent(records, intent_spec, *, require_delegation=False)`` already
    gates SV-AUTH behind a flag (default off), so legacy chains stay green.
  - ``check_delegation(records)`` already returns SV-AUTH-01..05.
  - ``DelegationGrant`` is the session-genesis record.

The gap that flag leaves: enforcement is *manual*. A caller has to remember to
pass ``require_delegation=True``. That means a session that opted into coverage by
opening with a DELEGATION genesis can still be verified without enforcement if
someone forgets the flag. This module closes that without touching legacy
behavior, using one principle:

    A chain is enforced if and only if it declares a delegation.

Concretely:

  - genesis is DELEGATION  -> the operator opted into coverage, so enforce
    (SV-AUTH must pass; an expired/denied/missing grant now FAILS).
  - genesis is NOT DELEGATION (legacy llm_start/tool_start) -> do not enforce,
    exactly as today. SV-AUTH never surfaces, nothing breaks.
  - an explicit override always wins, in either direction, for policy authors
    who want a hard floor ("every session in this deployment must be covered")
    or a hard exemption.

Liability stays with the policy author: the decision to require delegation
across a deployment is an explicit configuration, not a silent default.
"""
from __future__ import annotations

from dataclasses import dataclass

from airsdk._compat import StrEnum
from airsdk.containment.policy import Decision
from airsdk.types import AgDRRecord, StepKind

# Anchor (and any pre-genesis bookkeeping) records may precede the genesis.
# Keep this in sync with check_delegation._SKIP_BEFORE_GENESIS.
_SKIP_BEFORE_GENESIS = frozenset({StepKind.ANCHOR})


class EnforcementMode(StrEnum):
    """How require_delegation is decided for a chain."""

    AUTO = "auto"        # enforce iff the chain declares a DELEGATION genesis
    ALWAYS = "always"    # enforce every chain (deployment-wide human-on-the-hook floor)
    NEVER = "never"      # never enforce (legacy / migration escape hatch)


@dataclass(frozen=True)
class DelegationPolicy:
    """Policy-author configuration for SV-AUTH enforcement.

    Default is AUTO, which is the safe, backward-compatible behavior: a chain is
    enforced only if it opted in by declaring a delegation. Set ALWAYS for a
    deployment where every agent must be covered.
    """

    mode: EnforcementMode = EnforcementMode.AUTO


def declares_delegation(records: list[AgDRRecord]) -> bool:
    """True iff the chain's genesis (first non-anchor record) is a DELEGATION.

    This is the single signal that distinguishes 'opted into coverage' from
    'legacy chain'. It is intentionally structural and cheap: no signature or
    expiry checking here, that is check_delegation's job once we decide to run it.
    """
    genesis = next((r for r in records if r.kind not in _SKIP_BEFORE_GENESIS), None)
    return genesis is not None and genesis.kind == StepKind.DELEGATION


def should_require_delegation(
    records: list[AgDRRecord],
    policy: DelegationPolicy | None = None,
) -> bool:
    """Resolve whether SV-AUTH should be enforced for this chain.

    Pass the result straight into ``verify_intent(..., require_delegation=<this>)``.
    """
    policy = policy or DelegationPolicy()
    if policy.mode is EnforcementMode.ALWAYS:
        return True
    if policy.mode is EnforcementMode.NEVER:
        return False
    # AUTO
    return declares_delegation(records)


# --------------------------------------------------------------------------- #
# step-time containment (the recorder path)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ContainmentResult:
    decision: Decision
    rule: str = "require_delegation"
    reason: str = ""

    @property
    def blocked(self) -> bool:
        return self.decision == Decision.BLOCK


def evaluate_require_delegation(
    records_so_far: list[AgDRRecord],
    *,
    policy: DelegationPolicy | None = None,
) -> ContainmentResult:
    """Containment hook: deny the next gated step when the session is supposed
    to be covered but isn't.

    Call this from ContainmentPolicy.evaluate before a gated tool_start. It runs
    check_delegation over the chain-so-far only when enforcement applies for this
    chain (per the policy), so legacy chains are never blocked.

    Returns BLOCK with a clear reason if any SV-AUTH violation is present,
    otherwise ALLOW.
    """
    policy = policy or DelegationPolicy()
    if not should_require_delegation(records_so_far, policy):
        return ContainmentResult(
            Decision.ALLOW,
            reason="delegation not required for this chain",
        )

    # Lazy import breaks the containment <-> verification import cycle.
    from airsdk.verification.checks.delegation import check_delegation

    violations = check_delegation(records_so_far)
    if violations:
        first = violations[0]
        return ContainmentResult(
            Decision.BLOCK,
            reason=(
                f"no valid human delegation for this session "
                f"({first.check_id}: {first.actual})"
            ),
        )
    return ContainmentResult(
        Decision.ALLOW,
        reason="session covered by a valid delegation",
    )
