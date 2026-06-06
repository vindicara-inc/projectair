"""Structural verifier: orchestrates symbolic checks over an AgDR chain.

Ships the deterministic floor only (v1). LLM reasoning ceiling is v2.
"""
from __future__ import annotations

from airsdk.causal.inference import build_causal_graph
from airsdk.containment.require_delegation import (
    DelegationPolicy,
    should_require_delegation,
)
from airsdk.types import AgDRRecord, IntentSpec, StepKind
from airsdk.verification.checks.delegation import check_delegation
from airsdk.verification.checks.entity import check_entities
from airsdk.verification.checks.network import check_network
from airsdk.verification.checks.scope import check_scope
from airsdk.verification.checks.secrets import check_secrets
from airsdk.verification.checks.trajectory import check_exfiltration
from airsdk.verification.intent import extract_intent
from airsdk.verification.types import (
    IntentSource,
    IntentVerdict,
    IntentVerificationResult,
    Violation,
)


def verify_intent(
    records: list[AgDRRecord],
    intent_spec: IntentSpec | None = None,
    *,
    require_delegation: bool | None = None,
    delegation_policy: DelegationPolicy | None = None,
) -> IntentVerificationResult:
    """Run structural verification over a chain.

    If ``intent_spec`` is provided it overrides any INTENT_DECLARATION
    record in the chain (useful for re-verifying with a different spec).

    SV-AUTH delegation coverage is policy-driven. Pass ``require_delegation``
    for a boolean override, or ``delegation_policy`` for ``always`` /
    ``auto`` / ``never`` modes. When both are omitted, ``AUTO`` applies:
    legacy chains (no DELEGATION genesis) are not retroactively failed;
    chains that open with a DELEGATION genesis are enforced. Use
    ``check_delegation`` (or ``air verify-delegation``) to inspect coverage
    without affecting the intent verdict.
    """
    if not records:
        return IntentVerificationResult(
            verdict=IntentVerdict.INCONCLUSIVE,
            intent="",
            intent_source=IntentSource.NONE,
            violations=[],
            checked_steps=0,
            total_steps=0,
            summary="Empty chain.",
        )

    enforce = (
        require_delegation
        if require_delegation is not None
        else should_require_delegation(records, delegation_policy)
    )
    delegation_violations = check_delegation(records) if enforce else []

    goal, chain_spec, source = extract_intent(records)
    if intent_spec is not None:
        chain_spec = intent_spec
        goal = intent_spec.goal
        source = IntentSource.DECLARATION

    if not goal:
        if delegation_violations:
            ordered = sorted(delegation_violations, key=lambda v: (_severity_rank(v.severity), v.step_index))
            return IntentVerificationResult(
                verdict=IntentVerdict.FAILED,
                intent="",
                intent_source=IntentSource.NONE,
                violations=ordered,
                checked_steps=0,
                total_steps=len(records),
                summary="FAILED: uncovered agent (no valid human delegation).",
            )
        return IntentVerificationResult(
            verdict=IntentVerdict.INCONCLUSIVE,
            intent="",
            intent_source=IntentSource.NONE,
            violations=[],
            checked_steps=0,
            total_steps=len(records),
            summary="No intent found in chain. Cannot verify.",
        )

    actionable = [
        r for r in records
        if r.kind in (StepKind.TOOL_START, StepKind.TOOL_END)
    ]

    graph = build_causal_graph(records)

    violations: list[Violation] = []
    violations.extend(check_secrets(records, chain_spec))
    violations.extend(check_network(records, chain_spec))
    violations.extend(check_scope(records, chain_spec))
    violations.extend(check_exfiltration(records, graph))
    violations.extend(check_entities(records, chain_spec))
    violations.extend(delegation_violations)

    violations = _deduplicate(violations)
    violations.sort(key=lambda v: (_severity_rank(v.severity), v.step_index))

    if violations:
        crit = sum(1 for v in violations if v.severity == "critical")
        high = sum(1 for v in violations if v.severity == "high")
        parts = []
        if crit:
            parts.append(f"{crit} critical")
        if high:
            parts.append(f"{high} high")
        summary = f"FAILED: {', '.join(parts)} violation(s) against declared intent."
        verdict = IntentVerdict.FAILED
    elif source == IntentSource.EXTRACTED:
        summary = (
            "No violations detected, but verification is based on "
            "extracted free-text intent. Use IntentSpec for full coverage."
        )
        verdict = IntentVerdict.VERIFIED
    else:
        summary = "All steps consistent with declared intent."
        verdict = IntentVerdict.VERIFIED

    return IntentVerificationResult(
        verdict=verdict,
        intent=goal,
        intent_source=source,
        violations=violations,
        checked_steps=len(actionable),
        total_steps=len(records),
        summary=summary,
    )


def _severity_rank(severity: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2}.get(severity, 3)


def _deduplicate(violations: list[Violation]) -> list[Violation]:
    """Remove violations on the same step with the same check_id."""
    seen: set[tuple[str, int]] = set()
    out: list[Violation] = []
    for v in violations:
        key = (v.check_id, v.step_index)
        if key not in seen:
            seen.add(key)
            out.append(v)
    return out
