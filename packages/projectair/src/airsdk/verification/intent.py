"""Extract declared intent from an AgDR chain.

Three sources, in priority order:
1. INTENT_DECLARATION record (structured IntentSpec)
2. user_intent field on chain records (free-text, weaker)
3. Nothing found (verdict will be INCONCLUSIVE)
"""
from __future__ import annotations

from airsdk.types import AgDRRecord, IntentSpec, StepKind
from airsdk.verification.types import IntentSource


def extract_intent(
    records: list[AgDRRecord],
) -> tuple[str, IntentSpec | None, IntentSource]:
    """Return (goal_text, intent_spec_or_none, source).

    Searches for INTENT_DECLARATION first, then falls back to
    user_intent strings on the earliest records.
    """
    for record in records:
        if record.kind == StepKind.INTENT_DECLARATION and record.payload.intent_spec is not None:
            spec = record.payload.intent_spec
            return spec.goal, spec, IntentSource.DECLARATION

    for record in records:
        if record.payload.user_intent:
            return record.payload.user_intent, None, IntentSource.EXTRACTED

    return "", None, IntentSource.NONE
