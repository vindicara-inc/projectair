"""SV-ENTITY: access to entities outside declared scope."""
from __future__ import annotations

import json
import re

from airsdk.types import AgDRRecord, IntentSpec, StepKind
from airsdk.verification.types import Violation


def _extract_identifiers(text: str, patterns: list[re.Pattern[str]]) -> set[str]:
    found: set[str] = set()
    for pattern in patterns:
        found.update(pattern.findall(text))
    return found


def _build_patterns(entities: list[str]) -> list[re.Pattern[str]]:
    escaped = [re.escape(e) for e in entities]
    return [re.compile(rf"\b{pat}\b", re.IGNORECASE) for pat in escaped]


def _text_from_record(record: AgDRRecord) -> str:
    parts: list[str] = []
    if record.payload.tool_args:
        parts.append(json.dumps(record.payload.tool_args, default=str))
    if record.payload.tool_output:
        parts.append(record.payload.tool_output)
    if record.payload.response:
        parts.append(record.payload.response)
    return "\n".join(parts)


def check_entities(
    records: list[AgDRRecord],
    intent_spec: IntentSpec | None,
) -> list[Violation]:
    if not intent_spec or not intent_spec.allowed_entities:
        return []

    allowed = set(intent_spec.allowed_entities)
    allowed_lower = {e.lower() for e in allowed}

    violations: list[Violation] = []

    for idx, record in enumerate(records):
        if record.kind not in (StepKind.TOOL_START, StepKind.TOOL_END):
            continue

        text = _text_from_record(record)
        if not text:
            continue

        all_candidate_ids = _scan_for_entity_patterns(text)
        unauthorized = set()
        for cid in all_candidate_ids:
            if cid.lower() not in allowed_lower:
                unauthorized.add(cid)

        if unauthorized:
            sample = sorted(unauthorized)[:5]
            violations.append(Violation(
                check_id="SV-ENTITY-01",
                title="Entity access outside declared scope",
                severity="critical",
                step_index=idx,
                step_id=record.step_id,
                evidence=f"found references to: {', '.join(sample)}",
                expected=f"only entities: {', '.join(sorted(allowed))}",
                actual=f"{len(unauthorized)} unauthorized entity reference(s)",
            ))

    return violations


def _scan_for_entity_patterns(text: str) -> set[str]:
    """Scan text for common entity identifier patterns."""
    found: set[str] = set()
    found.update(re.findall(r"\bMRN[- ]?\d{4,}", text, re.IGNORECASE))
    found.update(re.findall(r"\bPAT[- ]?\d{4,}", text, re.IGNORECASE))
    found.update(re.findall(r"\b\d{3}-\d{2}-\d{4}\b", text))
    found.update(re.findall(r"\bACCT[- ]?\d{4,}", text, re.IGNORECASE))
    found.update(re.findall(r"\bCASE[- ]?\d{4,}", text, re.IGNORECASE))
    found.update(re.findall(r"\bORD[- ]?\d{4,}", text, re.IGNORECASE))
    found.update(re.findall(r"\bUSR[- ]?\d{4,}", text, re.IGNORECASE))
    return found
