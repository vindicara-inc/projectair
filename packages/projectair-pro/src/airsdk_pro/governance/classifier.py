"""NemoGuard auto-classification for data sensitivity suggestions."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from airsdk.types import AgDRRecord, StepKind

_PII_KEYWORDS = frozenset({
    "ssn", "social security", "date of birth", "dob", "passport",
    "driver's license", "credit card", "bank account", "tax id",
    "national id", "insurance number",
})
_PHI_KEYWORDS = frozenset({
    "patient", "diagnosis", "treatment", "medical record", "prescription",
    "lab result", "health", "clinical", "icd-10", "cpt code", "hipaa",
    "protected health", "phi", "hospital", "physician",
})
_FINANCIAL_KEYWORDS = frozenset({
    "account balance", "transaction", "wire transfer", "routing number",
    "investment", "portfolio", "salary", "compensation",
})


class SensitivitySuggestion(BaseModel):
    """Advisory suggestion for data sensitivity classification."""

    model_config = ConfigDict(extra="forbid")

    step_id: str
    suggested_sensitivity: str
    suggested_jurisdiction: str
    confidence: float
    matched_categories: list[str]


def _check_text(text: str) -> tuple[str, str, float, list[str]]:
    lower = text.lower()
    categories: list[str] = []

    for kw in _PHI_KEYWORDS:
        if kw in lower:
            categories.append(f"phi:{kw}")
    for kw in _PII_KEYWORDS:
        if kw in lower:
            categories.append(f"pii:{kw}")
    for kw in _FINANCIAL_KEYWORDS:
        if kw in lower:
            categories.append(f"financial:{kw}")

    if not categories:
        return "", "", 0.0, []

    phi_count = sum(1 for c in categories if c.startswith("phi:"))
    pii_count = sum(1 for c in categories if c.startswith("pii:"))

    if phi_count > 0:
        return "restricted", "HIPAA", min(0.5 + phi_count * 0.1, 1.0), categories
    if pii_count > 0:
        return "confidential", "GDPR", min(0.4 + pii_count * 0.1, 1.0), categories
    return "confidential", "", min(0.3 + len(categories) * 0.1, 1.0), categories


def classify_sensitivity(records: list[AgDRRecord]) -> list[SensitivitySuggestion]:
    """Scan chain records for PII/PHI patterns and suggest classifications.

    Uses keyword heuristics as a baseline. When NemoGuardClient is
    available, it can be used upstream to produce higher-confidence
    classifications; this function provides a zero-dependency floor.
    """
    suggestions: list[SensitivitySuggestion] = []

    for record in records:
        if record.kind not in (StepKind.TOOL_START, StepKind.LLM_END):
            continue

        texts: list[str] = []
        if record.payload.tool_args:
            for val in record.payload.tool_args.values():
                if isinstance(val, str):
                    texts.append(val)
        if record.payload.response:
            texts.append(record.payload.response)
        if record.payload.tool_output:
            texts.append(record.payload.tool_output)

        combined = " ".join(texts)
        if not combined:
            continue

        sensitivity, jurisdiction, confidence, categories = _check_text(combined)
        if categories:
            suggestions.append(SensitivitySuggestion(
                step_id=record.step_id,
                suggested_sensitivity=sensitivity,
                suggested_jurisdiction=jurisdiction,
                confidence=confidence,
                matched_categories=categories,
            ))

    return suggestions
