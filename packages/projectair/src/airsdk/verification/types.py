"""Types for structural verification of agent behavior against declared intent."""
from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class IntentVerdict(StrEnum):
    VERIFIED = "verified"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"


class IntentSource(StrEnum):
    DECLARATION = "declaration"
    EXTRACTED = "extracted"
    NONE = "none"


class Violation(BaseModel):
    """One structural violation found during intent verification."""

    model_config = ConfigDict(extra="forbid")

    check_id: str
    title: str
    severity: str
    step_index: int
    step_id: str
    evidence: str
    expected: str
    actual: str
    causal_path: list[int] = Field(default_factory=list)


class IntentVerificationResult(BaseModel):
    """Output of structural verification over an AgDR chain."""

    model_config = ConfigDict(extra="forbid")

    verdict: IntentVerdict
    intent: str
    intent_source: IntentSource
    violations: list[Violation]
    checked_steps: int
    total_steps: int
    summary: str
