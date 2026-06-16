"""Structural verification: the proof that the signed promise was kept.

Intent Capsules record what the agent declared it would do. Structural
verification checks whether the agent's actual behavior served that
declaration. The symbolic floor is deterministic and cannot be prompt-
injected. Experimental in v1; LLM reasoning ceiling ships in v2.
"""
from __future__ import annotations

from airsdk.verification.intent import extract_intent
from airsdk.verification.types import (
    IntentSource,
    IntentVerdict,
    IntentVerificationResult,
    Violation,
)
from airsdk.verification.verifier import verify_intent

__all__ = [
    "IntentSource",
    "IntentVerdict",
    "IntentVerificationResult",
    "Violation",
    "extract_intent",
    "verify_intent",
]
