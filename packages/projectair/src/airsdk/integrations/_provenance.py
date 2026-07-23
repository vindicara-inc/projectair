"""Shared helpers for building :class:`airsdk.types.DecisionProvenance`.

Each provider maps its own request/response shape to ``DecisionProvenance``
(field names differ: OpenAI ``system_fingerprint`` + ``usage.prompt_tokens``,
Anthropic ``stop_reason`` + ``usage.input_tokens``, Gemini ``usage_metadata``),
so the assembly stays in each integration. Only the genuinely provider-neutral
bits live here.
"""
from __future__ import annotations

from typing import Any


def normalize_stop(value: Any) -> list[str] | None:
    """Normalize a stop / stop_sequences argument (str | list | None) to a list."""
    if value is None:
        return None
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value]
    return None
