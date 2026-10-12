"""AgDR-to-Langfuse vocabulary: observation names, content fields, metadata.

Pure functions of a single :class:`~airsdk.types.AgDRRecord`; no Langfuse
import, so this module loads without the ``[langfuse]`` extra.
"""
from __future__ import annotations

from typing import Any

from airsdk.types import AgDRRecord, StepKind

# Stable, low-cardinality observation names. These are an API: Langfuse
# evaluators, dashboard filters and saved views target observations by name, so
# changing one silently breaks every query that referenced it. Dynamic values
# (step ids, models, retry counts) belong in metadata, never in the name.
ROOT_NAME = "agent-run"
GENERATION_NAME = "call-llm"
_MESSAGE_NAME = "agent-message"
_APPROVAL_NAME = "human-approval"
_ANCHOR_NAME = "anchor-chain"
_ATTESTATION_NAME = "attest-gpu"
_KEY_TRANSITION_NAME = "rotate-signing-key"
_AUDIT_REVIEW_NAME = "review-audit-trail"

# Every payload field whose *content* this transport can put in front of
# Langfuse. A PHI-bearing deployment should hash all of them, because
# CapturePolicy matches on field name: naming only `prompt` and `response`
# leaves the tool arguments, the tool output and the agent's final answer in the
# clear. Exported so callers can write
# ``CapturePolicy(hash_fields=CONTENT_FIELDS)`` instead of maintaining their own
# copy of the list and silently falling behind when a new field lands here.
CONTENT_FIELDS = frozenset(
    {
        "prompt",
        "response",
        "tool_args",
        "tool_output",
        "final_output",
        "user_intent",
        "message_content",
    }
)

# Records that only open the chain: they establish the root observation and are
# not additionally rendered as their own event.
GENESIS_KINDS = frozenset({StepKind.DELEGATION, StepKind.INTENT_DECLARATION})

# Point-in-time records rendered as Langfuse events rather than spans.
EVENT_NAMES = {
    StepKind.AGENT_MESSAGE: _MESSAGE_NAME,
    StepKind.HUMAN_APPROVAL: _APPROVAL_NAME,
    StepKind.ANCHOR: _ANCHOR_NAME,
    StepKind.GPU_ATTESTATION: _ATTESTATION_NAME,
    StepKind.KEY_TRANSITION: _KEY_TRANSITION_NAME,
    StepKind.AUDIT_REVIEW: _AUDIT_REVIEW_NAME,
}


def forensic_metadata(record: AgDRRecord) -> dict[str, Any]:
    """The chain coordinates that let a reviewer jump from Langfuse to `air verify`."""
    meta: dict[str, Any] = {
        "air.step_id": record.step_id,
        "air.kind": str(record.kind),
        "air.content_hash": record.content_hash,
        "air.prev_hash": record.prev_hash,
        "air.signer_key": record.signer_key,
        "air.signature_algorithm": str(record.signature_algorithm),
        "air.meta_signed": record.meta_signed,
        "air.agdr_version": record.version,
    }
    refs = record.payload.content_refs
    if refs:
        # The chain referenced these fields instead of storing them. Surfacing
        # the digest tells a reviewer the content exists and is integrity-
        # checkable via the reference vault, without leaking it.
        meta["air.content_refs"] = dict(refs)
    return meta


def end_metadata(record: AgDRRecord) -> dict[str, Any]:
    """Closing-record coordinates, namespaced so they do not clobber the opener's."""
    meta: dict[str, Any] = {
        "air.end_step_id": record.step_id,
        "air.end_content_hash": record.content_hash,
    }
    refs = record.payload.content_refs
    if refs:
        meta["air.end_content_refs"] = dict(refs)
    return meta


def model_parameters(record: AgDRRecord) -> dict[str, Any]:
    """Sampling parameters from ``DecisionProvenance``, minus the unset ones."""
    prov = record.payload.provenance
    if prov is None:
        return {}
    params = {
        "temperature": prov.temperature,
        "top_p": prov.top_p,
        "top_k": prov.top_k,
        "seed": prov.seed,
        "max_tokens": prov.max_tokens,
        "stop": prov.stop,
    }
    return {key: value for key, value in params.items() if value is not None}


def usage_details(record: AgDRRecord) -> dict[str, int]:
    """Token counts in Langfuse's ``input``/``output`` buckets for cost lookup."""
    prov = record.payload.provenance
    if prov is None:
        return {}
    usage: dict[str, int] = {}
    if prov.prompt_tokens is not None:
        usage["input"] = prov.prompt_tokens
    if prov.completion_tokens is not None:
        usage["output"] = prov.completion_tokens
    return usage
