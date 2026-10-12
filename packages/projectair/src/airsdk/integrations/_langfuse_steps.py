"""Render individual AgDR records as Langfuse child observations.

Each function takes the run's root observation and one record, and either
opens, closes, or emits a single child. ``capture`` mirrors
``LangfuseTransport(capture_content=...)``: when ``False``, bodies are withheld.
"""
from __future__ import annotations

from typing import Any

from airsdk.integrations._langfuse_mapping import (
    EVENT_NAMES,
    GENERATION_NAME,
    end_metadata,
    forensic_metadata,
    model_parameters,
    usage_details,
)
from airsdk.types import AGDR_VERSION, AgDRRecord, StepKind


class OpenObservation:
    """An observation awaiting its closing record, plus what the opener carried.

    A *_start and its *_end are two distinct signed records that each hold part
    of the picture: the request's sampling parameters and chain coordinates live
    on the start, the response's tokens and finish reason on the end. Langfuse
    needs them merged onto one observation, so the opener's state rides along.
    """

    __slots__ = ("metadata", "model_parameters", "observation")

    def __init__(
        self,
        observation: Any,
        metadata: dict[str, Any],
        model_parameters: dict[str, Any] | None = None,
    ) -> None:
        self.observation = observation
        self.metadata = metadata
        self.model_parameters = model_parameters or {}


def start_generation(root: Any, record: AgDRRecord, capture: bool) -> OpenObservation:
    prov = record.payload.provenance
    metadata = forensic_metadata(record)
    params = model_parameters(record)
    generation = root.start_observation(
        name=GENERATION_NAME,
        as_type="generation",
        input=record.payload.prompt if capture else None,
        model=prov.model if prov is not None else None,
        model_parameters=params,
        metadata=metadata,
        version=AGDR_VERSION,
    )
    return OpenObservation(generation, metadata, params)


def end_generation(
    root: Any, entry: OpenObservation | None, record: AgDRRecord, capture: bool
) -> None:
    if entry is None:
        # An llm_end with no matching llm_start (a truncated chain, or a
        # caller emitting ends directly). Record it rather than dropping it.
        entry = OpenObservation(
            root.start_observation(name=GENERATION_NAME, as_type="generation"), {}
        )

    prov = record.payload.provenance
    # Start coordinates first, then the end record's, so both signed records
    # are reachable from the one observation.
    metadata = {**entry.metadata, **end_metadata(record)}
    if prov is not None:
        metadata.update(
            {
                "air.provider": prov.provider,
                "air.model_version": prov.model_version,
                "air.system_fingerprint": prov.system_fingerprint,
                "air.finish_reason": prov.finish_reason,
            }
        )
    entry.observation.update(
        output=record.payload.response if capture else None,
        model=prov.model if prov is not None else None,
        # Request-time sampling parameters live on llm_start; keep them when
        # the closing record does not repeat them.
        model_parameters={**entry.model_parameters, **model_parameters(record)},
        usage_details=usage_details(record),
        metadata={key: value for key, value in metadata.items() if value is not None},
    )
    entry.observation.end()


def start_tool(root: Any, record: AgDRRecord, capture: bool) -> OpenObservation | None:
    """Open a tool span; returns ``None`` when containment closed it already."""
    payload = record.payload
    metadata = forensic_metadata(record)
    tool = root.start_observation(
        # Tool names are the low-cardinality identity of the step, and are
        # what LLM-as-a-judge evaluators and dashboards filter on.
        name=payload.tool_name or "tool",
        as_type="tool",
        input=payload.tool_args if capture else None,
        metadata=metadata,
        version=AGDR_VERSION,
    )
    if payload.blocked:
        # Containment tripped: no tool_end will follow, so close it here or
        # the span hangs open for the life of the trace.
        reason = payload.blocked_reason or "blocked by containment policy"
        tool.update(
            level="ERROR",
            status_message=reason,
            output={"blocked": True, "reason": reason, "challenge_id": payload.challenge_id},
        )
        tool.end()
        return None
    return OpenObservation(tool, metadata)


def end_tool(
    root: Any, entry: OpenObservation | None, record: AgDRRecord, capture: bool
) -> None:
    if entry is None:
        entry = OpenObservation(
            root.start_observation(name=record.payload.tool_name or "tool", as_type="tool"),
            {},
        )
    entry.observation.update(
        output=record.payload.tool_output if capture else None,
        metadata={**entry.metadata, **end_metadata(record)},
    )
    entry.observation.end()


def emit_event(root: Any, record: AgDRRecord, capture: bool) -> None:
    payload = record.payload
    output: Any = None
    if capture:
        if record.kind == StepKind.AGENT_MESSAGE:
            output = {
                "source_agent_id": payload.source_agent_id,
                "target_agent_id": payload.target_agent_id,
                "message_content": payload.message_content,
            }
        elif record.kind == StepKind.ANCHOR:
            output = {
                "anchored_chain_root": payload.anchored_chain_root,
                "anchored_step_range": payload.anchored_step_range,
            }
    root.start_observation(
        name=EVENT_NAMES[record.kind],
        as_type="event",
        output=output,
        metadata=forensic_metadata(record),
        version=AGDR_VERSION,
    ).end()
