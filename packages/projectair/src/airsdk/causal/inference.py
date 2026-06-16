"""Build a CausalGraph from an AgDR chain.

The inference is split into two passes:

1. **Hard edges** from explicit fields. Every record gets a CHAIN_LINK
   to its immediate predecessor. LLM_END pairs to its LLM_START.
   TOOL_END pairs to its TOOL_START. AGENT_MESSAGE records connect by
   target_agent_id.
2. **Soft edges** from content match. Tool outputs and LLM responses
   that reappear in later prompts or tool args get an OUTPUT_REUSE
   edge with confidence proportional to the matched length over the
   shorter of the two strings. The match has to clear a minimum length
   so accidental short overlaps ("Done.", "OK") do not generate noise.

Confidence floor for soft edges: 0.5. Length floor: 32 characters.
Both are conservative; tune via the demo chain test.
"""
from __future__ import annotations

from typing import Final

from airsdk.causal.types import CausalEdge, CausalGraph, CausalNode, EdgeKind
from airsdk.types import AgDRRecord, StepKind

_MIN_REUSE_LEN: Final[int] = 32
_FULL_REUSE_LEN: Final[int] = 128
_MIN_REUSE_CONFIDENCE: Final[float] = 0.5


def build_causal_graph(records: list[AgDRRecord]) -> CausalGraph:
    """Walk ``records`` and produce the inferred causal graph."""
    nodes = [_record_to_node(i, rec) for i, rec in enumerate(records)]
    edges: list[CausalEdge] = []
    edges.extend(_hard_edges(records))
    edges.extend(_soft_edges(records))
    return CausalGraph(nodes=nodes, edges=edges)


def _record_to_node(ordinal: int, record: AgDRRecord) -> CausalNode:
    return CausalNode(
        ordinal=ordinal,
        step_id=record.step_id,
        kind=record.kind.value,
        summary=_summarize(record),
    )


def _summarize(record: AgDRRecord) -> str:
    """One-line summary suitable for explain output."""
    payload = record.payload
    kind = record.kind
    if kind == StepKind.LLM_START and payload.prompt is not None:
        return _truncate(payload.prompt, 80)
    if kind == StepKind.LLM_END and payload.response is not None:
        return _truncate(payload.response, 80)
    if kind == StepKind.TOOL_START:
        name = payload.tool_name or "?"
        args = payload.tool_args or {}
        head = ", ".join(f"{k}={_truncate(str(v), 32)}" for k, v in list(args.items())[:2])
        return f"{name}({head})"
    if kind == StepKind.TOOL_END and payload.tool_output is not None:
        return _truncate(payload.tool_output, 80)
    if kind == StepKind.AGENT_FINISH and payload.final_output is not None:
        return _truncate(payload.final_output, 80)
    if kind == StepKind.AGENT_MESSAGE:
        src = payload.source_agent_id or "?"
        tgt = payload.target_agent_id or "?"
        body = _truncate(payload.message_content or "", 40)
        return f"{src} -> {tgt}: {body}"
    if kind == StepKind.ANCHOR:
        rkr = payload.rekor.log_index if payload.rekor else "?"
        return f"anchor (Rekor {rkr})"
    if kind == StepKind.INTENT_DECLARATION:
        goal = payload.intent_spec.goal if payload.intent_spec else payload.user_intent or "?"
        return _truncate(f"intent: {goal}", 80)
    return record.kind.value


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "..."


def _hard_edges(records: list[AgDRRecord]) -> list[CausalEdge]:
    edges: list[CausalEdge] = []
    pending_llm_start: int | None = None
    pending_tool_start: int | None = None
    last_llm_end: int | None = None

    for ordinal, rec in enumerate(records):
        # CHAIN_LINK: every non-first record links to the immediate prior.
        if ordinal > 0:
            edges.append(
                CausalEdge(
                    from_ordinal=ordinal - 1,
                    to_ordinal=ordinal,
                    kind=EdgeKind.CHAIN_LINK,
                    confidence=1.0,
                    evidence="prev_hash",
                ),
            )

        # LLM_PAIR: an LLM_END closes the most recent open LLM_START.
        if rec.kind == StepKind.LLM_START:
            pending_llm_start = ordinal
        elif rec.kind == StepKind.LLM_END and pending_llm_start is not None:
            edges.append(
                CausalEdge(
                    from_ordinal=pending_llm_start,
                    to_ordinal=ordinal,
                    kind=EdgeKind.LLM_PAIR,
                    confidence=1.0,
                    evidence="llm_start -> llm_end pair",
                ),
            )
            pending_llm_start = None
            last_llm_end = ordinal

        # TOOL_PAIR: a TOOL_END closes the most recent open TOOL_START.
        # LLM_DECISION: a TOOL_START is caused by the most recent LLM_END
        # (which decided to invoke the tool). Not present for orphan tool
        # calls (e.g. test fixtures with no preceding LLM step).
        if rec.kind == StepKind.TOOL_START:
            pending_tool_start = ordinal
            if last_llm_end is not None:
                edges.append(
                    CausalEdge(
                        from_ordinal=last_llm_end,
                        to_ordinal=ordinal,
                        kind=EdgeKind.LLM_DECISION,
                        confidence=1.0,
                        evidence="llm_end decided this tool call",
                    ),
                )
        elif rec.kind == StepKind.TOOL_END and pending_tool_start is not None:
            edges.append(
                CausalEdge(
                    from_ordinal=pending_tool_start,
                    to_ordinal=ordinal,
                    kind=EdgeKind.TOOL_PAIR,
                    confidence=1.0,
                    evidence="tool_start -> tool_end pair",
                ),
            )
            pending_tool_start = None

        # AGENT_MESSAGE: link by source/target agent id when both are set
        # on a prior record we can identify.
        if rec.kind == StepKind.AGENT_MESSAGE and rec.payload.target_agent_id:
            for prev_ord in range(ordinal - 1, -1, -1):
                prev = records[prev_ord]
                if (
                    prev.kind == StepKind.AGENT_MESSAGE
                    and prev.payload.source_agent_id == rec.payload.target_agent_id
                ):
                    edges.append(
                        CausalEdge(
                            from_ordinal=prev_ord,
                            to_ordinal=ordinal,
                            kind=EdgeKind.AGENT_MESSAGE,
                            confidence=1.0,
                            evidence=f"reply to {rec.payload.target_agent_id}",
                        ),
                    )
                    break
    return edges


def _soft_edges(records: list[AgDRRecord]) -> list[CausalEdge]:
    """Detect content reuse: prior output bytes appearing in later input bytes.

    Quadratic in the number of steps but with a fast early-exit: the
    inner loop returns on the first match for each (output, later-input)
    pair, and outputs/inputs shorter than the minimum length are skipped
    upfront. For chains under a few thousand steps this is fine; longer
    chains can be sharded by user_intent or session id without affecting
    semantics.
    """
    edges: list[CausalEdge] = []
    outputs: list[tuple[int, str]] = []  # (ordinal, output_text)

    for ordinal, rec in enumerate(records):
        # Capture every record's output-side text for later matching.
        out = _output_text(rec)
        if out is not None and len(out) >= _MIN_REUSE_LEN:
            outputs.append((ordinal, out))

        # Match this record's input-side text against earlier outputs.
        ins = _input_text(rec)
        if ins is None or len(ins) < _MIN_REUSE_LEN:
            continue
        for src_ord, src_text in outputs:
            if src_ord >= ordinal:
                break
            confidence, snippet = _content_overlap(src_text, ins)
            if confidence >= _MIN_REUSE_CONFIDENCE:
                edges.append(
                    CausalEdge(
                        from_ordinal=src_ord,
                        to_ordinal=ordinal,
                        kind=EdgeKind.OUTPUT_REUSE,
                        confidence=confidence,
                        evidence=f"matched bytes: {snippet!r}",
                    ),
                )
    return edges


def _output_text(record: AgDRRecord) -> str | None:
    p = record.payload
    if record.kind == StepKind.TOOL_END:
        return p.tool_output
    if record.kind == StepKind.LLM_END:
        return p.response
    if record.kind == StepKind.AGENT_MESSAGE:
        return p.message_content
    return None


def _input_text(record: AgDRRecord) -> str | None:
    p = record.payload
    if record.kind == StepKind.LLM_START:
        return p.prompt
    if record.kind == StepKind.TOOL_START and p.tool_args is not None:
        # Recursively flatten string values out of nested dicts/lists so
        # soft-match can find content reuse in tool arguments (e.g. an
        # SSH key embedded in an http_post body dict). Using str(value)
        # would escape embedded newlines and break exact substring match.
        return "\n".join(_flatten_strings(p.tool_args))
    return None


def _flatten_strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        out: list[str] = []
        for v in value.values():
            out.extend(_flatten_strings(v))
        return out
    if isinstance(value, list | tuple):
        out2: list[str] = []
        for v in value:
            out2.extend(_flatten_strings(v))
        return out2
    return [str(value)] if value is not None else []


def _content_overlap(src: str, dst: str) -> tuple[float, str]:
    """Return (confidence, snippet) for the largest contiguous substring of
    ``src`` that appears in ``dst``.

    Confidence is length-based, not ratio-based: in a forensic context the
    question is "is the matched substring long enough to be non-coincidental?",
    not "what fraction of the source appears". A 53-character match of an SSH
    key body in an HTTP POST is decisive evidence regardless of how much of
    the rest of the source key appears.

    Scale: ``_MIN_REUSE_LEN`` chars (32) -> 0.5 confidence, ``_FULL_REUSE_LEN``
    chars (128) -> 1.0. Below the minimum the match is reported as 0
    (treated as no signal).
    """
    if not src or not dst:
        return 0.0, ""
    best_len = 0
    best_snippet = ""
    # Greedy: try windows from longest to shortest, exit on first hit.
    window = min(len(src), 256)
    while window >= _MIN_REUSE_LEN:
        for i in range(0, len(src) - window + 1, max(1, window // 4)):
            chunk = src[i : i + window]
            if chunk in dst:
                best_len = window
                best_snippet = chunk[:64]
                break
        if best_len >= _MIN_REUSE_LEN:
            break
        window //= 2
    if best_len < _MIN_REUSE_LEN:
        return 0.0, ""
    span = _FULL_REUSE_LEN - _MIN_REUSE_LEN
    confidence = 0.5 + 0.5 * min(1.0, (best_len - _MIN_REUSE_LEN) / span)
    return confidence, best_snippet
