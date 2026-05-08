"""W3C Trace Context generation, parsing, and propagation per Section 5.

The Parent Trace ID (PTID) is the W3C trace_id verbatim: 32 lowercase hex
characters. The full traceparent header is propagated end-to-end so OTel
exporters do not break. Receiving agents generate a fresh parent-id
(span-id) for their own outbound calls per W3C standard span hierarchy.

Reference: https://www.w3.org/TR/trace-context/

Wire format::

    traceparent: 00-<trace-id>-<parent-id>-<trace-flags>
    Components:
      00              : version (current W3C spec)
      trace-id        : 32 lowercase hex chars (this is the PTID)
      parent-id       : 16 lowercase hex chars (the calling span's id)
      trace-flags     : 2 lowercase hex chars (sampling decision)

The ``tracestate`` header MAY carry vendor-specific extensions; receiving
agents propagate it unmodified.
"""
from __future__ import annotations

import re
import secrets
from dataclasses import dataclass

from .exceptions import PTIDInvalidError, W3CTraceContextError

_PTID_RE = re.compile(r"^[0-9a-f]{32}$")
_SPAN_ID_RE = re.compile(r"^[0-9a-f]{16}$")
_TRACE_FLAGS_RE = re.compile(r"^[0-9a-f]{2}$")
_TRACEPARENT_RE = re.compile(
    r"^(?P<version>[0-9a-f]{2})-"
    r"(?P<trace_id>[0-9a-f]{32})-"
    r"(?P<parent_id>[0-9a-f]{16})-"
    r"(?P<trace_flags>[0-9a-f]{2})$"
)

# Sentinel "all zero" values per W3C spec section 3.2.2.3 — invalid for use.
_ALL_ZERO_TRACE_ID = "0" * 32
_ALL_ZERO_SPAN_ID = "0" * 16


@dataclass(frozen=True, slots=True)
class TraceContext:
    """The W3C trace context for one hop in a workflow.

    ``trace_id`` is the PTID; it is immutable for the workflow's lifetime.
    ``parent_id`` is the span-id of the calling span; each agent generates
    a fresh one for its own outbound calls.
    """

    trace_id: str
    parent_id: str
    trace_flags: str = "01"  # sampled
    tracestate: str | None = None
    version: str = "00"

    def to_traceparent(self) -> str:
        """Serialize to the W3C traceparent header value."""
        return f"{self.version}-{self.trace_id}-{self.parent_id}-{self.trace_flags}"


def generate_ptid() -> str:
    """Mint a fresh 128-bit PTID (W3C trace_id, 32 lowercase hex)."""
    while True:
        candidate = secrets.token_hex(16)
        if candidate != _ALL_ZERO_TRACE_ID:
            return candidate


def generate_span_id() -> str:
    """Mint a fresh 64-bit span-id (W3C parent-id, 16 lowercase hex)."""
    while True:
        candidate = secrets.token_hex(8)
        if candidate != _ALL_ZERO_SPAN_ID:
            return candidate


def validate_ptid(ptid: str) -> None:
    """Confirm ``ptid`` is a syntactically valid W3C trace_id."""
    if not isinstance(ptid, str) or not _PTID_RE.match(ptid):
        raise PTIDInvalidError(
            f"PTID must be 32 lowercase hex characters; got {ptid!r}"
        )
    if ptid == _ALL_ZERO_TRACE_ID:
        raise PTIDInvalidError("all-zero trace_id is invalid per W3C 3.2.2.3")


def parse_traceparent(traceparent: str) -> TraceContext:
    """Parse a W3C traceparent header value into a :class:`TraceContext`.

    Strict parser: rejects malformed input rather than silently accepting it.
    Per Section 5.2 the receiving agent MUST extract all four components.
    """
    if not isinstance(traceparent, str):
        raise W3CTraceContextError(
            f"traceparent must be str; got {type(traceparent).__name__}"
        )
    match = _TRACEPARENT_RE.match(traceparent)
    if match is None:
        raise W3CTraceContextError(
            f"malformed traceparent: {traceparent!r}"
        )
    trace_id = match.group("trace_id")
    parent_id = match.group("parent_id")
    if trace_id == _ALL_ZERO_TRACE_ID:
        raise W3CTraceContextError("all-zero trace_id is invalid per W3C 3.2.2.3")
    if parent_id == _ALL_ZERO_SPAN_ID:
        raise W3CTraceContextError("all-zero parent-id is invalid per W3C 3.2.2.3")
    version = match.group("version")
    if version == "ff":
        raise W3CTraceContextError("traceparent version 'ff' is forbidden")
    return TraceContext(
        trace_id=trace_id,
        parent_id=parent_id,
        trace_flags=match.group("trace_flags"),
        version=version,
    )


def new_root_context(*, sampled: bool = True, tracestate: str | None = None) -> TraceContext:
    """Generate a fresh root W3C trace context for a new workflow."""
    flags = "01" if sampled else "00"
    return TraceContext(
        trace_id=generate_ptid(),
        parent_id=generate_span_id(),
        trace_flags=flags,
        tracestate=tracestate,
    )


def child_context(parent: TraceContext) -> TraceContext:
    """Derive a child context for an outbound call.

    Per Section 5.2, the receiving agent MUST preserve trace-id and trace-flags,
    and MUST generate a fresh parent-id for its own outbound calls. ``tracestate``
    propagates unmodified.
    """
    return TraceContext(
        trace_id=parent.trace_id,
        parent_id=generate_span_id(),
        trace_flags=parent.trace_flags,
        tracestate=parent.tracestate,
        version=parent.version,
    )


def reconcile_channels(
    *,
    jwt_air_ptid: str | None,
    traceparent_value: str | None,
    air_parent_trace_id_header: str | None,
) -> TraceContext:
    """Resolve the receiving agent's trace context per Section 5.4.

    Channel preference for propagation: W3C traceparent > JWT air_ptid >
    Air-Parent-Trace-Id fallback header. The JWT claim wins for trust; if
    multiple channels disagree on the trace-id, the agent fails closed
    (W3CTraceContextError).
    """
    candidates: list[tuple[str, str]] = []
    parsed: TraceContext | None = None

    if traceparent_value is not None:
        parsed = parse_traceparent(traceparent_value)
        candidates.append(("traceparent", parsed.trace_id))

    if jwt_air_ptid is not None:
        validate_ptid(jwt_air_ptid)
        candidates.append(("jwt.air_ptid", jwt_air_ptid))

    if air_parent_trace_id_header is not None:
        validate_ptid(air_parent_trace_id_header)
        candidates.append(("Air-Parent-Trace-Id", air_parent_trace_id_header))

    if not candidates:
        raise W3CTraceContextError(
            "no trace propagation channel present (traceparent, JWT air_ptid, "
            "or Air-Parent-Trace-Id required)"
        )

    seen: set[str] = {tid for _, tid in candidates}
    if len(seen) > 1:
        raise W3CTraceContextError(
            f"trace-id disagreement across channels: {dict(candidates)}"
        )

    if parsed is not None:
        return parsed

    # No traceparent provided: synthesize a fresh span-id; PTID came from
    # the JWT or fallback header.
    trace_id = next(tid for _, tid in candidates)
    return TraceContext(trace_id=trace_id, parent_id=generate_span_id())


__all__ = [
    "TraceContext",
    "child_context",
    "generate_ptid",
    "generate_span_id",
    "new_root_context",
    "parse_traceparent",
    "reconcile_channels",
    "validate_ptid",
]
