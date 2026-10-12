"""Langfuse observability for AgDR chains.

:class:`LangfuseTransport` is an :class:`airsdk.transport.Transport` sink that
mirrors every signed record an :class:`~airsdk.recorder.AIRRecorder` emits into
a `Langfuse <https://langfuse.com>`_ trace.

Why a transport and not a per-framework wrapper: the recorder hands *every*
record to *every* transport, so a single sink covers all the integrations in
this package -- ``instrument_anthropic``, ``instrument_openai``,
``instrument_gemini``, ``instrument_llamaindex``, ``instrument_adk``, the NeMo
bridges -- plus any hand-rolled ``recorder.llm_start`` / ``tool_start`` calls,
with no change to those wrappers and nothing to keep in sync as they evolve.

The two systems answer different questions and are complementary:

- The AgDR chain answers *"can I prove what this agent did?"* -- signed,
  hash-chained, externally anchored, court-supportable.
- Langfuse answers *"how is this agent behaving?"* -- latency, token spend,
  cost per model, prompt/response inspection, evaluation.

Every observation carries the originating ``step_id`` and ``content_hash`` in
its metadata, so a Langfuse trace is a navigable index into the signed chain:
find a slow or expensive step in Langfuse, then verify that exact step with
``air verify`` / ``air explain``.

Usage:

    from airsdk.recorder import AIRRecorder
    from airsdk.transport import FileTransport
    from airsdk.integrations.langfuse import LangfuseTransport

    recorder = AIRRecorder(
        log_path="agent.log",
        user_intent="Summarize the Q3 board deck",
        transports=[FileTransport("agent.log"), LangfuseTransport()],
    )

Credentials come from the standard Langfuse environment variables
(``LANGFUSE_PUBLIC_KEY``, ``LANGFUSE_SECRET_KEY``, ``LANGFUSE_BASE_URL``), or
pass a preconfigured client via ``client=``.

PHI and regulated chains
------------------------
Records reach a transport *after* :class:`airsdk.types.CapturePolicy` has run,
so on a ``phi_safe`` chain the referenced fields are already ``None`` and only
their salted ``content_refs`` digests remain. Langfuse therefore receives the
digest, never the plaintext -- the same data-minimization boundary the signed
chain enforces, with no second redaction path to keep correct.

``CapturePolicy`` matches on **field name**, so a policy that names only
``prompt`` and ``response`` still lets ``final_output``, ``tool_output``,
``tool_args`` and ``message_content`` through to Langfuse in the clear. Hash the
full set -- :data:`CONTENT_FIELDS` is exactly that set, as seen by this
transport::

    AIRRecorder(..., capture_policy=CapturePolicy(hash_fields=CONTENT_FIELDS))

Pass ``capture_content=False`` to withhold prompt/response/tool bodies even on
a chain that has no capture policy: observations then carry only structure,
timing, model provenance and token counts. That is the conservative default for
a deployment where the Langfuse project is not in scope for a BAA, and unlike a
capture policy it cannot be defeated by a field nobody remembered to name.

Install with the optional extra::

    pip install 'projectair[langfuse]'
"""
from __future__ import annotations

import contextlib
import logging
from typing import TYPE_CHECKING, Any

from airsdk.integrations._langfuse_mapping import (
    CONTENT_FIELDS,
    EVENT_NAMES,
    GENESIS_KINDS,
    ROOT_NAME,
    forensic_metadata,
)
from airsdk.integrations._langfuse_steps import (
    OpenObservation,
    emit_event,
    end_generation,
    end_tool,
    start_generation,
    start_tool,
)
from airsdk.types import AGDR_VERSION, AgDRRecord, StepKind

if TYPE_CHECKING:  # pragma: no cover - typing only
    from langfuse import Langfuse

__all__ = ["CONTENT_FIELDS", "LangfuseTransport"]

_log = logging.getLogger(__name__)


class LangfuseTransport:
    """Mirror every AgDR record into a Langfuse trace.

    One recorder (one AgDR chain) maps to one Langfuse trace, rooted at an
    ``agent`` observation. Within it:

    ==========================  ==========================================
    AgDR record                 Langfuse observation
    ==========================  ==========================================
    ``llm_start`` / ``llm_end`` one ``generation`` (opened, then closed)
    ``tool_start`` / ``tool_end`` one ``tool`` (opened, then closed)
    ``agent_message``           ``event``
    ``human_approval``          ``event``
    ``anchor``                  ``event``
    ``agent_finish``            closes the root and sets its output
    ==========================  ==========================================

    Generations and tools are opened by their ``*_start`` record and closed by
    the matching ``*_end``, so Langfuse latency is the real wall-clock duration
    of the call rather than a zero-width point. A ``tool_start`` blocked by a
    :class:`~airsdk.types.ContainmentPolicy` never receives a ``tool_end``; it
    is closed immediately at ``ERROR`` level with the block reason, which is
    what makes containment events visible in Langfuse instead of appearing as
    spans that hang open forever.

    Children are parented explicitly through the root observation object rather
    than through the ambient OpenTelemetry context, so an agent that emits
    records from a worker thread still produces a correctly nested tree.

    Parameters
    ----------
    client:
        A configured ``Langfuse`` client. Defaults to ``get_client()``, which
        reads the standard ``LANGFUSE_*`` environment variables.
    session_id:
        Groups several chains into one Langfuse session (e.g. every turn of a
        conversation). One chain is one trace; the session ties them together.
    user_id:
        The human this run is attributed to. Defaults to the delegation
        grant's subject when the chain opens with a ``DELEGATION`` record, so a
        delegated session is attributed to its actual authorizer.
    tags:
        Immutable trace tags for business-level filtering (``["prod", "billing"]``).
    capture_content:
        When ``False``, prompts, responses, tool arguments and tool output are
        withheld and only structure, provenance and token counts are sent.
        Content already referenced away by a ``CapturePolicy`` is never sent
        regardless of this flag.
    trace_name:
        Overrides the trace name. Keep it stable and low-cardinality.
    """

    def __init__(
        self,
        client: Langfuse | None = None,
        *,
        session_id: str | None = None,
        user_id: str | None = None,
        tags: list[str] | None = None,
        capture_content: bool = True,
        trace_name: str = ROOT_NAME,
    ) -> None:
        if client is None:
            try:
                from langfuse import get_client
            except ImportError as exc:  # pragma: no cover - import-guard path
                raise RuntimeError(
                    "LangfuseTransport requires the langfuse package. "
                    "Install it with: pip install 'projectair[langfuse]'"
                ) from exc
            client = get_client()
        self._client = client
        self._session_id = session_id
        self._user_id = user_id
        self._tags = tags
        self._capture_content = capture_content
        self._trace_name = trace_name

        self._stack = contextlib.ExitStack()
        self._root: Any | None = None
        self._closed = False
        # LIFO: the chain is sequential, so the most recently opened
        # generation/tool is the one a *_end record closes.
        self._open_generations: list[OpenObservation] = []
        self._open_tools: list[OpenObservation] = []

    @property
    def client(self) -> Langfuse:
        """The underlying Langfuse client, for scores and manual observations."""
        return self._client

    @property
    def trace_id(self) -> str | None:
        """Langfuse trace id for this chain, or ``None`` before the first record."""
        return None if self._root is None else str(self._root.trace_id)

    # -- Transport protocol -------------------------------------------------

    def emit(self, record: AgDRRecord) -> None:
        """Mirror one signed record. Never raises: observability must not break the agent."""
        try:
            self._emit(record)
        except Exception:
            _log.warning(
                "airsdk.langfuse_transport failed to mirror record",
                extra={"step_id": record.step_id, "kind": str(record.kind)},
                exc_info=True,
            )

    def drain(self, timeout: float) -> None:
        """Close any still-open observations and flush the Langfuse client."""
        del timeout  # the Langfuse client owns its own export deadline
        try:
            self._close_all()
            self._client.flush()
        except Exception:
            _log.warning("airsdk.langfuse_transport failed to drain", exc_info=True)

    # -- Internals ----------------------------------------------------------

    def _emit(self, record: AgDRRecord) -> None:
        if self._closed:
            return
        kind = record.kind
        if self._root is None:
            self._open_root(record)

        root, capture = self._root, self._capture_content
        if kind == StepKind.LLM_START:
            self._open_generations.append(start_generation(root, record, capture))
        elif kind == StepKind.LLM_END:
            entry = self._open_generations.pop() if self._open_generations else None
            end_generation(root, entry, record, capture)
        elif kind == StepKind.TOOL_START:
            tool = start_tool(root, record, capture)
            if tool is not None:
                self._open_tools.append(tool)
        elif kind == StepKind.TOOL_END:
            entry = self._open_tools.pop() if self._open_tools else None
            end_tool(root, entry, record, capture)
        elif kind == StepKind.AGENT_FINISH:
            self._finish(record)
        elif kind in EVENT_NAMES and kind not in GENESIS_KINDS:
            emit_event(root, record, capture)

    def _open_root(self, record: AgDRRecord) -> None:
        payload = record.payload
        user_id = self._user_id
        if user_id is None and payload.delegation is not None:
            user_id = getattr(payload.delegation, "subject", None)

        intent = payload.user_intent
        if intent is None and payload.intent_spec is not None:
            intent = payload.intent_spec.goal

        # start_as_current_observation + propagate_attributes is the documented
        # v4 path for trace-level correlating attributes; the ExitStack holds
        # both open for the life of the chain and unwinds them in _close_all.
        from langfuse import propagate_attributes

        self._root = self._stack.enter_context(
            self._client.start_as_current_observation(
                as_type="agent",
                name=self._trace_name,
                input=intent if self._capture_content else None,
                metadata={**forensic_metadata(record), "air.chain_genesis": record.step_id},
                version=AGDR_VERSION,
            )
        )
        self._stack.enter_context(
            propagate_attributes(
                trace_name=self._trace_name,
                user_id=user_id,
                session_id=self._session_id,
                tags=self._tags,
            )
        )

    def _finish(self, record: AgDRRecord) -> None:
        if self._root is not None:
            self._root.update(
                output=record.payload.final_output if self._capture_content else None,
                metadata=forensic_metadata(record),
            )
        self._close_all()

    def _close_all(self) -> None:
        """End every open observation, innermost first, then unwind the root."""
        if self._closed:
            return
        for open_list in (self._open_tools, self._open_generations):
            while open_list:
                entry = open_list.pop()
                with contextlib.suppress(Exception):
                    entry.observation.update(
                        level="WARNING",
                        status_message="chain ended before this step reported completion",
                    )
                    entry.observation.end()
        with contextlib.suppress(Exception):
            self._stack.close()
        self._closed = True
