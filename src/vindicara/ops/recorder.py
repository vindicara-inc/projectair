"""Per-invocation recorder factory + Vindicara-flavoured helpers.

Every Lambda invocation and every dashboard request opens a short
:class:`airsdk.AIRRecorder` against a :class:`DDBTransport` bound to the
ops chain table. :class:`OpsRecorder` wraps the AIRRecorder with helpers
that emit start/end pairs for Vindicara-specific event kinds, ensuring
``tool_name`` is set on both records so the redactor's per-kind policy
applies on publication.

Why the wrapper: AgDR's :class:`airsdk.types.StepKind` is a closed enum,
so the Vindicara taxonomy (``vindicara.api.request``, etc.) lives in the
``tool_name`` payload field. Callers that go through these helpers do not
need to remember to pass ``tool_name`` to both start and end.

The recorder is created on demand to avoid keeping a live boto3 client
between cold starts of the API Lambda. At Vindicara's traffic profile
the cost of recreating the boto3 resource on each request is negligible
compared to the network round-trip, and it keeps the module import path
free of side effects (which simplifies tests and lets the engine import
this module without lambda credentials).
"""
from __future__ import annotations

import os
import tempfile
import time
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any

from airsdk.recorder import AIRRecorder

from vindicara.ops.ddb_transport import DDBTransport, FailureMode
from vindicara.ops.schema import OpsKind

if TYPE_CHECKING:
    from collections.abc import Iterator

    from mypy_boto3_dynamodb.service_resource import Table


def open_recorder(
    chain_id: str,
    *,
    table: Table,
    failure_mode: FailureMode = FailureMode.SOFT,
) -> AIRRecorder:
    """Open a recorder for one chain.

    Caller owns the recorder; closing happens when the recorder goes out
    of scope (Python GC). The ``log_path`` argument required by AIRRecorder
    is set to a temporary file we never write to (the DDBTransport replaces
    the default FileTransport). The temp file is auto-cleaned by the OS.
    """
    transport = DDBTransport(table=table, chain_id=chain_id, failure_mode=failure_mode)
    log_path = os.path.join(tempfile.gettempdir(), f"vindicara-ops-{chain_id}.jsonl")
    return AIRRecorder(log_path=log_path, transports=[transport])


class OpsRecorder:
    """Vindicara-flavoured recorder wrapping an :class:`AIRRecorder`.

    Every helper emits a start record before the action and an end record
    after, both carrying the same ``tool_name`` so the redactor's per-kind
    policy applies. Callers in tight hot paths can also access the
    underlying ``recorder`` to emit raw step kinds.
    """

    def __init__(self, recorder: AIRRecorder) -> None:
        self._recorder = recorder

    @property
    def recorder(self) -> AIRRecorder:
        return self._recorder

    def api_request(
        self,
        *,
        method: str,
        path_template: str,
        status_code: int,
        duration_ms: float,
        **extra: Any,
    ) -> None:
        """Emit an API request as a tool_start + tool_end pair on the chain.

        Use this from a request-completion hook (after the handler has run
        and you know the status_code + duration). For pre/post split,
        call ``recorder.tool_start`` and ``recorder.tool_end`` directly.
        """
        self._recorder.tool_start(
            tool_name=OpsKind.API_REQUEST.value,
            tool_args={"method": method, "path_template": path_template},
            method=method,
            path_template=path_template,
        )
        self._recorder.tool_end(
            tool_output=str(status_code),
            tool_name=OpsKind.API_REQUEST.value,
            method=method,
            path_template=path_template,
            status_code=status_code,
            duration_ms=duration_ms,
            **extra,
        )

    def auth_event(
        self,
        kind: OpsKind,
        *,
        outcome: str,
        duration_ms: float,
        **extra: Any,
    ) -> None:
        """Emit a dashboard auth event (login, signup, mfa, etc.)."""
        self._recorder.tool_start(
            tool_name=kind.value,
            tool_args={"outcome": outcome},
            outcome=outcome,
        )
        self._recorder.tool_end(
            tool_output=outcome,
            tool_name=kind.value,
            outcome=outcome,
            duration_ms=duration_ms,
            **extra,
        )

    @contextmanager
    def time_request(
        self,
        *,
        method: str,
        path_template: str,
    ) -> Iterator[dict[str, Any]]:
        """Context manager wrapping a request: emits start eagerly, end on exit.

        The yielded dict is mutable. Caller sets ``status_code`` (and any
        other extra fields) before the block exits; the helper computes
        ``duration_ms`` automatically.
        """
        start = time.monotonic()
        self._recorder.tool_start(
            tool_name=OpsKind.API_REQUEST.value,
            tool_args={"method": method, "path_template": path_template},
            method=method,
            path_template=path_template,
        )
        bag: dict[str, Any] = {"status_code": 0}
        try:
            yield bag
        finally:
            duration_ms = (time.monotonic() - start) * 1000.0
            self._recorder.tool_end(
                tool_output=str(bag.get("status_code", 0)),
                tool_name=OpsKind.API_REQUEST.value,
                method=method,
                path_template=path_template,
                status_code=int(bag.get("status_code", 0)),
                duration_ms=duration_ms,
                **{k: v for k, v in bag.items() if k != "status_code"},
            )


@contextmanager
def request_chain(
    chain_id: str,
    *,
    table: Table,
    failure_mode: FailureMode = FailureMode.SOFT,
) -> Iterator[OpsRecorder]:
    """Context manager: yields an :class:`OpsRecorder` for one chain.

    The recorder is closed (no-op for DDBTransport, but symmetric with
    other transports) when the context exits. Exceptions inside the block
    propagate; the recorder still closes cleanly.
    """
    recorder = open_recorder(chain_id=chain_id, table=table, failure_mode=failure_mode)
    try:
        yield OpsRecorder(recorder)
    finally:
        for transport in recorder.transports:
            transport.drain(timeout=1.0)
