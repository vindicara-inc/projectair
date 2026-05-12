"""NVIDIA NemoClaw instrumentation for Project AIR.

Wires AIR forensic recording into NemoClaw's agent execution lifecycle
so that every agent step, tool call, inference request, and OpenShell
sandbox policy decision writes signed AgDR records through the supplied
:class:`airsdk.recorder.AIRRecorder`.

NemoClaw combines NVIDIA's OpenClaw agent platform with the OpenShell
hardened runtime. AIR captures what the agent did (forensic evidence);
OpenShell controls what the agent can do (sandbox enforcement). Together
they provide both prevention and evidence for HIPAA-regulated clinical
AI workflows.

Usage::

    from openclaw_sdk import OpenClawClient
    from airsdk.recorder import AIRRecorder
    from airsdk.integrations.nemoclaw import instrument_nemoclaw

    recorder = AIRRecorder("clinical-chain.jsonl")
    client = OpenClawClient(api_key="...")
    instrumented = instrument_nemoclaw(client, recorder)

    # All executions now produce signed forensic evidence
    result = instrumented.execute(pipeline="triage", input={...})

For inference-level capture on NemoClaw's L7 proxy, combine with
``instrument_openai`` which already handles any OpenAI-compatible
endpoint (including NIM and NemoClaw's inference gateway).
"""
from __future__ import annotations

import json
from typing import Any

from airsdk.recorder import AIRRecorder


class AIROpenClawHandler:
    """Callback handler that records OpenClaw execution events as signed capsules.

    Attach to an OpenClaw pipeline or client to capture the full agent
    lifecycle. Compatible with ``openclaw_sdk.callbacks.handler.CallbackHandler``.
    """

    def __init__(self, recorder: AIRRecorder) -> None:
        self._recorder = recorder

    @property
    def recorder(self) -> AIRRecorder:
        return self._recorder

    def on_execution_start(self, *, pipeline: str, input_data: Any, **kwargs: Any) -> None:
        self._recorder.llm_start(
            prompt=f"[openclaw:{pipeline}] {_serialize(input_data)}",
        )

    def on_execution_end(self, *, pipeline: str, output_data: Any, **kwargs: Any) -> None:
        self._recorder.llm_end(
            response=f"[openclaw:{pipeline}] {_serialize(output_data)}",
        )

    def on_tool_start(self, *, tool_name: str, tool_args: Any, **kwargs: Any) -> None:
        args = tool_args if isinstance(tool_args, dict) else {"raw": _serialize(tool_args)}
        self._recorder.tool_start(tool_name=tool_name, tool_args=args)

    def on_tool_end(self, *, tool_name: str, tool_output: Any, **kwargs: Any) -> None:
        self._recorder.tool_end(tool_output=_serialize(tool_output))

    def on_inference_start(self, *, model: str, messages: Any, **kwargs: Any) -> None:
        self._recorder.llm_start(
            prompt=f"[inference:{model}] {_serialize(messages)}",
        )

    def on_inference_end(self, *, model: str, response: Any, **kwargs: Any) -> None:
        self._recorder.llm_end(
            response=f"[inference:{model}] {_serialize(response)}",
        )

    def on_sandbox_policy_event(
        self,
        *,
        action: str,
        resource: str,
        decision: str,
        **kwargs: Any,
    ) -> None:
        """Capture OpenShell sandbox policy decisions in the chain."""
        self._recorder.tool_start(
            tool_name=f"openshell:{action}",
            tool_args={"resource": resource, "decision": decision, **kwargs},
        )
        self._recorder.tool_end(
            tool_output=f"policy decision: {decision} for {action} on {resource}",
        )


class _InstrumentedClient:
    """Proxy that intercepts OpenClaw client calls and records them."""

    def __init__(self, client: Any, handler: AIROpenClawHandler) -> None:
        self._client = client
        self._handler = handler

    def execute(self, *, pipeline: str = "", **kwargs: Any) -> Any:
        input_data = kwargs.get("input", kwargs)
        self._handler.on_execution_start(pipeline=pipeline, input_data=input_data)
        try:
            result = self._client.execute(pipeline=pipeline, **kwargs)
        except Exception:
            self._handler.on_execution_end(pipeline=pipeline, output_data="[error]")
            raise
        self._handler.on_execution_end(pipeline=pipeline, output_data=result)
        return result

    @property
    def recorder(self) -> AIRRecorder:
        return self._handler.recorder

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


def instrument_nemoclaw(
    client: Any,
    recorder: AIRRecorder,
) -> _InstrumentedClient:
    """Wrap an OpenClaw client with AIR forensic recording.

    Returns an instrumented proxy that records every execution as signed
    capsules. Non-execute methods pass through to the original client.
    """
    handler = AIROpenClawHandler(recorder)

    if hasattr(client, "add_callback"):
        client.add_callback(handler)
        return _InstrumentedClient(client, handler)

    if hasattr(client, "callbacks"):
        callbacks = client.callbacks
        if isinstance(callbacks, list):
            callbacks.append(handler)
        return _InstrumentedClient(client, handler)

    return _InstrumentedClient(client, handler)


def _serialize(obj: Any) -> str:
    """Best-effort JSON serialization for recording."""
    if isinstance(obj, str):
        return obj
    try:
        return json.dumps(obj, default=str, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(obj)
