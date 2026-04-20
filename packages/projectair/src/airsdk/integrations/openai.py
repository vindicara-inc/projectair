"""OpenAI SDK instrumentation.

Wraps an ``openai.OpenAI`` client so that every
``client.chat.completions.create(...)`` call writes a signed
``llm_start`` + ``llm_end`` AgDR pair through the supplied
:class:`airsdk.recorder.AIRRecorder`.

Scope: non-streaming and streaming chat completions. The wrapper does
not intercept tool-call execution (the SDK hands the tool invocation
back to your code); emit ``recorder.tool_start`` / ``recorder.tool_end``
manually around the call you make.

Usage:

    from openai import OpenAI
    from airsdk.recorder import AIRRecorder
    from airsdk.integrations.openai import instrument_openai

    recorder = AIRRecorder(log_path="agent.log", user_intent="...")
    client = instrument_openai(OpenAI(), recorder)

    # From now on, chat completions emit AgDR records automatically.
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "..."}],
    )
"""
from __future__ import annotations

from collections.abc import Iterator
from typing import Any, TypeVar

from airsdk.recorder import AIRRecorder

_T = TypeVar("_T")


def _format_messages(messages: list[dict[str, Any]]) -> str:
    """Flatten OpenAI chat messages into a single prompt string for AgDR storage."""
    parts: list[str] = []
    for message in messages:
        role = str(message.get("role", "user"))
        content = message.get("content", "")
        if isinstance(content, list):
            # Multi-modal content blocks. Stringify text parts, note non-text.
            rendered: list[str] = []
            for block in content:
                if isinstance(block, dict):
                    if block.get("type") == "text":
                        rendered.append(str(block.get("text", "")))
                    else:
                        rendered.append(f"[{block.get('type', 'content')} block]")
                else:
                    rendered.append(str(block))
            content = "\n".join(rendered)
        parts.append(f"{role}: {content}")
    return "\n".join(parts)


def _extract_response_text(response: Any) -> str:
    """Pull the assistant's text out of a chat completion response, tool calls included."""
    choices = getattr(response, "choices", None)
    if not choices:
        return ""
    message = getattr(choices[0], "message", None)
    if message is None:
        return ""
    content = getattr(message, "content", None) or ""
    tool_calls = getattr(message, "tool_calls", None) or []
    if tool_calls:
        summaries = []
        for call in tool_calls:
            name = getattr(getattr(call, "function", None), "name", "tool")
            args = getattr(getattr(call, "function", None), "arguments", "")
            summaries.append(f"[tool_call {name}({args})]")
        return content + ("\n" if content else "") + "\n".join(summaries)
    return str(content)


class _StreamProxy:
    """Wrap a streaming chat completion iterator, accumulate text, emit llm_end on exhaust."""

    def __init__(self, stream: Iterator[Any], recorder: AIRRecorder) -> None:
        self._stream = stream
        self._recorder = recorder
        self._chunks: list[str] = []
        self._emitted = False

    def __iter__(self) -> _StreamProxy:
        return self

    def __next__(self) -> Any:
        try:
            chunk = next(self._stream)
        except StopIteration:
            self._flush()
            raise
        # Pull any text delta out of the chunk and accumulate.
        choices = getattr(chunk, "choices", None) or []
        if choices:
            delta = getattr(choices[0], "delta", None)
            if delta is not None:
                text = getattr(delta, "content", None)
                if text:
                    self._chunks.append(str(text))
        return chunk

    def _flush(self) -> None:
        if self._emitted:
            return
        self._emitted = True
        self._recorder.llm_end(response="".join(self._chunks))

    def close(self) -> None:
        """Best-effort stream close; also flushes the llm_end record if not yet written."""
        closer = getattr(self._stream, "close", None)
        if callable(closer):
            closer()
        self._flush()


class _CompletionsProxy:
    def __init__(self, wrapped: Any, recorder: AIRRecorder) -> None:
        self._wrapped = wrapped
        self._recorder = recorder

    def create(self, *, messages: list[dict[str, Any]], **kwargs: Any) -> Any:
        prompt_text = _format_messages(messages)
        self._recorder.llm_start(prompt=prompt_text)
        response = self._wrapped.create(messages=messages, **kwargs)
        if kwargs.get("stream"):
            return _StreamProxy(iter(response), self._recorder)
        self._recorder.llm_end(response=_extract_response_text(response))
        return response

    def __getattr__(self, name: str) -> Any:
        return getattr(self._wrapped, name)


class _ChatProxy:
    def __init__(self, wrapped: Any, recorder: AIRRecorder) -> None:
        self._wrapped = wrapped
        self.completions = _CompletionsProxy(wrapped.completions, recorder)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._wrapped, name)


class InstrumentedOpenAI:
    """Transparent proxy around an OpenAI client that instruments chat completions."""

    def __init__(self, client: Any, recorder: AIRRecorder) -> None:
        self._client = client
        self._recorder = recorder
        self.chat = _ChatProxy(client.chat, recorder)

    @property
    def recorder(self) -> AIRRecorder:
        return self._recorder

    def __getattr__(self, name: str) -> Any:
        # Anything we don't explicitly proxy falls through to the underlying client.
        return getattr(self._client, name)


def instrument_openai(client: Any, recorder: AIRRecorder) -> InstrumentedOpenAI:
    """Return a transparent proxy around ``client`` that records chat completions.

    The proxy forwards any method / attribute access we don't recognise back to
    the underlying client, so ``client.embeddings``, ``client.images``, etc.,
    keep working unchanged. Only ``client.chat.completions.create`` is wrapped.
    """
    return InstrumentedOpenAI(client, recorder)
