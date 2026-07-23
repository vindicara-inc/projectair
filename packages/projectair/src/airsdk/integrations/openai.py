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

from airsdk.integrations._provenance import normalize_stop
from airsdk.recorder import AIRRecorder
from airsdk.types import DecisionProvenance, LogprobsSummary

_T = TypeVar("_T")


def _summarize_logprobs(response: Any) -> LogprobsSummary:
    """Summarize chosen-token logprobs from a chat completion, if present.

    OpenAI returns ``choices[0].logprobs.content`` as a list of tokens each
    carrying a ``.logprob``. The distribution the output was sampled from is
    the closest thing to the model showing its work for a stochastic choice,
    so record its shape (mean / min chosen-token logprob, token count). The
    full distribution is intentionally not dumped here to keep the signed
    chain lean; a caller who wants it sets ``LogprobsSummary.full``.
    """
    choices = getattr(response, "choices", None) or []
    if not choices:
        return LogprobsSummary(available=False)
    logprobs = getattr(choices[0], "logprobs", None)
    content = getattr(logprobs, "content", None) if logprobs is not None else None
    if not content:
        return LogprobsSummary(available=False)
    values = [lp for lp in (getattr(tok, "logprob", None) for tok in content) if lp is not None]
    if not values:
        return LogprobsSummary(available=True, token_count=len(content))
    return LogprobsSummary(
        available=True,
        mean_logprob=sum(values) / len(values),
        min_logprob=min(values),
        token_count=len(values),
    )


def _build_provenance(kwargs: dict[str, Any], response: Any) -> DecisionProvenance:
    """Assemble decision provenance from the request kwargs and the response.

    Request kwargs supply the sampling parameters (the mechanics of the
    non-determinism); the response supplies the resolved snapshot, backend
    fingerprint, finish reason, token usage, and logprobs.
    """
    usage = getattr(response, "usage", None)
    choices = getattr(response, "choices", None) or []
    finish_reason = getattr(choices[0], "finish_reason", None) if choices else None
    return DecisionProvenance(
        provider="openai",
        model=kwargs.get("model"),
        model_version=getattr(response, "model", None),
        system_fingerprint=getattr(response, "system_fingerprint", None),
        temperature=kwargs.get("temperature"),
        top_p=kwargs.get("top_p"),
        seed=kwargs.get("seed"),
        max_tokens=kwargs.get("max_tokens") or kwargs.get("max_completion_tokens"),
        stop=normalize_stop(kwargs.get("stop")),
        finish_reason=finish_reason,
        prompt_tokens=getattr(usage, "prompt_tokens", None),
        completion_tokens=getattr(usage, "completion_tokens", None),
        logprobs=_summarize_logprobs(response),
    )


def _request_provenance(kwargs: dict[str, Any]) -> DecisionProvenance:
    """Provenance known before the response arrives (streaming path)."""
    return DecisionProvenance(
        provider="openai",
        model=kwargs.get("model"),
        temperature=kwargs.get("temperature"),
        top_p=kwargs.get("top_p"),
        seed=kwargs.get("seed"),
        max_tokens=kwargs.get("max_tokens") or kwargs.get("max_completion_tokens"),
        stop=normalize_stop(kwargs.get("stop")),
    )


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

    def __init__(
        self,
        stream: Iterator[Any],
        recorder: AIRRecorder,
        provenance: DecisionProvenance | None = None,
    ) -> None:
        self._stream = stream
        self._recorder = recorder
        self._chunks: list[str] = []
        self._emitted = False
        self._provenance = provenance

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
            finish_reason = getattr(choices[0], "finish_reason", None)
            if finish_reason and self._provenance is not None:
                self._provenance.finish_reason = finish_reason
        # Resolved snapshot and backend fingerprint ride on the chunks.
        if self._provenance is not None:
            model_version = getattr(chunk, "model", None)
            if model_version:
                self._provenance.model_version = model_version
            fingerprint = getattr(chunk, "system_fingerprint", None)
            if fingerprint:
                self._provenance.system_fingerprint = fingerprint
        return chunk

    def _flush(self) -> None:
        if self._emitted:
            return
        self._emitted = True
        self._recorder.llm_end(response="".join(self._chunks), provenance=self._provenance)

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
            return _StreamProxy(iter(response), self._recorder, _request_provenance(kwargs))
        self._recorder.llm_end(
            response=_extract_response_text(response),
            provenance=_build_provenance(kwargs, response),
        )
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
