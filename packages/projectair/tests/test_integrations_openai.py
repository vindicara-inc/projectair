"""Tests for the OpenAI SDK instrumentation wrapper.

We mock the OpenAI client entirely so these tests don't require the openai
package at runtime or hit the network.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

from airsdk.agdr import load_chain, verify_chain
from airsdk.integrations.openai import instrument_openai
from airsdk.recorder import AIRRecorder
from airsdk.types import StepKind, VerificationStatus


def _fake_completion(content: str = "hello there") -> SimpleNamespace:
    """Build a response object shaped like openai.ChatCompletion."""
    message = SimpleNamespace(content=content, tool_calls=None)
    choice = SimpleNamespace(message=message, index=0, finish_reason="stop")
    return SimpleNamespace(id="chatcmpl-test", choices=[choice], model="gpt-4o")


def _fake_client(response_content: str = "hello there") -> MagicMock:
    """Build a minimal mock client with the shape openai.OpenAI() produces."""
    client = MagicMock()
    client.chat.completions.create = MagicMock(return_value=_fake_completion(response_content))
    return client


def test_instrument_emits_llm_start_and_llm_end(tmp_path: Path) -> None:
    recorder = AIRRecorder(log_path=tmp_path / "r.log")
    client = instrument_openai(_fake_client("gpt says hi"), recorder)

    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "hello"}],
    )

    assert response.choices[0].message.content == "gpt says hi"
    records = load_chain(tmp_path / "r.log")
    assert [r.kind for r in records] == [StepKind.LLM_START, StepKind.LLM_END]
    assert "user: hello" in (records[0].payload.prompt or "")
    assert records[1].payload.response == "gpt says hi"
    assert verify_chain(records).status == VerificationStatus.OK


def test_instrument_forwards_extra_kwargs(tmp_path: Path) -> None:
    recorder = AIRRecorder(log_path=tmp_path / "r.log")
    fake = _fake_client()
    client = instrument_openai(fake, recorder)

    client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "hi"}],
        temperature=0.3,
        max_tokens=128,
    )
    fake.chat.completions.create.assert_called_once()
    call_kwargs = fake.chat.completions.create.call_args.kwargs
    assert call_kwargs["temperature"] == 0.3
    assert call_kwargs["max_tokens"] == 128


def test_instrument_captures_tool_calls_in_response(tmp_path: Path) -> None:
    tool_call = SimpleNamespace(
        function=SimpleNamespace(name="crm_read", arguments='{"account": "acme"}'),
    )
    message = SimpleNamespace(content=None, tool_calls=[tool_call])
    choice = SimpleNamespace(message=message, index=0, finish_reason="tool_calls")
    response = SimpleNamespace(choices=[choice])

    recorder = AIRRecorder(log_path=tmp_path / "r.log")
    fake = _fake_client()
    fake.chat.completions.create.return_value = response
    client = instrument_openai(fake, recorder)

    client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": "look up acme"}])

    records = load_chain(tmp_path / "r.log")
    llm_end = records[1]
    assert "[tool_call crm_read" in (llm_end.payload.response or "")


def test_instrument_supports_streaming(tmp_path: Path) -> None:
    def make_chunk(text: str) -> SimpleNamespace:
        delta = SimpleNamespace(content=text)
        choice = SimpleNamespace(delta=delta, index=0, finish_reason=None)
        return SimpleNamespace(choices=[choice])

    chunks = [make_chunk("Hel"), make_chunk("lo"), make_chunk(" streamed")]

    recorder = AIRRecorder(log_path=tmp_path / "r.log")
    fake = _fake_client()
    fake.chat.completions.create.return_value = iter(chunks)
    client = instrument_openai(fake, recorder)

    stream = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "stream me"}],
        stream=True,
    )
    collected = list(stream)
    assert len(collected) == 3

    records = load_chain(tmp_path / "r.log")
    assert [r.kind for r in records] == [StepKind.LLM_START, StepKind.LLM_END]
    assert records[1].payload.response == "Hello streamed"


def test_instrument_passes_through_non_intercepted_methods(tmp_path: Path) -> None:
    recorder = AIRRecorder(log_path=tmp_path / "r.log")
    fake = _fake_client()
    fake.embeddings.create = MagicMock(return_value=SimpleNamespace(data=[]))
    client = instrument_openai(fake, recorder)

    # Not intercepted: should just forward to underlying client.
    client.embeddings.create(model="text-embedding-3-small", input="hi")
    fake.embeddings.create.assert_called_once()
    # No AgDR records should have been written.
    assert not (tmp_path / "r.log").exists() or not (tmp_path / "r.log").read_text()


def test_instrument_handles_multimodal_content(tmp_path: Path) -> None:
    recorder = AIRRecorder(log_path=tmp_path / "r.log")
    client = instrument_openai(_fake_client(), recorder)

    client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "What is this?"},
                    {"type": "image_url", "image_url": {"url": "https://example.com/img.png"}},
                ],
            }
        ],
    )
    records = load_chain(tmp_path / "r.log")
    prompt = records[0].payload.prompt or ""
    assert "What is this?" in prompt
    assert "[image_url block]" in prompt
