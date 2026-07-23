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


def _fake_completion_full(content: str = "hi") -> SimpleNamespace:
    """A response carrying the provenance surface: snapshot, fingerprint, usage, logprobs."""
    message = SimpleNamespace(content=content, tool_calls=None)
    token_logprobs = [SimpleNamespace(logprob=-0.1), SimpleNamespace(logprob=-0.5)]
    choice = SimpleNamespace(
        message=message,
        index=0,
        finish_reason="stop",
        logprobs=SimpleNamespace(content=token_logprobs),
    )
    return SimpleNamespace(
        id="chatcmpl-test",
        choices=[choice],
        model="gpt-4o-2024-08-06",
        system_fingerprint="fp_abc123",
        usage=SimpleNamespace(prompt_tokens=11, completion_tokens=2),
    )


def test_provenance_captures_model_params_and_fingerprint(tmp_path: Path) -> None:
    recorder = AIRRecorder(log_path=tmp_path / "r.log")
    fake = _fake_client()
    fake.chat.completions.create.return_value = _fake_completion_full()
    client = instrument_openai(fake, recorder)

    client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "decide"}],
        temperature=0.7,
        top_p=0.9,
        seed=42,
        max_tokens=256,
        stop="END",
    )

    prov = load_chain(tmp_path / "r.log")[1].payload.provenance
    assert prov is not None
    assert prov.provider == "openai"
    assert prov.model == "gpt-4o"  # as requested
    assert prov.model_version == "gpt-4o-2024-08-06"  # resolved snapshot
    assert prov.system_fingerprint == "fp_abc123"
    assert prov.temperature == 0.7
    assert prov.top_p == 0.9
    assert prov.seed == 42
    assert prov.max_tokens == 256
    assert prov.stop == ["END"]
    assert prov.finish_reason == "stop"
    assert prov.prompt_tokens == 11
    assert prov.completion_tokens == 2


def test_provenance_summarizes_logprobs(tmp_path: Path) -> None:
    recorder = AIRRecorder(log_path=tmp_path / "r.log")
    fake = _fake_client()
    fake.chat.completions.create.return_value = _fake_completion_full()
    client = instrument_openai(fake, recorder)

    client.chat.completions.create(
        model="gpt-4o", messages=[{"role": "user", "content": "x"}], logprobs=True
    )

    summary = load_chain(tmp_path / "r.log")[1].payload.provenance.logprobs
    assert summary is not None
    assert summary.available is True
    assert summary.token_count == 2
    assert summary.min_logprob == -0.5
    assert summary.mean_logprob == (-0.1 + -0.5) / 2


def test_provenance_absent_logprobs_marked_unavailable(tmp_path: Path) -> None:
    recorder = AIRRecorder(log_path=tmp_path / "r.log")
    client = instrument_openai(_fake_client("plain"), recorder)  # _fake_completion has no logprobs

    client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": "x"}])

    summary = load_chain(tmp_path / "r.log")[1].payload.provenance.logprobs
    assert summary is not None
    assert summary.available is False


def test_provenance_is_covered_by_the_signature(tmp_path: Path) -> None:
    """Provenance lives inside the signed content, so tampering breaks the chain."""
    recorder = AIRRecorder(log_path=tmp_path / "r.log")
    fake = _fake_client()
    fake.chat.completions.create.return_value = _fake_completion_full()
    client = instrument_openai(fake, recorder)
    client.chat.completions.create(
        model="gpt-4o", messages=[{"role": "user", "content": "x"}], temperature=0.7
    )

    records = load_chain(tmp_path / "r.log")
    assert verify_chain(records).status == VerificationStatus.OK
    # Rewrite the recorded temperature: the signature must no longer verify.
    records[1].payload.provenance.temperature = 0.0
    assert verify_chain(records).status != VerificationStatus.OK


def test_provenance_captured_on_streaming(tmp_path: Path) -> None:
    def make_chunk(text: str, *, last: bool = False) -> SimpleNamespace:
        delta = SimpleNamespace(content=text)
        choice = SimpleNamespace(delta=delta, index=0, finish_reason="stop" if last else None)
        return SimpleNamespace(choices=[choice], model="gpt-4o-2024-08-06", system_fingerprint="fp_stream")

    chunks = [make_chunk("Hel"), make_chunk("lo", last=True)]
    recorder = AIRRecorder(log_path=tmp_path / "r.log")
    fake = _fake_client()
    fake.chat.completions.create.return_value = iter(chunks)
    client = instrument_openai(fake, recorder)

    stream = client.chat.completions.create(
        model="gpt-4o", messages=[{"role": "user", "content": "x"}], temperature=0.5, stream=True
    )
    list(stream)

    prov = load_chain(tmp_path / "r.log")[1].payload.provenance
    assert prov is not None
    assert prov.temperature == 0.5  # request-side
    assert prov.model_version == "gpt-4o-2024-08-06"  # enriched from chunks
    assert prov.system_fingerprint == "fp_stream"
    assert prov.finish_reason == "stop"


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
