"""Tests for the Langfuse observability transport.

Uses a fake Langfuse client throughout; these tests never reach the Langfuse
API. What they pin down is the mapping from AgDR records to Langfuse
observations: types, nesting, start/end pairing, token usage, containment, and
the PHI boundary.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from airsdk.integrations.langfuse import LangfuseTransport
from airsdk.recorder import AIRRecorder
from airsdk.transport import FileTransport
from airsdk.types import CapturePolicy, DecisionProvenance, IntentSpec


class FakeObservation:
    """Records every call made against it so tests can assert on the tree."""

    def __init__(self, name: str, as_type: str, **kwargs: Any) -> None:
        self.name = name
        self.as_type = as_type
        self.kwargs: dict[str, Any] = dict(kwargs)
        self.updates: list[dict[str, Any]] = []
        self.children: list[FakeObservation] = []
        self.ended = False
        self.trace_id = "trace-fake"

    def start_observation(self, *, name: str, as_type: str = "span", **kwargs: Any) -> FakeObservation:
        child = FakeObservation(name, as_type, **kwargs)
        self.children.append(child)
        return child

    def update(self, **kwargs: Any) -> FakeObservation:
        self.updates.append(kwargs)
        self.kwargs.update({k: v for k, v in kwargs.items() if v is not None})
        return self

    def end(self) -> None:
        self.ended = True

    # -- helpers ---------------------------------------------------------

    def descendants(self) -> list[FakeObservation]:
        out: list[FakeObservation] = []
        for child in self.children:
            out.append(child)
            out.extend(child.descendants())
        return out

    def named(self, name: str) -> list[FakeObservation]:
        return [o for o in self.descendants() if o.name == name]


class FakeRootContext:
    """Mimics the context manager returned by start_as_current_observation."""

    def __init__(self, observation: FakeObservation) -> None:
        self._observation = observation
        self.exited = False

    def __enter__(self) -> FakeObservation:
        return self._observation

    def __exit__(self, *exc: object) -> bool:
        self.exited = True
        return False


class FakeLangfuse:
    def __init__(self) -> None:
        self.root: FakeObservation | None = None
        self.root_context: FakeRootContext | None = None
        self.propagated: dict[str, Any] | None = None
        self.flushed = 0

    def start_as_current_observation(self, *, as_type: str, name: str, **kwargs: Any) -> FakeRootContext:
        self.root = FakeObservation(name, as_type, **kwargs)
        self.root_context = FakeRootContext(self.root)
        return self.root_context

    def flush(self) -> None:
        self.flushed += 1


@pytest.fixture
def fake_langfuse(monkeypatch: pytest.MonkeyPatch) -> FakeLangfuse:
    """A fake client, with propagate_attributes stubbed to a no-op recorder."""
    import contextlib

    client = FakeLangfuse()

    @contextlib.contextmanager
    def fake_propagate(**kwargs: Any) -> Any:
        client.propagated = kwargs
        yield

    monkeypatch.setattr("langfuse.propagate_attributes", fake_propagate)
    return client


def _recorder(tmp_path: Path, transport: LangfuseTransport, **kwargs: Any) -> AIRRecorder:
    log = tmp_path / "chain.log"
    return AIRRecorder(
        log_path=log,
        transports=[FileTransport(log), transport],
        live=False,
        **kwargs,
    )


def test_llm_pair_becomes_one_generation_with_usage(
    tmp_path: Path, fake_langfuse: FakeLangfuse
) -> None:
    transport = LangfuseTransport(client=fake_langfuse)
    recorder = _recorder(tmp_path, transport, user_intent="Summarize the deck")

    recorder.llm_start(
        prompt="Summarize this",
        provenance=DecisionProvenance(provider="anthropic", model="claude-sonnet-4-6", temperature=0.2),
    )
    recorder.llm_end(
        response="Here is the summary",
        provenance=DecisionProvenance(
            provider="anthropic",
            model="claude-sonnet-4-6",
            model_version="claude-sonnet-4-6-20250101",
            finish_reason="end_turn",
            prompt_tokens=10,
            completion_tokens=5,
        ),
    )

    assert fake_langfuse.root is not None
    generations = fake_langfuse.root.named("call-llm")
    # One llm_start + one llm_end must collapse into a single generation, not two.
    assert len(generations) == 1
    generation = generations[0]
    assert generation.as_type == "generation"
    assert generation.ended
    assert generation.kwargs["input"] == "Summarize this"
    assert generation.kwargs["output"] == "Here is the summary"
    assert generation.kwargs["model"] == "claude-sonnet-4-6"
    assert generation.kwargs["model_parameters"]["temperature"] == 0.2
    assert generation.kwargs["usage_details"] == {"input": 10, "output": 5}
    assert generation.kwargs["metadata"]["air.finish_reason"] == "end_turn"


def test_tool_pair_nests_under_root_as_sibling_of_generation(
    tmp_path: Path, fake_langfuse: FakeLangfuse
) -> None:
    transport = LangfuseTransport(client=fake_langfuse)
    recorder = _recorder(tmp_path, transport, user_intent="Look something up")

    recorder.llm_start(prompt="What is the weather?")
    recorder.llm_end(response="I will check")
    recorder.tool_start(tool_name="get_weather", tool_args={"city": "Paris"})
    recorder.tool_end(tool_output="18C and clear")

    root = fake_langfuse.root
    assert root is not None
    # Both hang off the root: the tool is a sibling of the generation that
    # requested it, not a child of it.
    assert [child.name for child in root.children] == ["call-llm", "get_weather"]
    tool = root.named("get_weather")[0]
    assert tool.as_type == "tool"
    assert tool.ended
    assert tool.kwargs["input"] == {"city": "Paris"}
    assert tool.kwargs["output"] == "18C and clear"


def test_blocked_tool_is_closed_at_error_level(tmp_path: Path, fake_langfuse: FakeLangfuse) -> None:
    """A blocked tool_start never gets a tool_end, so the transport must close it."""
    from airsdk.containment.policy import ContainmentPolicy

    transport = LangfuseTransport(client=fake_langfuse)
    policy = ContainmentPolicy(deny_tools=["wire_transfer"])
    recorder = _recorder(tmp_path, transport, user_intent="Pay an invoice", containment=policy)

    from airsdk.containment.exceptions import BlockedActionError

    with pytest.raises(BlockedActionError):
        recorder.tool_start(tool_name="wire_transfer", tool_args={"amount": 100000})

    root = fake_langfuse.root
    assert root is not None
    tool = root.named("wire_transfer")[0]
    assert tool.ended, "a blocked tool must not be left hanging open"
    assert tool.kwargs["level"] == "ERROR"
    assert tool.kwargs["output"]["blocked"] is True


def test_agent_finish_sets_root_output_and_closes_trace(
    tmp_path: Path, fake_langfuse: FakeLangfuse
) -> None:
    transport = LangfuseTransport(client=fake_langfuse)
    recorder = _recorder(tmp_path, transport, user_intent="Write a haiku")

    recorder.llm_start(prompt="Write a haiku")
    recorder.llm_end(response="An old silent pond")
    recorder.agent_finish(final_output="An old silent pond")

    root = fake_langfuse.root
    assert root is not None
    assert root.as_type == "agent"
    assert root.kwargs["input"] == "Write a haiku"
    assert root.kwargs["output"] == "An old silent pond"
    assert fake_langfuse.root_context is not None
    assert fake_langfuse.root_context.exited, "agent_finish must unwind the root context"


def test_unclosed_observations_are_ended_on_drain(
    tmp_path: Path, fake_langfuse: FakeLangfuse
) -> None:
    """A chain that dies mid-call must not leave spans open forever."""
    transport = LangfuseTransport(client=fake_langfuse)
    recorder = _recorder(tmp_path, transport, user_intent="Do a thing")

    recorder.tool_start(tool_name="slow_tool", tool_args={})
    recorder.llm_start(prompt="thinking")
    transport.drain(timeout=1.0)

    root = fake_langfuse.root
    assert root is not None
    assert all(child.ended for child in root.children)
    assert root.named("call-llm")[0].kwargs["level"] == "WARNING"
    assert fake_langfuse.flushed == 1


def test_capture_policy_keeps_phi_out_of_langfuse(
    tmp_path: Path, fake_langfuse: FakeLangfuse
) -> None:
    """PHI referenced away by CapturePolicy must reach Langfuse only as a digest."""
    transport = LangfuseTransport(client=fake_langfuse)
    recorder = _recorder(
        tmp_path,
        transport,
        user_intent="Summarize the chart",
        capture_policy=CapturePolicy(hash_fields=frozenset({"prompt", "response"})),
    )

    phi = "Patient Jane Doe, MRN 123456, presents with chest pain"
    recorder.llm_start(prompt=phi)
    recorder.llm_end(response="Recommend ECG")

    root = fake_langfuse.root
    assert root is not None
    generation = root.named("call-llm")[0]
    assert generation.kwargs["input"] is None
    assert generation.kwargs.get("output") is None
    # The digest is present so the step stays integrity-checkable via the vault.
    assert "prompt" in generation.kwargs["metadata"]["air.content_refs"]
    assert "response" in generation.kwargs["metadata"]["air.end_content_refs"]
    # And no fragment of the plaintext escaped anywhere into the trace.
    assert "Jane Doe" not in repr(fake_langfuse.root.__dict__)
    assert "123456" not in repr(fake_langfuse.root.__dict__)


def test_capture_content_false_withholds_bodies_but_keeps_provenance(
    tmp_path: Path, fake_langfuse: FakeLangfuse
) -> None:
    transport = LangfuseTransport(client=fake_langfuse, capture_content=False)
    recorder = _recorder(tmp_path, transport, user_intent="secret intent")

    recorder.llm_start(prompt="secret prompt")
    recorder.llm_end(
        response="secret response",
        provenance=DecisionProvenance(model="gpt-4o", prompt_tokens=7, completion_tokens=3),
    )

    root = fake_langfuse.root
    assert root is not None
    assert root.kwargs["input"] is None
    generation = root.named("call-llm")[0]
    assert generation.kwargs["input"] is None
    assert generation.kwargs.get("output") is None
    # Structure and cost survive: that is the point of the conservative mode.
    assert generation.kwargs["model"] == "gpt-4o"
    assert generation.kwargs["usage_details"] == {"input": 7, "output": 3}
    assert "secret" not in repr(fake_langfuse.root.__dict__)


def test_every_observation_carries_chain_coordinates(
    tmp_path: Path, fake_langfuse: FakeLangfuse
) -> None:
    """The Langfuse trace must be navigable back to the signed chain."""
    transport = LangfuseTransport(client=fake_langfuse)
    recorder = _recorder(tmp_path, transport, intent_spec=IntentSpec(goal="Do the thing"))

    record = recorder.llm_start(prompt="hello")
    recorder.llm_end(response="hi")

    root = fake_langfuse.root
    assert root is not None
    generation = root.named("call-llm")[0]
    metadata = generation.kwargs["metadata"]
    assert metadata["air.step_id"] == record.step_id
    assert metadata["air.content_hash"] == record.content_hash
    assert metadata["air.signer_key"] == recorder.public_key_hex


def test_transport_never_raises_into_the_agent(
    tmp_path: Path, fake_langfuse: FakeLangfuse
) -> None:
    """A broken observability sink must not take the agent down."""
    transport = LangfuseTransport(client=fake_langfuse)
    recorder = _recorder(tmp_path, transport, user_intent="Keep going")

    def explode(**kwargs: Any) -> Any:
        raise RuntimeError("langfuse is down")

    recorder.llm_start(prompt="one")
    assert fake_langfuse.root is not None
    fake_langfuse.root.start_observation = explode  # type: ignore[assignment]

    # The agent keeps running and the signed chain is unaffected.
    recorder.llm_end(response="two")
    recorder.tool_start(tool_name="t", tool_args={})
    recorder.tool_end(tool_output="ok")
    recorder.agent_finish(final_output="done")

    from airsdk.agdr import load_chain, verify_chain
    from airsdk.types import VerificationStatus

    chain = load_chain(recorder.log_path)
    assert verify_chain(chain).status is VerificationStatus.OK


def test_trace_attributes_are_propagated(tmp_path: Path, fake_langfuse: FakeLangfuse) -> None:
    transport = LangfuseTransport(
        client=fake_langfuse,
        session_id="conversation-42",
        user_id="kevin@vindicara.io",
        tags=["prod", "billing"],
    )
    recorder = _recorder(tmp_path, transport, user_intent="Do the thing")
    recorder.llm_start(prompt="hi")

    assert fake_langfuse.propagated == {
        "trace_name": "agent-run",
        "user_id": "kevin@vindicara.io",
        "session_id": "conversation-42",
        "tags": ["prod", "billing"],
    }


def test_content_fields_covers_every_field_the_transport_can_expose(
    tmp_path: Path, fake_langfuse: FakeLangfuse
) -> None:
    """CONTENT_FIELDS must hash away everything a reviewer could read in Langfuse.

    This is the regression guard for the field-name trap: a policy that names
    only prompt/response still ships tool arguments, tool output and the final
    answer to Langfuse in the clear.
    """
    from airsdk.integrations.langfuse import CONTENT_FIELDS

    transport = LangfuseTransport(client=fake_langfuse)
    recorder = _recorder(
        tmp_path,
        transport,
        user_intent="Summarize the chart for Jane Doe MRN 123456",
        capture_policy=CapturePolicy(hash_fields=CONTENT_FIELDS),
    )

    recorder.llm_start(prompt="Jane Doe, MRN 123456, chest pain")
    recorder.llm_end(response="Recommend ECG for Jane Doe")
    recorder.tool_start(tool_name="fetch_chart", tool_args={"mrn": "123456"})
    recorder.tool_end(tool_output="Jane Doe: troponin elevated")
    recorder.agent_finish(final_output="Jane Doe should receive an ECG")

    leaked = repr(fake_langfuse.root.__dict__ if fake_langfuse.root else {})
    for secret in ("Jane Doe", "123456", "chest pain", "troponin", "ECG"):
        assert secret not in leaked, f"{secret!r} reached Langfuse"
