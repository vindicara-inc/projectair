"""Recorder ↔ orchestrator wiring: the documented user-facing integration."""
from __future__ import annotations

from pathlib import Path

from airsdk.anchoring.orchestrator import AnchoringOrchestrator
from airsdk.anchoring.policy import AnchoringPolicy
from airsdk.recorder import AIRRecorder
from airsdk.types import RekorAnchor, RFC3161Anchor


class _FakeTSA:
    def __init__(self) -> None:
        self.calls = 0

    @property
    def tsa_url(self) -> str:
        return "https://fake.tsa"

    def anchor(self, _root: bytes) -> RFC3161Anchor:
        self.calls += 1
        return RFC3161Anchor(
            tsa_url="https://fake.tsa",
            timestamp_token_b64="QUFBQQ==",  # noqa: S106 - test stub
            timestamp_iso="2026-05-06T00:00:00Z",
            tsa_certificate_chain_pem=["-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----"],
        )


class _FakeRekor:
    def __init__(self) -> None:
        self.calls = 0

    def anchor(self, sha256_digest: bytes) -> RekorAnchor:
        self.calls += 1
        return RekorAnchor(
            log_index=self.calls,
            uuid=f"uuid-{self.calls}",
            integrated_time=1746368390,
            log_id="aa" * 32,
            inclusion_proof={f"uuid-{self.calls}": {"body": "x", "logIndex": self.calls}},
            rekor_url="https://fake.rekor",
        )


def test_attach_orchestrator_then_step_triggers_anchor(tmp_path: Path) -> None:
    """The documented integration: build recorder, build orchestrator over its
    signer + transports, attach. Steps emitted through the recorder land on
    disk and trigger anchoring once the cadence is reached."""
    log_path = tmp_path / "chain.jsonl"
    recorder = AIRRecorder(log_path)

    tsa = _FakeTSA()
    rekor = _FakeRekor()
    orchestrator = AnchoringOrchestrator(
        signer=recorder.signer,
        transports=recorder.transports,
        rfc3161_client=tsa,
        rekor_client=rekor,
        policy=AnchoringPolicy(anchor_every_n_steps=2, anchor_every_n_seconds=999),
    )
    recorder.attach_orchestrator(orchestrator)
    assert recorder.orchestrator is orchestrator

    recorder.llm_start(prompt="hi")
    recorder.llm_end(response="ok")
    assert orchestrator.flush(timeout=2.0)

    assert tsa.calls == 1
    assert rekor.calls == 1

    # The anchor record lands on the same file the recorder writes to,
    # chained forward from the most recent step.
    text = log_path.read_text()
    assert '"kind":"llm_start"' in text
    assert '"kind":"llm_end"' in text
    assert '"kind":"anchor"' in text


def test_recorder_without_orchestrator_unchanged(tmp_path: Path) -> None:
    """Anchoring is opt-in. Recorders without an orchestrator behave as in 0.3.x."""
    log_path = tmp_path / "chain.jsonl"
    recorder = AIRRecorder(log_path)
    recorder.llm_start(prompt="x")
    recorder.agent_finish(final_output="y")
    assert recorder.orchestrator is None
    text = log_path.read_text()
    assert '"kind":"anchor"' not in text
