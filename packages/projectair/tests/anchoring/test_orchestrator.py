"""Tests for the anchoring orchestrator: policy, fail-open/closed, idempotency."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from airsdk.agdr import Signer
from airsdk.anchoring.exceptions import (
    AnchorRequiredError,
    RekorUnreachableError,
    TSAUnreachableError,
)
from airsdk.anchoring.orchestrator import (
    AnchoringOrchestrator,
    AnchoringPolicy,
    FailurePolicy,
)
from airsdk.transport import FileTransport
from airsdk.types import RekorAnchor, RFC3161Anchor, StepKind


class _FakeTSA:
    def __init__(self, fail: bool = False) -> None:
        self.calls = 0
        self._fail = fail

    @property
    def tsa_url(self) -> str:
        return "https://fake.tsa"

    def anchor(self, _chain_root: bytes) -> RFC3161Anchor:
        self.calls += 1
        if self._fail:
            raise TSAUnreachableError("fake outage")
        return RFC3161Anchor(
            tsa_url="https://fake.tsa",
            timestamp_token_b64="QUFBQQ==",  # noqa: S106 - test stub, not a credential
            timestamp_iso="2026-05-06T00:00:00Z",
            tsa_certificate_chain_pem=["-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----"],
        )


class _FakeRekor:
    def __init__(self, fail: bool = False) -> None:
        self.calls = 0
        self._fail = fail

    def anchor(self, sha256_digest: bytes) -> RekorAnchor:
        self.calls += 1
        if self._fail:
            raise RekorUnreachableError("fake outage")
        return RekorAnchor(
            log_index=42,
            uuid=sha256_digest.hex(),
            integrated_time=1746368390,
            log_id="c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
            inclusion_proof={"fake-uuid": {"body": "AAAA", "logIndex": 42}},
            rekor_url="https://fake.rekor",
        )


def _make_orchestrator(
    tmp_path: Path,
    *,
    tsa: Any = None,
    rekor: Any = None,
    policy: AnchoringPolicy | None = None,
    failure: FailurePolicy | None = None,
) -> tuple[AnchoringOrchestrator, FileTransport, Signer]:
    log_path = tmp_path / "chain.jsonl"
    transport = FileTransport(log_path, fsync=False)
    signer = Signer.generate()
    orchestrator = AnchoringOrchestrator(
        signer=signer,
        transports=[transport],
        rfc3161_client=tsa,
        rekor_client=rekor,
        policy=policy or AnchoringPolicy(anchor_every_n_steps=3, anchor_every_n_seconds=999),
        failure_policy=failure or FailurePolicy(),
    )
    return orchestrator, transport, signer


def _emit_steps(orchestrator: AnchoringOrchestrator, signer: Signer, count: int) -> None:
    for i in range(count):
        rec = signer.sign(StepKind.LLM_START, {"prompt": f"step {i}"})
        orchestrator.observe_step(rec)
    # Cadence-driven emissions run on a daemon thread; tests deterministically
    # wait on them via flush() rather than relying on timing.
    assert orchestrator.flush(timeout=2.0)


def test_policy_triggers_at_step_threshold(tmp_path: Path) -> None:
    tsa = _FakeTSA()
    rekor = _FakeRekor()
    orchestrator, _, signer = _make_orchestrator(tmp_path, tsa=tsa, rekor=rekor)

    _emit_steps(orchestrator, signer, 2)
    assert tsa.calls == 0  # below threshold

    _emit_steps(orchestrator, signer, 1)
    assert tsa.calls == 1
    assert rekor.calls == 1


def test_idempotency_no_double_anchor(tmp_path: Path) -> None:
    tsa = _FakeTSA()
    rekor = _FakeRekor()
    orchestrator, _, signer = _make_orchestrator(tmp_path, tsa=tsa, rekor=rekor)
    _emit_steps(orchestrator, signer, 3)
    assert tsa.calls == 1

    # emit_anchor_now with no new steps must NOT re-anchor the same root.
    second = orchestrator.emit_anchor_now()
    assert second is None
    assert tsa.calls == 1
    assert rekor.calls == 1


def test_fail_open_default_swallows_tsa_error(tmp_path: Path) -> None:
    tsa = _FakeTSA(fail=True)
    rekor = _FakeRekor()
    orchestrator, _, signer = _make_orchestrator(tmp_path, tsa=tsa, rekor=rekor)
    _emit_steps(orchestrator, signer, 3)
    health = orchestrator.health()
    assert health.last_anchor_status == "tsa_failed"
    # Backlog stays so the catch-up path can drain it later.
    assert health.unanchored_step_count == 3


def test_fail_closed_for_action_blocks(tmp_path: Path) -> None:
    tsa = _FakeTSA(fail=True)
    rekor = _FakeRekor()
    orchestrator, _, signer = _make_orchestrator(
        tmp_path,
        tsa=tsa,
        rekor=rekor,
        failure=FailurePolicy(
            on_anchor_failure="fail_open",
            fail_closed_for_actions=[{"tool": "stripe_charge"}],
        ),
    )
    _emit_steps(orchestrator, signer, 3)  # anchor attempt fails (fail-open default)
    with pytest.raises(AnchorRequiredError):
        orchestrator.should_block({"tool": "stripe_charge", "amount_cents": 9_999})


def test_should_block_passes_for_other_actions(tmp_path: Path) -> None:
    orchestrator, _, _signer = _make_orchestrator(
        tmp_path,
        tsa=_FakeTSA(),
        rekor=_FakeRekor(),
        failure=FailurePolicy(fail_closed_for_actions=[{"tool": "stripe_charge"}]),
    )
    # Healthy + non-matching action: should not raise.
    orchestrator.should_block({"tool": "send_email"})


def test_anchor_record_lands_on_chain(tmp_path: Path) -> None:
    tsa = _FakeTSA()
    rekor = _FakeRekor()
    orchestrator, transport, signer = _make_orchestrator(tmp_path, tsa=tsa, rekor=rekor)
    _emit_steps(orchestrator, signer, 3)

    lines = transport.log_path.read_text().strip().splitlines()
    assert any('"kind":"anchor"' in line for line in lines), "anchor record must be on disk"


def test_hydrate_from_chain_resumes_backlog(tmp_path: Path) -> None:
    tsa = _FakeTSA()
    rekor = _FakeRekor()
    orchestrator, transport, signer = _make_orchestrator(
        tmp_path, tsa=tsa, rekor=rekor,
        policy=AnchoringPolicy(anchor_every_n_steps=999, anchor_every_n_seconds=999),
    )
    # Three steps, no anchor (cadence not yet reached).
    records = []
    for i in range(3):
        rec = signer.sign(StepKind.LLM_START, {"prompt": f"step {i}"})
        records.append(rec)
        transport.emit(rec)
    orchestrator.hydrate_from_chain(records)
    # Hydration with non-empty backlog spawns an immediate background emit
    # so an orphaned backlog from a prior process gets anchored even when
    # the current process observes no further steps.
    assert orchestrator.flush(timeout=2.0)
    assert tsa.calls == 1
    assert rekor.calls == 1
    assert orchestrator.health().unanchored_step_count == 0


def test_anchoring_disabled_when_no_clients(tmp_path: Path) -> None:
    orchestrator, _, signer = _make_orchestrator(tmp_path, tsa=None, rekor=None)
    _emit_steps(orchestrator, signer, 3)
    # No clients = no anchor records emitted, but no errors either.
    health = orchestrator.health()
    assert health.last_anchor_status == "ok"


def test_observe_step_returns_fast_under_slow_tsa(tmp_path: Path) -> None:
    """Spec §14.4: observe_step overhead <1ms regardless of TSA latency.

    A 500ms-sleeping fake TSA must not block the agent's hot path. The
    cadence-triggered emission runs on a daemon thread.
    """
    import time as _time

    class _SlowTSA:
        @property
        def tsa_url(self) -> str:
            return "https://slow.tsa"

        def anchor(self, _root: bytes) -> RFC3161Anchor:
            _time.sleep(0.5)
            return RFC3161Anchor(
                tsa_url="https://slow.tsa",
                timestamp_token_b64="QUFBQQ==",  # noqa: S106 - test stub
                timestamp_iso="2026-05-06T00:00:00Z",
                tsa_certificate_chain_pem=["-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----"],
            )

    orchestrator, _, signer = _make_orchestrator(
        tmp_path,
        tsa=_SlowTSA(),
        rekor=None,
        policy=AnchoringPolicy(anchor_every_n_steps=2, anchor_every_n_seconds=999, rekor_enabled=False),
    )
    rec1 = signer.sign(StepKind.LLM_START, {"prompt": "warm"})
    orchestrator.observe_step(rec1)

    rec2 = signer.sign(StepKind.LLM_START, {"prompt": "trigger"})
    start = _time.monotonic()
    orchestrator.observe_step(rec2)
    elapsed_ms = (_time.monotonic() - start) * 1000
    assert elapsed_ms < 50, f"hot-path overhead too high: {elapsed_ms:.1f}ms"
    assert orchestrator.flush(timeout=2.0)
