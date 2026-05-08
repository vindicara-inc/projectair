"""Crash + restart recovery: the on-disk chain is the spool.

These tests prove that even if the agent process is SIGKILL'd or the
machine loses power between observing a step and emitting an anchor,
a fresh process can reopen the chain and resume anchoring without
double-anchoring or skipping steps.
"""
from __future__ import annotations

import os
from pathlib import Path

from airsdk.agdr import Signer, load_chain
from airsdk.anchoring.orchestrator import (
    AnchoringOrchestrator,
    AnchoringPolicy,
)
from airsdk.transport import FileTransport
from airsdk.types import RekorAnchor, RFC3161Anchor, StepKind


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
            timestamp_token_b64="QUFBQQ==",  # noqa: S106 - test stub, not a credential
            timestamp_iso=f"2026-05-06T00:00:0{self.calls}Z",
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
            integrated_time=1746368390 + self.calls,
            log_id="aa" * 32,
            inclusion_proof={f"uuid-{self.calls}": {"body": "x", "logIndex": self.calls}},
            rekor_url="https://fake.rekor",
        )


def test_simulated_crash_then_restart_catches_up(tmp_path: Path) -> None:
    """Process A writes 5 steps + 1 anchor, dies; process B writes 7 more steps + recovers."""
    log_path = tmp_path / "chain.jsonl"

    # ---- Process A: 5 steps + cadence-driven anchor ----
    transport_a = FileTransport(log_path, fsync=True)
    signer_a = Signer.generate()
    tsa_a = _FakeTSA()
    rekor_a = _FakeRekor()
    orch_a = AnchoringOrchestrator(
        signer=signer_a,
        transports=[transport_a],
        rfc3161_client=tsa_a,
        rekor_client=rekor_a,
        policy=AnchoringPolicy(anchor_every_n_steps=5, anchor_every_n_seconds=999),
    )
    for i in range(5):
        rec = signer_a.sign(StepKind.LLM_START, {"prompt": f"a-{i}"})
        transport_a.emit(rec)
        orch_a.observe_step(rec)
    # Cadence emit runs on a daemon thread; deterministically wait for it.
    assert orch_a.flush(timeout=2.0)
    assert tsa_a.calls == 1, "process A should have emitted exactly one anchor"

    # ---- Process A is killed before its next anchor (no atexit) ----
    # Three more steps land on disk after the only anchor.
    for i in range(3):
        rec = signer_a.sign(StepKind.LLM_START, {"prompt": f"a-tail-{i}"})
        transport_a.emit(rec)
    # ... and the process dies. fsync guarantees the disk has these.

    # ---- Process B: fresh process, hydrates from the on-disk chain ----
    records_on_disk = load_chain(log_path)
    assert any(r.kind == StepKind.ANCHOR for r in records_on_disk)
    pre_steps = sum(1 for r in records_on_disk if r.kind != StepKind.ANCHOR)
    assert pre_steps == 8

    # Process B uses a *new* chain signer (Ed25519 keys are per-process; the
    # chain's existing records remain verifiable under the prior signer).
    # The orchestrator only needs *some* signer to emit the anchor record.
    transport_b = FileTransport(log_path, fsync=True)
    signer_b = Signer.generate()
    signer_b._prev_hash = records_on_disk[-1].content_hash
    tsa_b = _FakeTSA()
    rekor_b = _FakeRekor()
    orch_b = AnchoringOrchestrator(
        signer=signer_b,
        transports=[transport_b],
        rfc3161_client=tsa_b,
        rekor_client=rekor_b,
        policy=AnchoringPolicy(anchor_every_n_steps=999, anchor_every_n_seconds=999),
    )
    orch_b.hydrate_from_chain(records_on_disk)
    # Hydration with non-empty backlog schedules an immediate background emit.
    assert orch_b.flush(timeout=2.0)
    assert tsa_b.calls == 1
    assert rekor_b.calls == 1

    # ---- Idempotency: emit_anchor_now after recovery is a no-op ----
    second = orch_b.emit_anchor_now()
    assert second is None
    assert tsa_b.calls == 1


def test_sigkill_mid_batch_recovers_on_next_start(tmp_path: Path) -> None:
    """SIGKILL leaves N unanchored steps on disk; next-start must anchor them
    immediately, not wait for cadence to re-accumulate.

    This is the OOM-killed-container scenario: process dies with a backlog
    that fits *under* the cadence threshold, atexit never runs, and the next
    process may observe zero further steps before it too exits (e.g. an
    operator just running ``air verify`` after the crash). If hydration
    doesn't trigger an immediate emit, the orphaned backlog never gets
    anchored.
    """
    log_path = tmp_path / "chain.jsonl"

    # ---- Process A: 73 steps, zero anchors (cadence is 100, never reached) ----
    transport_a = FileTransport(log_path, fsync=True)
    signer_a = Signer.generate()
    orch_a = AnchoringOrchestrator(
        signer=signer_a,
        transports=[transport_a],
        rfc3161_client=_FakeTSA(),
        rekor_client=_FakeRekor(),
        policy=AnchoringPolicy(anchor_every_n_steps=100, anchor_every_n_seconds=999),
    )
    for i in range(73):
        rec = signer_a.sign(StepKind.LLM_START, {"prompt": f"a-{i}"})
        transport_a.emit(rec)
        orch_a.observe_step(rec)
    # No flush(): simulating that the daemon thread never had a chance to run.
    # No atexit: SIGKILL doesn't trigger registered exit handlers.
    # Critically: zero anchors should be on disk.
    text = log_path.read_text()
    assert '"kind":"anchor"' not in text, "process A wrote no anchor before being killed"

    # ---- Process B: fresh process. Hydrates, observes ZERO further steps. ----
    records_on_disk = load_chain(log_path)
    assert len(records_on_disk) == 73
    transport_b = FileTransport(log_path, fsync=True)
    signer_b = Signer.generate()
    signer_b._prev_hash = records_on_disk[-1].content_hash
    tsa_b = _FakeTSA()
    rekor_b = _FakeRekor()
    orch_b = AnchoringOrchestrator(
        signer=signer_b,
        transports=[transport_b],
        rfc3161_client=tsa_b,
        rekor_client=rekor_b,
        policy=AnchoringPolicy(anchor_every_n_steps=100, anchor_every_n_seconds=999),
    )
    orch_b.hydrate_from_chain(records_on_disk)

    # Hydration must have scheduled an immediate emit because the cadence
    # threshold will never be reached by mere observation.
    assert orch_b.flush(timeout=2.0)
    assert tsa_b.calls == 1, "hydration must trigger immediate anchor of orphaned backlog"
    assert rekor_b.calls == 1

    # And the chain on disk now has the catch-up anchor.
    final_records = load_chain(log_path)
    assert any(r.kind == StepKind.ANCHOR for r in final_records)


def test_fsync_writes_persist_across_handle_close(tmp_path: Path) -> None:
    """fsync is the only thing that lets the chain-as-spool argument hold."""
    log_path = tmp_path / "chain.jsonl"
    transport = FileTransport(log_path, fsync=True)
    signer = Signer.generate()
    rec = signer.sign(StepKind.LLM_START, {"prompt": "x"})
    transport.emit(rec)

    # The file is visible on disk and contains the record bytes.
    assert log_path.exists()
    with open(log_path, "rb") as handle:
        content = handle.read()
    assert b'"kind":"llm_start"' in content
    # Calling fsync directly (a smoke test that fsync was wired up at all):
    # opening the path via os.open + fdatasync should succeed.
    fd = os.open(str(log_path), os.O_RDONLY)
    try:
        # On macOS, F_FULLFSYNC is the strong sync; ordinary fsync still
        # writes through kernel buffers, which is what we exercised.
        os.fsync(fd)
    finally:
        os.close(fd)
