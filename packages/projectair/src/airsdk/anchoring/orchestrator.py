"""Decides when to anchor and what to do when anchoring fails.

Three layers of recovery protect a chain across process boundaries:

1. ``observe_step`` enqueues; the next policy-due trigger anchors.
2. ``atexit`` runs a best-effort flush with a 2s budget on clean exit.
3. ``hydrate_from_chain`` rebuilds state from disk on next start, so
   SIGKILL and power loss recover via on-disk truth.

Idempotency: a chain root is only anchored once. Catch-up on startup
and atexit on shutdown can both target the same backlog; the duplicate
is a no-op.
"""
from __future__ import annotations

import atexit
import logging
import threading
import time
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import hashes

from airsdk.anchoring.exceptions import (
    AnchoringError,
    AnchorRequiredError,
    RekorError,
    TSAError,
)
from airsdk.anchoring.policy import AnchoringPolicy, FailurePolicy, OrchestratorHealth
from airsdk.anchoring.rekor import RekorClient
from airsdk.anchoring.rfc3161 import RFC3161Client
from airsdk.types import AgDRPayload, AgDRRecord, StepKind

if TYPE_CHECKING:
    from airsdk.agdr import Signer
    from airsdk.transport import Transport

_log = logging.getLogger(__name__)
_ATEXIT_BUDGET_SECONDS: float = 2.0


def _sha256(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()


class AnchoringOrchestrator:
    """Stitches RFC 3161 + Rekor into the AgDR chain on a policy cadence.

    Construct with the recorder's ``signer`` and ``transports`` so anchor
    records chain forward correctly and land on the same sinks. Without
    TSA or Rekor clients anchoring is a no-op (useful for tests).
    """

    def __init__(
        self,
        signer: Signer,
        transports: list[Transport],
        rfc3161_client: RFC3161Client | None = None,
        rekor_client: RekorClient | None = None,
        policy: AnchoringPolicy | None = None,
        failure_policy: FailurePolicy | None = None,
    ) -> None:
        self._signer = signer
        self._transports = transports
        self._rfc3161 = rfc3161_client
        self._rekor = rekor_client
        self._policy = policy or AnchoringPolicy()
        self._failure_policy = failure_policy or FailurePolicy()
        self._lock = threading.Lock()
        self._unanchored_steps: list[AgDRRecord] = []
        self._last_anchor_time = time.monotonic()
        self._last_anchor_status = "ok"
        self._anchored_roots: set[str] = set()
        self._atexit_registered = False
        self._inflight_workers: list[threading.Thread] = []
        self._workers_lock = threading.Lock()

    # -- Hot path ----------------------------------------------------

    def observe_step(self, record: AgDRRecord) -> None:
        """Record a step. Returns in <1ms; the actual emit runs on a daemon
        thread when the cadence trips, so TSA/Rekor latency never blocks
        the agent's hot path."""
        if record.kind == StepKind.ANCHOR:
            with self._lock:
                root = record.payload.anchored_chain_root
                if root is not None:
                    self._anchored_roots.add(root)
                self._unanchored_steps.clear()
                self._last_anchor_time = time.monotonic()
                self._last_anchor_status = "ok"
            return
        with self._lock:
            self._unanchored_steps.append(record)
            should_anchor = self._policy_due_locked()
        if should_anchor:
            self._spawn_emit_worker()

    def _spawn_emit_worker(self) -> threading.Thread:
        worker = threading.Thread(
            target=self._safe_emit,
            daemon=True,
            name="airsdk-anchoring",
        )
        with self._workers_lock:
            self._inflight_workers.append(worker)
        worker.start()
        return worker

    def flush(self, timeout: float = 5.0) -> bool:
        """Wait for in-flight background emits to finish. Returns True on
        completion, False on timeout. ``atexit`` already does a 2s flush."""
        deadline = time.monotonic() + timeout
        with self._workers_lock:
            workers = list(self._inflight_workers)
        for worker in workers:
            remaining = max(0.0, deadline - time.monotonic())
            worker.join(timeout=remaining)
        with self._workers_lock:
            self._inflight_workers = [w for w in self._inflight_workers if w.is_alive()]
            return not self._inflight_workers

    def should_block(self, action: dict[str, object]) -> None:
        """Raise ``AnchorRequiredError`` if this action requires fail-closed
        and the pipeline is unhealthy; otherwise return."""
        if not self._action_requires_fail_closed(action):
            return
        with self._lock:
            health = self._health_locked()
        if health.last_anchor_status == "ok" and health.unanchored_step_count == 0:
            return
        raise AnchorRequiredError(
            f"action {action!r} requires anchor but pipeline is "
            f"{health.last_anchor_status} with backlog={health.unanchored_step_count}",
        )

    def emit_anchor_now(self) -> AgDRRecord | None:
        """Force an anchor emission. Returns the new anchor record or None."""
        return self._safe_emit()

    def health(self) -> OrchestratorHealth:
        with self._lock:
            return self._health_locked()

    def hydrate_from_chain(self, records: list[AgDRRecord]) -> None:
        """Resume state from an on-disk chain after a crash or fresh process start.

        Walks the records and recovers two things:

        - the chain roots already anchored (idempotency keys), so we do
          not re-anchor the same hash twice across process restarts;
        - the unanchored backlog (every step after the last ANCHOR
          record), so the next scheduled emission catches it up.

        If the backlog is non-empty, schedule an immediate background
        emit. Otherwise the recovered process might observe zero further
        steps (e.g. the agent finished and the operator is just running
        ``air verify`` later) and the orphaned backlog would never get
        anchored. This is the bug a SIGKILL'd container hits on restart.
        """
        with self._lock:
            self._unanchored_steps.clear()
            self._anchored_roots.clear()
            for rec in records:
                if rec.kind == StepKind.ANCHOR:
                    root = rec.payload.anchored_chain_root
                    if root:
                        self._anchored_roots.add(root)
                    self._unanchored_steps.clear()
                else:
                    self._unanchored_steps.append(rec)
            self._last_anchor_time = time.monotonic()
            self._last_anchor_status = "ok"
            backlog = len(self._unanchored_steps)

        if backlog > 0 and (self._rfc3161 is not None or self._rekor is not None):
            self._spawn_emit_worker()

    def register_atexit(self) -> None:
        """Best-effort flush on clean shutdown. Idempotent."""
        if self._atexit_registered:
            return
        atexit.register(self._atexit_flush)
        self._atexit_registered = True

    # -- internal -----------------------------------------------------

    def _policy_due_locked(self) -> bool:
        if not self._unanchored_steps:
            return False
        if len(self._unanchored_steps) >= self._policy.anchor_every_n_steps:
            return True
        elapsed = time.monotonic() - self._last_anchor_time
        return elapsed >= self._policy.anchor_every_n_seconds

    def _action_requires_fail_closed(self, action: dict[str, object]) -> bool:
        if self._failure_policy.on_anchor_failure == "fail_closed":
            return True
        for rule in self._failure_policy.fail_closed_for_actions:
            if all(action.get(k) == v for k, v in rule.items()):
                return True
        return False

    def _health_locked(self) -> OrchestratorHealth:
        elapsed = time.monotonic() - self._last_anchor_time
        next_due = max(0.0, self._policy.anchor_every_n_seconds - elapsed)
        return OrchestratorHealth(
            unanchored_step_count=len(self._unanchored_steps),
            seconds_since_last_anchor=elapsed,
            last_anchor_status=self._last_anchor_status,
            next_anchor_due_seconds=next_due,
        )

    def _safe_emit(self) -> AgDRRecord | None:
        try:
            return self._emit()
        except (TSAError, RekorError) as exc:
            with self._lock:
                self._last_anchor_status = self._classify_failure(exc)
            _log.warning("anchoring failed (fail-open): %s", exc)
            return None
        except AnchoringError as exc:
            with self._lock:
                self._last_anchor_status = "error"
            _log.error("anchoring error: %s", exc)
            return None

    def _classify_failure(self, exc: AnchoringError) -> str:
        if isinstance(exc, TSAError) and isinstance(exc, RekorError):
            return "both_failed"
        if isinstance(exc, TSAError):
            return "tsa_failed"
        if isinstance(exc, RekorError):
            return "rekor_failed"
        return "error"

    def _emit(self) -> AgDRRecord | None:
        with self._lock:
            if not self._unanchored_steps:
                return None
            chain_root_hex = self._unanchored_steps[-1].content_hash
            if chain_root_hex in self._anchored_roots:
                return None
            # Claim the root atomically: anything else trying to anchor the
            # same backlog while we're on the network sees this as a no-op.
            # If the network call fails the claim is released in `except`.
            self._anchored_roots.add(chain_root_hex)
            from_step = self._unanchored_steps[0].step_id
            to_step = self._unanchored_steps[-1].step_id
            steps_snapshot = list(self._unanchored_steps)

        try:
            chain_root_bytes = bytes.fromhex(chain_root_hex)
            sha256_digest = _sha256(chain_root_bytes)

            rfc3161_anchor = None
            rekor_anchor = None
            if self._rfc3161 is not None and self._policy.rfc3161_enabled:
                rfc3161_anchor = self._rfc3161.anchor(chain_root_bytes)
            if self._rekor is not None and self._policy.rekor_enabled:
                rekor_anchor = self._rekor.anchor(sha256_digest)
        except Exception:
            # Release the claim so a future retry can attempt this root again.
            with self._lock:
                self._anchored_roots.discard(chain_root_hex)
            raise

        payload = AgDRPayload(
            anchored_chain_root=chain_root_hex,
            anchored_step_range={"from_step_id": from_step, "to_step_id": to_step},
            rfc3161=rfc3161_anchor,
            rekor=rekor_anchor,
        )
        record = self._signer.sign(StepKind.ANCHOR, payload)
        for transport in self._transports:
            transport.emit(record)
        with self._lock:
            # Drop the steps that were anchored; preserve any new ones
            # that arrived while we were on the network.
            new_steps = self._unanchored_steps[len(steps_snapshot):]
            self._unanchored_steps = new_steps
            self._last_anchor_time = time.monotonic()
            self._last_anchor_status = "ok"
        return record

    def _atexit_flush(self) -> None:
        try:
            t = threading.Thread(target=self._safe_emit, daemon=True)
            t.start()
            t.join(timeout=_ATEXIT_BUDGET_SECONDS)
            if t.is_alive():
                _log.warning("atexit anchor flush timed out; recovery deferred to next start")
        except Exception as exc:
            _log.warning("atexit anchor flush raised: %s", exc)
