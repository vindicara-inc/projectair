"""Tests for the LocalAlerter dedup core behind ``air watch``.

The dedup contract is the load-bearing part: over a growing, append-only chain
the same finding must surface exactly once, while a genuinely new finding (new
step, or same detector at a new step) must always come through.
"""

from __future__ import annotations

import pytest

import airsdk.alerting as alerting
from airsdk.alerting import LocalAlerter
from airsdk.types import Finding


def _finding(detector_id: str, step_index: int) -> Finding:
    return Finding(
        detector_id=detector_id,
        title=f"{detector_id} title",
        severity="high",
        step_id=f"step-{step_index}",
        step_index=step_index,
        description="example",
    )


def test_new_findings_dedups_by_detector_and_step(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A growing chain: each tick the detectors see more findings.
    ticks = iter(
        [
            [_finding("ASI02", 3)],  # tick 1: one finding
            [_finding("ASI02", 3), _finding("ASI06", 5)],  # tick 2: ASI02 repeats
            [_finding("ASI02", 3), _finding("ASI06", 5)],  # tick 3: nothing new
        ]
    )
    monkeypatch.setattr(
        alerting, "run_detectors", lambda records, registry=None: next(ticks)
    )
    alerter = LocalAlerter()

    assert [f.detector_id for f in alerter.new_findings([])] == ["ASI02"]
    assert [f.detector_id for f in alerter.new_findings([])] == ["ASI06"]
    assert alerter.new_findings([]) == []
    assert alerter.seen_count == 2


def test_same_detector_at_new_step_alerts_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ticks = iter(
        [
            [_finding("ASI02", 1)],
            [_finding("ASI02", 1), _finding("ASI02", 7)],  # same detector, new step
        ]
    )
    monkeypatch.setattr(
        alerting, "run_detectors", lambda records, registry=None: next(ticks)
    )
    alerter = LocalAlerter()

    assert [f.step_index for f in alerter.new_findings([])] == [1]
    assert [f.step_index for f in alerter.new_findings([])] == [7]
    assert alerter.seen_count == 2
