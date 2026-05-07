"""Explanation tests for the SSH-exfiltration demo chain.

The advisor's acceptance criterion: ``air explain --step 8`` against the
demo chain should pull out the load-bearing ~7 records (poisoned README
write -> README read by tool -> LLM prompt with injection -> SSH key
read -> network egress) and exclude pre-attack legitimate setup. These
tests lock that in.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from airsdk._concrete_demo import build_concrete_demo_log
from airsdk.agdr import load_chain
from airsdk.causal import build_causal_graph, explain_step
from airsdk.causal.explain import explain_finding
from airsdk.causal.types import EdgeKind
from airsdk.detections import run_detectors


def _demo() -> tuple:  # type: ignore[type-arg]
    with tempfile.TemporaryDirectory() as tmp:
        log_path = Path(tmp) / "demo.jsonl"
        build_concrete_demo_log(log_path)
        records = load_chain(log_path)
    return records, build_causal_graph(records)


def test_explain_step_8_surfaces_load_bearing_records() -> None:
    """Explanation of the exfiltration step (8) must include records 2-8
    and exclude pre-attack records 0, 1 and the wrap-up record 9."""
    _, graph = _demo()
    explanation = explain_step(graph, target_ordinal=8)
    ordinals = {n.ordinal for n in explanation.nodes}
    assert ordinals == {2, 3, 4, 5, 6, 7, 8}, f"unexpected explanation set: {ordinals}"
    assert explanation.targets == [8]


def test_explain_step_excludes_pre_attack_setup() -> None:
    """The user's initial prompt (step 0) and the agent's first response
    (step 1) are legitimate setup that has no causal bearing on the
    exfiltration. They must NOT appear in the explanation."""
    _, graph = _demo()
    explanation = explain_step(graph, target_ordinal=8)
    ordinals = {n.ordinal for n in explanation.nodes}
    assert 0 not in ordinals
    assert 1 not in ordinals


def test_explain_step_excludes_post_outcome_records() -> None:
    """The AGENT_FINISH at step 9 happened AFTER the exfiltration; it
    cannot be a cause of step 8."""
    _, graph = _demo()
    explanation = explain_step(graph, target_ordinal=8)
    ordinals = {n.ordinal for n in explanation.nodes}
    assert 9 not in ordinals


def test_explain_step_includes_critical_data_flow_edges() -> None:
    """The two OUTPUT_REUSE edges (poisoned README and SSH key) must
    survive the explanation's edge filter."""
    _, graph = _demo()
    explanation = explain_step(graph, target_ordinal=8)
    soft_edges = {
        (e.from_ordinal, e.to_ordinal)
        for e in explanation.edges
        if e.kind == EdgeKind.OUTPUT_REUSE
    }
    assert soft_edges == {(3, 4), (7, 8)}, f"missing data-flow edges: {soft_edges}"


def test_explain_finding_asi02_reaches_exfil() -> None:
    """ASI02 (tool misuse) flags the read_file SSH-key step. Explaining
    by detector must yield the same load-bearing set as explaining the
    flagged step directly."""
    records, graph = _demo()
    findings = run_detectors(records)
    explanation = explain_finding(graph, findings, "ASI02")
    assert explanation.targets, "ASI02 must flag at least one record in the demo chain"
    ordinals = {n.ordinal for n in explanation.nodes}
    # Any reasonable explanation must include the SSH key read (6), the
    # SSH key tool_end (7), and the LLM that decided to read it (5).
    assert {5, 6, 7}.issubset(ordinals), f"ASI02 explanation missed core records: {ordinals}"


def test_explain_finding_unknown_detector_returns_empty() -> None:
    """A detector id that flags nothing must return an empty Explanation,
    not raise."""
    records, graph = _demo()
    findings = run_detectors(records)
    explanation = explain_finding(graph, findings, "ASI99-NONEXISTENT")
    assert explanation.targets == []
    assert explanation.nodes == []
    assert explanation.edges == []


def test_explain_step_out_of_range_raises() -> None:
    _, graph = _demo()
    try:
        explain_step(graph, target_ordinal=999)
    except IndexError:
        return
    raise AssertionError("explain_step must raise IndexError on out-of-range ordinal")
