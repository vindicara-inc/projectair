"""Inference tests for the SSH-exfiltration demo chain.

The demo chain (`_concrete_demo.py`) is the canonical Layer 2 fixture:
poisoned README -> LLM context -> SSH key read -> network egress. The
inference engine must surface this story cleanly: the data-flow edges
(OUTPUT_REUSE 3->4 and 7->8) and the decision edges (LLM_DECISION 5->6
and 5->8) must be present at high confidence. The legitimate setup
steps (0, 1) must NOT appear in a depth-bounded explanation of the
exfiltration step.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from airsdk._concrete_demo import build_concrete_demo_log
from airsdk.agdr import load_chain
from airsdk.causal import build_causal_graph
from airsdk.causal.types import EdgeKind


def _demo_records() -> list:  # type: ignore[type-arg]
    with tempfile.TemporaryDirectory() as tmp:
        log_path = Path(tmp) / "demo.jsonl"
        build_concrete_demo_log(log_path)
        return load_chain(log_path)


def test_demo_chain_has_expected_step_count() -> None:
    """The demo chain has 10 records. If this changes, every other test
    here needs the new ordinals."""
    assert len(_demo_records()) == 10


def test_chain_link_edges_present_for_every_step() -> None:
    """Every non-first record links structurally to its predecessor."""
    graph = build_causal_graph(_demo_records())
    chain_links = [e for e in graph.edges if e.kind == EdgeKind.CHAIN_LINK]
    # 9 chain_link edges for a 10-record chain.
    assert len(chain_links) == 9
    assert all(e.confidence == 1.0 for e in chain_links)


def test_llm_pair_and_tool_pair_hard_edges() -> None:
    graph = build_causal_graph(_demo_records())
    llm_pairs = [(e.from_ordinal, e.to_ordinal) for e in graph.edges if e.kind == EdgeKind.LLM_PAIR]
    tool_pairs = [(e.from_ordinal, e.to_ordinal) for e in graph.edges if e.kind == EdgeKind.TOOL_PAIR]
    assert (0, 1) in llm_pairs, "step 0 LLM_START -> step 1 LLM_END pair missing"
    assert (4, 5) in llm_pairs, "step 4 LLM_START -> step 5 LLM_END pair missing"
    assert (2, 3) in tool_pairs, "step 2 TOOL_START -> step 3 TOOL_END pair missing"
    assert (6, 7) in tool_pairs, "step 6 TOOL_START -> step 7 TOOL_END pair missing"


def test_llm_decision_edges_for_every_tool_call() -> None:
    """Every tool call has an LLM_DECISION edge from the LLM_END that
    decided it. This is the hard causal link for "why did the agent call
    this tool" - load-bearing for every forensic explanation."""
    graph = build_causal_graph(_demo_records())
    decisions = {(e.from_ordinal, e.to_ordinal) for e in graph.edges if e.kind == EdgeKind.LLM_DECISION}
    # LLM_END at 1 decided TOOL_START at 2 (read_file README).
    assert (1, 2) in decisions
    # LLM_END at 5 decided TOOL_START at 6 (read_file SSH key) AND TOOL_START
    # at 8 (http_post exfiltration); no LLM_END between 5 and 8 so it points
    # at both.
    assert (5, 6) in decisions
    assert (5, 8) in decisions


def test_output_reuse_for_poisoned_readme() -> None:
    """The poisoned README content (step 3 tool_output) must show up as
    an OUTPUT_REUSE soft edge into step 4's LLM_START prompt at high
    confidence. This is the data-flow proof of prompt injection."""
    graph = build_causal_graph(_demo_records())
    matches = [
        e for e in graph.edges
        if e.kind == EdgeKind.OUTPUT_REUSE and e.from_ordinal == 3 and e.to_ordinal == 4
    ]
    assert len(matches) == 1, "OUTPUT_REUSE edge 3->4 must exist exactly once"
    assert matches[0].confidence >= 0.9, (
        f"poisoned-README data flow should be high confidence; got {matches[0].confidence}"
    )


def test_output_reuse_for_ssh_key_exfiltration() -> None:
    """The leaked SSH key (step 7 tool_output) must show up as an
    OUTPUT_REUSE soft edge into step 8's TOOL_START args (http_post body)
    at high confidence. This is the data-flow proof of credential
    exfiltration."""
    graph = build_causal_graph(_demo_records())
    matches = [
        e for e in graph.edges
        if e.kind == EdgeKind.OUTPUT_REUSE and e.from_ordinal == 7 and e.to_ordinal == 8
    ]
    assert len(matches) == 1, "OUTPUT_REUSE edge 7->8 must exist exactly once"
    assert matches[0].confidence >= 0.9, (
        f"SSH-key data flow should be high confidence; got {matches[0].confidence}"
    )


def test_no_spurious_output_reuse_in_demo() -> None:
    """The only soft edges in the demo chain must be the two real ones.
    A false positive here destroys trust faster than the rest of the
    chain protects it."""
    graph = build_causal_graph(_demo_records())
    soft = {(e.from_ordinal, e.to_ordinal) for e in graph.edges if e.kind == EdgeKind.OUTPUT_REUSE}
    assert soft == {(3, 4), (7, 8)}, f"unexpected soft edges in demo chain: {soft}"
