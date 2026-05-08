"""Narrowed evidence excerpts from a causal graph.

The deliverable is a chronological story, not a graph dump. A forensic
analyst types ``air explain --step <id>`` or ``air explain --finding
<detector_id>`` and gets the load-bearing 5-7 records that mattered, with
edges marked hard (derived) or soft (inferred). Anything else is noise
they have to filter out before they can write a report.

Two entry points:

- :func:`explain_step` walks the graph backward from a single step and
  returns the chronological set of ancestors plus the step itself.
- :func:`explain_finding` finds the records flagged by a detector_id and
  returns the union of their ancestor sets.

Both return :class:`Explanation` so the CLI can render consistently.
"""
from __future__ import annotations

from collections import deque

from pydantic import BaseModel, ConfigDict

from airsdk.causal.types import CausalEdge, CausalGraph, CausalNode, EdgeKind
from airsdk.types import Finding

# CHAIN_LINK is a structural property (every record has prev_hash to the
# immediately prior). It is NOT a semantic causal relationship; treating
# it as one would drag every prior record into every explanation. The
# real causal edges are LLM_PAIR / TOOL_PAIR / LLM_DECISION /
# AGENT_MESSAGE / OUTPUT_REUSE.
_CAUSAL_EDGE_KINDS: frozenset[EdgeKind] = frozenset({
    EdgeKind.LLM_PAIR,
    EdgeKind.TOOL_PAIR,
    EdgeKind.LLM_DECISION,
    EdgeKind.AGENT_MESSAGE,
    EdgeKind.OUTPUT_REUSE,
})


class Explanation(BaseModel):
    """A narrowed evidence excerpt for one or more target steps.

    ``records`` is the chronological list of ordinals (sorted) the
    explainer determined are load-bearing. ``edges`` is the subset of
    graph edges that connect them. ``targets`` are the originally-asked-
    about steps so the CLI can highlight them.
    """

    model_config = ConfigDict(extra="forbid")

    targets: list[int]
    nodes: list[CausalNode]
    edges: list[CausalEdge]


def explain_step(graph: CausalGraph, target_ordinal: int, max_depth: int = 4) -> Explanation:
    """Return the chronological causal ancestry of ``target_ordinal``.

    BFS backward over causal edges (excluding CHAIN_LINK), bounded by
    ``max_depth`` to prevent runaway explanations on densely-connected
    chains. Default 4 is calibrated against the SSH-exfiltration demo:
    that flow's load-bearing 6-7 records are within depth 4 of the
    exfiltration step, and pre-attack legit setup steps fall outside.
    Includes the target itself.
    """
    if target_ordinal < 0 or target_ordinal >= len(graph.nodes):
        raise IndexError(f"ordinal {target_ordinal} out of range")
    selected: set[int] = {target_ordinal}
    visited: set[int] = set()
    queue: deque[tuple[int, int]] = deque([(target_ordinal, 0)])

    while queue:
        ord_, depth = queue.popleft()
        if ord_ in visited or depth >= max_depth:
            continue
        visited.add(ord_)
        for edge in graph.incoming(ord_):
            if edge.kind not in _CAUSAL_EDGE_KINDS:
                continue
            selected.add(edge.from_ordinal)
            queue.append((edge.from_ordinal, depth + 1))

    return _build_explanation(graph, [target_ordinal], selected)


def explain_finding(
    graph: CausalGraph,
    findings: list[Finding],
    detector_id: str,
) -> Explanation:
    """Return the union of ancestor sets for every record flagged by
    ``detector_id``."""
    targets: list[int] = []
    selected: set[int] = set()
    for finding in findings:
        if finding.detector_id != detector_id:
            continue
        ord_ = graph.find_ordinal(finding.step_id)
        if ord_ is None:
            continue
        targets.append(ord_)
        partial = explain_step(graph, ord_)
        selected.update(n.ordinal for n in partial.nodes)

    if not targets:
        # No records flagged by this detector. Return an empty explanation.
        return Explanation(targets=[], nodes=[], edges=[])

    return _build_explanation(graph, targets, selected)


def _build_explanation(
    graph: CausalGraph,
    targets: list[int],
    selected: set[int],
) -> Explanation:
    """Materialize a chronological Explanation from a node-ordinal set."""
    ordered = sorted(selected)
    nodes = [graph.node(o) for o in ordered]
    edges = [
        e for e in graph.edges
        if e.from_ordinal in selected and e.to_ordinal in selected
    ]
    return Explanation(
        targets=sorted(set(targets)),
        nodes=nodes,
        edges=edges,
    )
