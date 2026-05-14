"""SV-EXFIL: structural trajectory analysis via the causal graph.

This is the check that makes structural verification structural, not
just another detector. It traverses causal paths in the graph to prove
that secret material flowed from access to egress. Per-step checks
(SV-NET, SV-SECRET) flag the individual steps; SV-EXFIL proves the
trajectory connecting them.
"""
from __future__ import annotations

from collections import deque

from airsdk.causal.types import CausalGraph, EdgeKind
from airsdk.types import AgDRRecord, StepKind
from airsdk.verification.checks.network import _is_network_tool
from airsdk.verification.checks.secrets import _output_contains_secret, _path_matches_secret
from airsdk.verification.types import Violation


def _find_secret_sources(records: list[AgDRRecord]) -> list[int]:
    """Ordinals of TOOL_END records whose output contains secret material."""
    sources: list[int] = []
    for idx, rec in enumerate(records):
        if rec.kind == StepKind.TOOL_END:
            output = rec.payload.tool_output or ""
            if _output_contains_secret(output):
                sources.append(idx)
        if rec.kind == StepKind.TOOL_START:
            args = rec.payload.tool_args or {}
            for key in ("path", "file", "filename", "filepath"):
                val = args.get(key)
                if isinstance(val, str) and _path_matches_secret(val):
                    sources.append(idx)
                    break
    return sources


def _find_network_sinks(records: list[AgDRRecord]) -> list[int]:
    """Ordinals of TOOL_START records that perform network egress."""
    sinks: list[int] = []
    for idx, rec in enumerate(records):
        if rec.kind == StepKind.TOOL_START:
            name = rec.payload.tool_name or ""
            if _is_network_tool(name):
                sinks.append(idx)
    return sinks


def _find_causal_path(
    graph: CausalGraph,
    source: int,
    sink: int,
) -> list[int] | None:
    """BFS forward from source to sink over non-CHAIN_LINK edges.

    Returns the ordinal path if reachable, else None. Excludes
    CHAIN_LINK edges because every record links to its predecessor;
    traversing those would make everything reachable from everything.
    """
    if source >= sink:
        return None
    visited: set[int] = set()
    parent: dict[int, int] = {}
    queue: deque[int] = deque([source])
    visited.add(source)

    while queue:
        current = queue.popleft()
        if current == sink:
            path = []
            node = sink
            while node != source:
                path.append(node)
                node = parent[node]
            path.append(source)
            path.reverse()
            return path
        for edge in graph.outgoing(current):
            if edge.kind == EdgeKind.CHAIN_LINK:
                continue
            nxt = edge.to_ordinal
            if nxt not in visited:
                visited.add(nxt)
                parent[nxt] = current
                queue.append(nxt)
    return None


def _describe_path(path: list[int], records: list[AgDRRecord]) -> str:
    parts: list[str] = []
    for ordinal in path:
        rec = records[ordinal]
        name = rec.payload.tool_name or rec.kind.value
        parts.append(f"#{ordinal} {name}")
    return " -> ".join(parts)


def check_exfiltration(
    records: list[AgDRRecord],
    graph: CausalGraph,
) -> list[Violation]:
    """Find causal paths from secret sources to network sinks."""
    sources = _find_secret_sources(records)
    sinks = _find_network_sinks(records)
    violations: list[Violation] = []
    seen_pairs: set[tuple[int, int]] = set()

    for src in sources:
        for sink in sinks:
            if (src, sink) in seen_pairs:
                continue
            path = _find_causal_path(graph, src, sink)
            if path is None:
                continue
            seen_pairs.add((src, sink))
            sink_rec = records[sink]
            src_rec = records[src]
            src_label = src_rec.payload.tool_name or src_rec.kind.value
            sink_label = sink_rec.payload.tool_name or sink_rec.kind.value

            violations.append(Violation(
                check_id="SV-EXFIL-01",
                title="Secret material exfiltrated via network",
                severity="critical",
                step_index=sink,
                step_id=sink_rec.step_id,
                evidence=f"causal path from secret source to network egress: {_describe_path(path, records)}",
                expected="no causal path from secret access to network egress",
                actual=f"{src_label} (step #{src}) -> {sink_label} (step #{sink})",
                causal_path=path,
            ))
    return violations
