"""CLI command for Layer 2 causal explanation.

Exposes ``air explain`` against an existing AgDR chain. Two modes:

- ``--step <step_id>`` walks the graph backward from one step, printing
  the chronological causal ancestry as a narrowed evidence excerpt.
- ``--finding <detector_id>`` runs the detector pipeline against the
  chain, finds every record flagged by ``detector_id``, and prints the
  union of their ancestor sets.

Output is intentionally short: a forensic analyst reading this should
walk away with the 5-7 records that mattered, marked hard or soft.
Anything else is noise.
"""
from __future__ import annotations

from pathlib import Path

import typer

from airsdk import __version__ as airsdk_version
from airsdk.agdr import load_chain
from airsdk.causal import (
    CausalGraph,
    Explanation,
    build_causal_graph,
    explain_finding,
    explain_step,
)
from airsdk.causal.types import CausalEdge, EdgeKind
from airsdk.detections import run_detectors


def register(app: typer.Typer) -> None:
    """Attach the explain command to ``app``."""
    app.command(name="explain")(explain_cmd)


def explain_cmd(
    chain: Path = typer.Argument(..., exists=True, dir_okay=False, help="Chain JSONL file."),
    step: str | None = typer.Option(None, "--step", help="Step UUID or 0-based ordinal."),
    finding: str | None = typer.Option(None, "--finding", help="Detector id (e.g. ASI01, AIR-02)."),
) -> None:
    """Explain the causal ancestry of a step or detector finding."""
    if (step is None) == (finding is None):
        typer.secho("Pass exactly one of --step or --finding", fg=typer.colors.RED)
        raise typer.Exit(code=2)

    typer.secho(f"[AIR v{airsdk_version}] Explaining {chain}", fg=typer.colors.WHITE, bold=True)
    records = load_chain(chain)
    graph = build_causal_graph(records)

    if step is not None:
        ord_ = _resolve_step(step, graph, len(records))
        explanation = explain_step(graph, ord_)
        target_label = f"step {ord_}"
    else:
        assert finding is not None
        findings = run_detectors(records)
        explanation = explain_finding(graph, findings, finding)
        if not explanation.targets:
            typer.secho(
                f"  No records flagged by detector {finding!r}.",
                fg=typer.colors.YELLOW,
            )
            return
        target_label = f"detector {finding} ({len(explanation.targets)} flagged step(s))"

    _render(explanation, target_label)


def _resolve_step(step_arg: str, graph: CausalGraph, total: int) -> int:
    """Accept either a numeric ordinal or a step_id (UUID)."""
    if step_arg.isdigit():
        ord_ = int(step_arg)
        if ord_ < 0 or ord_ >= total:
            typer.secho(f"  Ordinal {ord_} out of range (chain has {total} records).", fg=typer.colors.RED)
            raise typer.Exit(code=2)
        return ord_
    found = graph.find_ordinal(step_arg)
    if found is None:
        typer.secho(f"  Step id {step_arg!r} not found in chain.", fg=typer.colors.RED)
        raise typer.Exit(code=2)
    return found


def _render(explanation: Explanation, target_label: str) -> None:
    typer.secho(f"\nTarget: {target_label}", fg=typer.colors.BRIGHT_WHITE, bold=True)
    typer.secho(f"  {len(explanation.nodes)} relevant record(s) in causal ancestry", fg=typer.colors.BRIGHT_BLACK)
    typer.echo("")

    targets = set(explanation.targets)
    edges_by_target = _edges_grouped(explanation.edges)
    for node in explanation.nodes:
        is_target = node.ordinal in targets
        marker = "*" if is_target else " "
        color = typer.colors.YELLOW if is_target else typer.colors.WHITE
        typer.secho(f"  {marker} step {node.ordinal:>3}  {node.kind:<14}  {node.summary}", fg=color)
        for edge in edges_by_target.get(node.ordinal, []):
            arrow, edge_color = _edge_marker(edge)
            typer.secho(
                f"           {arrow} step {edge.from_ordinal} ({edge.kind.value}, conf={edge.confidence:.2f})",
                fg=edge_color,
            )
    typer.echo("")
    typer.secho(
        "  Legend:  <- hard edge (derived from explicit fields)   ~~ soft edge (inferred by content match)",
        fg=typer.colors.BRIGHT_BLACK,
    )


def _edges_grouped(edges: list[CausalEdge]) -> dict[int, list[CausalEdge]]:
    grouped: dict[int, list[CausalEdge]] = {}
    for edge in edges:
        grouped.setdefault(edge.to_ordinal, []).append(edge)
    return grouped


def _edge_marker(edge: CausalEdge) -> tuple[str, str]:
    if edge.kind == EdgeKind.OUTPUT_REUSE:
        return "~~", typer.colors.CYAN
    return "<-", typer.colors.GREEN
