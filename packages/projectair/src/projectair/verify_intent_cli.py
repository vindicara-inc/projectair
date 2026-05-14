"""CLI command for structural verification (experimental).

Exposes ``air verify-intent`` against an existing AgDR chain. Checks
whether the agent's actual behavior structurally served its declared
intent. The symbolic floor is deterministic and cannot be prompt-
injected.
"""
from __future__ import annotations

from pathlib import Path

import typer

from airsdk import __version__ as airsdk_version
from airsdk.agdr import load_chain
from airsdk.verification import (
    IntentVerdict,
    IntentVerificationResult,
    Violation,
    verify_intent,
)


def register(app: typer.Typer) -> None:
    app.command(name="verify-intent")(verify_intent_cmd)


def verify_intent_cmd(
    chain: Path = typer.Argument(..., exists=True, dir_okay=False, help="Chain JSONL file."),
) -> None:
    """Verify that agent behavior served its declared intent (experimental).

    Runs structural verification over the chain: checks for secret
    access, undeclared network egress, filesystem scope violations,
    and causal exfiltration paths. Produces a VERIFIED / FAILED /
    INCONCLUSIVE verdict.
    """
    typer.secho(
        f"[AIR v{airsdk_version}] Structural Verification (experimental)",
        fg=typer.colors.WHITE, bold=True,
    )
    typer.secho(f"  Chain: {chain}", fg=typer.colors.BRIGHT_BLACK)

    records = load_chain(chain)
    result = verify_intent(records)

    typer.echo()
    _render_result(result)

    if result.verdict == IntentVerdict.FAILED:
        raise typer.Exit(code=2)


def _render_result(result: IntentVerificationResult) -> None:
    _verdict_color = {
        IntentVerdict.VERIFIED: typer.colors.GREEN,
        IntentVerdict.FAILED: typer.colors.RED,
        IntentVerdict.INCONCLUSIVE: typer.colors.YELLOW,
    }
    color = _verdict_color[result.verdict]

    typer.secho(f"  Intent:  {result.intent or '(none)'}", fg=typer.colors.WHITE)
    typer.secho(f"  Source:  {result.intent_source.value}", fg=typer.colors.BRIGHT_BLACK)
    typer.secho(
        f"  Verdict: {result.verdict.value.upper()}",
        fg=color, bold=True,
    )
    typer.echo()

    if result.violations:
        typer.secho(f"  {len(result.violations)} violation(s):", fg=typer.colors.WHITE, bold=True)
        typer.echo()
        for v in result.violations:
            _render_violation(v)
    else:
        typer.secho(f"  {result.summary}", fg=color)

    typer.echo()
    typer.secho(
        f"  {result.checked_steps} actionable steps checked out of {result.total_steps} total.",
        fg=typer.colors.BRIGHT_BLACK,
    )


def _severity_color(severity: str) -> str:
    return {
        "critical": typer.colors.RED,
        "high": typer.colors.YELLOW,
        "medium": typer.colors.CYAN,
    }.get(severity, typer.colors.WHITE)


def _render_violation(v: Violation) -> None:
    color = _severity_color(v.severity)
    typer.secho(
        f"  [{v.severity.upper()}] {v.check_id}: {v.title}",
        fg=color, bold=True,
    )
    typer.secho(f"    Step:     #{v.step_index}", fg=typer.colors.WHITE)
    typer.secho(f"    Evidence: {v.evidence}", fg=typer.colors.WHITE)
    typer.secho(f"    Expected: {v.expected}", fg=typer.colors.BRIGHT_BLACK)
    typer.secho(f"    Actual:   {v.actual}", fg=typer.colors.BRIGHT_BLACK)
    if v.causal_path:
        path_str = " -> ".join(f"#{o}" for o in v.causal_path)
        typer.secho(f"    Path:     {path_str}", fg=typer.colors.CYAN)
    typer.echo()
