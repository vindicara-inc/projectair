"""`air detect-premium` CLI command (Pro).

Runs the premium ASI04 sub-detectors (ASI04-PD / ASI04-TM / ASI04-USF)
against an AgDR log and prints findings (or writes them as JSON to a
file). Defers airsdk_pro imports to the command body so OSS-only
installs still expose the help text.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import typer

from airsdk import __version__ as airsdk_version
from airsdk.agdr import load_chain, verify_chain
from airsdk.types import ForensicReport, VerificationStatus

PRO_INSTALL_MESSAGE = (
    "Premium detectors require the projectair-pro package.\n\n"
    "  pip install projectair-pro\n"
    "  air login --license <token>\n\n"
    "Buy a license at https://vindicara.io/pricing"
)


def _severity_color(severity: str) -> str:
    return {
        "critical": typer.colors.RED,
        "high": typer.colors.YELLOW,
        "medium": typer.colors.CYAN,
    }.get(severity, typer.colors.WHITE)


def register(app: typer.Typer) -> None:
    """Register the `air detect-premium` command on the parent CLI app."""

    @app.command("detect-premium")
    def detect_premium(
        log: Path = typer.Argument(..., exists=True, readable=True, help="Path to a JSONL AgDR log."),
        output: Path | None = typer.Option(
            None, "--output", "-o",
            help="Optional JSON file to write findings to (in addition to stdout summary).",
        ),
    ) -> None:
        """Run premium ASI04 sub-detectors on an AgDR log (Pro).

        Premium sub-detectors covered:
          - ASI04-PD: dependency install surface (pip/npm/cargo/curl|bash, ...)
          - ASI04-TM: tool manifest drift (same tool_name, diverging args)
          - ASI04-USF: untrusted source fetch (raw github / gist / pastebin / ngrok)
        """
        try:
            from airsdk_pro.detectors import (
                PREMIUM_DETECTOR_IDS,
                run_premium_detectors,
            )
            from airsdk_pro.license import LicenseError
        except ImportError:
            typer.secho(PRO_INSTALL_MESSAGE, fg=typer.colors.YELLOW)
            raise typer.Exit(code=2) from None

        records = load_chain(log)
        verification = verify_chain(records)
        if verification.status != VerificationStatus.OK:
            typer.secho(
                f"[WARNING] Chain verification did NOT pass: {verification.reason}.",
                fg=typer.colors.YELLOW, err=True,
            )

        try:
            findings = run_premium_detectors(records)
        except LicenseError as exc:
            typer.secho(f"License check failed: {exc}", fg=typer.colors.RED)
            raise typer.Exit(code=2) from exc

        typer.secho(f"Premium detectors run on {len(records)} records:", fg=typer.colors.WHITE, bold=True)
        for code, name, _description in PREMIUM_DETECTOR_IDS:
            count = sum(1 for f in findings if f.detector_id == code)
            typer.secho(f"  {code:<10} {name:<55} {count} finding(s)", fg=typer.colors.BRIGHT_BLACK)
        typer.echo()
        if findings:
            for f in findings:
                typer.secho(
                    f"  {f.detector_id} {f.title} at step {f.step_index}",
                    fg=_severity_color(f.severity),
                )
                typer.secho(f"    {f.description}", fg=typer.colors.BRIGHT_BLACK)
        else:
            typer.secho("  No premium findings on this trace.", fg=typer.colors.GREEN)

        if output is not None:
            report = ForensicReport(
                air_version=airsdk_version,
                report_id=str(uuid4()),
                source_log=str(log.resolve()),
                generated_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                records=len(records),
                conversations=1,
                verification=verification,
                findings=findings,
            )
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(report.model_dump(mode="json"), indent=2), encoding="utf-8")
            typer.secho(f"Premium findings written to {output.resolve()}", fg=typer.colors.GREEN, bold=True)


__all__ = ["register"]
