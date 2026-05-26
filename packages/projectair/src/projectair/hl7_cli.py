"""HL7v2 + FHIR R4 clinical evidence CLI commands (Pro).

Registers the ``air hl7`` subcommand group. All command bodies defer the
``airsdk_pro`` import so OSS installs without Pro still see the help text
and receive a clean install message at runtime.
"""
from __future__ import annotations

from pathlib import Path

import typer


def register(app: typer.Typer) -> None:
    """Attach ``hl7_app`` to ``app`` as the ``hl7`` sub-group."""
    hl7_app = typer.Typer(
        name="hl7",
        help="HL7v2 + FHIR R4 clinical evidence tools (Pro).",
        no_args_is_help=True,
        add_completion=False,
    )
    app.add_typer(hl7_app, name="hl7")

    @hl7_app.command("parse")
    def hl7_parse(
        file: Path = typer.Argument(..., help="Path to .hl7 file"),
    ) -> None:
        """Parse and display HL7v2 messages."""
        try:
            from airsdk_pro.hl7 import parse_hl7v2
        except ImportError:
            typer.echo("Error: HL7v2 support requires projectair-pro.")
            raise typer.Exit(1)
        content = file.read_text()
        for chunk in content.split("MSH|"):
            if not chunk.strip():
                continue
            raw = "MSH|" + chunk
            msg = parse_hl7v2(raw)
            typer.echo(f"  Type: {msg.message_type}")
            typer.echo(f"  Facility: {msg.sending_facility}")
            typer.echo(f"  Timestamp: {msg.timestamp}")
            if msg.pid:
                typer.echo(f"  Patient MRN: {msg.pid.primary_mrn}")
            typer.echo(f"  OBX count: {len(msg.obx)}")
            typer.echo("")

    @hl7_app.command("capture")
    def hl7_capture(
        file: Path = typer.Argument(..., help="Path to .hl7 file"),
        chain: Path = typer.Option(Path("hl7-chain.jsonl"), help="Output chain path"),
    ) -> None:
        """Parse HL7v2, map to FHIR R4, write signed capsules."""
        try:
            from airsdk_pro.hl7 import RedactionPolicy, instrument_hl7
        except ImportError:
            typer.echo("Error: HL7v2 support requires projectair-pro.")
            raise typer.Exit(1)
        from airsdk.recorder import AIRRecorder
        rec = AIRRecorder(chain)
        policy = RedactionPolicy()
        content = file.read_text()
        count = 0
        for chunk in content.split("MSH|"):
            if not chunk.strip():
                continue
            raw = "MSH|" + chunk
            instrument_hl7(rec, raw, redaction_policy=policy)
            count += 1
        typer.echo(f"  {count} message(s) captured to {chain}")
