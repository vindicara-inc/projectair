"""`air governance ...` CLI subcommand group (Pro).

Defers all imports of ``airsdk_pro.governance`` to the command body so the
OSS ``projectair`` package keeps working when ``projectair-pro`` is not
installed.
"""
from __future__ import annotations

from pathlib import Path

import typer

from airsdk.agdr import load_chain

PRO_INSTALL_MESSAGE = (
    "Data governance requires the projectair-pro package.\n\n"
    "  pip install projectair-pro\n"
    "  air login --license <token>\n\n"
    "Buy a license at https://vindicara.io/pricing"
)


def register(app: typer.Typer) -> None:
    """Register the `air governance ...` subcommand group."""
    gov_app = typer.Typer(
        name="governance",
        help="Data governance: query, DSAR, OpenLineage export, classification. Pro feature.",
        no_args_is_help=True,
        add_completion=False,
    )
    app.add_typer(gov_app, name="governance")

    @gov_app.command("index")
    def index_cmd(
        chains: list[Path] = typer.Argument(..., exists=True, readable=True, help="AgDR chain files."),
        registry_path: Path | None = typer.Option(None, "--registry", help="YAML/JSON data-asset registry."),
    ) -> None:
        """Build governance index from chains and print summary."""
        try:
            from airsdk_pro.governance.indexer import index_chains
            from airsdk_pro.governance.registry import DataAssetRegistry
        except ImportError:
            typer.secho(PRO_INSTALL_MESSAGE, fg=typer.colors.YELLOW)
            raise typer.Exit(code=2) from None

        loaded = [load_chain(c) for c in chains]
        reg = None
        if registry_path:
            if str(registry_path).endswith((".yaml", ".yml")):
                reg = DataAssetRegistry.from_yaml(registry_path)
            else:
                reg = DataAssetRegistry.from_json(registry_path)

        idx = index_chains(loaded, registry=reg)
        typer.secho(
            f"Indexed {len(idx.accesses)} data accesses across {len(chains)} chain(s). "
            f"Subjects: {len(idx.by_subject)}, Assets: {len(idx.by_asset)}, Agents: {len(idx.by_agent)}.",
            fg=typer.colors.GREEN,
        )

    @gov_app.command("query")
    def query_cmd(
        chains: list[Path] = typer.Argument(..., exists=True, readable=True, help="AgDR chain files."),
        subject: str | None = typer.Option(None, "--subject", help="Filter by data subject ID."),
        asset: str | None = typer.Option(None, "--asset", help="Filter by data asset ID."),
    ) -> None:
        """Query data accesses by subject or asset."""
        try:
            from airsdk_pro.governance.indexer import index_chains
            from airsdk_pro.governance.query import query
        except ImportError:
            typer.secho(PRO_INSTALL_MESSAGE, fg=typer.colors.YELLOW)
            raise typer.Exit(code=2) from None

        loaded = [load_chain(c) for c in chains]
        idx = index_chains(loaded)
        results = query(idx, subject_id=subject, asset_id=asset)
        for r in results:
            assets = ", ".join(a.asset_id for a in r.data_assets)
            typer.echo(f"  [{r.timestamp}] {r.tool_name} ({r.access_type}) -> {assets} [{r.policy_decision}]")
        typer.secho(f"\n{len(results)} access(es) found.", fg=typer.colors.GREEN)

    @gov_app.command("dsar")
    def dsar_cmd(
        chains: list[Path] = typer.Argument(..., exists=True, readable=True, help="AgDR chain files."),
        subject: str = typer.Option(..., "--subject", help="Data subject ID."),
        subject_type: str = typer.Option("", "--type", help="Subject type (patient, employee, ...)."),
        jurisdiction: str = typer.Option("", "--jurisdiction", help="HIPAA, GDPR, CCPA, or empty."),
    ) -> None:
        """Generate a DSAR report for a data subject."""
        try:
            from airsdk_pro.governance.dsar import generate_dsar, render_dsar_markdown
            from airsdk_pro.governance.indexer import index_chains
        except ImportError:
            typer.secho(PRO_INSTALL_MESSAGE, fg=typer.colors.YELLOW)
            raise typer.Exit(code=2) from None

        loaded = [load_chain(c) for c in chains]
        idx = index_chains(loaded)
        report = generate_dsar(idx, subject, subject_type=subject_type, jurisdiction=jurisdiction, chains_searched=len(chains))
        typer.echo(render_dsar_markdown(report))

    @gov_app.command("export")
    def export_cmd(
        chains: list[Path] = typer.Argument(..., exists=True, readable=True, help="AgDR chain files."),
        openlineage: bool = typer.Option(True, "--openlineage/--no-openlineage", help="Export as OpenLineage."),
        output: Path | None = typer.Option(None, "--output", "-o", help="Write to file instead of stdout."),
    ) -> None:
        """Export governance data as OpenLineage events."""
        try:
            from airsdk_pro.governance.indexer import index_chains
            from airsdk_pro.governance.openlineage import export_openlineage, export_openlineage_jsonl
        except ImportError:
            typer.secho(PRO_INSTALL_MESSAGE, fg=typer.colors.YELLOW)
            raise typer.Exit(code=2) from None

        loaded = [load_chain(c) for c in chains]
        idx = index_chains(loaded)
        events = export_openlineage(idx, chain_id=str(chains[0]))
        jsonl = export_openlineage_jsonl(events)
        if output:
            output.write_text(jsonl + "\n")
            typer.secho(f"Wrote {len(events)} OpenLineage events to {output}.", fg=typer.colors.GREEN)
        else:
            typer.echo(jsonl)

    @gov_app.command("classify")
    def classify_cmd(
        chains: list[Path] = typer.Argument(..., exists=True, readable=True, help="AgDR chain files."),
    ) -> None:
        """Run sensitivity classification on chain records."""
        try:
            from airsdk_pro.governance.classifier import classify_sensitivity
        except ImportError:
            typer.secho(PRO_INSTALL_MESSAGE, fg=typer.colors.YELLOW)
            raise typer.Exit(code=2) from None

        for chain_path in chains:
            records = load_chain(chain_path)
            suggestions = classify_sensitivity(records)
            if suggestions:
                typer.secho(f"\n{chain_path.name}: {len(suggestions)} suggestion(s)", fg=typer.colors.YELLOW)
                for s in suggestions:
                    typer.echo(
                        f"  step {s.step_id[:8]}... -> {s.suggested_sensitivity} "
                        f"({s.suggested_jurisdiction}) confidence={s.confidence:.2f} "
                        f"matched={','.join(s.matched_categories[:3])}"
                    )
            else:
                typer.secho(f"\n{chain_path.name}: no sensitive data detected.", fg=typer.colors.GREEN)
