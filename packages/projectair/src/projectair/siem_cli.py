"""`air siem ...` CLI subcommand group (Pro).

Defers all imports of ``airsdk_pro.siem`` to the command body so the OSS
``projectair`` package keeps working when ``projectair-pro`` is not
installed; the user gets a clean install message instead of an
ImportError. Same pattern the Pro report commands use.
"""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import typer

from airsdk import __version__ as airsdk_version
from airsdk.agdr import load_chain, verify_chain
from airsdk.detections import run_detectors
from airsdk.types import ForensicReport, VerificationStatus

PRO_INSTALL_MESSAGE = (
    "SIEM push requires the projectair-pro package.\n\n"
    "  pip install projectair-pro\n"
    "  air login --license <token>\n\n"
    "Buy a license at https://vindicara.io/pricing"
)


def _build_report(log: Path) -> ForensicReport:
    records = load_chain(log)
    finishes = sum(1 for r in records if r.kind.value == "agent_finish")
    conversations = max(finishes, 1)
    verification = verify_chain(records)
    findings = run_detectors(records)
    return ForensicReport(
        air_version=airsdk_version,
        report_id=str(uuid4()),
        source_log=str(log.resolve()),
        generated_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        records=len(records),
        conversations=conversations,
        verification=verification,
        findings=findings,
    )


def _print_chain_warning_or_ok(report: ForensicReport) -> None:
    if report.verification.status != VerificationStatus.OK:
        typer.secho(
            "[WARNING] Chain verification did NOT pass: "
            f"{report.verification.reason}. Findings will still push.",
            fg=typer.colors.YELLOW, err=True,
        )
    else:
        typer.secho(
            f"[Chain verified] {report.verification.records_verified} signatures valid.",
            fg=typer.colors.GREEN,
        )


def register(app: typer.Typer) -> None:
    """Register the `air siem ...` subcommand group on the parent CLI app."""
    siem_app = typer.Typer(
        name="siem",
        help="Push findings to a SIEM (Datadog, Splunk HEC, Sumo, Sentinel). Pro feature.",
        no_args_is_help=True,
        add_completion=False,
    )
    app.add_typer(siem_app, name="siem")

    @siem_app.command("datadog")
    def datadog(
        log: Path = typer.Argument(..., exists=True, readable=True, help="Path to a JSON-lines AgDR log."),
        api_key: str = typer.Option(..., "--api-key", help="Datadog API key.", envvar="DD_API_KEY"),
        site: str = typer.Option("datadoghq.com", "--site", help="Datadog site (e.g. datadoghq.eu)."),
        min_severity: str | None = typer.Option(None, "--min-severity", help="Drop findings below this severity (low|medium|high|critical)."),
    ) -> None:
        """Push findings to the Datadog Logs API v2 endpoint for the configured site."""
        try:
            from airsdk_pro.license import LicenseError
            from airsdk_pro.siem import push_to_datadog
        except ImportError:
            typer.secho(PRO_INSTALL_MESSAGE, fg=typer.colors.YELLOW)
            raise typer.Exit(code=2) from None
        report = _build_report(log)
        _print_chain_warning_or_ok(report)
        try:
            result = push_to_datadog(report, api_key=api_key, site=site, min_severity=min_severity)
        except LicenseError as exc:
            typer.secho(f"License check failed: {exc}", fg=typer.colors.RED)
            raise typer.Exit(code=2) from exc
        typer.secho(f"Datadog: pushed {result.events_sent} events (HTTP {result.http_status}).", fg=typer.colors.GREEN, bold=True)

    @siem_app.command("splunk")
    def splunk(
        log: Path = typer.Argument(..., exists=True, readable=True, help="Path to a JSON-lines AgDR log."),
        hec_url: str = typer.Option(..., "--hec-url", help="Full Splunk HEC URL ending in /services/collector.", envvar="SPLUNK_HEC_URL"),
        hec_token: str = typer.Option(..., "--hec-token", help="Splunk HEC token.", envvar="SPLUNK_HEC_TOKEN"),
        index: str | None = typer.Option(None, "--index", help="Optional Splunk index name."),
        min_severity: str | None = typer.Option(None, "--min-severity"),
    ) -> None:
        """Push findings to a Splunk HTTP Event Collector endpoint."""
        try:
            from airsdk_pro.license import LicenseError
            from airsdk_pro.siem import push_to_splunk_hec
        except ImportError:
            typer.secho(PRO_INSTALL_MESSAGE, fg=typer.colors.YELLOW)
            raise typer.Exit(code=2) from None
        report = _build_report(log)
        _print_chain_warning_or_ok(report)
        try:
            result = push_to_splunk_hec(
                report,
                hec_url=hec_url,
                hec_token=hec_token,
                index=index,
                min_severity=min_severity,
            )
        except LicenseError as exc:
            typer.secho(f"License check failed: {exc}", fg=typer.colors.RED)
            raise typer.Exit(code=2) from exc
        typer.secho(f"Splunk HEC: pushed {result.events_sent} events (HTTP {result.http_status}).", fg=typer.colors.GREEN, bold=True)

    @siem_app.command("sumo")
    def sumo(
        log: Path = typer.Argument(..., exists=True, readable=True, help="Path to a JSON-lines AgDR log."),
        http_source_url: str = typer.Option(..., "--http-source-url", help="Sumo Logic Hosted HTTP Source URL.", envvar="SUMO_HTTP_SOURCE_URL"),
        category: str | None = typer.Option(None, "--category", help="Sumo X-Sumo-Category header."),
        host: str | None = typer.Option(None, "--host", help="Sumo X-Sumo-Host header."),
        name: str | None = typer.Option(None, "--name", help="Sumo X-Sumo-Name header."),
        min_severity: str | None = typer.Option(None, "--min-severity"),
    ) -> None:
        """Push findings to a Sumo Logic Hosted HTTP Source."""
        try:
            from airsdk_pro.license import LicenseError
            from airsdk_pro.siem import push_to_sumo
        except ImportError:
            typer.secho(PRO_INSTALL_MESSAGE, fg=typer.colors.YELLOW)
            raise typer.Exit(code=2) from None
        report = _build_report(log)
        _print_chain_warning_or_ok(report)
        try:
            result = push_to_sumo(
                report,
                http_source_url=http_source_url,
                category=category,
                host=host,
                name=name,
                min_severity=min_severity,
            )
        except LicenseError as exc:
            typer.secho(f"License check failed: {exc}", fg=typer.colors.RED)
            raise typer.Exit(code=2) from exc
        typer.secho(f"Sumo: pushed {result.events_sent} events (HTTP {result.http_status}).", fg=typer.colors.GREEN, bold=True)

    @siem_app.command("sentinel")
    def sentinel(
        log: Path = typer.Argument(..., exists=True, readable=True, help="Path to a JSON-lines AgDR log."),
        workspace_id: str = typer.Option(..., "--workspace-id", help="Azure Log Analytics workspace ID.", envvar="SENTINEL_WORKSPACE_ID"),
        shared_key: str = typer.Option(..., "--shared-key", help="Workspace shared key (base64).", envvar="SENTINEL_SHARED_KEY"),
        log_type: str = typer.Option("VindicaraAIR", "--log-type", help="Custom-log table name (Sentinel appends _CL)."),
        min_severity: str | None = typer.Option(None, "--min-severity"),
    ) -> None:
        """Push findings to a Microsoft Sentinel workspace via Azure Log Analytics Data Collector API."""
        try:
            from airsdk_pro.license import LicenseError
            from airsdk_pro.siem import push_to_sentinel
        except ImportError:
            typer.secho(PRO_INSTALL_MESSAGE, fg=typer.colors.YELLOW)
            raise typer.Exit(code=2) from None
        report = _build_report(log)
        _print_chain_warning_or_ok(report)
        try:
            result = push_to_sentinel(
                report,
                workspace_id=workspace_id,
                shared_key=shared_key,
                log_type=log_type,
                min_severity=min_severity,
            )
        except LicenseError as exc:
            typer.secho(f"License check failed: {exc}", fg=typer.colors.RED)
            raise typer.Exit(code=2) from exc
        typer.secho(f"Sentinel: pushed {result.events_sent} events (HTTP {result.http_status}).", fg=typer.colors.GREEN, bold=True)


__all__ = ["register"]
