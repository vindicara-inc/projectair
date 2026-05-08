"""`air alert ...` CLI subcommand group (Pro).

Defers airsdk_pro imports to the command body so OSS-only installs
still expose the help text and emit a clean install message at runtime.
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
    "Incident alerting requires the projectair-pro package.\n\n"
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


def _print_chain_warning(report: ForensicReport) -> None:
    if report.verification.status != VerificationStatus.OK:
        typer.secho(
            f"[WARNING] Chain verification did NOT pass: {report.verification.reason}.",
            fg=typer.colors.YELLOW, err=True,
        )


def register(app: typer.Typer) -> None:
    """Register the `air alert ...` subcommand group on the parent CLI app."""
    alert_app = typer.Typer(
        name="alert",
        help="Send incident alerts (Slack, PagerDuty, generic webhook). Pro feature.",
        no_args_is_help=True,
        add_completion=False,
    )
    app.add_typer(alert_app, name="alert")

    @alert_app.command("slack")
    def slack(
        log: Path = typer.Argument(..., exists=True, readable=True, help="Path to a JSONL AgDR log."),
        webhook_url: str = typer.Option(..., "--webhook-url", help="Slack Incoming Webhook URL.", envvar="AIR_ALERT_SLACK_WEBHOOK"),
        channel: str | None = typer.Option(None, "--channel", help="Optional channel override (legacy webhooks only)."),
        min_severity: str = typer.Option("high", "--min-severity"),
    ) -> None:
        """Send a single summary message to a Slack Incoming Webhook."""
        try:
            from airsdk_pro.alerts import alert_to_slack
            from airsdk_pro.license import LicenseError
        except ImportError:
            typer.secho(PRO_INSTALL_MESSAGE, fg=typer.colors.YELLOW)
            raise typer.Exit(code=2) from None
        report = _build_report(log)
        _print_chain_warning(report)
        try:
            result = alert_to_slack(report, webhook_url=webhook_url, channel=channel, min_severity=min_severity)
        except LicenseError as exc:
            typer.secho(f"License check failed: {exc}", fg=typer.colors.RED)
            raise typer.Exit(code=2) from exc
        typer.secho(
            f"Slack: alerted on {result.findings_alerted} finding(s) (HTTP {result.http_status}).",
            fg=typer.colors.GREEN, bold=True,
        )

    @alert_app.command("pagerduty")
    def pagerduty(
        log: Path = typer.Argument(..., exists=True, readable=True, help="Path to a JSONL AgDR log."),
        integration_key: str = typer.Option(
            ..., "--integration-key",
            help="PagerDuty Events v2 integration key (32-char routing key).",
            envvar="AIR_ALERT_PD_INTEGRATION_KEY",
        ),
        min_severity: str = typer.Option("high", "--min-severity"),
    ) -> None:
        """Send one PagerDuty Events v2 trigger event per qualifying finding."""
        try:
            from airsdk_pro.alerts import alert_to_pagerduty
            from airsdk_pro.license import LicenseError
        except ImportError:
            typer.secho(PRO_INSTALL_MESSAGE, fg=typer.colors.YELLOW)
            raise typer.Exit(code=2) from None
        report = _build_report(log)
        _print_chain_warning(report)
        try:
            result = alert_to_pagerduty(report, integration_key=integration_key, min_severity=min_severity)
        except LicenseError as exc:
            typer.secho(f"License check failed: {exc}", fg=typer.colors.RED)
            raise typer.Exit(code=2) from exc
        typer.secho(
            f"PagerDuty: alerted on {result.findings_alerted} finding(s) (HTTP {result.http_status}).",
            fg=typer.colors.GREEN, bold=True,
        )

    @alert_app.command("webhook")
    def webhook(
        log: Path = typer.Argument(..., exists=True, readable=True, help="Path to a JSONL AgDR log."),
        url: str = typer.Option(..., "--url", help="Destination webhook URL.", envvar="AIR_ALERT_WEBHOOK_URL"),
        secret: str | None = typer.Option(
            None, "--secret",
            help="Optional shared secret for HMAC-SHA256 signing (sent as X-Vindicara-Alert-Signature).",
            envvar="AIR_ALERT_WEBHOOK_SECRET",
        ),
        min_severity: str = typer.Option("high", "--min-severity"),
    ) -> None:
        """Send a JSON alert summary to a customer-owned HTTPS webhook."""
        try:
            from airsdk_pro.alerts import alert_to_webhook
            from airsdk_pro.license import LicenseError
        except ImportError:
            typer.secho(PRO_INSTALL_MESSAGE, fg=typer.colors.YELLOW)
            raise typer.Exit(code=2) from None
        report = _build_report(log)
        _print_chain_warning(report)
        try:
            result = alert_to_webhook(report, url=url, secret=secret, min_severity=min_severity)
        except LicenseError as exc:
            typer.secho(f"License check failed: {exc}", fg=typer.colors.RED)
            raise typer.Exit(code=2) from exc
        typer.secho(
            f"Webhook: alerted on {result.findings_alerted} finding(s) (HTTP {result.http_status}).",
            fg=typer.colors.GREEN, bold=True,
        )


__all__ = ["register"]
