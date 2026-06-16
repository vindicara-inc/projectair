"""`air cloud ...` CLI subcommand group (Pro).

Defers all imports of ``airsdk_pro.cloud`` to the command body so OSS
installs without ``projectair-pro`` continue to expose the help text
and emit a clean install message at runtime.
"""
from __future__ import annotations

from pathlib import Path

import typer

from airsdk.agdr import load_chain

PRO_INSTALL_MESSAGE = (
    "AIR Cloud client requires the projectair-pro package.\n\n"
    "  pip install projectair-pro          # webhook destination\n"
    "  pip install 'projectair-pro[s3]'    # also enables S3 destination\n"
    "  air login --license <token>\n\n"
    "Buy a license at https://vindicara.io/pricing"
)


def register(app: typer.Typer) -> None:
    """Register the `air cloud ...` subcommand group on the parent CLI app."""
    cloud_app = typer.Typer(
        name="cloud",
        help="Push signed Intent Capsule chains to durable storage (webhook or S3). Pro feature.",
        no_args_is_help=True,
        add_completion=False,
    )
    app.add_typer(cloud_app, name="cloud")

    @cloud_app.command("push-webhook")
    def push_webhook(
        log: Path = typer.Argument(..., exists=True, readable=True, help="Path to a JSONL AgDR log."),
        url: str = typer.Option(..., "--url", help="Destination webhook URL.", envvar="AIR_CLOUD_WEBHOOK_URL"),
        secret: str | None = typer.Option(
            None, "--secret",
            help="Optional shared secret for HMAC-SHA256 signing (sent as X-Vindicara-Signature).",
            envvar="AIR_CLOUD_WEBHOOK_SECRET",
        ),
        tenant_id: str | None = typer.Option(
            None, "--tenant-id",
            help="Optional tenant routing header (X-Tenant-Id) for multi-tenant receivers.",
        ),
    ) -> None:
        """Push the chain at ``log`` to a customer-owned HTTPS webhook."""
        try:
            from airsdk_pro.cloud import push_chain_to_webhook
            from airsdk_pro.license import LicenseError
        except ImportError:
            typer.secho(PRO_INSTALL_MESSAGE, fg=typer.colors.YELLOW)
            raise typer.Exit(code=2) from None

        records = load_chain(log)
        extra: dict[str, str] | None = {"X-Tenant-Id": tenant_id} if tenant_id else None
        try:
            result = push_chain_to_webhook(
                records, url=url, secret=secret, extra_headers=extra
            )
        except LicenseError as exc:
            typer.secho(f"License check failed: {exc}", fg=typer.colors.RED)
            raise typer.Exit(code=2) from exc
        typer.secho(
            f"Webhook: pushed {result.records_sent} records ({result.bytes_sent} bytes) to {result.endpoint}",
            fg=typer.colors.GREEN, bold=True,
        )

    @cloud_app.command("push-s3")
    def push_s3(
        log: Path = typer.Argument(..., exists=True, readable=True, help="Path to a JSONL AgDR log."),
        bucket: str = typer.Option(..., "--bucket", help="Destination S3 bucket name.", envvar="AIR_CLOUD_S3_BUCKET"),
        key: str = typer.Option(..., "--key", help="Destination S3 object key.", envvar="AIR_CLOUD_S3_KEY"),
        region: str | None = typer.Option(None, "--region", help="AWS region for the bucket."),
        no_sse: bool = typer.Option(
            False, "--no-sse",
            help="Disable server-side encryption (default is AES256).",
        ),
    ) -> None:
        """Upload the chain at ``log`` to a customer-owned S3 bucket (requires `[s3]` extra)."""
        try:
            from airsdk_pro.cloud import push_chain_to_s3
            from airsdk_pro.license import LicenseError
        except ImportError:
            typer.secho(PRO_INSTALL_MESSAGE, fg=typer.colors.YELLOW)
            raise typer.Exit(code=2) from None

        records = load_chain(log)
        try:
            result = push_chain_to_s3(
                records,
                bucket=bucket,
                key=key,
                region=region,
                sse=None if no_sse else "AES256",
            )
        except LicenseError as exc:
            typer.secho(f"License check failed: {exc}", fg=typer.colors.RED)
            raise typer.Exit(code=2) from exc
        typer.secho(
            f"S3: uploaded {result.records_sent} records ({result.bytes_sent} bytes) to {result.endpoint}",
            fg=typer.colors.GREEN, bold=True,
        )


__all__ = ["register"]
