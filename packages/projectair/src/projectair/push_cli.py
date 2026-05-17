"""``air push``: upload a signed chain to AIR Cloud."""
from __future__ import annotations

import json
import os
from pathlib import Path

import typer

_DEFAULT_CLOUD_URL = "https://cloud.vindicara.io"


def _resolve_api_key(option: str | None) -> str:
    key = option or os.environ.get("AIRSDK_CLOUD_API_KEY", "")
    if not key:
        typer.secho(
            "API key required. Pass --api-key or set AIRSDK_CLOUD_API_KEY.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=2)
    return key


def _resolve_cloud_url(option: str | None) -> str:
    url = option or os.environ.get("AIRSDK_CLOUD_URL", _DEFAULT_CLOUD_URL)
    return url.rstrip("/")


def _push(
    chain: Path = typer.Argument(
        ..., exists=True, readable=True, help="Path to a JSONL chain file."
    ),
    api_key: str | None = typer.Option(
        None,
        "--api-key",
        "-k",
        help="AIR Cloud API key (or set AIRSDK_CLOUD_API_KEY env var).",
    ),
    cloud_url: str | None = typer.Option(
        None,
        "--cloud-url",
        help=f"AIR Cloud endpoint (default: {_DEFAULT_CLOUD_URL}, or AIRSDK_CLOUD_URL env var).",
    ),
) -> None:
    """Push a signed forensic chain to AIR Cloud."""
    import httpx

    key = _resolve_api_key(api_key)
    url = _resolve_cloud_url(cloud_url)

    lines = chain.read_text(encoding="utf-8").splitlines()
    records: list[dict[str, object]] = []
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            records.append(json.loads(stripped))
        except json.JSONDecodeError as exc:
            typer.secho(f"Invalid JSON at line {i}: {exc}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=2) from exc

    if not records:
        typer.secho("Chain file is empty.", fg=typer.colors.YELLOW, err=True)
        raise typer.Exit(code=2)

    typer.secho(
        f"[AIR Cloud] Pushing {len(records)} records to {url}",
        fg=typer.colors.WHITE,
        bold=True,
    )

    client = httpx.Client(
        base_url=url,
        headers={"X-API-Key": key},
        timeout=30.0,
    )

    pushed = 0
    for rec in records:
        resp = client.post("/v1/capsules", json=rec)
        if resp.status_code in (200, 201):
            pushed += 1
        else:
            typer.secho(
                f"Failed at record {pushed + 1}: HTTP {resp.status_code}: {resp.text[:200]}",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=1)
        if pushed % 50 == 0:
            typer.secho(f"  {pushed}/{len(records)}...", fg=typer.colors.BRIGHT_BLACK)

    client.close()

    typer.secho(
        f"[AIR Cloud] Pushed {pushed}/{len(records)} records.",
        fg=typer.colors.GREEN,
        bold=True,
    )


def register(app: typer.Typer) -> None:
    app.command("push")(_push)
