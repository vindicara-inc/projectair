"""CLI command for the hardware root of trust: ``air attest``.

Readiness: experimental (W1 of `docs/NVIDIA_INTEGRATION_SPEC.md`).
Collects GPU attestation evidence, calls NRAS, and prints the EAT plus the
nonce binding. With ``--record <chain>`` the resulting GPU_ATTESTATION
record is appended to the chain for inspection.
"""
from __future__ import annotations

import secrets
from pathlib import Path

import typer

from airsdk import __version__ as airsdk_version
from airsdk.agdr import Signer, load_chain
from airsdk.attestation import (
    AttestationError,
    AttestationProvider,
    FixtureNRAS,
    GPUAttestationConfig,
    NRASClient,
    attest_session,
)
from airsdk.attestation.config import DEFAULT_NRAS_URL
from airsdk.transport import FileTransport
from airsdk.types import StepKind


def register(app: typer.Typer) -> None:
    """Attach the attestation command to ``app``."""
    app.command(name="attest")(attest_cmd)


def attest_cmd(
    nras_url: str = typer.Option(DEFAULT_NRAS_URL, "--nras-url", help="NRAS endpoint."),
    gpu_arch: str = typer.Option("hopper", "--gpu-arch", help="hopper | blackwell | vera_rubin."),
    record: Path | None = typer.Option(
        None, "--record", exists=True, dir_okay=False,
        help="Chain JSONL to bind the nonce to and append the record onto.",
    ),
    fixture: bool = typer.Option(
        False, "--fixture",
        help="Use the simulated in-process NRAS (no GPU, no network). "
        "Tokens are marked x-nvidia-simulated.",
    ),
    fixture_cert_out: Path | None = typer.Option(
        None, "--fixture-cert-out",
        help="Where to write the fixture signing certificate for offline verify.",
    ),
) -> None:
    """[experimental] Collect evidence, call NRAS, print the EAT and nonce binding."""
    typer.secho(
        f"[AIR v{airsdk_version}] GPU attestation (experimental)",
        fg=typer.colors.WHITE, bold=True,
    )
    if record is not None:
        records = load_chain(record)
        if not records or records[0].kind != StepKind.DELEGATION:
            typer.secho(
                "[FAIL] --record chain must open with a DELEGATION genesis "
                "record; the nonce binds to it.", fg=typer.colors.RED, bold=True,
            )
            raise typer.Exit(code=1)
        genesis_hash = records[0].content_hash
        typer.echo(f"  Nonce binds to DELEGATION genesis {records[0].step_id}")
    else:
        genesis_hash = secrets.token_bytes(32).hex()
        typer.secho(
            "  No --record chain given: using an ephemeral genesis value. "
            "This attestation binds to no session.", fg=typer.colors.YELLOW,
        )

    provider: AttestationProvider | None
    config = GPUAttestationConfig(nras_url=nras_url, gpu_arch=gpu_arch)
    if fixture:
        simulated = FixtureNRAS()
        provider = simulated
        cert_target = fixture_cert_out if fixture_cert_out is not None else Path(
            "fixture-nras-cert.pem"
        )
        simulated.write_signing_certificate(cert_target)
        typer.secho("  Provider: simulated NRAS (fixture). NOT real hardware evidence.", fg=typer.colors.YELLOW)
        typer.echo(f"  Fixture signing certificate written to {cert_target}")
    else:
        provider = NRASClient(config)
        typer.echo(f"  Provider: NRAS at {nras_url}")

    try:
        attestation = attest_session(genesis_hash, config, provider=provider)
    except AttestationError as exc:
        typer.secho(f"\n[FAIL] {exc}", fg=typer.colors.RED, bold=True)
        raise typer.Exit(code=1) from exc

    typer.secho(f"  nonce:          {attestation.nonce}", fg=typer.colors.BRIGHT_BLACK)
    typer.secho(f"  gpu_arch:       {attestation.gpu_arch}", fg=typer.colors.BRIGHT_BLACK)
    typer.secho(f"  claims_version: {attestation.claims_version}", fg=typer.colors.BRIGHT_BLACK)
    typer.secho(f"  rim_matched:    {attestation.rim_matched}", fg=typer.colors.BRIGHT_BLACK)
    typer.secho(f"  device EATs:    {len(attestation.device_eats)}", fg=typer.colors.BRIGHT_BLACK)
    typer.echo(f"  detached EAT:\n{attestation.detached_eat}")

    if record is not None:
        records = load_chain(record)
        signer = Signer.from_env()
        signer._prev_hash = records[-1].content_hash
        appended = signer.sign(
            kind=StepKind.GPU_ATTESTATION,
            payload={"attestation": attestation},
        )
        FileTransport(record).emit(appended)
        typer.secho(f"\nGPU_ATTESTATION record appended to {record}.", fg=typer.colors.GREEN, bold=True)
        typer.echo(f"Verify with: air verify-public {record} --attestation offline")
