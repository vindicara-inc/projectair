"""CLI commands for Layer 1 anchoring.

Exposes ``air anchor``, ``air verify``, and ``air verify-public``. The
commands are registered against the main Typer app from ``cli.py``.
"""
from __future__ import annotations

from pathlib import Path

import typer

from airsdk import __version__ as airsdk_version
from airsdk.agdr import Signer, load_chain, verify_chain
from airsdk.anchoring import (
    AnchoringOrchestrator,
    AnchoringPolicy,
    RekorClient,
    RFC3161Client,
    load_anchoring_key,
)
from airsdk.anchoring.rekor import DEFAULT_REKOR_URL
from airsdk.anchoring.rfc3161 import DEFAULT_TSA_URL
from airsdk.transport import FileTransport
from airsdk.types import StepKind, VerificationStatus


def register(app: typer.Typer) -> None:
    """Attach the anchoring commands to ``app``."""
    app.command(name="anchor")(anchor_cmd)
    app.command(name="verify")(verify_cmd)
    app.command(name="verify-public")(verify_public_cmd)


def anchor_cmd(
    chain: Path = typer.Argument(..., exists=True, dir_okay=False, help="Chain JSONL file."),
    tsa_url: str = typer.Option(DEFAULT_TSA_URL, "--tsa-url", help="RFC 3161 TSA endpoint."),
    rekor_url: str = typer.Option(DEFAULT_REKOR_URL, "--rekor-url", help="Sigstore Rekor base URL."),
    no_tsa: bool = typer.Option(False, "--no-tsa", help="Skip RFC 3161 anchoring."),
    no_rekor: bool = typer.Option(False, "--no-rekor", help="Skip Sigstore Rekor anchoring."),
) -> None:
    """Force-emit an anchor record covering the unanchored tail of ``chain``."""
    typer.secho(f"[AIR v{airsdk_version}] Anchoring {chain}", fg=typer.colors.WHITE, bold=True)
    records = load_chain(chain)
    if not records:
        typer.secho("Chain is empty; nothing to anchor.", fg=typer.colors.YELLOW)
        raise typer.Exit(code=0)

    anchoring_key = load_anchoring_key()
    rfc3161 = None if no_tsa else RFC3161Client(tsa_url=tsa_url)
    rekor = None if no_rekor else RekorClient(signing_key=anchoring_key, rekor_url=rekor_url)

    # Resume the chain by seeding the signer's prev_hash to the tail. We
    # also need a chain-signer key; in the OSS path we generate a fresh
    # key and append the anchor with it. Auditors trace the anchor
    # signer separately from prior step signers, which is correct.
    signer = Signer.from_env()
    signer._prev_hash = records[-1].content_hash

    transport = FileTransport(chain)
    orchestrator = AnchoringOrchestrator(
        signer=signer,
        transports=[transport],
        rfc3161_client=rfc3161,
        rekor_client=rekor,
        policy=AnchoringPolicy(rfc3161_enabled=not no_tsa, rekor_enabled=not no_rekor),
    )
    orchestrator.hydrate_from_chain(records)
    anchor_record = orchestrator.emit_anchor_now()
    if anchor_record is None:
        typer.secho("No unanchored steps to anchor (chain is up to date).", fg=typer.colors.GREEN)
        return

    payload = anchor_record.payload
    typer.secho(f"  chain root:   {payload.anchored_chain_root}", fg=typer.colors.BRIGHT_BLACK)
    if payload.rfc3161:
        typer.secho(f"  RFC 3161:     OK at {payload.rfc3161.timestamp_iso}", fg=typer.colors.GREEN)
    if payload.rekor:
        typer.secho(f"  Rekor:        OK log_index={payload.rekor.log_index}", fg=typer.colors.GREEN)
    typer.secho(f"\nAnchor appended to {chain}.", fg=typer.colors.WHITE, bold=True)
    typer.echo(f"Verify with: air verify-public {chain}")


def verify_cmd(
    chain: Path = typer.Argument(..., exists=True, dir_okay=False, help="Chain JSONL file."),
    check_anchors: bool = typer.Option(False, "--check-anchors", help="Also verify embedded anchors."),
) -> None:
    """Verify chain integrity. ``--check-anchors`` also re-verifies anchors."""
    typer.secho(f"[AIR v{airsdk_version}] Verifying {chain}", fg=typer.colors.WHITE, bold=True)
    records = load_chain(chain)
    typer.echo(f"  Steps:         {sum(1 for r in records if r.kind != StepKind.ANCHOR)}")
    typer.echo(f"  Anchor records: {sum(1 for r in records if r.kind == StepKind.ANCHOR)}")

    chain_result = verify_chain(records)
    if chain_result.status != VerificationStatus.OK:
        typer.secho(f"\n[FAIL] {chain_result.reason}", fg=typer.colors.RED, bold=True)
        raise typer.Exit(code=1)
    typer.secho(f"  Signatures + chain links: OK ({chain_result.records_verified} records)", fg=typer.colors.GREEN)

    if check_anchors:
        ok = _verify_anchors(records)
        if not ok:
            raise typer.Exit(code=1)
    typer.secho("\nCHAIN VERIFIED.", fg=typer.colors.GREEN, bold=True)


def verify_public_cmd(
    chain: Path = typer.Argument(..., exists=True, dir_okay=False, help="Chain JSONL file."),
) -> None:
    """Verify a chain using only public infrastructure (no Vindicara calls)."""
    typer.secho(f"[AIR v{airsdk_version}] Public verification of {chain}", fg=typer.colors.WHITE, bold=True)
    typer.secho("  Using only TSA roots bundled with the SDK and the public Sigstore Rekor.", fg=typer.colors.BRIGHT_BLACK)
    records = load_chain(chain)
    chain_result = verify_chain(records)
    if chain_result.status != VerificationStatus.OK:
        typer.secho(f"\n[FAIL] {chain_result.reason}", fg=typer.colors.RED, bold=True)
        raise typer.Exit(code=1)
    typer.secho(f"  Signatures + chain links: OK ({chain_result.records_verified} records)", fg=typer.colors.GREEN)
    if not _verify_anchors(records):
        raise typer.Exit(code=1)
    typer.secho("\nCHAIN VERIFIED with public infrastructure.", fg=typer.colors.GREEN, bold=True)
    typer.echo("This chain is independently verifiable. No Vindicara API call was made.")


def _verify_anchors(records: list) -> bool:  # type: ignore[type-arg]
    anchors = [r for r in records if r.kind == StepKind.ANCHOR]
    if not anchors:
        typer.secho("  No anchor records on this chain.", fg=typer.colors.YELLOW)
        typer.echo("  Run `air anchor <chain>` to add an external anchor.")
        return True
    rfc3161 = RFC3161Client()
    ok_3161 = 0
    ok_rekor = 0
    for anchor in anchors:
        chain_root_hex = anchor.payload.anchored_chain_root
        if chain_root_hex is None:
            typer.secho("  [FAIL] anchor record missing anchored_chain_root", fg=typer.colors.RED)
            return False
        chain_root_bytes = bytes.fromhex(chain_root_hex)
        if anchor.payload.rfc3161 is not None:
            try:
                rfc3161.verify(anchor.payload.rfc3161, chain_root_bytes)
                ok_3161 += 1
            except Exception as exc:
                typer.secho(f"  [FAIL] RFC 3161 verify: {exc}", fg=typer.colors.RED)
                return False
        if anchor.payload.rekor is not None:
            try:
                _verify_rekor_offline(anchor.payload.rekor, chain_root_bytes)
                ok_rekor += 1
            except Exception as exc:
                typer.secho(f"  [FAIL] Rekor verify: {exc}", fg=typer.colors.RED)
                return False
    typer.secho(
        f"  RFC 3161 anchors verified: {ok_3161}/{sum(1 for a in anchors if a.payload.rfc3161)}",
        fg=typer.colors.GREEN,
    )
    typer.secho(
        f"  Rekor anchors verified:    {ok_rekor}/{sum(1 for a in anchors if a.payload.rekor)}",
        fg=typer.colors.GREEN,
    )
    return True


def _verify_rekor_offline(anchor: object, chain_root: bytes) -> None:
    from hashlib import sha256

    digest = sha256(chain_root).digest()
    # Build a transient RekorClient just to call its verify() helper. The
    # signing key is irrelevant for verification (we only inspect the
    # stored proof). The placeholder key is never used.
    placeholder = Signer.generate()
    client = RekorClient(signing_key=placeholder._priv, rekor_url=anchor.rekor_url)  # type: ignore[attr-defined]
    client.verify(anchor, digest)  # type: ignore[arg-type]
