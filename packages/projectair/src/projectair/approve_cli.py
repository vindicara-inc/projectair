"""CLI command for Layer 3 step-up approval against an Auth0 tenant.

Three modes, picked by flag combination:

- ``--token <jwt>``: caller already has a verified Auth0 access token
  (e.g. from a custom approval router). Submit it directly.
- ``--device``: run the OAuth 2.0 Device Authorization Grant. CLI prints
  a user code + verification URL; operator authenticates on their phone
  or laptop; CLI polls Auth0's token endpoint and submits the resulting
  token automatically.
- ``--authorize-url``: just print the Auth0 ``/authorize`` URL for a
  browser-based flow. The receiving service swaps the code for a token
  and submits it via ``--token`` later.

All three end at the same point: ``recorder.approve(challenge_id, token)``
verifies the token and unblocks the halted action on the chain.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import typer

from airsdk import __version__ as airsdk_version
from airsdk.containment import (
    ApprovalInvalidError,
    Auth0DeviceFlowError,
    Auth0Tenant,
    Auth0Verifier,
    build_authorize_url,
    make_pkce_pair,
    poll_device_token,
    start_device_flow,
)
from airsdk.recorder import AIRRecorder


def register(app: typer.Typer) -> None:
    """Attach the approve command to ``app``."""
    app.command(name="approve")(approve_cmd)


def approve_cmd(
    chain: Path = typer.Option(..., "--chain", exists=True, dir_okay=False, help="Chain JSONL file."),
    challenge_id: str = typer.Option(..., "--challenge-id", help="Challenge id from the StepUpRequiredError."),
    tenant_domain: str = typer.Option(..., "--tenant", help="Auth0 tenant domain, e.g. example.us.auth0.com."),
    audience: str = typer.Option(..., "--audience", help="Auth0 API identifier the token is for."),
    client_id: str | None = typer.Option(None, "--client-id", help="Auth0 application client id (required for --device or --authorize-url)."),
    token: str | None = typer.Option(None, "--token", help="Pre-obtained Auth0 access token (mode A)."),
    use_device: bool = typer.Option(False, "--device", help="Run the OAuth 2.0 Device Authorization Grant (mode B)."),
    print_authorize_url: bool = typer.Option(False, "--authorize-url", help="Print an Auth0 /authorize URL for browser flow (mode C)."),
    redirect_uri: str = typer.Option("", "--redirect-uri", help="Required with --authorize-url."),
    scope: str = typer.Option("openid email profile", "--scope", help="OAuth scope; default 'openid email profile'."),
    poll_timeout_seconds: float = typer.Option(300.0, "--poll-timeout", help="Max seconds to poll the token endpoint in --device mode."),
    jwks_uri: str | None = typer.Option(None, "--jwks-uri", help="Override the JWKS URI used for token verification (defaults to https://<tenant>/.well-known/jwks.json). Use for testing against a local IdP."),
    issuer: str | None = typer.Option(None, "--issuer", help="Override the expected issuer claim (defaults to https://<tenant>/). Use for testing."),
) -> None:
    """Submit a Layer 3 step-up approval to a halted chain."""
    modes = [token is not None, use_device, print_authorize_url]
    if sum(modes) != 1:
        typer.secho(
            "Pick exactly one of --token, --device, or --authorize-url",
            fg=typer.colors.RED,
        )
        raise typer.Exit(code=2)

    tenant = Auth0Tenant(
        domain=tenant_domain,
        audience=audience,
        client_id=client_id,
        scope=scope,
    )

    if print_authorize_url:
        if redirect_uri == "":
            typer.secho("--authorize-url requires --redirect-uri", fg=typer.colors.RED)
            raise typer.Exit(code=2)
        if client_id is None:
            typer.secho("--authorize-url requires --client-id", fg=typer.colors.RED)
            raise typer.Exit(code=2)
        verifier_str, challenge_str = make_pkce_pair()
        url = build_authorize_url(
            tenant,
            challenge_id=challenge_id,
            redirect_uri=redirect_uri,
            code_challenge=challenge_str,
        )
        typer.secho(f"\n[AIR v{airsdk_version}] Authorize URL:", fg=typer.colors.WHITE, bold=True)
        typer.echo(f"\n  {url}\n")
        typer.secho("PKCE code_verifier (use when exchanging the code):", fg=typer.colors.BRIGHT_BLACK)
        typer.echo(f"  {verifier_str}")
        typer.secho(
            "\nAfter the operator authenticates and your service swaps the code for a token, "
            "re-run with --token <jwt> to submit the approval.",
            fg=typer.colors.BRIGHT_BLACK,
        )
        return

    if use_device:
        if client_id is None:
            typer.secho("--device requires --client-id", fg=typer.colors.RED)
            raise typer.Exit(code=2)
        token = _run_device_flow(tenant, poll_timeout_seconds)

    assert token is not None
    _submit_approval(chain, challenge_id, tenant, token, jwks_uri=jwks_uri, issuer=issuer)


def _run_device_flow(tenant: Auth0Tenant, poll_timeout_seconds: float) -> str:
    typer.secho(
        f"\n[AIR v{airsdk_version}] Starting OAuth 2.0 Device Authorization Grant",
        fg=typer.colors.WHITE,
        bold=True,
    )
    typer.secho(f"  Auth0 tenant: {tenant.domain}", fg=typer.colors.BRIGHT_BLACK)
    auth = start_device_flow(tenant)
    typer.echo("")
    typer.secho("On any device, open:", fg=typer.colors.BRIGHT_WHITE)
    typer.secho(f"  {auth.verification_uri}", fg=typer.colors.CYAN, bold=True)
    typer.secho("And enter user code:", fg=typer.colors.BRIGHT_WHITE)
    typer.secho(f"  {auth.user_code}", fg=typer.colors.YELLOW, bold=True)
    typer.echo("")
    typer.secho(
        f"  (or open this URL directly to skip the user-code prompt:\n  {auth.verification_uri_complete})",
        fg=typer.colors.BRIGHT_BLACK,
    )
    typer.echo("")
    typer.secho(
        f"Polling for approval (timeout {poll_timeout_seconds:.0f}s)...",
        fg=typer.colors.BRIGHT_BLACK,
    )
    start = time.monotonic()
    try:
        token = poll_device_token(
            tenant,
            auth.device_code,
            interval=auth.interval,
            max_poll_seconds=poll_timeout_seconds,
        )
    except Auth0DeviceFlowError as exc:
        typer.secho(f"\n  Device flow failed: {exc}", fg=typer.colors.RED, bold=True)
        raise typer.Exit(code=1) from exc
    elapsed = time.monotonic() - start
    typer.secho(f"  Approved (after {elapsed:.1f}s).", fg=typer.colors.GREEN)
    return token


def _submit_approval(
    chain: Path,
    challenge_id: str,
    tenant: Auth0Tenant,
    token: str,
    *,
    jwks_uri: str | None = None,
    issuer: str | None = None,
) -> None:
    typer.secho(
        f"\n[AIR v{airsdk_version}] Submitting approval for challenge {challenge_id}",
        fg=typer.colors.WHITE,
        bold=True,
    )
    verifier = Auth0Verifier(
        issuer=issuer or tenant.issuer,
        audience=tenant.audience,
        jwks_uri=jwks_uri,
    )
    # NOTE: AIRRecorder.approve resumes the halted action by re-emitting
    # the original tool_start. ``air approve`` invoked from the CLI is
    # the operator path, distinct from the agent-process path. The
    # operator's recorder cannot resume the agent's action directly;
    # what it CAN do is record the HUMAN_APPROVAL on the chain so the
    # agent (when it next polls or is restarted) sees the approval and
    # proceeds. v1: we still record the approval to the chain via a
    # locally-constructed recorder pointed at the same log file. The
    # chain captures the verified human decision; agents that already
    # raised StepUpRequiredError pick up the approval on next start.
    recorder = AIRRecorder(chain, auth0_verifier=verifier)
    # No pending challenge in this process, so ``approve`` would refuse.
    # For the CLI path we verify the token directly, append a
    # HUMAN_APPROVAL record, and let the calling process resume.
    try:
        claims = verifier.verify(token)
    except ApprovalInvalidError as exc:
        typer.secho(f"  Token verification failed: {exc}", fg=typer.colors.RED, bold=True)
        raise typer.Exit(code=1) from exc

    _append_human_approval(recorder, challenge_id, token, claims)
    typer.secho(
        f"  Verified token from {claims.email or claims.sub} ({claims.issuer})",
        fg=typer.colors.GREEN,
    )
    typer.secho(
        f"  HUMAN_APPROVAL appended to {chain}",
        fg=typer.colors.GREEN,
    )


def _append_human_approval(
    recorder: AIRRecorder,
    challenge_id: str,
    token: str,
    claims: object,  # Auth0Claims, but avoid a forward import dance for typer
) -> None:
    """Append a HUMAN_APPROVAL record without consuming a pending challenge.

    The CLI flow runs in a different process from the agent that raised
    StepUpRequiredError; only the chain on disk is shared. We bypass
    ``recorder.approve``'s pending-challenge check and write the
    approval record directly via the internal ``_emit`` so the agent
    process can pick up the approval on its next chain reload.
    """
    from airsdk.types import HumanApproval, StepKind

    auth0_claims = claims  # Auth0Claims
    approval = HumanApproval(
        challenge_id=challenge_id,
        decision="approve",
        approver_sub=auth0_claims.sub,  # type: ignore[attr-defined]
        approver_email=auth0_claims.email,  # type: ignore[attr-defined]
        issuer=auth0_claims.issuer,  # type: ignore[attr-defined]
        audience=auth0_claims.audience,  # type: ignore[attr-defined]
        token_jti=auth0_claims.jti,  # type: ignore[attr-defined]
        issued_at=auth0_claims.issued_at,  # type: ignore[attr-defined]
        expires_at=auth0_claims.expires_at,  # type: ignore[attr-defined]
        signed_token=token,
    )
    recorder._emit(
        StepKind.HUMAN_APPROVAL,
        {"challenge_id": challenge_id, "human_approval": approval},
    )
    sys.stdout.flush()
