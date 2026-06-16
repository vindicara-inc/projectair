"""CLI commands for Delegated Authority.

Exposes:
    air authorize          run the human ceremony, write a DELEGATION genesis record
    air verify-delegation  run SV-AUTH over a chain and report human coverage

The thesis: no agent is autonomous. ``air authorize`` binds an entire session
to the authenticated human who authorized it; ``air verify-delegation`` proves
(or disproves) that a chain is covered by valid, unexpired delegated authority.
"""
from __future__ import annotations

import os
from pathlib import Path

import blake3
import typer

from airsdk import __version__ as airsdk_version
from airsdk.agdr import load_chain
from airsdk.containment import Auth0Verifier
from airsdk.recorder import AIRRecorder
from airsdk.types import DelegationGrant, IntentSpec
from airsdk.verification.checks.delegation import check_delegation
from airsdk.verification.types import Violation


def register(app: typer.Typer) -> None:
    app.command(name="authorize")(authorize_cmd)
    app.command(name="verify-delegation")(verify_delegation_cmd)


def authorize_cmd(
    agent: str = typer.Option(..., "--agent", help="Agent id being authorized, e.g. claims-bot."),
    policy: str = typer.Option(..., "--policy", help="Policy id, e.g. hipaa-claims-v3."),
    goal: str = typer.Option(..., "--goal", help="The scope goal the human authorizes."),
    out: Path = typer.Option(Path("chain.jsonl"), "--out", help="Chain file to start."),
    allowed_tools: str = typer.Option("", "--allowed-tools", help="Comma-separated allowed tools."),
    allowed_paths: str = typer.Option("", "--allowed-paths", help="Comma-separated allowed paths."),
    allowed_network: str = typer.Option("", "--allowed-network", help="Comma-separated allowed hosts."),
    ttl: int = typer.Option(3600, "--ttl", help="Grant lifetime in seconds."),
    auth: str = typer.Option("auth0", "--auth", help="auth0 | webauthn."),
    token: str | None = typer.Option(
        None,
        "--token",
        help="Auth0 passkey token (id/access JWT). Supply directly when not using the interactive flow.",
    ),
    policy_file: Path | None = typer.Option(
        None,
        "--policy-file",
        help="Path to the versioned ruleset document; its bytes are hashed into the grant. "
        "Falls back to hashing the policy id when omitted.",
    ),
) -> None:
    """Authorize an agent deployment with a human passkey, write the genesis record."""
    typer.secho(
        f"[AIR v{airsdk_version}] Delegated Authority (beta)",
        fg=typer.colors.WHITE,
        bold=True,
    )

    scope = IntentSpec(
        goal=goal,
        allowed_tools=_split(allowed_tools),
        allowed_paths=_split(allowed_paths),
        allowed_network=_split(allowed_network),
    )
    policy_hash = _policy_hash(policy, policy_file)

    if auth == "auth0":
        grant = _mint_auth0_grant(
            agent=agent, policy=policy, policy_hash=policy_hash, scope=scope, ttl=ttl, token=token
        )
    elif auth == "webauthn":
        raise typer.BadParameter(
            "native WebAuthn authorization runs through the ceremony server "
            "(airsdk.delegation.webauthn + the reference FastAPI app). Deploy it "
            "at an origin you control and authorize from the browser; the CLI "
            "auth0 path is the fast path for terminals."
        )
    else:
        raise typer.BadParameter(f"unknown --auth {auth!r}; expected 'auth0' or 'webauthn'")

    recorder = AIRRecorder(out)  # no intent_spec=, so the delegation is the genesis
    record = recorder.open_delegation(grant)

    typer.echo()
    typer.secho(
        f"  Authorized {agent} under {policy} by {grant.authorizer_email or grant.authorizer_sub}",
        fg=typer.colors.GREEN,
        bold=True,
    )
    typer.secho(f"    delegation_id {grant.delegation_id}", fg=typer.colors.BRIGHT_BLACK)
    typer.secho(f"    genesis step  {record.step_id}", fg=typer.colors.BRIGHT_BLACK)
    typer.secho(f"    chain         {out}", fg=typer.colors.BRIGHT_BLACK)


def verify_delegation_cmd(
    chain: Path = typer.Argument(..., exists=True, dir_okay=False, help="AgDR chain JSONL."),
) -> None:
    """Check that a session is covered by a valid, unexpired human delegation."""
    typer.secho(
        f"[AIR v{airsdk_version}] Delegation coverage (SV-AUTH)",
        fg=typer.colors.WHITE,
        bold=True,
    )
    typer.secho(f"  Chain: {chain}", fg=typer.colors.BRIGHT_BLACK)
    typer.echo()

    records = load_chain(chain)
    violations = check_delegation(records)

    if not violations:
        genesis = records[0]
        grant = genesis.payload.delegation
        who = (grant.authorizer_email or grant.authorizer_sub) if grant else "unknown"
        policy_id = grant.policy_id if grant else "?"
        typer.secho(f"  COVERED: authorized by {who} under {policy_id}", fg=typer.colors.GREEN, bold=True)
        raise typer.Exit(code=0)

    typer.secho(f"  UNCOVERED: {len(violations)} delegation finding(s)", fg=typer.colors.RED, bold=True)
    typer.echo()
    for v in violations:
        _render_violation(v)
    raise typer.Exit(code=1)


def _mint_auth0_grant(
    *, agent: str, policy: str, policy_hash: str, scope: IntentSpec, ttl: int, token: str | None
) -> DelegationGrant:
    from airsdk.delegation.auth0_passkey import mint_grant_from_auth0

    if token is None:
        raise typer.BadParameter(
            "no Auth0 token supplied. Complete the passkey login against your "
            "tenant and pass the resulting JWT with --token. The interactive "
            "authorization-code-with-PKCE flow is the days 3-5 milestone; the "
            "--token path is live now and is what the SDK form uses."
        )

    verifier = _verifier_from_env()
    try:
        return mint_grant_from_auth0(
            token=token,
            verifier=verifier,
            agent_id=agent,
            policy_id=policy,
            policy_hash=policy_hash,
            scope=scope,
            ttl_seconds=ttl,
        )
    except Exception as exc:  # surface any token-verification failure as a clean CLI error
        typer.secho(f"  Token rejected: {exc}", fg=typer.colors.RED, bold=True)
        raise typer.Exit(code=1) from exc


def _verifier_from_env() -> Auth0Verifier:
    issuer = os.environ.get("AIR_AUTH0_ISSUER")
    domain = os.environ.get("AIR_AUTH0_DOMAIN")
    audience = os.environ.get("AIR_AUTH0_AUDIENCE")
    if issuer is None and domain is not None:
        issuer = f"https://{domain}/"
    if not issuer or not audience:
        raise typer.BadParameter(
            "set AIR_AUTH0_ISSUER (or AIR_AUTH0_DOMAIN) and AIR_AUTH0_AUDIENCE "
            "so the token can be verified against your tenant's JWKS."
        )
    return Auth0Verifier(issuer=issuer, audience=audience)


def _policy_hash(policy_id: str, policy_file: Path | None) -> str:
    """Hash the ruleset document so the grant binds to the exact policy in force.

    Hashes the file bytes when ``policy_file`` is given; otherwise hashes the
    policy id as a stable placeholder so the grant still carries a deterministic
    digest.
    """
    if policy_file is not None:
        return blake3.blake3(policy_file.read_bytes()).hexdigest()
    return blake3.blake3(policy_id.encode()).hexdigest()


def _split(s: str) -> list[str]:
    return [x.strip() for x in s.split(",") if x.strip()]


def _severity_color(severity: str) -> str:
    return {
        "critical": typer.colors.RED,
        "high": typer.colors.YELLOW,
        "medium": typer.colors.CYAN,
    }.get(severity, typer.colors.WHITE)


def _render_violation(v: Violation) -> None:
    typer.secho(f"  [{v.severity.upper()}] {v.check_id}: {v.title}", fg=_severity_color(v.severity), bold=True)
    typer.secho(f"    Step:     #{v.step_index}", fg=typer.colors.WHITE)
    typer.secho(f"    Actual:   {v.actual}", fg=typer.colors.BRIGHT_BLACK)
    typer.echo()
