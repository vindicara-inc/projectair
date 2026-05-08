"""``air handoff`` CLI subcommand group (Layer 4).

Wave 1 ships ``air handoff verify`` only; the full suite (trace, graph,
emit-test, validate-proof, rekor-queue) ships incrementally per the spec
Section 9.1.

The verifier needs three inputs to run:

    1. The chain JSONL files (``--chain``, repeatable).
    2. An identity manifest mapping each agent's ``identity_certificate_hash``
       to its raw Ed25519 public key in base64 (``--identity-manifest``).
       Wave 1 does not consult Sigstore Fulcio; the manifest is the
       operator's vouching list of legitimate agent identities.
    3. One or more IdP descriptors (``--idp``, repeatable) so the
       AdapterRouter can route the capability token's ``iss`` claim to a
       verifier-only Auth0Adapter that fetches JWKS via OIDC Discovery.

The CLI does not silently fall back to OIDC Discovery against unknown
issuers. Operators must register every issuer they intend to trust.
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from typing import Annotated

import typer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from airsdk.handoff.exceptions import HandoffError
from airsdk.handoff.idp.auth0 import Auth0Adapter
from airsdk.handoff.idp.base import AdapterRouter, IdPAdapter
from airsdk.handoff.verifier import ChainSet, CrossAgentVerifier

handoff_app = typer.Typer(
    name="handoff",
    help="AgDR Handoff Protocol (Layer 4) operations.",
    no_args_is_help=True,
    add_completion=False,
)


def _parse_idp_spec(spec: str) -> IdPAdapter:
    """Parse a ``--idp`` value of the form ``issuer=URL;jwks=URL;audience=AUD``."""
    parts: dict[str, str] = {}
    for chunk in spec.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "=" not in chunk:
            raise typer.BadParameter(
                f"--idp segment {chunk!r} must be key=value (issuer=...;jwks=...;audience=...)"
            )
        k, v = chunk.split("=", 1)
        parts[k.strip()] = v.strip()
    issuer = parts.get("issuer")
    jwks = parts.get("jwks") or parts.get("jwks_uri")
    audience = parts.get("audience") or parts.get("aud")
    if not issuer or not jwks or not audience:
        raise typer.BadParameter(
            "--idp must include issuer=, jwks=, and audience= "
            f"(got keys: {sorted(parts)})"
        )
    return Auth0Adapter(
        domain=parts.get("domain") or issuer.removeprefix("https://").rstrip("/"),
        audience=audience,
        issuer=issuer,
        jwks_uri=jwks,
        verify_only=True,
    )


def _load_identity_manifest(path: Path) -> dict[str, Ed25519PublicKey]:
    """Load a JSON map ``{cert_hash: <base64 raw 32-byte pubkey>}``."""
    raw = json.loads(path.read_text())
    if not isinstance(raw, dict):
        raise typer.BadParameter(
            "identity manifest must be a JSON object mapping cert_hash to base64 pubkey"
        )
    out: dict[str, Ed25519PublicKey] = {}
    for cert_hash, b64 in raw.items():
        if not isinstance(cert_hash, str) or not isinstance(b64, str):
            raise typer.BadParameter(
                "identity manifest entries must map string -> string"
            )
        try:
            pk_bytes = base64.b64decode(b64, validate=True)
        except Exception as e:
            raise typer.BadParameter(
                f"identity manifest entry for {cert_hash!r} is not valid base64: {e}"
            ) from e
        if len(pk_bytes) != 32:
            raise typer.BadParameter(
                f"Ed25519 public key for {cert_hash!r} must be 32 raw bytes; "
                f"got {len(pk_bytes)}"
            )
        out[cert_hash] = Ed25519PublicKey.from_public_bytes(pk_bytes)
    return out


@handoff_app.command("verify")
def verify(
    ptid: Annotated[
        str,
        typer.Option("--ptid", help="Parent Trace ID (32 lowercase hex)."),
    ],
    chain: Annotated[
        list[Path],
        typer.Option(
            "--chain",
            help="Path to a chain JSON Lines file. Repeatable.",
            exists=True,
            readable=True,
        ),
    ],
    identity_manifest: Annotated[
        Path,
        typer.Option(
            "--identity-manifest",
            help=(
                "JSON file mapping each cert_hash to its base64-encoded "
                "raw Ed25519 public key. Required for signature checks."
            ),
            exists=True,
            readable=True,
        ),
    ],
    idp: Annotated[
        list[str] | None,
        typer.Option(
            "--idp",
            help=(
                "IdP descriptor of the form "
                "'issuer=URL;jwks=URL;audience=AUD'. Repeatable."
            ),
        ),
    ] = None,
    skew_tolerance_seconds: Annotated[
        int,
        typer.Option("--skew", help="Clock-skew tolerance for temporal ordering."),
    ] = 5,
) -> None:
    """Verify a cross-agent chain set by Parent Trace ID."""
    typer.echo(f"verifying {len(chain)} chain(s) for PTID {ptid}")
    pubkeys = _load_identity_manifest(identity_manifest)
    typer.echo(f"  identities loaded: {len(pubkeys)}")

    router = AdapterRouter()
    for spec in idp or []:
        adapter = _parse_idp_spec(spec)
        router.register(adapter)
    typer.echo(f"  IdP adapters     : {len(router.issuers())}")

    chain_set = ChainSet.from_paths(chain)
    verifier = CrossAgentVerifier(
        adapter_router=router,
        skew_tolerance_seconds=skew_tolerance_seconds,
        identity_pubkeys=pubkeys,
    )
    try:
        result = verifier.verify_chain_set(chain_set, parent_trace_id=ptid)
    except HandoffError as e:
        typer.secho(f"VERIFICATION FAILED: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from e
    for flag in result.flags:
        typer.secho(f"  flag: {flag}", fg=typer.colors.YELLOW)
    if not result.passed:
        for d in result.diagnostics:
            typer.secho(f"  fail: {d}", fg=typer.colors.RED, err=True)
        typer.secho("VERIFICATION FAILED", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    typer.secho(
        f"CROSS-AGENT CHAIN VERIFIED ({result.handoffs} handoff/"
        f"{result.acceptances} acceptance across {result.chains_examined} chain(s))",
        fg=typer.colors.GREEN,
    )


def register(app: typer.Typer) -> None:
    """Wire the ``handoff`` subcommand group onto the parent ``air`` app."""
    app.add_typer(handoff_app, name="handoff")


def main() -> None:
    """Standalone entry for ``python -m projectair.handoff_cli``."""
    handoff_app()
    sys.exit(0)


if __name__ == "__main__":
    main()
