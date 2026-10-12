"""First-run email capture for Project AIR (Free tier).

Project AIR is free. The first time a product command runs, the CLI asks where
to send the results: it captures an email, stores it in ``config.toml``
(``identity.email``), and registers it with the Vindicara API so the scan
results can be delivered. Subsequent runs are silent.

Non-interactive use (CI, scripts) supplies the email up front via the
``AIR_EMAIL`` environment variable or ``air config set identity.email <addr>``;
otherwise the command exits with a clear message rather than hanging on a prompt.

The gate is intentionally enforced for every command except ``config`` (so the
email can always be set non-interactively as the escape hatch) and any
invocation that asks for ``--help``: reading the docs never requires an email.
"""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING

import typer
from typer.core import TyperGroup

from projectair.config import config_dir, get_config, set_config

if TYPE_CHECKING:  # pragma: no cover - typing only
    # Typer >=0.2x vendors Click; annotations are strings, so older Typer
    # releases running on upstream Click never import this.
    from typer._click.core import Context

# Same Vindicara API origin the update checker uses (single source of truth).
_REGISTER_URL = "https://cloud.vindicara.io/v1/identity/register"
_REGISTERED_MARKER = "registered"
# ``ctx.meta`` key set by :class:`IdentityGatedGroup`, read by the root callback.
HELP_REQUESTED = "air.help_requested"
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _valid_email(email: str) -> bool:
    return bool(_EMAIL_RE.match(email.strip()))


def stored_email() -> str | None:
    """Resolve the activation email: AIR_EMAIL env wins, else config.toml."""
    env = (os.environ.get("AIR_EMAIL") or "").strip()
    if env:
        return env
    return get_config("identity", "email")


def _marker_path() -> Path:
    return config_dir() / _REGISTERED_MARKER


def _register(email: str) -> bool:
    """Best-effort POST of the email to the Vindicara API. Never raises."""
    from projectair import __version__

    payload = json.dumps(
        {
            "email": email,
            "source": "first_run",
            "version": __version__,
            "platform": sys.platform,
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        _REGISTER_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            status: int = resp.status
            return 200 <= status < 300
    except Exception:
        return False


def _persist_registration(email: str) -> None:
    """Record the email locally and register it once (marker prevents re-POST)."""
    if _register(email):
        try:
            _marker_path().parent.mkdir(parents=True, exist_ok=True)
            _marker_path().touch(exist_ok=True)
        except OSError:
            pass


class IdentityGatedGroup(TyperGroup):
    """Root group that notes whether help was asked for anywhere on the line.

    Click hands the arguments to the subcommand before the root callback runs,
    so the callback cannot see ``air hl7 --help``; this records it first.
    """

    def invoke(self, ctx: Context) -> object:
        # Click >=8.2 keeps the unparsed subcommand words in ``_protected_args``;
        # 8.1 named it ``protected_args``.
        protected: list[str] | None = getattr(ctx, "_protected_args", None)
        if protected is None:
            protected = getattr(ctx, "protected_args", [])
        args = [*protected, *ctx.args]
        ctx.meta[HELP_REQUESTED] = any(arg in ctx.help_option_names for arg in args)
        return super().invoke(ctx)


def ensure_identity() -> None:
    """Enforce the activation email. Prompt interactively or fail closed.

    Raises ``typer.Exit(2)`` in non-interactive sessions with no email so a
    script fails loudly with remediation instead of hanging on a prompt.
    """
    email = stored_email()
    if email and _valid_email(email):
        if not _marker_path().exists():
            _persist_registration(email)
        return

    interactive = sys.stdin.isatty() and sys.stdout.isatty()
    if not interactive:
        typer.secho(
            "Project AIR needs an email to send your results to.",
            fg=typer.colors.RED,
            err=True,
        )
        typer.secho("  Set it:   air config set identity.email you@example.com", err=True)
        typer.secho("  Or in CI: AIR_EMAIL=you@example.com air <command>", err=True)
        raise typer.Exit(2)

    typer.secho("Where should we send your results?", fg=typer.colors.BRIGHT_WHITE, bold=True)
    typer.echo("  Run the scan and we'll email you the results when it's done. Free, no spam.")
    while True:
        entered = typer.prompt("  Email").strip()
        if _valid_email(entered):
            break
        typer.secho("  That doesn't look like an email address. Try again.", fg=typer.colors.RED)

    set_config("identity", "email", entered)
    _persist_registration(entered)
    typer.secho(f"  Thanks, your results will go to {entered}.", fg=typer.colors.GREEN)
    typer.echo()


__all__ = ["HELP_REQUESTED", "IdentityGatedGroup", "ensure_identity", "stored_email"]
