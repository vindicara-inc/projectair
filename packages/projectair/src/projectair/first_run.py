"""First-run email prompt for the ``air`` CLI.

Triggers once, on first ``air demo`` or ``air trace``, when:

1. No session file exists (user has not run ``air login``).
2. No ``~/.config/projectair/prompted`` marker file exists.
3. stdin is a TTY (not CI / piped).

Prompts the user to opt in to security advisories and an automatic update
check. Failures during the POST registration call are silently ignored so
the user is never blocked.
"""
from __future__ import annotations

import sys

from projectair.config import (
    get_config,
    has_been_prompted,
    load_session,
    mark_prompted,
    set_config,
)

_REGISTER_URL = "https://api.vindicara.io/api/v1/identity/register"


def maybe_prompt_first_run() -> None:
    """Trigger the first-run prompt if conditions are met.

    Conditions (all must hold):
    - ``prompted`` marker does not exist.
    - No session file exists (user is not logged in).
    - stdin is a TTY.

    When stdin is not a TTY, the marker is created silently so the prompt
    never surfaces in CI or piped environments.
    """
    if has_been_prompted():
        return
    if load_session() is not None:
        return
    if not sys.stdin.isatty():
        mark_prompted()
        return
    _do_prompt()


def _do_prompt() -> None:
    """Render the interactive first-run prompt and persist user choices."""
    print()
    print("  Want security advisories and release notes for Project AIR?")
    raw_email = input("  Email (or press Enter to skip): ").strip()

    if raw_email:
        _post_registration(raw_email)
        set_config("identity", "email", raw_email)
        print()
        print("  Thanks! You'll get security advisories only. No spam.")

    print()
    raw_update = input("  Check for AIR updates automatically? [Y/n]: ").strip().lower()
    if raw_update in ("", "y"):
        set_config("telemetry", "update_check", "true")
        print("  Update checks enabled. Disable anytime: air config set telemetry.update_check false")
    else:
        set_config("telemetry", "update_check", "false")

    mark_prompted()


def _post_registration(email: str) -> None:
    """POST the email to the Vindicara registration endpoint.

    Failures are silently swallowed; the user is never blocked by network issues.
    """
    try:
        import platform

        import httpx

        from airsdk import __version__ as version

        httpx.post(
            _REGISTER_URL,
            json={
                "email": email,
                "source": "first_run",
                "version": version,
                "platform": platform.system(),
            },
            timeout=5.0,
        )
    except Exception:  # noqa: BLE001
        pass
