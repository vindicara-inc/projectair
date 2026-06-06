"""Opt-in automatic update checker for the ``air`` CLI.

Runs on every ``air`` command when:

1. ``get_config("telemetry", "update_check") == "true"``
2. 24 hours have passed since the ``last_check`` timestamp stored in config.

Makes a GET to the Vindicara version-check endpoint. If a newer version is
available, prints a one-line upgrade hint. Silent on all network errors.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from projectair.config import get_config, set_config

_VERSION_CHECK_URL = "https://api.vindicara.io/api/v1/telemetry/version-check"
_CACHE_HOURS = 24


def maybe_check_update() -> None:
    """Check for an updated version if the user has opted in and 24 h have elapsed.

    Skips silently when:
    - ``telemetry.update_check`` is not ``"true"``
    - The last check happened fewer than 24 hours ago.
    - Any network or parsing error occurs.
    """
    if get_config("telemetry", "update_check") != "true":
        return

    last_check_raw = get_config("telemetry", "last_check")
    if last_check_raw is not None:
        last_check = _parse_last_check(last_check_raw)
        if last_check is not None and datetime.now(UTC) - last_check < timedelta(
            hours=_CACHE_HOURS
        ):
            return

    _fetch_and_print()


def _fetch_and_print() -> None:
    """Hit the version-check endpoint, persist last_check, and print if outdated."""
    try:
        import platform
        import socket

        import blake3
        import httpx

        from airsdk import __version__ as installed_version

        raw_host = socket.gethostname().encode()
        session_id = blake3.blake3(raw_host).hexdigest()[:16]

        response = httpx.get(
            _VERSION_CHECK_URL,
            params={
                "version": installed_version,
                "python": platform.python_version(),
                "platform": platform.system(),
                "session_id": session_id,
            },
            timeout=2.0,
        )
        response.raise_for_status()

        data = response.json()
        latest: str = data.get("latest_version", "")

        set_config("telemetry", "last_check", datetime.now(UTC).isoformat())

        if latest and _is_newer(latest, installed_version):
            print(
                f"A newer version of AIR is available ({latest})."
                " Run: pip install --upgrade projectair"
            )
    except ImportError:
        # Optional dependencies; skip update hint when unavailable.
        return
    except (httpx.HTTPError, OSError, ValueError):
        # Best-effort update hint; never block the CLI on network or parse failures.
        return


def _parse_last_check(raw: str) -> datetime | None:
    """Parse a stored ``last_check`` timestamp, returning None when corrupt."""
    try:
        last_check = datetime.fromisoformat(raw)
        if last_check.tzinfo is None:
            last_check = last_check.replace(tzinfo=UTC)
        return last_check
    except ValueError:
        return None


def _is_newer(latest: str, installed: str) -> bool:
    """Return True when *latest* is strictly newer than *installed*.

    Compares tuples of integers from version strings. Falls back to string
    inequality when parsing fails.
    """
    try:
        def _parse(v: str) -> tuple[int, ...]:
            return tuple(int(x) for x in v.split("."))

        return _parse(latest) > _parse(installed)
    except ValueError:
        return latest != installed
