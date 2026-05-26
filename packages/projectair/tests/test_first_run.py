"""Tests for projectair.first_run.

Uses monkeypatch to redirect XDG_CONFIG_HOME so every test operates in a
temporary directory and never touches the real ~/.config/projectair/.
"""
from __future__ import annotations

import importlib
import sys
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _setup_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    """Point XDG_CONFIG_HOME at tmp_path and reload config so paths resolve there."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("APPDATA", raising=False)
    import projectair.config as cfg_mod
    importlib.reload(cfg_mod)


def _reload_first_run() -> Any:
    """Reload the first_run module so it picks up fresh config module state."""
    import projectair.first_run as fr_mod
    importlib.reload(fr_mod)
    return fr_mod


# ---------------------------------------------------------------------------
# test_prompt_collects_email
# ---------------------------------------------------------------------------

def test_prompt_collects_email(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """When user enters an email address, _post_registration is called and email is stored in config."""
    _setup_env(monkeypatch, tmp_path)
    fr = _reload_first_run()

    monkeypatch.setattr("sys.stdin.isatty", lambda: True)

    posted: list[str] = []

    def fake_post(email: str) -> None:
        posted.append(email)

    with patch("builtins.input", side_effect=["user@example.com", "Y"]):
        with patch.object(fr, "_post_registration", side_effect=fake_post):
            fr.maybe_prompt_first_run()

    import projectair.config as cfg
    importlib.reload(cfg)
    assert cfg.get_config("identity", "email") == "user@example.com"
    assert posted == ["user@example.com"]
    assert cfg.has_been_prompted()


# ---------------------------------------------------------------------------
# test_prompt_skip_creates_marker
# ---------------------------------------------------------------------------

def test_prompt_skip_creates_marker(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """When user presses Enter (skips email), no POST is made and marker is created."""
    _setup_env(monkeypatch, tmp_path)
    fr = _reload_first_run()

    monkeypatch.setattr("sys.stdin.isatty", lambda: True)

    post_called = False

    def fake_post(email: str) -> None:  # pragma: no cover
        nonlocal post_called
        post_called = True

    with patch("builtins.input", side_effect=["", "n"]):
        with patch.object(fr, "_post_registration", side_effect=fake_post):
            fr.maybe_prompt_first_run()

    import projectair.config as cfg
    importlib.reload(cfg)
    assert not post_called
    assert cfg.has_been_prompted()


# ---------------------------------------------------------------------------
# test_prompt_not_shown_twice
# ---------------------------------------------------------------------------

def test_prompt_not_shown_twice(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """When the prompted marker already exists, input() is never called."""
    _setup_env(monkeypatch, tmp_path)

    # Create the marker manually.
    import projectair.config as cfg
    importlib.reload(cfg)
    cfg.mark_prompted()

    fr = _reload_first_run()
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)

    input_called = False

    def fake_input(prompt: str = "") -> str:  # pragma: no cover
        nonlocal input_called
        input_called = True
        return ""

    with patch("builtins.input", side_effect=fake_input):
        fr.maybe_prompt_first_run()

    assert not input_called


# ---------------------------------------------------------------------------
# test_prompt_skipped_in_non_tty
# ---------------------------------------------------------------------------

def test_prompt_skipped_in_non_tty(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """When stdin is not a TTY, prompt is skipped silently and marker is created."""
    _setup_env(monkeypatch, tmp_path)
    fr = _reload_first_run()

    monkeypatch.setattr("sys.stdin.isatty", lambda: False)

    input_called = False

    def fake_input(prompt: str = "") -> str:  # pragma: no cover
        nonlocal input_called
        input_called = True
        return ""

    with patch("builtins.input", side_effect=fake_input):
        fr.maybe_prompt_first_run()

    import projectair.config as cfg
    importlib.reload(cfg)
    assert not input_called
    assert cfg.has_been_prompted()


# ---------------------------------------------------------------------------
# test_prompt_skipped_when_logged_in
# ---------------------------------------------------------------------------

def test_prompt_skipped_when_logged_in(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """When session.json exists (user is logged in), no input() call is made."""
    _setup_env(monkeypatch, tmp_path)

    import projectair.config as cfg
    importlib.reload(cfg)
    cfg.save_session({"email": "existing@example.com", "sub": "auth0|abc", "expires_at": 9999999999})

    fr = _reload_first_run()
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)

    input_called = False

    def fake_input(prompt: str = "") -> str:  # pragma: no cover
        nonlocal input_called
        input_called = True
        return ""

    with patch("builtins.input", side_effect=fake_input):
        fr.maybe_prompt_first_run()

    assert not input_called


# ---------------------------------------------------------------------------
# test_update_check_opt_in
# ---------------------------------------------------------------------------

def test_update_check_opt_in(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """When user answers Y to update check, config stores 'true'."""
    _setup_env(monkeypatch, tmp_path)
    fr = _reload_first_run()

    monkeypatch.setattr("sys.stdin.isatty", lambda: True)

    with patch("builtins.input", side_effect=["", "Y"]):
        with patch.object(fr, "_post_registration"):
            fr.maybe_prompt_first_run()

    import projectair.config as cfg
    importlib.reload(cfg)
    assert cfg.get_config("telemetry", "update_check") == "true"


# ---------------------------------------------------------------------------
# test_update_check_opt_out
# ---------------------------------------------------------------------------

def test_update_check_opt_out(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """When user answers n to update check, config stores 'false'."""
    _setup_env(monkeypatch, tmp_path)
    fr = _reload_first_run()

    monkeypatch.setattr("sys.stdin.isatty", lambda: True)

    with patch("builtins.input", side_effect=["", "n"]):
        with patch.object(fr, "_post_registration"):
            fr.maybe_prompt_first_run()

    import projectair.config as cfg
    importlib.reload(cfg)
    assert cfg.get_config("telemetry", "update_check") == "false"


# ---------------------------------------------------------------------------
# test_post_registration_silent_on_network_error
# ---------------------------------------------------------------------------

def test_post_registration_silent_on_network_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """_post_registration does not raise on network errors."""
    _setup_env(monkeypatch, tmp_path)
    fr = _reload_first_run()

    import httpx

    with patch("httpx.post", side_effect=httpx.ConnectError("unreachable")):
        # Should not raise.
        fr._post_registration("user@example.com")
