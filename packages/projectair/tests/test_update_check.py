"""Tests for projectair.update_check.

Uses monkeypatch to redirect XDG_CONFIG_HOME so every test operates in a
temporary directory and never touches the real ~/.config/projectair/.
"""
from __future__ import annotations

import importlib
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _setup_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("APPDATA", raising=False)
    import projectair.config as cfg_mod
    importlib.reload(cfg_mod)


def _reload_update_check() -> Any:
    import projectair.update_check as uc_mod
    importlib.reload(uc_mod)
    return uc_mod


# ---------------------------------------------------------------------------
# test_check_skipped_when_disabled
# ---------------------------------------------------------------------------

def test_check_skipped_when_disabled(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """When telemetry.update_check is not 'true', no HTTP call is made."""
    _setup_env(monkeypatch, tmp_path)
    uc = _reload_update_check()

    http_called = False

    def fake_get(*args: Any, **kwargs: Any) -> Any:  # pragma: no cover
        nonlocal http_called
        http_called = True
        return MagicMock()

    with patch("httpx.get", side_effect=fake_get):
        uc.maybe_check_update()

    assert not http_called


# ---------------------------------------------------------------------------
# test_check_prints_update_available
# ---------------------------------------------------------------------------

def test_check_prints_update_available(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    """When server returns a newer version, prints the upgrade message."""
    _setup_env(monkeypatch, tmp_path)

    import projectair.config as cfg
    importlib.reload(cfg)
    cfg.set_config("telemetry", "update_check", "true")

    uc = _reload_update_check()

    mock_response = MagicMock()
    mock_response.json.return_value = {"latest_version": "99.0.0"}
    mock_response.raise_for_status = MagicMock()

    with patch("httpx.get", return_value=mock_response):
        uc.maybe_check_update()

    captured = capsys.readouterr()
    assert "99.0.0" in captured.out
    assert "pip install --upgrade projectair" in captured.out


# ---------------------------------------------------------------------------
# test_check_silent_on_current_version
# ---------------------------------------------------------------------------

def test_check_silent_on_current_version(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    """When installed version equals the latest, no output is printed."""
    _setup_env(monkeypatch, tmp_path)

    import projectair.config as cfg
    importlib.reload(cfg)
    cfg.set_config("telemetry", "update_check", "true")

    uc = _reload_update_check()

    from airsdk import __version__ as current_version

    mock_response = MagicMock()
    mock_response.json.return_value = {"latest_version": current_version}
    mock_response.raise_for_status = MagicMock()

    with patch("httpx.get", return_value=mock_response):
        uc.maybe_check_update()

    captured = capsys.readouterr()
    assert "newer version" not in captured.out
    assert "pip install" not in captured.out


# ---------------------------------------------------------------------------
# test_check_silent_on_network_error
# ---------------------------------------------------------------------------

def test_check_silent_on_network_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    """When httpx raises ConnectError, no output is printed and no exception propagates."""
    _setup_env(monkeypatch, tmp_path)

    import projectair.config as cfg
    importlib.reload(cfg)
    cfg.set_config("telemetry", "update_check", "true")

    uc = _reload_update_check()

    import httpx

    with patch("httpx.get", side_effect=httpx.ConnectError("unreachable")):
        uc.maybe_check_update()

    captured = capsys.readouterr()
    assert captured.out == ""


# ---------------------------------------------------------------------------
# test_check_respects_24h_cache
# ---------------------------------------------------------------------------

def test_check_respects_24h_cache(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """When last_check is less than 24 hours ago, no HTTP call is made."""
    _setup_env(monkeypatch, tmp_path)

    import projectair.config as cfg
    importlib.reload(cfg)
    cfg.set_config("telemetry", "update_check", "true")
    recent = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    cfg.set_config("telemetry", "last_check", recent)

    uc = _reload_update_check()

    http_called = False

    def fake_get(*args: Any, **kwargs: Any) -> Any:  # pragma: no cover
        nonlocal http_called
        http_called = True
        return MagicMock()

    with patch("httpx.get", side_effect=fake_get):
        uc.maybe_check_update()

    assert not http_called
