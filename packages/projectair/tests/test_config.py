"""Tests for projectair.config.

Uses monkeypatch to redirect XDG_CONFIG_HOME so every test operates in a
temporary directory and never touches the real ~/.config/projectair/.
"""
from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _import_config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """Import config module fresh with XDG_CONFIG_HOME pointing at tmp_path.

    We also unset APPDATA so the Windows branch is not triggered on macOS/Linux
    CI runners.
    """
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("APPDATA", raising=False)
    # Force reimport so module-level state picks up the env override.
    import importlib
    import projectair.config as cfg_mod
    importlib.reload(cfg_mod)
    return cfg_mod


# ---------------------------------------------------------------------------
# config_dir
# ---------------------------------------------------------------------------

def test_config_dir_returns_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg = _import_config(monkeypatch, tmp_path)
    result = cfg.config_dir()
    assert result == tmp_path / "projectair"


def test_config_dir_xdg_used(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """config_dir should honour XDG_CONFIG_HOME."""
    cfg = _import_config(monkeypatch, tmp_path)
    assert cfg.config_dir().parent == tmp_path


# ---------------------------------------------------------------------------
# get_config / set_config
# ---------------------------------------------------------------------------

def test_get_returns_none_for_missing_key(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg = _import_config(monkeypatch, tmp_path)
    assert cfg.get_config("identity", "email") is None


def test_get_returns_none_when_no_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg = _import_config(monkeypatch, tmp_path)
    # config.toml does not exist yet
    assert not (cfg.config_dir() / "config.toml").exists()
    assert cfg.get_config("telemetry", "update_check") is None


def test_set_and_get_roundtrip(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg = _import_config(monkeypatch, tmp_path)
    cfg.set_config("identity", "email", "alice@example.com")
    assert cfg.get_config("identity", "email") == "alice@example.com"


def test_set_creates_directory(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg = _import_config(monkeypatch, tmp_path)
    config_directory = cfg.config_dir()
    assert not config_directory.exists()
    cfg.set_config("telemetry", "update_check", "true")
    assert config_directory.exists()


def test_set_multiple_sections(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg = _import_config(monkeypatch, tmp_path)
    cfg.set_config("identity", "email", "bob@example.com")
    cfg.set_config("telemetry", "update_check", "false")
    assert cfg.get_config("identity", "email") == "bob@example.com"
    assert cfg.get_config("telemetry", "update_check") == "false"


def test_set_overwrites_existing_value(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg = _import_config(monkeypatch, tmp_path)
    cfg.set_config("identity", "email", "first@example.com")
    cfg.set_config("identity", "email", "second@example.com")
    assert cfg.get_config("identity", "email") == "second@example.com"


def test_get_missing_section_returns_none(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg = _import_config(monkeypatch, tmp_path)
    cfg.set_config("identity", "email", "alice@example.com")
    assert cfg.get_config("nosuchsection", "key") is None


def test_get_missing_key_in_existing_section_returns_none(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = _import_config(monkeypatch, tmp_path)
    cfg.set_config("identity", "email", "alice@example.com")
    assert cfg.get_config("identity", "nosuchkey") is None


# ---------------------------------------------------------------------------
# list_config
# ---------------------------------------------------------------------------

def test_list_config_returns_empty_when_no_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = _import_config(monkeypatch, tmp_path)
    assert cfg.list_config() == {}


def test_list_config_returns_all(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg = _import_config(monkeypatch, tmp_path)
    cfg.set_config("identity", "email", "carol@example.com")
    cfg.set_config("telemetry", "update_check", "true")
    cfg.set_config("telemetry", "last_check", "2026-05-26T12:00:00")

    result = cfg.list_config()
    assert result["identity"]["email"] == "carol@example.com"
    assert result["telemetry"]["update_check"] == "true"
    assert result["telemetry"]["last_check"] == "2026-05-26T12:00:00"


# ---------------------------------------------------------------------------
# session_path / load_session / save_session / delete_session
# ---------------------------------------------------------------------------

def test_session_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg = _import_config(monkeypatch, tmp_path)
    sp = cfg.session_path()
    assert sp.name == "session.json"
    assert sp.parent == cfg.config_dir()


def test_load_session_returns_none_when_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = _import_config(monkeypatch, tmp_path)
    assert cfg.load_session() is None


def test_save_and_load_session(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg = _import_config(monkeypatch, tmp_path)
    data = {"user": "dave", "token": "abc123", "expires": 9999999}
    cfg.save_session(data)
    loaded = cfg.load_session()
    assert loaded == data


def test_save_session_creates_directory(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg = _import_config(monkeypatch, tmp_path)
    assert not cfg.config_dir().exists()
    cfg.save_session({"x": 1})
    assert cfg.config_dir().exists()


def test_save_session_mode_0600(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg = _import_config(monkeypatch, tmp_path)
    cfg.save_session({"secret": "value"})
    sp = cfg.session_path()
    file_mode = stat.S_IMODE(os.stat(sp).st_mode)
    assert file_mode == 0o600


def test_delete_session_returns_true(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg = _import_config(monkeypatch, tmp_path)
    cfg.save_session({"x": 1})
    assert cfg.delete_session() is True
    assert not cfg.session_path().exists()


def test_delete_session_returns_false_when_not_exists(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = _import_config(monkeypatch, tmp_path)
    assert cfg.delete_session() is False


# ---------------------------------------------------------------------------
# has_been_prompted / mark_prompted
# ---------------------------------------------------------------------------

def test_prompted_marker_initially_false(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg = _import_config(monkeypatch, tmp_path)
    assert cfg.has_been_prompted() is False


def test_prompted_marker(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg = _import_config(monkeypatch, tmp_path)
    assert cfg.has_been_prompted() is False
    cfg.mark_prompted()
    assert cfg.has_been_prompted() is True


def test_mark_prompted_creates_directory(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg = _import_config(monkeypatch, tmp_path)
    assert not cfg.config_dir().exists()
    cfg.mark_prompted()
    assert cfg.config_dir().exists()


def test_mark_prompted_idempotent(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg = _import_config(monkeypatch, tmp_path)
    cfg.mark_prompted()
    cfg.mark_prompted()  # should not raise
    assert cfg.has_been_prompted() is True
