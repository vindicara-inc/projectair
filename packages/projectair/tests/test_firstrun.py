"""First-run activation-email gate tests."""
from __future__ import annotations

import pytest
import typer

from projectair.firstrun import _valid_email, ensure_identity


def test_email_validation() -> None:
    assert _valid_email("dev@example.com")
    assert _valid_email("a.b+tag@sub.example.co")
    assert not _valid_email("nope")
    assert not _valid_email("a@b")  # no dot in domain
    assert not _valid_email("")


def test_air_email_env_satisfies_gate(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setenv("AIR_EMAIL", "dev@example.com")
    # Pre-mark registered so the gate makes no network call.
    (tmp_path / "projectair").mkdir(parents=True, exist_ok=True)
    (tmp_path / "projectair" / "registered").touch()
    ensure_identity()  # must not raise or prompt


def test_config_email_satisfies_gate(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("AIR_EMAIL", raising=False)
    from projectair.config import set_config

    set_config("identity", "email", "dev@example.com")
    (tmp_path / "projectair" / "registered").touch()
    ensure_identity()  # must not raise


def test_non_tty_without_email_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    # pytest runs non-interactively (stdin is not a TTY); with no email the gate
    # must exit rather than hang on a prompt.
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("AIR_EMAIL", raising=False)
    with pytest.raises(typer.Exit):
        ensure_identity()


@pytest.mark.parametrize("argv", [["--help"], ["verify", "--help"], ["report", "alcoa", "--help"]])
def test_help_is_never_gated(monkeypatch: pytest.MonkeyPatch, tmp_path, argv: list[str]) -> None:
    # Reading the docs must not require an email, at any depth of subcommand.
    from typer.testing import CliRunner

    from projectair.cli import app

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("AIR_EMAIL", raising=False)
    result = CliRunner().invoke(app, argv)
    assert result.exit_code == 0, result.output
    assert "Usage:" in result.output


def test_real_command_is_still_gated(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    from typer.testing import CliRunner

    from projectair.cli import app

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("AIR_EMAIL", raising=False)
    result = CliRunner().invoke(app, ["trace", str(tmp_path / "missing.log")])
    assert result.exit_code == 2
    assert "needs an email" in result.output
