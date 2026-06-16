"""Tests for ``air hl7`` CLI subcommands (Task 14)."""
from __future__ import annotations


def test_hl7_parse_help() -> None:
    from typer.testing import CliRunner

    from projectair.cli import app

    runner = CliRunner()
    result = runner.invoke(app, ["hl7", "parse", "--help"])
    assert result.exit_code == 0
    assert "Parse" in result.stdout


def test_hl7_capture_help() -> None:
    from typer.testing import CliRunner

    from projectair.cli import app

    runner = CliRunner()
    result = runner.invoke(app, ["hl7", "capture", "--help"])
    assert result.exit_code == 0
    assert "capture" in result.stdout.lower()


def test_hl7_group_help() -> None:
    from typer.testing import CliRunner

    from projectair.cli import app

    runner = CliRunner()
    result = runner.invoke(app, ["hl7", "--help"])
    assert result.exit_code == 0
    assert "parse" in result.stdout.lower()
    assert "capture" in result.stdout.lower()


def test_hl7_parse_missing_pro(tmp_path: object) -> None:
    """When projectair-pro is not installed, parse exits with code 1."""
    import sys
    from pathlib import Path
    from unittest.mock import patch

    from typer.testing import CliRunner

    from projectair.cli import app

    runner = CliRunner()
    hl7_file = Path(str(tmp_path)) / "test.hl7"
    hl7_file.write_text(
        "MSH|^~\\&|LAB|HOSP|AI|V|20260511||ORU^R01|M1|P|2.5\r"
        "PID|1||MRN-0001^^^HOSP^MR\r"
    )

    # Simulate airsdk_pro not installed by making the import raise ImportError
    with patch.dict(sys.modules, {"airsdk_pro": None, "airsdk_pro.hl7": None}):
        result = runner.invoke(app, ["hl7", "parse", str(hl7_file)])
    assert result.exit_code == 1
    assert "projectair-pro" in result.stdout
