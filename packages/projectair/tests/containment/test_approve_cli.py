"""End-to-end CLI test for ``air approve``.

The CLI is the operator-side surface: an SRE responding to a step-up
challenge picks one of the three modes (token, device flow, authorize
URL) and submits the approval. These tests exercise mode A (token in
hand) against the in-process mock IdP, plus the print-only mode C
(authorize URL builder) which has no network round-trip.

Mode B (device flow) is covered by the unit tests in
``test_auth0_flows.py`` since it requires a real Auth0 device-code
endpoint to round-trip end to end.
"""
from __future__ import annotations

import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from typer.testing import CliRunner

from airsdk.containment import (
    Auth0Verifier,
    ContainmentPolicy,
    StepUpRequiredError,
)
from airsdk.recorder import AIRRecorder
from airsdk.types import StepKind
from projectair.cli import app

if TYPE_CHECKING:
    from tests.containment.conftest import MockIdP


def test_approve_cli_with_token_mode_writes_human_approval(
    mock_idp: MockIdP,
) -> None:
    """The agent process raised StepUpRequiredError and exited; an
    operator runs ``air approve --token <jwt>`` to finalize the chain.
    The HUMAN_APPROVAL must land with the verified claims."""
    with tempfile.TemporaryDirectory() as tmp:
        log_path = Path(tmp) / "chain.jsonl"
        verifier = Auth0Verifier(mock_idp.issuer, mock_idp.audience, jwks_uri=mock_idp.jwks_uri)
        rec = AIRRecorder(
            log_path,
            containment=ContainmentPolicy(step_up_for_actions=[{"tool": "send_email"}]),
            auth0_verifier=verifier,
        )
        rec.llm_start(prompt="setup")
        try:
            rec.tool_start(tool_name="send_email", tool_args={"to": "x@y.com"})
            raise AssertionError("expected StepUpRequiredError")
        except StepUpRequiredError as e:
            challenge_id = e.challenge_id

        token = mock_idp.issue_token(sub="auth0|approver", email="ops@example.com")

        runner = CliRunner()
        result = runner.invoke(
            app,
            [
                "approve",
                "--chain", str(log_path),
                "--challenge-id", challenge_id,
                "--tenant", _domain_from_issuer(mock_idp.issuer),
                "--audience", mock_idp.audience,
                "--token", token,
                "--jwks-uri", mock_idp.jwks_uri,
                "--issuer", mock_idp.issuer,
            ],
        )
        assert result.exit_code == 0, result.output
        assert "HUMAN_APPROVAL appended" in result.output

        # The chain on disk now has the HUMAN_APPROVAL record with the
        # verified claims. The agent process (when it next reads the
        # chain) sees the approval and resumes.
        from airsdk.agdr import load_chain

        records = load_chain(log_path)
        kinds = [r.kind.value for r in records]
        assert kinds[-1] == "human_approval"
        approval = records[-1].payload.human_approval
        assert approval is not None
        assert approval.approver_sub == "auth0|approver"
        assert approval.approver_email == "ops@example.com"
        assert approval.signed_token == token
        assert records[-1].kind == StepKind.HUMAN_APPROVAL


def test_approve_cli_authorize_url_mode_prints_well_formed_url(tmp_path: Path) -> None:
    """Mode C (no network): the CLI prints an Auth0 /authorize URL the
    operator can paste into a browser. Verify the URL is well-formed."""
    chain = tmp_path / "chain.jsonl"
    chain.write_text("")  # any path that exists is sufficient

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "approve",
            "--chain", str(chain),
            "--challenge-id", "challenge-xyz",
            "--tenant", "tenant.us.auth0.com",
            "--audience", "https://api.vindicara.io",
            "--client-id", "cli-app",
            "--redirect-uri", "https://app/callback",
            "--authorize-url",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "https://tenant.us.auth0.com/authorize" in result.output
    assert "client_id=cli-app" in result.output
    assert "audience=" in result.output
    assert "state=challenge-xyz" in result.output
    assert "code_challenge=" in result.output  # PKCE on by default
    assert "code_challenge_method=S256" in result.output
    assert "code_verifier" in result.output  # printed for the operator to keep


def test_approve_cli_rejects_missing_mode(tmp_path: Path) -> None:
    chain = tmp_path / "chain.jsonl"
    chain.write_text("")
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "approve",
            "--chain", str(chain),
            "--challenge-id", "x",
            "--tenant", "t.us.auth0.com",
            "--audience", "https://api.x",
        ],
    )
    assert result.exit_code != 0
    assert "Pick exactly one" in result.output


def test_approve_cli_rejects_multiple_modes(tmp_path: Path) -> None:
    chain = tmp_path / "chain.jsonl"
    chain.write_text("")
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "approve",
            "--chain", str(chain),
            "--challenge-id", "x",
            "--tenant", "t.us.auth0.com",
            "--audience", "https://api.x",
            "--token", "abc",
            "--device",
        ],
    )
    assert result.exit_code != 0
    assert "Pick exactly one" in result.output


def _domain_from_issuer(issuer: str) -> str:
    """Mock IdP issuer is http://127.0.0.1:PORT/ ; the tenant is host:port."""
    from urllib.parse import urlparse

    return urlparse(issuer).netloc
