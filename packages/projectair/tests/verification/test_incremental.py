"""Tests for incremental verification in AIRRecorder."""
from __future__ import annotations

from pathlib import Path

import pytest

from airsdk.containment import BlockedActionError
from airsdk.recorder import AIRRecorder
from airsdk.types import IntentSpec


class TestIncrementalVerification:
    def test_halts_on_secret_access(self, tmp_path: Path) -> None:
        spec = IntentSpec(
            goal="Refactor the auth module",
            allowed_paths=["src/auth/"],
            allowed_network=[],
            secret_access=False,
        )
        recorder = AIRRecorder(
            tmp_path / "chain.jsonl",
            intent_spec=spec,
            verify_on_step=True,
        )
        recorder.llm_start(prompt="Refactoring auth module")
        recorder.llm_end(response="I will read the source files")
        recorder.tool_start(tool_name="read_file", tool_args={"path": "src/auth/main.py"})
        recorder.tool_end(tool_output="def authenticate(): ...")
        recorder.tool_start(
            tool_name="read_file",
            tool_args={"path": "/home/user/.ssh/id_rsa"},
        )

        with pytest.raises(BlockedActionError, match="Structural verification failed"):
            recorder.tool_end(
                tool_output="-----BEGIN OPENSSH PRIVATE KEY-----",
            )

    def test_no_halt_when_verify_off(self, tmp_path: Path) -> None:
        spec = IntentSpec(
            goal="Refactor the auth module",
            allowed_paths=["src/auth/"],
            secret_access=False,
        )
        recorder = AIRRecorder(
            tmp_path / "chain.jsonl",
            intent_spec=spec,
            verify_on_step=False,
        )
        recorder.llm_start(prompt="Refactoring auth module")
        recorder.llm_end(response="Reading SSH key")
        record = recorder.tool_start(
            tool_name="read_file",
            tool_args={"path": "/home/user/.ssh/id_rsa"},
        )
        assert record is not None

    def test_no_halt_for_in_scope_actions(self, tmp_path: Path) -> None:
        spec = IntentSpec(
            goal="Refactor the auth module",
            allowed_paths=["src/auth/"],
            allowed_network=[],
            secret_access=False,
        )
        recorder = AIRRecorder(
            tmp_path / "chain.jsonl",
            intent_spec=spec,
            verify_on_step=True,
        )
        recorder.llm_start(prompt="Refactoring auth module")
        recorder.llm_end(response="I will read the source files")
        record = recorder.tool_start(
            tool_name="read_file",
            tool_args={"path": "src/auth/main.py"},
        )
        assert record is not None

    def test_halts_on_entity_violation(self, tmp_path: Path) -> None:
        spec = IntentSpec(
            goal="Review patient MRN-0042",
            allowed_entities=["MRN-0042"],
        )
        recorder = AIRRecorder(
            tmp_path / "chain.jsonl",
            intent_spec=spec,
            verify_on_step=True,
        )
        recorder.tool_start(
            tool_name="ehr_query",
            tool_args={"mrn": "MRN-0042"},
        )
        with pytest.raises(BlockedActionError, match="Structural verification failed"):
            recorder.tool_end(
                tool_output="MRN-0042: HbA1c 8.4%\nMRN-9999: unauthorized",
            )
