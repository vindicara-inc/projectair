"""Tests for the NemoGuard sensitivity classifier."""
from __future__ import annotations

from airsdk.agdr import Signer
from airsdk.types import StepKind

from airsdk_pro.governance.classifier import classify_sensitivity


class TestClassifier:
    def test_detects_phi(self) -> None:
        signer = Signer.generate()
        records = [
            signer.sign(StepKind.TOOL_START, {
                "tool_name": "query_db",
                "tool_args": {"sql": "SELECT patient diagnosis treatment FROM records"},
            }),
        ]
        suggestions = classify_sensitivity(records)
        assert len(suggestions) == 1
        assert suggestions[0].suggested_sensitivity == "restricted"
        assert suggestions[0].suggested_jurisdiction == "HIPAA"

    def test_detects_pii(self) -> None:
        signer = Signer.generate()
        records = [
            signer.sign(StepKind.TOOL_START, {
                "tool_name": "lookup",
                "tool_args": {"query": "Find the SSN and date of birth for user 123"},
            }),
        ]
        suggestions = classify_sensitivity(records)
        assert len(suggestions) == 1
        assert suggestions[0].suggested_sensitivity == "confidential"

    def test_no_sensitive_data(self) -> None:
        signer = Signer.generate()
        records = [
            signer.sign(StepKind.TOOL_START, {
                "tool_name": "ping",
                "tool_args": {"host": "example.com"},
            }),
        ]
        suggestions = classify_sensitivity(records)
        assert len(suggestions) == 0

    def test_skips_non_actionable_records(self) -> None:
        signer = Signer.generate()
        records = [
            signer.sign(StepKind.LLM_START, {"prompt": "patient diagnosis"}),
        ]
        suggestions = classify_sensitivity(records)
        assert len(suggestions) == 0

    def test_detects_in_llm_response(self) -> None:
        signer = Signer.generate()
        records = [
            signer.sign(StepKind.LLM_END, {
                "response": "The patient medical record shows a diagnosis of diabetes.",
            }),
        ]
        suggestions = classify_sensitivity(records)
        assert len(suggestions) == 1
