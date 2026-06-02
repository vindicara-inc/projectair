"""Tests for SV-ENTITY: entity access outside declared scope."""
from __future__ import annotations

from airsdk.agdr import Signer
from airsdk.types import AgDRPayload, IntentSpec, StepKind
from airsdk.verification.checks.entity import check_entities
from airsdk.verification.verifier import verify_intent


def _make_records(
    signer: Signer,
    steps: list[tuple[StepKind, dict[str, object]]],
) -> list[object]:
    records = []
    for kind, fields in steps:
        payload = AgDRPayload.model_validate({
            "user_intent": "Review patient MRN-0042",
            **fields,
        })
        records.append(signer.sign(kind=kind, payload=payload))
    return records


class TestEntityCheck:
    def test_no_violation_when_only_allowed_entity(self) -> None:
        signer = Signer.generate()
        spec = IntentSpec(
            goal="Review patient MRN-0042",
            allowed_entities=["MRN-0042"],
        )
        records = _make_records(signer, [
            (StepKind.TOOL_START, {
                "tool_name": "ehr_query",
                "tool_args": {"mrn": "MRN-0042", "record_type": "labs"},
            }),
            (StepKind.TOOL_END, {
                "tool_output": "Patient MRN-0042: HbA1c 8.4%",
            }),
        ])
        violations = check_entities(records, spec)
        assert len(violations) == 0

    def test_violation_when_unauthorized_entity_in_output(self) -> None:
        signer = Signer.generate()
        spec = IntentSpec(
            goal="Review patient MRN-0042",
            allowed_entities=["MRN-0042"],
        )
        records = _make_records(signer, [
            (StepKind.TOOL_START, {
                "tool_name": "ehr_query",
                "tool_args": {"mrn": "MRN-0042"},
            }),
            (StepKind.TOOL_END, {
                "tool_output": (
                    "MRN-0042: HbA1c 8.4%\n"
                    "MRN-1001: Glucose 186\n"
                    "MRN-1002: Creatinine 1.2\n"
                ),
            }),
        ])
        violations = check_entities(records, spec)
        assert len(violations) >= 1
        assert violations[0].check_id == "SV-ENTITY-01"
        assert violations[0].severity == "critical"

    def test_violation_when_unauthorized_entity_in_args(self) -> None:
        signer = Signer.generate()
        spec = IntentSpec(
            goal="Review patient MRN-0042",
            allowed_entities=["MRN-0042"],
        )
        records = _make_records(signer, [
            (StepKind.TOOL_START, {
                "tool_name": "ehr_query",
                "tool_args": {"mrn": "MRN-9999"},
            }),
        ])
        violations = check_entities(records, spec)
        assert len(violations) >= 1

    def test_no_entities_declared_skips_check(self) -> None:
        signer = Signer.generate()
        spec = IntentSpec(goal="General task")
        records = _make_records(signer, [
            (StepKind.TOOL_START, {
                "tool_name": "ehr_query",
                "tool_args": {"mrn": "MRN-9999"},
            }),
        ])
        violations = check_entities(records, spec)
        assert len(violations) == 0


class TestEntityInVerifier:
    def test_entity_violation_causes_failed_verdict(self) -> None:
        signer = Signer.generate()
        spec = IntentSpec(
            goal="Review patient MRN-0042",
            allowed_entities=["MRN-0042"],
        )
        intent_record = signer.sign(
            kind=StepKind.INTENT_DECLARATION,
            payload=AgDRPayload.model_validate({
                "user_intent": spec.goal,
                "intent_spec": spec,
            }),
        )
        tool_start = signer.sign(
            kind=StepKind.TOOL_START,
            payload=AgDRPayload.model_validate({
                "user_intent": spec.goal,
                "tool_name": "ehr_query",
                "tool_args": {"mrn": "MRN-0042"},
            }),
        )
        tool_end = signer.sign(
            kind=StepKind.TOOL_END,
            payload=AgDRPayload.model_validate({
                "user_intent": spec.goal,
                "tool_output": "MRN-0042: ok\nMRN-5555: unauthorized data",
            }),
        )
        result = verify_intent([intent_record, tool_start, tool_end], spec)
        assert result.verdict.value == "failed"
        entity_violations = [
            v for v in result.violations if v.check_id == "SV-ENTITY-01"
        ]
        assert len(entity_violations) >= 1
