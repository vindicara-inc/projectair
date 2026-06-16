"""Intent capsule entity scope tests for HL7v2 chains (Task 15).

SV-ENTITY-01 fires when a chain contains tool records that reference patient
entity identifiers not in the declared allowed_entities scope.

``check_entities`` inspects ``tool_args``, ``tool_output``, and ``response``
for entity identifier patterns (MRN-NNNN, etc). We inject the unauthorized
MRN into tool_args directly so the check can find it.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from _helpers import requires_vendor_key
from airsdk.recorder import AIRRecorder
from airsdk.types import IntentSpec
from airsdk.verification import verify_intent


@requires_vendor_key
def test_entity_violation_on_unauthorized_mrn(
    licensed: Path,
    recorder: AIRRecorder,
) -> None:
    """IntentSpec with allowed_entities=['MRN-0042'] + unauthorized MRN-9999 -> SV-ENTITY-01."""
    # Write an authorized record (MRN-0042 is in scope)
    recorder.tool_start(
        tool_name="hl7v2_receive",
        tool_args={"message_type": "ORU^R01", "patient_id": "MRN-0042"},
    )
    recorder.tool_end(tool_output="MSH|ACK")

    # Write an unauthorized record (MRN-9999 is NOT in scope)
    recorder.tool_start(
        tool_name="hl7v2_receive",
        tool_args={"message_type": "ORU^R01", "patient_id": "MRN-9999"},
    )
    recorder.tool_end(tool_output="MSH|ACK")

    from airsdk.agdr import load_chain
    records = load_chain(recorder.log_path)

    spec = IntentSpec(
        goal="Process authorized HL7v2 messages for declared patients only.",
        allowed_entities=["MRN-0042"],
    )
    result = verify_intent(records, intent_spec=spec)

    violation_ids = [v.check_id for v in result.violations]
    assert "SV-ENTITY-01" in violation_ids, (
        f"Expected SV-ENTITY-01 but got: {violation_ids}. "
        f"Violations: {result.violations}"
    )


@requires_vendor_key
def test_no_entity_violation_when_authorized(
    licensed: Path,
    recorder: AIRRecorder,
) -> None:
    """Only authorized MRN used -> no SV-ENTITY-01 violations."""
    recorder.tool_start(
        tool_name="hl7v2_receive",
        tool_args={"message_type": "ORU^R01", "patient_id": "MRN-0042"},
    )
    recorder.tool_end(tool_output="MSH|ACK")

    from airsdk.agdr import load_chain
    records = load_chain(recorder.log_path)

    spec = IntentSpec(
        goal="Process authorized HL7v2 messages for declared patients only.",
        allowed_entities=["MRN-0042"],
    )
    result = verify_intent(records, intent_spec=spec)
    entity_violations = [v for v in result.violations if v.check_id == "SV-ENTITY-01"]
    assert not entity_violations


@requires_vendor_key
def test_empty_allowed_entities_skips_entity_check(
    licensed: Path,
    recorder: AIRRecorder,
) -> None:
    """When allowed_entities is empty, entity check is skipped entirely."""
    recorder.tool_start(
        tool_name="hl7v2_receive",
        tool_args={"patient_id": "MRN-9999"},
    )
    recorder.tool_end(tool_output="MSH|ACK")

    from airsdk.agdr import load_chain
    records = load_chain(recorder.log_path)

    # No allowed_entities means check_entities is a no-op
    spec = IntentSpec(goal="Process messages.")
    result = verify_intent(records, intent_spec=spec)
    entity_violations = [v for v in result.violations if v.check_id == "SV-ENTITY-01"]
    assert not entity_violations
