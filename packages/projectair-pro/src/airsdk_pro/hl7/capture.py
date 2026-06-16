"""HL7v2 capsule capture -- emit signed AgDR records for incoming HL7 messages.

``instrument_hl7`` is the single entry point. It parses the raw HL7v2 message,
applies PHI redaction, optionally maps to FHIR R4, and writes two signed records
(tool_start + tool_end) to the recorder's chain. The records carry structured
HL7v2 and FHIR metadata in the AgDRPayload HL7 fields so downstream forensic
tools can reconstruct what clinical data the agent touched without reading any
raw PHI.

BAA requirement: ``RedactionPolicy`` enforces ``baa_acknowledged=True`` at
construction time. Attempting to capture without a BAA raises immediately.
"""
from __future__ import annotations

import uuid
from decimal import Decimal
from datetime import datetime, timezone
from typing import Any

from airsdk.recorder import AIRRecorder
from airsdk.types import AgDRRecord, DataSubjectRef

from airsdk_pro.gate import requires_pro
from airsdk_pro.hl7.fhir import map_to_fhir, project_for_chain
from airsdk_pro.hl7.parser import parse_hl7v2
from airsdk_pro.hl7.redaction import RedactionPolicy, redact_dob, redact_identifier, redact_mcid

HL7_FHIR_FEATURE = "hl7-fhir-integration"


def _sanitize_for_chain(obj: Any) -> Any:
    """Recursively convert Decimal values to float for JSON serializability.

    ``fhir.resources`` uses Pydantic v1 which serializes numeric values
    as ``Decimal``. The AgDR chain uses stdlib ``json.dumps`` which does not
    handle ``Decimal``. This helper walks the projected dict tree and converts
    any ``Decimal`` to ``float`` so the payload can be canonicalized without
    error.
    """
    if isinstance(obj, Decimal):
        return float(obj)
    if isinstance(obj, dict):
        return {k: _sanitize_for_chain(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize_for_chain(v) for v in obj]
    return obj


def _build_segments_dict(msg: object, policy: RedactionPolicy) -> dict[str, Any]:
    """Project a parsed HL7v2Message to a redaction-safe dict for the chain.

    Only stable, non-free-text fields are included. In REDACTED mode:
    - MRN is replaced with its BLAKE3 hash
    - DOB is truncated to year (90+ rule applied)
    - Name fields are omitted
    """
    from airsdk_pro.hl7.types import HL7v2Message  # local import to avoid circularity

    if not isinstance(msg, HL7v2Message):
        return {}

    result: dict[str, Any] = {}

    msh = msg.msh
    result["MSH"] = {
        "sending_application": msh.sending_application,
        "sending_facility": msh.sending_facility,
        "receiving_application": msh.receiving_application,
        "receiving_facility": msh.receiving_facility,
        "message_type": msh.message_type,
        "message_control_id": redact_mcid(msh.message_control_id),
        "version_id": msh.version_id,
    }

    if msg.pid is not None:
        pid = msg.pid
        pid_entry: dict[str, Any] = {}
        if pid.primary_mrn is not None:
            pid_entry["mrn"] = redact_identifier(pid.primary_mrn, policy)
        if pid.date_of_birth is not None:
            pid_entry["dob"] = redact_dob(pid.date_of_birth, policy)
        if pid.gender is not None:
            pid_entry["gender"] = pid.gender
        result["PID"] = pid_entry

    if msg.obr is not None:
        obr = msg.obr
        result["OBR"] = {
            "universal_service_id": obr.universal_service_id,
            "placer_order_number": obr.placer_order_number,
            "filler_order_number": obr.filler_order_number,
        }

    if msg.obx:
        result["OBX"] = [
            {
                "set_id": obx.set_id,
                "value_type": obx.value_type,
                "observation_id": obx.observation_id,
                "observation_id_text": obx.observation_id_text,
                "observation_id_system": obx.observation_id_system,
                "value_numeric": obx.value_numeric,
                "units": obx.units,
                "reference_range": obx.reference_range,
                "abnormal_flags": obx.abnormal_flags,
                "observation_status": obx.observation_status,
            }
            for obx in msg.obx
        ]

    return result


def _build_ack(msg: object) -> str:
    """Build a minimal HL7v2 AA ACK message string.

    The original message control ID is passed through ``redact_mcid`` so the
    ACK does not leak the encounter date into the tool_output field.
    """
    from airsdk_pro.hl7.types import HL7v2Message

    if not isinstance(msg, HL7v2Message):
        return "MSH|^~\\&|VINDICARA|AIR|||" + _utc_ts() + "||ACK|ACK001|P|2.5\rMSA|AA|\r"

    msh = msg.msh
    new_mcid = "ACK" + str(uuid.uuid4().hex[:8]).upper()
    original_mcid_safe = redact_mcid(msh.message_control_id)
    ts = _utc_ts()

    return (
        f"MSH|^~\\&|VINDICARA|AIR|{msh.sending_application}|{msh.sending_facility}"
        f"|{ts}||ACK|{new_mcid}|P|{msh.version_id or '2.5'}\r"
        f"MSA|AA|{original_mcid_safe}\r"
    )


def _utc_ts() -> str:
    """Current UTC timestamp in HL7v2 DTM format (YYYYMMDDHHmmss)."""
    now = datetime.now(tz=timezone.utc)
    return now.strftime("%Y%m%d%H%M%S")


@requires_pro(feature=HL7_FHIR_FEATURE)
def instrument_hl7(
    recorder: AIRRecorder,
    raw_message: str,
    *,
    map_fhir: bool = True,
    redaction_policy: RedactionPolicy | None = None,
    data_subjects: list[DataSubjectRef] | None = None,
) -> tuple[AgDRRecord, AgDRRecord]:
    """Parse an HL7v2 message and emit a signed tool_start + tool_end pair.

    Steps:
    1. Create a default RedactionPolicy if none is provided (REDACTED mode).
    2. Parse the raw message via ``parse_hl7v2``.
    3. If no ``data_subjects`` and the PID segment has a primary MRN, auto-
       create a DataSubjectRef using the redacted (BLAKE3-hashed) MRN so the
       chain carries jurisdiction metadata without raw PHI.
    4. If ``map_fhir`` is True, map to FHIR R4 and project resources for the
       chain payload.
    5. Build a redaction-safe ``hl7v2_segments`` dict.
    6. Emit ``tool_start`` with message metadata + HL7/FHIR fields.
    7. Emit ``tool_end`` with the HL7v2 ACK as ``tool_output``.
    8. Return (start_record, end_record).

    Parameters
    ----------
    recorder:
        The AIRRecorder instance to write records to.
    raw_message:
        Raw pipe-delimited HL7v2 message string.
    map_fhir:
        When True (default), map the message to FHIR R4 resources and embed
        the projected resources in the ``fhir_resources`` payload field.
    redaction_policy:
        Controls PHI handling. Defaults to REDACTED mode (identifier hashing,
        name omission, DOB truncation to year). Requires ``baa_acknowledged=True``.
    data_subjects:
        Optional explicit data subject references. When None and the PID
        segment contains a primary MRN, a DataSubjectRef is auto-created
        with the hashed MRN and HIPAA jurisdiction.

    Returns
    -------
    Tuple of (tool_start AgDRRecord, tool_end AgDRRecord).

    Raises
    ------
    HL7v2ParseError:
        If the raw message is malformed and cannot be parsed.
    LicenseMissingError / LicenseInvalidError / LicenseExpiredError:
        If a valid Pro license with the ``hl7-fhir-integration`` feature
        is not installed.
    """
    policy = redaction_policy if redaction_policy is not None else RedactionPolicy()

    msg = parse_hl7v2(raw_message)

    # Auto-tag data subjects from PID if caller did not provide them
    resolved_subjects: list[DataSubjectRef] | None = data_subjects
    redacted_mrn: str | None = None
    if resolved_subjects is None and msg.pid is not None and msg.pid.primary_mrn is not None:
        redacted_mrn = redact_identifier(msg.pid.primary_mrn, policy)
        resolved_subjects = [
            DataSubjectRef(
                subject_id=redacted_mrn,
                subject_type="patient",
                jurisdiction="HIPAA",
            )
        ]

    # Build FHIR R4 projections, sanitizing Decimal values to float so the
    # projections are JSON-serializable through the AgDR canonical encoder.
    fhir_chain_resources: list[dict[str, Any]] | None = None
    if map_fhir:
        fhir_resources = map_to_fhir(msg, redaction_policy=policy)
        fhir_chain_resources = [
            _sanitize_for_chain(project_for_chain(r)) for r in fhir_resources
        ]

    # Build redacted segments dict for the chain
    segments_dict = _build_segments_dict(msg, policy)

    # Redact the message control ID before it enters tool_args
    safe_mcid = redact_mcid(msg.message_control_id)

    tool_args: dict[str, Any] = {
        "message_type": msg.message_type,
        "sending_facility": msg.sending_facility,
        "message_control_id": safe_mcid,
    }

    start_record = recorder.tool_start(
        tool_name="hl7v2_receive",
        tool_args=tool_args,
        data_subjects=resolved_subjects,
        hl7v2_message_type=msg.message_type,
        hl7v2_segments=segments_dict,
        fhir_resources=fhir_chain_resources,
    )

    ack = _build_ack(msg)
    end_record = recorder.tool_end(tool_output=ack)

    return start_record, end_record
