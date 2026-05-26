"""Pydantic models for parsed HL7v2 segments and sidecar results (Pro)."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class PatientIdentifier(BaseModel):
    model_config = ConfigDict(extra="forbid")

    value: str
    type_code: str  # MR, SS, AN, VN, etc.
    assigning_authority: str = ""


class MSHSegment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    field_separator: str = "|"
    encoding_characters: str = "^~\\&"
    sending_application: str = ""
    sending_facility: str = ""
    receiving_application: str = ""
    receiving_facility: str = ""
    datetime: str = ""
    message_type: str = ""
    message_control_id: str = ""
    processing_id: str = ""
    version_id: str = ""
    character_set: str = "ASCII"


class PIDSegment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    identifiers: list[PatientIdentifier] = Field(default_factory=list)
    primary_mrn: str | None = None
    family_name: str | None = None
    given_name: str | None = None
    date_of_birth: str | None = None
    gender: str | None = None


class OBXSegment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    set_id: int
    value_type: str  # NM, ST, CWE, TS, DT, TX, FT, SN
    observation_id: str
    observation_id_system: str = ""
    observation_id_text: str = ""
    value_numeric: float | None = None
    value_string: str | None = None
    value_coded: str | None = None
    value_coded_system: str | None = None
    value_coded_text: str | None = None
    value_datetime: str | None = None
    units: str | None = None
    reference_range: str | None = None
    abnormal_flags: str | None = None
    observation_status: str | None = None


class ORCSegment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    order_control: str = ""
    order_number: str = ""
    order_status: str = ""
    ordering_provider: str = ""
    ordering_provider_id: str = ""


class OBRSegment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    set_id: int = 1
    placer_order_number: str = ""
    filler_order_number: str = ""
    universal_service_id: str = ""
    priority: str = ""
    ordering_provider: str = ""
    result_status: str = ""


class PV1Segment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    patient_class: str = ""
    assigned_location: str = ""
    attending_doctor: str = ""
    visit_number: str = ""


class TXASegment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    set_id: int = 1
    document_type: str = ""
    document_status: str = ""
    originator: str = ""
    authentication_datetime: str = ""


class NK1Segment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    set_id: int = 1
    name: str = ""
    relationship: str = ""


class HL7v2Message(BaseModel):
    model_config = ConfigDict(extra="forbid")

    raw: str
    message_type: str
    message_control_id: str
    timestamp: str
    timestamp_precision: str  # "year"|"month"|"day"|"second"|"millisecond"
    sending_facility: str
    receiving_facility: str
    character_set: str = "ASCII"
    msh: MSHSegment
    pid: PIDSegment | None = None
    pv1: PV1Segment | None = None
    obx: list[OBXSegment] = Field(default_factory=list)
    orc: ORCSegment | None = None
    obr: OBRSegment | None = None
    txa: TXASegment | None = None
    nk1: list[NK1Segment] = Field(default_factory=list)
    z_segments: dict[str, list[list[str]]] = Field(default_factory=dict)


class HL7v2ParseError(Exception):
    """Raised when an HL7v2 message cannot be parsed."""


class SidecarResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message_type: str
    patient_mrn_hash: str | None = None
    patient_mrn: str | None = None
    records_written: int = 0
    fhir_resource_types: list[str] = Field(default_factory=list)
    findings_count: int = 0
    siem_events_sent: int = 0
    fhir_push_success: bool | None = None


class FHIRPushResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    success: bool
    status_code: int
    resources_created: int = 0
    resources_failed: int = 0
    error: str | None = None
