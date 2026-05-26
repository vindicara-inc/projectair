"""FHIR R4 resource mapping for HL7v2 segments (Pro).

Maps parsed HL7v2 segments (``HL7v2Message``) to FHIR R4 resources via the
``fhir.resources`` library. PHI redaction is applied at the mapping boundary
so that no raw patient identifiers enter downstream chains or FHIR push
payloads unless the caller explicitly selects ``PHIMode.RAW``.

Public surface:
    normalize_code_system(raw) -- translate HL7 table 0396 codes to FHIR URIs
    map_to_fhir(message, *, redaction_policy) -- return list[MappedResource]
    project_for_chain(resource) -- strip to a minimal dict for AgDR payloads
"""
from __future__ import annotations

import uuid
from typing import Any

from fhir.resources.observation import Observation
from fhir.resources.patient import Patient

from airsdk_pro.hl7.redaction import PHIMode, RedactionPolicy, redact_dob, redact_identifier
from airsdk_pro.hl7.types import HL7v2Message, OBXSegment, PIDSegment

# ---------------------------------------------------------------------------
# Code system normalisation (FHIR URIs for HL7 table 0396 entries)
# ---------------------------------------------------------------------------

_CODE_SYSTEMS: dict[str, str] = {
    "LN": "http://loinc.org",
    "LOINC": "http://loinc.org",
    "SCT": "http://snomed.info/sct",
    "SNOMED": "http://snomed.info/sct",
    "CPT": "http://www.ama-assn.org/go/cpt",
    "CPT4": "http://www.ama-assn.org/go/cpt",
    "I10": "http://hl7.org/fhir/sid/icd-10-cm",
    "ICD10": "http://hl7.org/fhir/sid/icd-10-cm",
}
_LOCAL_SYSTEM = "urn:oid:2.16.840.1.113883.6.LOCAL"

_HL7_GENDER: dict[str, str] = {
    "F": "female",
    "M": "male",
    "O": "other",
    "U": "unknown",
}

_OBX_STATUS: dict[str, str] = {
    "F": "final",
    "P": "preliminary",
    "C": "amended",
    "X": "cancelled",
    "I": "registered",
}
_DEFAULT_OBS_STATUS = "unknown"

# FHIR identifier type system (HL7 v2 table 0203 codes)
_IDENTIFIER_TYPE_SYSTEM = "http://terminology.hl7.org/CodeSystem/v2-0203"


def normalize_code_system(raw: str) -> str:
    """Translate an HL7 table 0396 coding system identifier to a FHIR URI.

    Known systems (LN, SCT, CPT, I10, etc.) are mapped to their canonical
    FHIR URIs. Unknown systems fall back to a local OID namespace so the
    code remains unambiguously typed instead of being discarded.
    """
    return _CODE_SYSTEMS.get(raw.upper(), f"{_LOCAL_SYSTEM}:{raw}")


# ---------------------------------------------------------------------------
# MappedResource wrapper
# ---------------------------------------------------------------------------


class MappedResource:
    """Thin wrapper around a ``fhir.resources`` model instance.

    Provides a stable interface so callers never need to import
    ``fhir.resources`` directly.
    """

    def __init__(self, resource: Any) -> None:  # noqa: ANN401
        self._resource = resource

    @property
    def resource_type(self) -> str:
        """FHIR resource type string, e.g. ``"Patient"`` or ``"Observation"``."""
        return self._resource.resource_type  # type: ignore[no-any-return]

    @property
    def identifier(self) -> Any:  # noqa: ANN401
        """Identifier list for the underlying resource (may be empty list)."""
        return getattr(self._resource, "identifier", []) or []

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain ``dict`` via the underlying Pydantic model.

        ``None`` fields are excluded so the output is compact and
        compatible with FHIR JSON interchange.
        """
        return dict(self._resource.dict(exclude_none=True))


# ---------------------------------------------------------------------------
# Mapping helpers
# ---------------------------------------------------------------------------

_DEFAULT_POLICY = RedactionPolicy(phi_mode=PHIMode.REDACTED)


def _map_patient(pid: PIDSegment, policy: RedactionPolicy) -> MappedResource:
    """Build a FHIR R4 Patient from a parsed PID segment."""
    patient_id = str(uuid.uuid4())
    identifiers: list[dict[str, Any]] = []

    for ident in pid.identifiers:
        raw_value = ident.value
        mapped_value = redact_identifier(raw_value, policy)
        entry: dict[str, Any] = {
            "value": mapped_value,
            "type": {
                "coding": [{"system": _IDENTIFIER_TYPE_SYSTEM, "code": ident.type_code}]
            },
        }
        if ident.assigning_authority:
            entry["system"] = f"urn:oid:{ident.assigning_authority}"
        identifiers.append(entry)

    payload: dict[str, Any] = {
        "resourceType": "Patient",
        "id": patient_id,
    }
    if identifiers:
        payload["identifier"] = identifiers

    if pid.gender:
        payload["gender"] = _HL7_GENDER.get(pid.gender.upper(), "unknown")

    if pid.date_of_birth:
        redacted_dob = redact_dob(pid.date_of_birth, policy)
        if policy.phi_mode == PHIMode.RAW:
            # Raw mode: emit full ISO date if parseable
            raw_dob = pid.date_of_birth
            if len(raw_dob) >= 8:
                payload["birthDate"] = f"{raw_dob[:4]}-{raw_dob[4:6]}-{raw_dob[6:8]}"
            elif len(raw_dob) >= 4:
                payload["birthDate"] = raw_dob[:4]
        elif redacted_dob and redacted_dob != "90+":
            payload["birthDate"] = redacted_dob

    if policy.phi_mode == PHIMode.RAW and pid.family_name:
        name_entry: dict[str, Any] = {}
        if pid.family_name:
            name_entry["family"] = pid.family_name
        if pid.given_name:
            name_entry["given"] = [pid.given_name]
        if name_entry:
            payload["name"] = [name_entry]

    resource = Patient.parse_obj(payload)
    return MappedResource(resource)


def _build_obs_code(obx: OBXSegment) -> dict[str, Any]:
    """Build the FHIR CodeableConcept for OBX-3."""
    system = normalize_code_system(obx.observation_id_system) if obx.observation_id_system else _LOCAL_SYSTEM
    coding: dict[str, Any] = {"system": system, "code": obx.observation_id}
    if obx.observation_id_text:
        coding["display"] = obx.observation_id_text
    return {"coding": [coding]}


def _build_obs_value(obx: OBXSegment) -> dict[str, Any]:
    """Dispatch OBX value to the appropriate FHIR value[x] field."""
    vtype = obx.value_type.upper()

    if vtype == "NM" and obx.value_numeric is not None:
        quantity: dict[str, Any] = {"value": obx.value_numeric}
        if obx.units:
            quantity["unit"] = obx.units
            quantity["system"] = "http://unitsofmeasure.org"
            quantity["code"] = obx.units
        return {"valueQuantity": quantity}

    if vtype in {"ST", "TX", "FT"} and obx.value_string is not None:
        return {"valueString": obx.value_string}

    if vtype in {"CWE", "CE", "CNE"} and obx.value_coded is not None:
        cc_system = normalize_code_system(obx.value_coded_system) if obx.value_coded_system else _LOCAL_SYSTEM
        cc_coding: dict[str, Any] = {"system": cc_system, "code": obx.value_coded}
        if obx.value_coded_text:
            cc_coding["display"] = obx.value_coded_text
        return {"valueCodeableConcept": {"coding": [cc_coding]}}

    if vtype in {"TS", "DTM", "DT"} and obx.value_datetime is not None:
        return {"valueDateTime": obx.value_datetime}

    # Fall back to valueString for any unhandled type that has a string value
    if obx.value_string is not None:
        return {"valueString": obx.value_string}

    return {}


def _map_observation(obx: OBXSegment, patient_id: str) -> MappedResource:
    """Build a FHIR R4 Observation from a parsed OBX segment."""
    obs_id = str(uuid.uuid4())
    raw_status = (obx.observation_status or "F").strip()
    status = _OBX_STATUS.get(raw_status.upper(), _DEFAULT_OBS_STATUS)

    payload: dict[str, Any] = {
        "resourceType": "Observation",
        "id": obs_id,
        "status": status,
        "code": _build_obs_code(obx),
        "subject": {"reference": f"Patient/{patient_id}"},
    }
    payload.update(_build_obs_value(obx))

    resource = Observation.parse_obj(payload)
    return MappedResource(resource)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def map_to_fhir(
    message: HL7v2Message,
    *,
    redaction_policy: RedactionPolicy | None = None,
) -> list[MappedResource]:
    """Map a parsed ``HL7v2Message`` to a list of FHIR R4 ``MappedResource`` objects.

    Always returns Patient first (if PID is present), then all Observations
    in OBX segment order. PHI redaction is applied at this boundary.

    Args:
        message: Parsed HL7v2 message from ``parse_hl7v2``.
        redaction_policy: Controls PHI handling. Defaults to
            ``PHIMode.REDACTED`` (identifier hashing, name omission, DOB
            truncation to year). Pass a policy with ``PHIMode.RAW`` only
            when your BAA explicitly permits raw PHI in clinical chains.

    Returns:
        Ordered list: zero or one ``Patient``, then zero or more
        ``Observation`` resources.
    """
    policy = redaction_policy if redaction_policy is not None else _DEFAULT_POLICY
    resources: list[MappedResource] = []

    patient_id: str | None = None

    if message.pid is not None:
        patient_resource = _map_patient(message.pid, policy)
        resources.append(patient_resource)
        # Extract the generated patient id for Observation subject references
        patient_dict = patient_resource.to_dict()
        patient_id = patient_dict.get("id", str(uuid.uuid4()))

    if patient_id is None:
        # No PID: generate a synthetic placeholder id for subject refs
        patient_id = str(uuid.uuid4())

    for obx in message.obx:
        resources.append(_map_observation(obx, patient_id))

    return resources


def project_for_chain(resource: MappedResource) -> dict[str, Any]:
    """Project a ``MappedResource`` to a minimal dict for AgDR chain payloads.

    The projection retains only fields that are stable and safe for the
    immutable audit chain: ``resourceType``, ``id``, ``code`` (for
    Observations), and ``identifier`` (for Patients, already redacted
    upstream). PHI-bearing free-text fields such as ``name``, ``birthDate``,
    and ``valueString`` are stripped so the chain payload is safe even when
    the caller forgets to apply a REDACTED policy before calling this function.

    Args:
        resource: A ``MappedResource`` instance returned by ``map_to_fhir``.

    Returns:
        A plain ``dict`` suitable for embedding in an AgDR payload field.
    """
    full = resource.to_dict()
    projection: dict[str, Any] = {
        "resourceType": full.get("resourceType", ""),
        "id": full.get("id", ""),
    }

    rtype = resource.resource_type
    if rtype == "Patient":
        if "identifier" in full:
            projection["identifier"] = full["identifier"]
        if "gender" in full:
            projection["gender"] = full["gender"]
    elif rtype == "Observation":
        if "code" in full:
            projection["code"] = full["code"]
        if "status" in full:
            projection["status"] = full["status"]
        if "subject" in full:
            projection["subject"] = full["subject"]
        # valueQuantity is safe (no PHI); omit valueString / valueDateTime
        if "valueQuantity" in full:
            projection["valueQuantity"] = full["valueQuantity"]
        if "valueCodeableConcept" in full:
            projection["valueCodeableConcept"] = full["valueCodeableConcept"]

    return projection
