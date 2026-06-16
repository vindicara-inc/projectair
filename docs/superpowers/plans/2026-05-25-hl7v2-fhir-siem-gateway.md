# HL7v2 + FHIR R4 Clinical Evidence Sidecar Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Pro-tier clinical evidence sidecar that parses HL7v2 messages, maps them to FHIR R4 resources, captures them as signed forensic capsules with PHI redaction, and pushes clinical-context-enriched findings to SIEM targets.

**Architecture:** Vendored hl7apy for parsing with a thin Pydantic wrapper; fhir.resources for FHIR R4 models with strict projection at the chain boundary; async pipeline with commit-level ACK (parse + stage) and batched signing downstream; PHI redaction by default with BAA always required; Enterprise-only pricing.

**Tech Stack:** Python 3.12+, Pydantic v2, hl7apy (vendored), fhir.resources (PyPI), httpx, FastAPI, asyncio, blake3

**Spec:** `docs/superpowers/specs/2026-05-25-hl7v2-fhir-siem-gateway-design.md` (v3)

---

### Task 1: Vendor hl7apy and add fhir.resources dependency

**Files:**
- Create: `packages/projectair-pro/src/airsdk_pro/_vendor/hl7apy/` (vendored copy)
- Create: `packages/projectair-pro/src/airsdk_pro/_vendor/__init__.py`
- Modify: `packages/projectair-pro/pyproject.toml`

- [ ] **Step 1: Vendor hl7apy into the repo**

```bash
cd /tmp && pip install hl7apy --target /tmp/hl7apy_download
cp -r /tmp/hl7apy_download/hl7apy packages/projectair-pro/src/airsdk_pro/_vendor/hl7apy
```

Create `packages/projectair-pro/src/airsdk_pro/_vendor/__init__.py`:

```python
"""Vendored third-party libraries. Hash-pinned, version-locked."""
```

- [ ] **Step 2: Record the vendor metadata**

Create `packages/projectair-pro/src/airsdk_pro/_vendor/hl7apy/VENDOR.md`:

```markdown
# Vendored: hl7apy

- **Version:** (output of `pip show hl7apy | grep Version`)
- **Source:** https://github.com/crs4/hl7apy
- **License:** MIT
- **Vendored on:** 2026-05-25
- **SHA256 of sdist:** (output of `pip hash`)
- **Re-vendoring policy:** check upstream quarterly; pull security fixes immediately; pull feature releases on next minor version. Each re-vendor is a tracked commit.
```

- [ ] **Step 3: Add fhir.resources to pyproject.toml dependencies**

In `packages/projectair-pro/pyproject.toml`, add to `dependencies`:

```toml
"fhir.resources>=7.1.0,<8.0",
```

Also update the `projectair` version pin to allow 1.0.x:

```toml
"projectair>=1.0.0,<2.0",
```

- [ ] **Step 4: Verify imports work**

```bash
source .venv-air/bin/activate
pip install -e "packages/projectair-pro[dev]"
python -c "from airsdk_pro._vendor.hl7apy.core import Message; print('hl7apy OK')"
python -c "from fhir.resources.patient import Patient; print('fhir.resources OK')"
```

- [ ] **Step 5: Commit**

```bash
git add packages/projectair-pro/src/airsdk_pro/_vendor/ packages/projectair-pro/pyproject.toml
git commit -m "chore: vendor hl7apy and add fhir.resources dependency"
```

---

### Task 2: Types and PHI redaction policy

**Files:**
- Create: `packages/projectair-pro/src/airsdk_pro/hl7/__init__.py`
- Create: `packages/projectair-pro/src/airsdk_pro/hl7/types.py`
- Create: `packages/projectair-pro/src/airsdk_pro/hl7/redaction.py`
- Create: `packages/projectair-pro/tests/hl7/__init__.py`
- Create: `packages/projectair-pro/tests/hl7/test_redaction.py`

- [ ] **Step 1: Write the failing tests for RedactionPolicy**

Create `packages/projectair-pro/tests/hl7/__init__.py` (empty).

Create `packages/projectair-pro/tests/hl7/test_redaction.py`:

```python
"""Tests for PHI redaction policy."""
from __future__ import annotations

import pytest
from pydantic import ValidationError


def test_baa_required_for_all_clinical_chains() -> None:
    from airsdk_pro.hl7.redaction import RedactionPolicy
    with pytest.raises(ValidationError, match="baa_acknowledged must be True"):
        RedactionPolicy(baa_acknowledged=False)


def test_redacted_mode_is_default() -> None:
    from airsdk_pro.hl7.redaction import PHIMode, RedactionPolicy
    policy = RedactionPolicy()
    assert policy.phi_mode == PHIMode.REDACTED
    assert policy.baa_acknowledged is True


def test_phi_fields_blocked_in_redacted_mode() -> None:
    from airsdk_pro.hl7.redaction import RedactionPolicy
    with pytest.raises(ValidationError, match="PHI-class fields"):
        RedactionPolicy(allowed_fields=["mrn", "name"])


def test_non_phi_fields_allowed_in_redacted_mode() -> None:
    from airsdk_pro.hl7.redaction import RedactionPolicy
    policy = RedactionPolicy(allowed_fields=["facility", "message_type"])
    assert policy.allowed_fields == ["facility", "message_type"]


def test_raw_mode_accepts_any_fields() -> None:
    from airsdk_pro.hl7.redaction import PHIMode, RedactionPolicy
    policy = RedactionPolicy(phi_mode=PHIMode.RAW)
    assert policy.phi_mode == PHIMode.RAW


def test_redact_mrn_hashes_value() -> None:
    from airsdk_pro.hl7.redaction import RedactionPolicy, redact_identifier
    policy = RedactionPolicy()
    result = redact_identifier("MRN-0042", policy)
    assert result != "MRN-0042"
    assert len(result) == 64  # BLAKE3 hex


def test_raw_mode_preserves_mrn() -> None:
    from airsdk_pro.hl7.redaction import PHIMode, RedactionPolicy, redact_identifier
    policy = RedactionPolicy(phi_mode=PHIMode.RAW)
    assert redact_identifier("MRN-0042", policy) == "MRN-0042"


def test_redact_dob_truncates_to_year() -> None:
    from airsdk_pro.hl7.redaction import RedactionPolicy, redact_dob
    policy = RedactionPolicy()
    assert redact_dob("1985-03-15", policy) == "1985"


def test_redact_dob_age_90_plus() -> None:
    from airsdk_pro.hl7.redaction import RedactionPolicy, redact_dob
    policy = RedactionPolicy()
    assert redact_dob("1930-06-01", policy) == "90+"


def test_redact_dob_raw_preserves() -> None:
    from airsdk_pro.hl7.redaction import PHIMode, RedactionPolicy, redact_dob
    policy = RedactionPolicy(phi_mode=PHIMode.RAW)
    assert redact_dob("1985-03-15", policy) == "1985-03-15"


def test_redact_mcid_strips_date_components() -> None:
    from airsdk_pro.hl7.redaction import RedactionPolicy, redact_mcid
    policy = RedactionPolicy()
    result = redact_mcid("20260511-0042")
    assert "20260511" not in result
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest packages/projectair-pro/tests/hl7/test_redaction.py -v
```

Expected: FAIL (modules not found)

- [ ] **Step 3: Implement the types and redaction modules**

Create `packages/projectair-pro/src/airsdk_pro/hl7/__init__.py`:

```python
"""HL7v2 + FHIR R4 clinical evidence sidecar (Pro)."""
```

Create `packages/projectair-pro/src/airsdk_pro/hl7/types.py`:

```python
"""Pydantic models for HL7v2 parsed segments."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class PatientIdentifier(BaseModel):
    model_config = ConfigDict(extra="forbid")
    value: str
    type_code: str
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
    value_type: str
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
    timestamp_precision: str
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
    pass


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
```

Create `packages/projectair-pro/src/airsdk_pro/hl7/redaction.py`:

```python
"""PHI redaction policy for clinical chains."""
from __future__ import annotations

import re
from datetime import date, datetime
from enum import StrEnum

import blake3
from pydantic import BaseModel, ConfigDict, Field, model_validator


class PHIMode(StrEnum):
    REDACTED = "redacted"
    RAW = "raw"


PHI_CLASS_FIELDS: frozenset[str] = frozenset({
    "mrn", "name", "family_name", "given_name", "date_of_birth",
    "ssn", "address", "phone", "email", "medical_record_number",
    "account_number", "visit_number", "device_serial",
})

_DATE_PATTERN = re.compile(r"\d{8}")


class RedactionPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    phi_mode: PHIMode = PHIMode.REDACTED
    baa_acknowledged: bool = True
    allowed_fields: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_phi_safety(self) -> RedactionPolicy:
        if not self.baa_acknowledged:
            raise ValueError(
                "baa_acknowledged must be True for clinical chains. "
                "All HL7v2 chains contain PHI-derived data regardless "
                "of redaction mode."
            )
        if self.phi_mode == PHIMode.REDACTED and self.allowed_fields:
            phi_leak = PHI_CLASS_FIELDS & set(self.allowed_fields)
            if phi_leak:
                raise ValueError(
                    f"allowed_fields contains PHI-class fields "
                    f"{sorted(phi_leak)} in REDACTED mode. Either "
                    f"switch to PHIMode.RAW or remove these fields."
                )
        return self


class PHIRedactionError(Exception):
    pass


def redact_identifier(value: str, policy: RedactionPolicy) -> str:
    if policy.phi_mode == PHIMode.RAW:
        return value
    return blake3.blake3(value.encode()).hexdigest()


def redact_dob(dob: str, policy: RedactionPolicy) -> str:
    if policy.phi_mode == PHIMode.RAW:
        return dob
    try:
        year = int(dob[:4])
    except (ValueError, IndexError):
        return ""
    current_year = date.today().year
    if current_year - year >= 90:
        return "90+"
    return str(year)


def redact_mcid(mcid: str) -> str:
    return _DATE_PATTERN.sub("XXXXXXXX", mcid)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest packages/projectair-pro/tests/hl7/test_redaction.py -v
```

Expected: all pass

- [ ] **Step 5: Commit**

```bash
git add packages/projectair-pro/src/airsdk_pro/hl7/ packages/projectair-pro/tests/hl7/
git commit -m "feat(hl7): add types and PHI redaction policy with BAA-always enforcement"
```

---

### Task 3: HL7v2 parser wrapper over vendored hl7apy

**Files:**
- Create: `packages/projectair-pro/src/airsdk_pro/hl7/parser.py`
- Create: `packages/projectair-pro/tests/hl7/test_parser.py`

- [ ] **Step 1: Write the failing tests**

Create `packages/projectair-pro/tests/hl7/test_parser.py`:

```python
"""Tests for HL7v2 parser wrapper."""
from __future__ import annotations

import pytest

from airsdk_pro.hl7.types import HL7v2ParseError

SAMPLE_ORU_R01 = (
    "MSH|^~\\&|LAB|HOSP-MAIN|AI-AGENT|VINDICARA|20260511120000||ORU^R01|MSG001|P|2.5\r"
    "PID|1||MRN-0042^^^HOSP-MAIN^MR~123-45-6789^^^SSA^SS||DOE^JANE||19850315|F\r"
    "OBR|1|ORD001|FIL001|14749-6^HbA1c^LN|||20260511\r"
    "OBX|1|NM|14749-6^HbA1c^LN||8.4|%|<7.0|H|||F\r"
    "OBX|2|NM|2345-7^Glucose^LN||186|mg/dL|74-106|H|||F\r"
    "OBX|3|ST|LOCAL001^Custom Test^LOCAL||Positive||||F\r"
)

SAMPLE_ADT_A01 = (
    "MSH|^~\\&|ADT|HOSP-MAIN|AI|VINDICARA|20260511||ADT^A01|MSG002|P|2.5\r"
    "PID|1||MRN-0042^^^HOSP-MAIN^MR||DOE^JANE||19850315|F\r"
    "PV1|1|I|5-EAST^501^A|||DR-CHEN^CHEN^SARAH\r"
)


def test_parse_oru_r01() -> None:
    from airsdk_pro.hl7.parser import parse_hl7v2
    msg = parse_hl7v2(SAMPLE_ORU_R01)
    assert msg.message_type == "ORU^R01"
    assert msg.sending_facility == "HOSP-MAIN"
    assert msg.message_control_id == "MSG001"
    assert msg.pid is not None
    assert msg.pid.primary_mrn == "MRN-0042"
    assert len(msg.pid.identifiers) == 2
    assert msg.pid.identifiers[0].type_code == "MR"
    assert msg.pid.identifiers[1].type_code == "SS"
    assert len(msg.obx) == 3
    assert msg.obx[0].value_type == "NM"
    assert msg.obx[0].value_numeric == 8.4
    assert msg.obx[0].observation_id_system == "LN"
    assert msg.obx[2].value_type == "ST"
    assert msg.obx[2].value_string == "Positive"
    assert msg.obx[2].observation_id_system == "LOCAL"


def test_parse_adt_a01() -> None:
    from airsdk_pro.hl7.parser import parse_hl7v2
    msg = parse_hl7v2(SAMPLE_ADT_A01)
    assert msg.message_type == "ADT^A01"
    assert msg.pv1 is not None
    assert msg.pv1.patient_class == "I"


def test_parse_multiple_pid_identifiers() -> None:
    from airsdk_pro.hl7.parser import parse_hl7v2
    msg = parse_hl7v2(SAMPLE_ORU_R01)
    assert len(msg.pid.identifiers) == 2
    mrn_id = msg.pid.identifiers[0]
    assert mrn_id.value == "MRN-0042"
    assert mrn_id.assigning_authority == "HOSP-MAIN"
    ssn_id = msg.pid.identifiers[1]
    assert ssn_id.value == "123-45-6789"
    assert ssn_id.type_code == "SS"


def test_parse_obx_code_system_local() -> None:
    from airsdk_pro.hl7.parser import parse_hl7v2
    msg = parse_hl7v2(SAMPLE_ORU_R01)
    local_obx = msg.obx[2]
    assert local_obx.observation_id == "LOCAL001"
    assert local_obx.observation_id_system == "LOCAL"


def test_parse_z_segments_preserved() -> None:
    from airsdk_pro.hl7.parser import parse_hl7v2
    raw = SAMPLE_ORU_R01 + "ZPM|1|EPIC_CUSTOM_FIELD|VALUE\r"
    msg = parse_hl7v2(raw)
    assert "ZPM" in msg.z_segments
    assert msg.z_segments["ZPM"][0][1] == "EPIC_CUSTOM_FIELD"


def test_parse_variable_precision_timestamp() -> None:
    from airsdk_pro.hl7.parser import parse_hl7v2
    msg = parse_hl7v2(SAMPLE_ORU_R01)
    assert msg.timestamp_precision == "second"
    assert "2026-05-11" in msg.timestamp


def test_parse_malformed_raises() -> None:
    from airsdk_pro.hl7.parser import parse_hl7v2
    with pytest.raises(HL7v2ParseError):
        parse_hl7v2("NOT A VALID HL7 MESSAGE")


def test_parse_missing_msh_raises() -> None:
    from airsdk_pro.hl7.parser import parse_hl7v2
    with pytest.raises(HL7v2ParseError):
        parse_hl7v2("PID|1||MRN-0042\r")
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest packages/projectair-pro/tests/hl7/test_parser.py -v
```

Expected: FAIL (parse_hl7v2 not found)

- [ ] **Step 3: Implement the parser wrapper**

Create `packages/projectair-pro/src/airsdk_pro/hl7/parser.py`:

```python
"""Thin Pydantic wrapper over vendored hl7apy."""
from __future__ import annotations

import re
from datetime import datetime

from airsdk_pro._vendor.hl7apy.core import Message as Hl7apyMessage
from airsdk_pro._vendor.hl7apy.parser import parse_message
from airsdk_pro.hl7.types import (
    HL7v2Message,
    HL7v2ParseError,
    MSHSegment,
    NK1Segment,
    OBRSegment,
    OBXSegment,
    ORCSegment,
    PatientIdentifier,
    PIDSegment,
    PV1Segment,
    TXASegment,
)

_TS_PRECISIONS = {
    4: "year", 6: "month", 8: "day",
    10: "hour", 12: "minute", 14: "second",
}


def _parse_timestamp(raw: str) -> tuple[str, str]:
    digits = re.match(r"(\d+)", raw)
    if not digits:
        return raw, "unknown"
    ts = digits.group(1)
    precision = "millisecond" if len(ts) > 14 else _TS_PRECISIONS.get(len(ts), "second")
    try:
        dt = datetime.strptime(ts[:14].ljust(14, "0"), "%Y%m%d%H%M%S")
        iso = dt.isoformat()
    except ValueError:
        iso = raw
    return iso, precision


def _parse_pid_identifiers(pid_segment: object) -> list[PatientIdentifier]:
    ids: list[PatientIdentifier] = []
    try:
        for cx in pid_segment.pid_3.children:
            value = str(cx.cx_1) if hasattr(cx, "cx_1") else str(cx)
            type_code = str(cx.cx_5) if hasattr(cx, "cx_5") else "MR"
            auth = str(cx.cx_4) if hasattr(cx, "cx_4") else ""
            ids.append(PatientIdentifier(
                value=value, type_code=type_code, assigning_authority=auth,
            ))
    except Exception:
        pass
    return ids


def _parse_obx(obx_seg: object, set_id: int) -> OBXSegment:
    vtype = str(getattr(obx_seg, "obx_2", "ST"))
    code_parts = str(getattr(obx_seg, "obx_3", "")).split("^")
    obs_id = code_parts[0] if code_parts else ""
    obs_text = code_parts[1] if len(code_parts) > 1 else ""
    obs_system = code_parts[2] if len(code_parts) > 2 else ""
    raw_value = str(getattr(obx_seg, "obx_5", ""))
    val_num = None
    val_str = None
    val_coded = None
    val_coded_sys = None
    val_coded_text = None
    val_dt = None
    if vtype in ("NM", "SN"):
        try:
            val_num = float(raw_value)
        except ValueError:
            val_str = raw_value
    elif vtype == "CWE":
        cwe_parts = raw_value.split("^")
        val_coded = cwe_parts[0] if cwe_parts else raw_value
        val_coded_text = cwe_parts[1] if len(cwe_parts) > 1 else None
        val_coded_sys = cwe_parts[2] if len(cwe_parts) > 2 else None
    elif vtype in ("TS", "DT"):
        val_dt = raw_value
    else:
        val_str = raw_value

    return OBXSegment(
        set_id=set_id,
        value_type=vtype,
        observation_id=obs_id,
        observation_id_system=obs_system,
        observation_id_text=obs_text,
        value_numeric=val_num,
        value_string=val_str,
        value_coded=val_coded,
        value_coded_system=val_coded_sys,
        value_coded_text=val_coded_text,
        value_datetime=val_dt,
        units=str(getattr(obx_seg, "obx_6", None) or ""),
        reference_range=str(getattr(obx_seg, "obx_7", None) or ""),
        abnormal_flags=str(getattr(obx_seg, "obx_8", None) or ""),
        observation_status=str(getattr(obx_seg, "obx_11", None) or ""),
    )


def parse_hl7v2(raw: str) -> HL7v2Message:
    """Parse a raw HL7v2 pipe-delimited message."""
    if not raw.strip().startswith("MSH"):
        raise HL7v2ParseError("Message must start with MSH segment")
    try:
        msg = parse_message(raw.strip(), find_groups=False)
    except Exception as exc:
        raise HL7v2ParseError(f"hl7apy parse failed: {exc}") from exc

    msh = msg.msh
    raw_ts = str(getattr(msh, "msh_7", ""))
    iso_ts, precision = _parse_timestamp(raw_ts)
    msg_type = str(getattr(msh, "msh_9", ""))
    char_set = str(getattr(msh, "msh_18", "ASCII") or "ASCII")

    pid_segment = None
    if hasattr(msg, "pid"):
        pid = msg.pid
        identifiers = _parse_pid_identifiers(pid)
        primary = next((i.value for i in identifiers if i.type_code == "MR"), None)
        name_parts = str(getattr(pid, "pid_5", "")).split("^")
        pid_segment = PIDSegment(
            identifiers=identifiers,
            primary_mrn=primary,
            family_name=name_parts[0] if name_parts else None,
            given_name=name_parts[1] if len(name_parts) > 1 else None,
            date_of_birth=str(getattr(pid, "pid_7", None) or ""),
            gender=str(getattr(pid, "pid_8", None) or ""),
        )

    pv1_segment = None
    if hasattr(msg, "pv1"):
        pv1 = msg.pv1
        pv1_segment = PV1Segment(
            patient_class=str(getattr(pv1, "pv1_2", "")),
            assigned_location=str(getattr(pv1, "pv1_3", "")),
            attending_doctor=str(getattr(pv1, "pv1_7", "")),
        )

    obx_list: list[OBXSegment] = []
    for idx, obx in enumerate(getattr(msg, "obx", []), start=1):
        obx_list.append(_parse_obx(obx, idx))

    orc_segment = None
    if hasattr(msg, "orc"):
        orc = msg.orc
        orc_segment = ORCSegment(
            order_control=str(getattr(orc, "orc_1", "")),
            order_number=str(getattr(orc, "orc_2", "")),
            order_status=str(getattr(orc, "orc_5", "")),
            ordering_provider=str(getattr(orc, "orc_12", "")),
        )

    obr_segment = None
    if hasattr(msg, "obr"):
        obr = msg.obr
        obr_segment = OBRSegment(
            placer_order_number=str(getattr(obr, "obr_2", "")),
            filler_order_number=str(getattr(obr, "obr_3", "")),
            universal_service_id=str(getattr(obr, "obr_4", "")),
            ordering_provider=str(getattr(obr, "obr_16", "")),
        )

    z_segs: dict[str, list[list[str]]] = {}
    for seg in raw.strip().split("\r"):
        seg_id = seg[:3]
        if seg_id.startswith("Z"):
            fields = seg.split("|")
            z_segs.setdefault(seg_id, []).append(fields[1:])

    return HL7v2Message(
        raw=raw,
        message_type=msg_type,
        message_control_id=str(getattr(msh, "msh_10", "")),
        timestamp=iso_ts,
        timestamp_precision=precision,
        sending_facility=str(getattr(msh, "msh_4", "")),
        receiving_facility=str(getattr(msh, "msh_6", "")),
        character_set=char_set,
        msh=MSHSegment(
            sending_facility=str(getattr(msh, "msh_4", "")),
            receiving_facility=str(getattr(msh, "msh_6", "")),
            datetime=raw_ts,
            message_type=msg_type,
            message_control_id=str(getattr(msh, "msh_10", "")),
            character_set=char_set,
        ),
        pid=pid_segment,
        pv1=pv1_segment,
        obx=obx_list,
        orc=orc_segment,
        obr=obr_segment,
        z_segments=z_segs,
    )
```

Note: the hl7apy attribute access patterns (`msh_7`, `pid_3`, `obx_2`, etc.) are hl7apy's standard segment-field accessors. The actual field names depend on the vendored version; adjust if needed after Step 4.

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest packages/projectair-pro/tests/hl7/test_parser.py -v
```

Expected: all pass. If hl7apy attribute access patterns differ from expected, adjust the parser wrapper to match the vendored version's API.

- [ ] **Step 5: Commit**

```bash
git add packages/projectair-pro/src/airsdk_pro/hl7/parser.py packages/projectair-pro/tests/hl7/test_parser.py
git commit -m "feat(hl7): add HL7v2 parser wrapper over vendored hl7apy"
```

---

### Task 4: FHIR R4 resource mapping

**Files:**
- Create: `packages/projectair-pro/src/airsdk_pro/hl7/fhir.py`
- Create: `packages/projectair-pro/tests/hl7/test_fhir.py`

- [ ] **Step 1: Write the failing tests**

Create `packages/projectair-pro/tests/hl7/test_fhir.py`:

```python
"""Tests for HL7v2 -> FHIR R4 mapping."""
from __future__ import annotations

from airsdk_pro.hl7.test_parser import SAMPLE_ORU_R01


def test_map_produces_patient() -> None:
    from airsdk_pro.hl7.fhir import map_to_fhir
    from airsdk_pro.hl7.parser import parse_hl7v2
    msg = parse_hl7v2(SAMPLE_ORU_R01)
    resources = map_to_fhir(msg)
    patients = [r for r in resources if r.resource_type == "Patient"]
    assert len(patients) == 1


def test_map_produces_observations() -> None:
    from airsdk_pro.hl7.fhir import map_to_fhir
    from airsdk_pro.hl7.parser import parse_hl7v2
    msg = parse_hl7v2(SAMPLE_ORU_R01)
    resources = map_to_fhir(msg)
    obs = [r for r in resources if r.resource_type == "Observation"]
    assert len(obs) == 3


def test_code_system_loinc_normalized() -> None:
    from airsdk_pro.hl7.fhir import normalize_code_system
    assert normalize_code_system("LN") == "http://loinc.org"
    assert normalize_code_system("LOINC") == "http://loinc.org"


def test_code_system_snomed_normalized() -> None:
    from airsdk_pro.hl7.fhir import normalize_code_system
    assert normalize_code_system("SCT") == "http://snomed.info/sct"


def test_code_system_local_passthrough() -> None:
    from airsdk_pro.hl7.fhir import normalize_code_system
    result = normalize_code_system("LOCAL")
    assert "LOCAL" in result


def test_redacted_patient_hashes_mrn() -> None:
    from airsdk_pro.hl7.fhir import map_to_fhir
    from airsdk_pro.hl7.parser import parse_hl7v2
    from airsdk_pro.hl7.redaction import RedactionPolicy
    msg = parse_hl7v2(SAMPLE_ORU_R01)
    resources = map_to_fhir(msg, redaction_policy=RedactionPolicy())
    patient = [r for r in resources if r.resource_type == "Patient"][0]
    assert patient.identifier[0].value != "MRN-0042"
    assert len(patient.identifier[0].value) == 64


def test_chain_projection_strips_extra_fields() -> None:
    from airsdk_pro.hl7.fhir import map_to_fhir, project_for_chain
    from airsdk_pro.hl7.parser import parse_hl7v2
    msg = parse_hl7v2(SAMPLE_ORU_R01)
    resources = map_to_fhir(msg)
    projections = [project_for_chain(r) for r in resources]
    for p in projections:
        assert "resourceType" in p
        assert "id" in p
```

- [ ] **Step 2: Run to verify failure**

```bash
pytest packages/projectair-pro/tests/hl7/test_fhir.py -v
```

- [ ] **Step 3: Implement FHIR mapping**

Create `packages/projectair-pro/src/airsdk_pro/hl7/fhir.py`:

```python
"""HL7v2 segment -> FHIR R4 resource mapping."""
from __future__ import annotations

from typing import Any
from uuid import uuid4

from fhir.resources.observation import Observation
from fhir.resources.patient import Patient

from airsdk_pro.hl7.redaction import RedactionPolicy, redact_dob, redact_identifier
from airsdk_pro.hl7.types import HL7v2Message, OBXSegment

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


def normalize_code_system(raw: str) -> str:
    return _CODE_SYSTEMS.get(raw.upper(), f"{_LOCAL_SYSTEM}:{raw}")


class MappedResource:
    """Wrapper holding a fhir.resources model for chain projection."""

    def __init__(self, resource: Any) -> None:
        self._resource = resource

    @property
    def resource_type(self) -> str:
        return self._resource.resource_type

    @property
    def identifier(self) -> Any:
        return getattr(self._resource, "identifier", [])

    def to_dict(self) -> dict[str, Any]:
        return self._resource.dict(exclude_none=True)


def _map_patient(
    msg: HL7v2Message,
    policy: RedactionPolicy | None,
) -> MappedResource | None:
    if msg.pid is None:
        return None
    pid = msg.pid
    p = policy or RedactionPolicy()
    identifiers = []
    for ident in pid.identifiers:
        identifiers.append({
            "value": redact_identifier(ident.value, p),
            "type": {"coding": [{"code": ident.type_code}]},
            "assigner": {"display": ident.assigning_authority} if ident.assigning_authority else None,
        })
    patient_data: dict[str, Any] = {
        "resourceType": "Patient",
        "id": str(uuid4()),
        "identifier": identifiers,
        "gender": pid.gender.lower() if pid.gender else None,
    }
    if p.phi_mode.value == "raw":
        if pid.family_name or pid.given_name:
            patient_data["name"] = [{"family": pid.family_name, "given": [pid.given_name] if pid.given_name else []}]
        if pid.date_of_birth:
            patient_data["birthDate"] = pid.date_of_birth
    else:
        if pid.date_of_birth:
            patient_data["birthDate"] = redact_dob(pid.date_of_birth, p)
    return MappedResource(Patient.parse_obj(patient_data))


def _map_obx(obx: OBXSegment, subject_ref: str | None) -> MappedResource:
    code_system = normalize_code_system(obx.observation_id_system)
    obs_data: dict[str, Any] = {
        "resourceType": "Observation",
        "id": str(uuid4()),
        "status": obx.observation_status or "final",
        "code": {
            "coding": [{
                "system": code_system,
                "code": obx.observation_id,
                "display": obx.observation_id_text,
            }],
        },
    }
    if subject_ref:
        obs_data["subject"] = {"reference": subject_ref}
    if obx.value_numeric is not None:
        obs_data["valueQuantity"] = {
            "value": obx.value_numeric,
            "unit": obx.units or "",
        }
    elif obx.value_coded:
        obs_data["valueCodeableConcept"] = {
            "coding": [{
                "code": obx.value_coded,
                "system": normalize_code_system(obx.value_coded_system or ""),
                "display": obx.value_coded_text or "",
            }],
        }
    elif obx.value_string:
        obs_data["valueString"] = obx.value_string
    elif obx.value_datetime:
        obs_data["valueDateTime"] = obx.value_datetime
    return MappedResource(Observation.parse_obj(obs_data))


def map_to_fhir(
    message: HL7v2Message,
    *,
    redaction_policy: RedactionPolicy | None = None,
) -> list[MappedResource]:
    resources: list[MappedResource] = []
    patient = _map_patient(message, redaction_policy)
    subject_ref = None
    if patient:
        resources.append(patient)
        subject_ref = f"Patient/{patient.to_dict()['id']}"
    for obx in message.obx:
        resources.append(_map_obx(obx, subject_ref))
    return resources


def project_for_chain(resource: MappedResource) -> dict[str, Any]:
    d = resource.to_dict()
    return {k: v for k, v in d.items() if v is not None}
```

- [ ] **Step 4: Run tests**

```bash
pytest packages/projectair-pro/tests/hl7/test_fhir.py -v
```

- [ ] **Step 5: Commit**

```bash
git add packages/projectair-pro/src/airsdk_pro/hl7/fhir.py packages/projectair-pro/tests/hl7/test_fhir.py
git commit -m "feat(hl7): add FHIR R4 resource mapping with code system normalization"
```

---

### Task 5: Capsule capture (instrument_hl7)

**Files:**
- Create: `packages/projectair-pro/src/airsdk_pro/hl7/capture.py`
- Create: `packages/projectair-pro/tests/hl7/test_capture.py`
- Modify: `packages/projectair/src/airsdk/types.py` (add hl7v2 payload fields)

- [ ] **Step 1: Add AgDR payload fields (OSS)**

In `packages/projectair/src/airsdk/types.py`, add to `AgDRPayload` class (after `data_subjects`):

```python
hl7v2_message_type: str | None = None
hl7v2_segments: dict[str, Any] | None = None
fhir_resources: list[dict[str, Any]] | None = None
```

- [ ] **Step 2: Write failing capture tests**

Create `packages/projectair-pro/tests/hl7/test_capture.py`:

```python
"""Tests for HL7v2 capsule capture."""
from __future__ import annotations

import tempfile
from pathlib import Path

from airsdk.agdr import verify_chain, load_chain
from airsdk.recorder import AIRRecorder
from airsdk_pro.hl7.test_parser import SAMPLE_ORU_R01


def test_instrument_hl7_writes_two_records(tmp_path: Path) -> None:
    from airsdk_pro.hl7.capture import instrument_hl7
    from airsdk_pro.hl7.redaction import RedactionPolicy
    rec = AIRRecorder(tmp_path / "chain.jsonl")
    policy = RedactionPolicy()
    start, end = instrument_hl7(rec, SAMPLE_ORU_R01, redaction_policy=policy)
    assert start.kind.value == "tool_start"
    assert end.kind.value == "tool_end"


def test_chain_verifies_after_capture(tmp_path: Path) -> None:
    from airsdk_pro.hl7.capture import instrument_hl7
    from airsdk_pro.hl7.redaction import RedactionPolicy
    rec = AIRRecorder(tmp_path / "chain.jsonl")
    instrument_hl7(rec, SAMPLE_ORU_R01, redaction_policy=RedactionPolicy())
    chain = load_chain(tmp_path / "chain.jsonl")
    result = verify_chain(chain)
    assert result.status.value == "ok"


def test_capture_auto_tags_data_subject(tmp_path: Path) -> None:
    from airsdk_pro.hl7.capture import instrument_hl7
    from airsdk_pro.hl7.redaction import RedactionPolicy
    rec = AIRRecorder(tmp_path / "chain.jsonl")
    start, _ = instrument_hl7(rec, SAMPLE_ORU_R01, redaction_policy=RedactionPolicy())
    assert start.payload.data_subjects is not None
    assert len(start.payload.data_subjects) >= 1
    assert start.payload.data_subjects[0].jurisdiction == "HIPAA"


def test_capture_includes_fhir_resources(tmp_path: Path) -> None:
    from airsdk_pro.hl7.capture import instrument_hl7
    from airsdk_pro.hl7.redaction import RedactionPolicy
    rec = AIRRecorder(tmp_path / "chain.jsonl")
    start, _ = instrument_hl7(rec, SAMPLE_ORU_R01, redaction_policy=RedactionPolicy())
    assert start.payload.fhir_resources is not None
    assert len(start.payload.fhir_resources) >= 1


def test_capture_redacts_mrn_by_default(tmp_path: Path) -> None:
    from airsdk_pro.hl7.capture import instrument_hl7
    from airsdk_pro.hl7.redaction import RedactionPolicy
    rec = AIRRecorder(tmp_path / "chain.jsonl")
    start, _ = instrument_hl7(rec, SAMPLE_ORU_R01, redaction_policy=RedactionPolicy())
    assert start.payload.hl7v2_segments is not None
    pid_data = start.payload.hl7v2_segments.get("pid", {})
    if "primary_mrn" in pid_data:
        assert pid_data["primary_mrn"] != "MRN-0042"
```

- [ ] **Step 3: Implement capture**

Create `packages/projectair-pro/src/airsdk_pro/hl7/capture.py`:

```python
"""HL7v2 capsule capture with PHI redaction."""
from __future__ import annotations

from airsdk.recorder import AIRRecorder
from airsdk.types import AgDRRecord, DataAssetRef, DataSubjectRef

from airsdk_pro.gate import requires_pro
from airsdk_pro.hl7.fhir import map_to_fhir, project_for_chain
from airsdk_pro.hl7.parser import parse_hl7v2
from airsdk_pro.hl7.redaction import (
    PHIMode,
    RedactionPolicy,
    redact_identifier,
    redact_mcid,
)

HL7_FHIR_FEATURE = "hl7-fhir-integration"


@requires_pro(feature=HL7_FHIR_FEATURE)
def instrument_hl7(
    recorder: AIRRecorder,
    raw_message: str,
    *,
    map_fhir: bool = True,
    redaction_policy: RedactionPolicy | None = None,
    data_subjects: list[DataSubjectRef] | None = None,
) -> tuple[AgDRRecord, AgDRRecord]:
    policy = redaction_policy or RedactionPolicy()
    message = parse_hl7v2(raw_message)

    if data_subjects is None and message.pid and message.pid.primary_mrn:
        mrn = redact_identifier(message.pid.primary_mrn, policy)
        data_subjects = [
            DataSubjectRef(
                subject_id=mrn,
                subject_type="patient",
                jurisdiction="HIPAA",
            ),
        ]

    fhir_dicts = None
    if map_fhir:
        resources = map_to_fhir(message, redaction_policy=policy)
        fhir_dicts = [project_for_chain(r) for r in resources]

    segments_dict = _redact_segments(message, policy)

    start = recorder.tool_start(
        tool_name="hl7v2_receive",
        tool_args={
            "message_type": message.message_type,
            "sending_facility": message.sending_facility,
            "message_control_id": redact_mcid(message.message_control_id),
        },
        data_subjects=data_subjects,
        hl7v2_message_type=message.message_type,
        hl7v2_segments=segments_dict,
        fhir_resources=fhir_dicts,
    )

    ack = f"MSH|^~\\&|AIR|VINDICARA|||{message.timestamp}||ACK|{message.message_control_id}|P|2.5\rMSA|AA|{message.message_control_id}"
    end = recorder.tool_end(tool_output=ack)
    return start, end


def _redact_segments(
    message: HL7v2Message,
    policy: RedactionPolicy,
) -> dict:
    from airsdk_pro.hl7.types import HL7v2Message
    d = message.model_dump(exclude={"raw"})
    if policy.phi_mode == PHIMode.REDACTED and message.pid:
        pid = d.get("pid", {})
        if pid.get("primary_mrn"):
            pid["primary_mrn"] = redact_identifier(message.pid.primary_mrn, policy)
        for ident in pid.get("identifiers", []):
            ident["value"] = redact_identifier(ident["value"], policy)
        pid.pop("family_name", None)
        pid.pop("given_name", None)
        if pid.get("date_of_birth"):
            from airsdk_pro.hl7.redaction import redact_dob
            pid["date_of_birth"] = redact_dob(pid["date_of_birth"], policy)
    return d
```

- [ ] **Step 4: Run tests**

```bash
pytest packages/projectair-pro/tests/hl7/test_capture.py -v
```

Note: `recorder.tool_start` may not accept `hl7v2_message_type` etc. as kwargs directly. If the current `AIRRecorder.tool_start` signature uses `**extra`, these will pass through to `AgDRPayload`. If not, use the `**extra` pattern in the recorder.

- [ ] **Step 5: Commit**

```bash
git add packages/projectair/src/airsdk/types.py packages/projectair-pro/src/airsdk_pro/hl7/capture.py packages/projectair-pro/tests/hl7/test_capture.py
git commit -m "feat(hl7): add capsule capture with PHI redaction and FHIR mapping"
```

---

### Task 6: EntityScope for intent capsule patient scope

**Files:**
- Modify: `packages/projectair/src/airsdk/types.py` (add EntityScope, extend IntentSpec)
- Create: `packages/projectair/tests/verification/test_entity_scope.py`
- Modify: `packages/projectair/src/airsdk/verification/checks/entity.py` (support EntityScope)

- [ ] **Step 1: Write failing tests**

Create `packages/projectair/tests/verification/test_entity_scope.py`:

```python
"""Tests for EntityScope-based entity verification."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from airsdk.types import EntityScope, IntentSpec


def test_entity_scope_static() -> None:
    scope = EntityScope(scope_type="static")
    assert scope.scope_type == "static"


def test_entity_scope_facility() -> None:
    scope = EntityScope(
        scope_type="facility",
        facility="HOSP-MAIN",
        unit="5-EAST",
        time_window_hours=12,
    )
    assert scope.facility == "HOSP-MAIN"


def test_intent_spec_entities_and_scope_exclusive() -> None:
    with pytest.raises(ValidationError, match="mutually exclusive"):
        IntentSpec(
            goal="test",
            allowed_entities=["MRN-0042"],
            entity_scope=EntityScope(scope_type="facility", facility="X"),
        )


def test_facility_scope_matches_facility() -> None:
    from airsdk_pro.hl7.types import HL7v2Message
    scope = EntityScope(
        scope_type="facility",
        facility="HOSP-MAIN",
    )
    assert scope.matches_facility("HOSP-MAIN")
    assert not scope.matches_facility("OTHER-HOSP")
```

- [ ] **Step 2: Add EntityScope to types.py**

In `packages/projectair/src/airsdk/types.py`, add before `IntentSpec`:

```python
class EntityScope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scope_type: str
    facility: str | None = None
    unit: str | None = None
    time_window_hours: int | None = None
    roster_source: str | None = None
    refresh_interval_seconds: int = 300
    predicate: str | None = None

    def matches_facility(self, facility: str) -> bool:
        if self.scope_type != "facility":
            return True
        return self.facility is not None and self.facility == facility
```

Extend `IntentSpec` to add `entity_scope` with mutual exclusivity validator:

```python
class IntentSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    goal: str
    allowed_tools: list[str] = Field(default_factory=list)
    allowed_paths: list[str] = Field(default_factory=list)
    allowed_network: list[str] = Field(default_factory=list)
    allowed_entities: list[str] = Field(default_factory=list)
    entity_scope: EntityScope | None = None
    secret_access: bool = False
    non_goals: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_scope_exclusivity(self) -> IntentSpec:
        if self.allowed_entities and self.entity_scope:
            raise ValueError(
                "allowed_entities and entity_scope are mutually exclusive. "
                "Use allowed_entities for static lists or entity_scope for "
                "facility/roster/predicate scoping."
            )
        return self
```

- [ ] **Step 3: Run tests**

```bash
pytest packages/projectair/tests/verification/test_entity_scope.py -v
```

- [ ] **Step 4: Commit**

```bash
git add packages/projectair/src/airsdk/types.py packages/projectair/tests/verification/test_entity_scope.py
git commit -m "feat: add EntityScope for facility/roster/predicate patient scoping"
```

---

### Task 7: FHIR R4 server push client

**Files:**
- Create: `packages/projectair-pro/src/airsdk_pro/hl7/fhir_client.py`
- Create: `packages/projectair-pro/tests/hl7/test_fhir_client.py`

- [ ] **Step 1: Write failing tests**

Create `packages/projectair-pro/tests/hl7/test_fhir_client.py`:

```python
"""Tests for FHIR R4 server push client."""
from __future__ import annotations

from unittest.mock import MagicMock

import httpx
import pytest

from airsdk_pro.hl7.types import FHIRPushResult


def test_push_bundle_success() -> None:
    from airsdk_pro.hl7.fhir_client import FHIRClient
    mock_response = httpx.Response(200, json={"resourceType": "Bundle", "type": "transaction-response", "entry": [{"response": {"status": "201"}}]})
    transport = httpx.MockTransport(lambda req: mock_response)
    client = FHIRClient("http://localhost:8080/fhir", client=httpx.Client(transport=transport))
    result = client.push_bundle([{"resourceType": "Patient", "id": "test-1"}])
    assert result.success
    assert result.resources_created == 1


def test_push_bundle_auth_failure_retries() -> None:
    from airsdk_pro.hl7.fhir_client import FHIRClient
    call_count = 0

    def handler(req: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return httpx.Response(401)
        return httpx.Response(200, json={"resourceType": "Bundle", "type": "transaction-response", "entry": []})

    transport = httpx.MockTransport(handler)
    client = FHIRClient("http://localhost:8080/fhir", client=httpx.Client(transport=transport))
    result = client.push_bundle([])
    assert result.success
    assert call_count == 2


def test_push_bundle_returns_failure_on_500() -> None:
    from airsdk_pro.hl7.fhir_client import FHIRClient
    transport = httpx.MockTransport(lambda req: httpx.Response(500, text="Internal Server Error"))
    client = FHIRClient("http://localhost:8080/fhir", client=httpx.Client(transport=transport))
    result = client.push_bundle([{"resourceType": "Patient", "id": "test-1"}])
    assert not result.success
    assert result.status_code == 500
```

- [ ] **Step 2: Implement FHIR client**

Create `packages/projectair-pro/src/airsdk_pro/hl7/fhir_client.py`:

```python
"""FHIR R4 server push client with SMART on FHIR auth."""
from __future__ import annotations

from typing import Any

import httpx

from airsdk_pro.gate import requires_pro
from airsdk_pro.hl7.types import FHIRPushResult

HL7_FHIR_FEATURE = "hl7-fhir-integration"


class FHIRClient:
    def __init__(
        self,
        fhir_url: str,
        *,
        client_id: str | None = None,
        client_secret: str | None = None,
        token_url: str | None = None,
        scopes: list[str] | None = None,
        timeout: float = 30.0,
        client: httpx.Client | None = None,
    ) -> None:
        self._fhir_url = fhir_url.rstrip("/")
        self._client_id = client_id
        self._client_secret = client_secret
        self._token_url = token_url
        self._scopes = scopes or []
        self._timeout = timeout
        self._client = client or httpx.Client(timeout=timeout)
        self._token: str | None = None

    def _get_token(self) -> str | None:
        if not self._token_url or not self._client_id:
            return None
        resp = self._client.post(
            self._token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret or "",
                "scope": " ".join(self._scopes),
            },
        )
        resp.raise_for_status()
        self._token = resp.json()["access_token"]
        return self._token

    def _headers(self) -> dict[str, str]:
        h: dict[str, str] = {"Content-Type": "application/fhir+json"}
        if self._token:
            h["Authorization"] = f"Bearer {self._token}"
        return h

    @requires_pro(feature=HL7_FHIR_FEATURE)
    def push_bundle(
        self,
        resources: list[dict[str, Any]],
    ) -> FHIRPushResult:
        bundle = {
            "resourceType": "Bundle",
            "type": "transaction",
            "entry": [
                {
                    "resource": r,
                    "request": {
                        "method": "POST",
                        "url": r.get("resourceType", ""),
                    },
                }
                for r in resources
            ],
        }
        resp = self._client.post(
            self._fhir_url,
            json=bundle,
            headers=self._headers(),
        )
        if resp.status_code == 401:
            self._get_token()
            resp = self._client.post(
                self._fhir_url,
                json=bundle,
                headers=self._headers(),
            )
        if resp.status_code >= 400:
            return FHIRPushResult(
                success=False,
                status_code=resp.status_code,
                error=resp.text[:500],
            )
        body = resp.json()
        entries = body.get("entry", [])
        created = sum(
            1 for e in entries
            if e.get("response", {}).get("status", "").startswith("201")
        )
        return FHIRPushResult(
            success=True,
            status_code=resp.status_code,
            resources_created=created,
            resources_failed=len(resources) - created,
        )
```

- [ ] **Step 3: Run tests**

```bash
pytest packages/projectair-pro/tests/hl7/test_fhir_client.py -v
```

- [ ] **Step 4: Commit**

```bash
git add packages/projectair-pro/src/airsdk_pro/hl7/fhir_client.py packages/projectair-pro/tests/hl7/test_fhir_client.py
git commit -m "feat(hl7): add FHIR R4 server push client with SMART on FHIR auth"
```

---

### Task 8: HTTP receiver and MLLP listener

**Files:**
- Create: `packages/projectair-pro/src/airsdk_pro/hl7/http.py`
- Create: `packages/projectair-pro/src/airsdk_pro/hl7/mllp.py`
- Create: `packages/projectair-pro/tests/hl7/test_http.py`
- Create: `packages/projectair-pro/tests/hl7/test_mllp.py`

- [ ] **Step 1: Write failing HTTP tests**

Create `packages/projectair-pro/tests/hl7/test_http.py`:

```python
"""Tests for HL7v2 HTTP receiver."""
from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from fastapi import FastAPI

from airsdk.recorder import AIRRecorder
from airsdk_pro.hl7.test_parser import SAMPLE_ORU_R01


@pytest.fixture
def app_with_hl7(tmp_path: Path) -> FastAPI:
    from airsdk_pro.hl7.http import create_hl7_router
    from airsdk_pro.hl7.redaction import RedactionPolicy
    app = FastAPI()
    rec = AIRRecorder(tmp_path / "chain.jsonl")
    router = create_hl7_router(rec, redaction_policy=RedactionPolicy())
    app.include_router(router, prefix="/clinical")
    return app


@pytest.mark.asyncio
async def test_post_valid_message_returns_aa(app_with_hl7: FastAPI) -> None:
    async with AsyncClient(transport=ASGITransport(app=app_with_hl7), base_url="http://test") as client:
        resp = await client.post(
            "/clinical/hl7v2/ingest",
            content=SAMPLE_ORU_R01,
            headers={"Content-Type": "application/hl7-v2"},
        )
    assert resp.status_code == 200
    assert "MSA|AA" in resp.text


@pytest.mark.asyncio
async def test_post_malformed_returns_ar(app_with_hl7: FastAPI) -> None:
    async with AsyncClient(transport=ASGITransport(app=app_with_hl7), base_url="http://test") as client:
        resp = await client.post(
            "/clinical/hl7v2/ingest",
            content="NOT A VALID MESSAGE",
            headers={"Content-Type": "application/hl7-v2"},
        )
    assert resp.status_code == 400
    assert "MSA|AR" in resp.text
```

- [ ] **Step 2: Write failing MLLP tests**

Create `packages/projectair-pro/tests/hl7/test_mllp.py`:

```python
"""Tests for MLLP TCP listener."""
from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

import pytest

from airsdk.recorder import AIRRecorder

MLLP_START = b"\x0b"
MLLP_END = b"\x1c\x0d"


def _frame(message: str) -> bytes:
    return MLLP_START + message.encode() + MLLP_END


@pytest.mark.asyncio
async def test_mllp_accepts_framed_message(tmp_path: Path) -> None:
    from airsdk_pro.hl7.mllp import MLLPListener
    from airsdk_pro.hl7.redaction import RedactionPolicy
    from airsdk_pro.hl7.test_parser import SAMPLE_ORU_R01

    rec = AIRRecorder(tmp_path / "chain.jsonl")
    listener = MLLPListener(
        host="127.0.0.1",
        port=0,
        recorder=rec,
        redaction_policy=RedactionPolicy(),
    )
    await listener.start()
    port = listener.port

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(_frame(SAMPLE_ORU_R01))
    await writer.drain()
    response = await asyncio.wait_for(reader.read(4096), timeout=5.0)
    writer.close()
    await writer.wait_closed()
    await listener.stop()

    ack_text = response.decode(errors="replace")
    assert "MSA|AA" in ack_text


@pytest.mark.asyncio
async def test_mllp_rejects_unframed(tmp_path: Path) -> None:
    from airsdk_pro.hl7.mllp import MLLPListener
    from airsdk_pro.hl7.redaction import RedactionPolicy

    rec = AIRRecorder(tmp_path / "chain.jsonl")
    listener = MLLPListener(
        host="127.0.0.1", port=0, recorder=rec,
        redaction_policy=RedactionPolicy(),
    )
    await listener.start()
    port = listener.port

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"NOT FRAMED")
    await writer.drain()
    await asyncio.sleep(0.5)
    writer.close()
    await writer.wait_closed()
    await listener.stop()
```

- [ ] **Step 3: Implement HTTP receiver**

Create `packages/projectair-pro/src/airsdk_pro/hl7/http.py`:

```python
"""HTTP endpoint for HL7v2 message ingestion."""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, Request, Response

from airsdk.recorder import AIRRecorder
from airsdk_pro.hl7.capture import instrument_hl7
from airsdk_pro.hl7.redaction import RedactionPolicy
from airsdk_pro.hl7.types import HL7v2ParseError


def create_hl7_router(
    recorder: AIRRecorder,
    *,
    pipeline_queue: asyncio.Queue | None = None,
    redaction_policy: RedactionPolicy | None = None,
) -> APIRouter:
    router = APIRouter()
    policy = redaction_policy or RedactionPolicy()

    @router.post("/hl7v2/ingest")
    async def ingest(request: Request) -> Response:
        body = (await request.body()).decode(errors="replace")
        try:
            start, end = instrument_hl7(
                recorder, body, redaction_policy=policy,
            )
        except HL7v2ParseError as exc:
            nak = f"MSH|^~\\&|AIR|VINDICARA||||||ACK||P|2.5\rMSA|AR||{exc}"
            return Response(content=nak, status_code=400, media_type="application/hl7-v2")

        mcid = start.payload.tool_args.get("message_control_id", "") if start.payload.tool_args else ""
        ack = f"MSH|^~\\&|AIR|VINDICARA||||||ACK|{mcid}|P|2.5\rMSA|AA|{mcid}"
        return Response(content=ack, status_code=200, media_type="application/hl7-v2")

    return router
```

- [ ] **Step 4: Implement MLLP listener**

Create `packages/projectair-pro/src/airsdk_pro/hl7/mllp.py`:

```python
"""MLLP (Minimum Lower Layer Protocol) TCP listener."""
from __future__ import annotations

import asyncio
from typing import Any

from airsdk.recorder import AIRRecorder
from airsdk_pro.hl7.capture import instrument_hl7
from airsdk_pro.hl7.redaction import RedactionPolicy
from airsdk_pro.hl7.types import HL7v2ParseError

MLLP_START = b"\x0b"
MLLP_END = b"\x1c\x0d"


class MLLPListener:
    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 2575,
        recorder: AIRRecorder | None = None,
        pipeline_queue: asyncio.Queue | None = None,
        redaction_policy: RedactionPolicy | None = None,
    ) -> None:
        self._host = host
        self._port = port
        self._recorder = recorder
        self._policy = redaction_policy or RedactionPolicy()
        self._server: asyncio.Server | None = None

    @property
    def port(self) -> int:
        if self._server and self._server.sockets:
            return self._server.sockets[0].getsockname()[1]
        return self._port

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_connection, self._host, self._port,
        )

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            while True:
                data = await asyncio.wait_for(reader.read(1024 * 1024), timeout=300.0)
                if not data:
                    break
                if not data.startswith(MLLP_START) or MLLP_END not in data:
                    continue
                start_idx = data.index(MLLP_START) + 1
                end_idx = data.index(MLLP_END)
                message = data[start_idx:end_idx].decode(errors="replace")
                try:
                    if self._recorder:
                        instrument_hl7(
                            self._recorder, message,
                            redaction_policy=self._policy,
                        )
                    mcid = ""
                    for line in message.split("\r"):
                        if line.startswith("MSH"):
                            fields = line.split("|")
                            if len(fields) > 9:
                                mcid = fields[9]
                            break
                    ack = f"MSH|^~\\&|AIR|VINDICARA||||||ACK|{mcid}|P|2.5\rMSA|AA|{mcid}"
                except HL7v2ParseError:
                    ack = "MSH|^~\\&|AIR|VINDICARA||||||ACK||P|2.5\rMSA|AR|"

                writer.write(MLLP_START + ack.encode() + MLLP_END)
                await writer.drain()
        except (asyncio.TimeoutError, ConnectionResetError):
            pass
        finally:
            writer.close()
```

- [ ] **Step 5: Run tests**

```bash
pytest packages/projectair-pro/tests/hl7/test_http.py packages/projectair-pro/tests/hl7/test_mllp.py -v
```

- [ ] **Step 6: Commit**

```bash
git add packages/projectair-pro/src/airsdk_pro/hl7/http.py packages/projectair-pro/src/airsdk_pro/hl7/mllp.py packages/projectair-pro/tests/hl7/test_http.py packages/projectair-pro/tests/hl7/test_mllp.py
git commit -m "feat(hl7): add HTTP receiver and MLLP TCP listener"
```

---

### Task 9: Clinical evidence sidecar (gateway orchestrator)

**Files:**
- Create: `packages/projectair-pro/src/airsdk_pro/hl7/gateway.py`
- Create: `packages/projectair-pro/tests/hl7/test_gateway.py`

- [ ] **Step 1: Write failing tests**

Create `packages/projectair-pro/tests/hl7/test_gateway.py`:

```python
"""Tests for the clinical evidence sidecar pipeline."""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from airsdk.recorder import AIRRecorder
from airsdk_pro.hl7.test_parser import SAMPLE_ORU_R01


@pytest.mark.asyncio
async def test_sidecar_processes_message(tmp_path: Path) -> None:
    from airsdk_pro.hl7.gateway import ClinicalSidecar
    from airsdk_pro.hl7.redaction import RedactionPolicy
    rec = AIRRecorder(tmp_path / "chain.jsonl")
    sidecar = ClinicalSidecar(
        rec,
        redaction_policy=RedactionPolicy(),
    )
    result = await sidecar.process(SAMPLE_ORU_R01)
    assert result.message_type == "ORU^R01"
    assert result.records_written == 2


@pytest.mark.asyncio
async def test_sidecar_processes_file(tmp_path: Path) -> None:
    from airsdk_pro.hl7.gateway import ClinicalSidecar
    from airsdk_pro.hl7.redaction import RedactionPolicy
    hl7_file = tmp_path / "messages.hl7"
    hl7_file.write_text(SAMPLE_ORU_R01)
    rec = AIRRecorder(tmp_path / "chain.jsonl")
    sidecar = ClinicalSidecar(rec, redaction_policy=RedactionPolicy())
    results = await sidecar.process_file(hl7_file)
    assert len(results) >= 1


@pytest.mark.asyncio
async def test_sidecar_lag_starts_at_zero(tmp_path: Path) -> None:
    from airsdk_pro.hl7.gateway import ClinicalSidecar
    from airsdk_pro.hl7.redaction import RedactionPolicy
    rec = AIRRecorder(tmp_path / "chain.jsonl")
    sidecar = ClinicalSidecar(rec, redaction_policy=RedactionPolicy())
    assert sidecar.lag_seconds == 0.0
    assert sidecar.dead_letter_count == 0
```

- [ ] **Step 2: Implement the sidecar**

Create `packages/projectair-pro/src/airsdk_pro/hl7/gateway.py`:

```python
"""Clinical evidence sidecar pipeline orchestrator."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from airsdk.recorder import AIRRecorder

from airsdk_pro.gate import requires_pro
from airsdk_pro.hl7.capture import HL7_FHIR_FEATURE, instrument_hl7
from airsdk_pro.hl7.fhir import map_to_fhir, project_for_chain
from airsdk_pro.hl7.parser import parse_hl7v2
from airsdk_pro.hl7.redaction import RedactionPolicy
from airsdk_pro.hl7.types import HL7v2ParseError, SidecarResult


class SidecarConfig:
    pass


@requires_pro(feature=HL7_FHIR_FEATURE)
class ClinicalSidecar:
    def __init__(
        self,
        recorder: AIRRecorder,
        *,
        fhir_client: Any | None = None,
        siem_config: SidecarConfig | None = None,
        redaction_policy: RedactionPolicy | None = None,
        queue_size: int = 10_000,
        dead_letter_path: Path | None = None,
    ) -> None:
        self._recorder = recorder
        self._fhir_client = fhir_client
        self._policy = redaction_policy or RedactionPolicy()
        self._dead_letter_path = dead_letter_path
        self._dead_letters: list[dict[str, Any]] = []
        self._last_enqueue_time: float = 0.0

    @property
    def lag_seconds(self) -> float:
        if self._last_enqueue_time == 0.0:
            return 0.0
        return time.monotonic() - self._last_enqueue_time

    @property
    def dead_letter_count(self) -> int:
        return len(self._dead_letters)

    async def process(self, raw_message: str) -> SidecarResult:
        self._last_enqueue_time = time.monotonic()
        try:
            start, end = instrument_hl7(
                self._recorder,
                raw_message,
                redaction_policy=self._policy,
            )
        except HL7v2ParseError as exc:
            self._dead_letters.append({
                "raw": raw_message[:1000],
                "error": str(exc),
                "timestamp": time.time(),
                "retry_count": 0,
            })
            return SidecarResult(
                message_type="UNKNOWN",
                records_written=0,
            )

        msg_type = start.payload.hl7v2_message_type or "UNKNOWN"
        fhir_types = []
        if start.payload.fhir_resources:
            fhir_types = [r.get("resourceType", "") for r in start.payload.fhir_resources]

        self._last_enqueue_time = 0.0
        return SidecarResult(
            message_type=msg_type,
            patient_mrn_hash=start.payload.data_subjects[0].subject_id if start.payload.data_subjects else None,
            records_written=2,
            fhir_resource_types=fhir_types,
        )

    async def process_file(self, path: Path) -> list[SidecarResult]:
        content = path.read_text()
        messages = content.split("MSH|")
        results: list[SidecarResult] = []
        for msg in messages:
            if msg.strip():
                results.append(await self.process("MSH|" + msg))
        return results

    async def replay_dead_letters(self, max_batch: int = 100) -> int:
        replayed = 0
        remaining: list[dict[str, Any]] = []
        for dl in self._dead_letters[:max_batch]:
            try:
                await self.process(dl["raw"])
                replayed += 1
            except Exception:
                dl["retry_count"] += 1
                if dl["retry_count"] < 3:
                    remaining.append(dl)
        self._dead_letters = remaining + self._dead_letters[max_batch:]
        return replayed
```

- [ ] **Step 3: Run tests**

```bash
pytest packages/projectair-pro/tests/hl7/test_gateway.py -v
```

- [ ] **Step 4: Commit**

```bash
git add packages/projectair-pro/src/airsdk_pro/hl7/gateway.py packages/projectair-pro/tests/hl7/test_gateway.py
git commit -m "feat(hl7): add clinical evidence sidecar pipeline orchestrator"
```

---

### Task 10: Module re-exports and __init__.py wiring

**Files:**
- Modify: `packages/projectair-pro/src/airsdk_pro/hl7/__init__.py`
- Modify: `packages/projectair-pro/src/airsdk_pro/__init__.py`

- [ ] **Step 1: Wire hl7/__init__.py re-exports**

Update `packages/projectair-pro/src/airsdk_pro/hl7/__init__.py`:

```python
"""HL7v2 + FHIR R4 clinical evidence sidecar (Pro)."""
from airsdk_pro.hl7.capture import HL7_FHIR_FEATURE, instrument_hl7
from airsdk_pro.hl7.fhir import map_to_fhir, normalize_code_system, project_for_chain
from airsdk_pro.hl7.fhir_client import FHIRClient
from airsdk_pro.hl7.gateway import ClinicalSidecar
from airsdk_pro.hl7.http import create_hl7_router
from airsdk_pro.hl7.mllp import MLLPListener
from airsdk_pro.hl7.parser import parse_hl7v2
from airsdk_pro.hl7.redaction import (
    PHI_CLASS_FIELDS,
    PHIMode,
    PHIRedactionError,
    RedactionPolicy,
    redact_dob,
    redact_identifier,
    redact_mcid,
)
from airsdk_pro.hl7.types import (
    FHIRPushResult,
    HL7v2Message,
    HL7v2ParseError,
    SidecarResult,
)

__all__ = [
    "ClinicalSidecar",
    "FHIRClient",
    "FHIRPushResult",
    "HL7_FHIR_FEATURE",
    "HL7v2Message",
    "HL7v2ParseError",
    "MLLPListener",
    "PHI_CLASS_FIELDS",
    "PHIMode",
    "PHIRedactionError",
    "RedactionPolicy",
    "SidecarResult",
    "create_hl7_router",
    "instrument_hl7",
    "map_to_fhir",
    "normalize_code_system",
    "parse_hl7v2",
    "project_for_chain",
    "redact_dob",
    "redact_identifier",
    "redact_mcid",
]
```

- [ ] **Step 2: Add hl7 imports to airsdk_pro/__init__.py**

Add to the existing `packages/projectair-pro/src/airsdk_pro/__init__.py`:

```python
from airsdk_pro.hl7 import (
    HL7_FHIR_FEATURE,
    ClinicalSidecar,
    FHIRClient,
    MLLPListener,
    RedactionPolicy,
    create_hl7_router,
    instrument_hl7,
    parse_hl7v2,
)
```

And add those names to `__all__`.

- [ ] **Step 3: Run the full test suite**

```bash
pytest packages/projectair-pro/tests/hl7/ -v
```

Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add packages/projectair-pro/src/airsdk_pro/hl7/__init__.py packages/projectair-pro/src/airsdk_pro/__init__.py
git commit -m "feat(hl7): wire module re-exports and public API"
```

---

### Task 11: E2E demo script

**Files:**
- Create: `packages/projectair-pro/scripts/e2e_hl7_fhir.py`

- [ ] **Step 1: Write the demo script**

Create `packages/projectair-pro/scripts/e2e_hl7_fhir.py`:

```python
"""E2E demo: HL7v2 clinical evidence sidecar.

Usage:
    python scripts/e2e_hl7_fhir.py
    python scripts/e2e_hl7_fhir.py --live-fhir http://localhost:8080/fhir
    python scripts/e2e_hl7_fhir.py --phi-raw
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import tempfile
from pathlib import Path

from airsdk.agdr import load_chain, verify_chain
from airsdk.recorder import AIRRecorder
from airsdk.types import IntentSpec

from airsdk_pro.hl7 import (
    ClinicalSidecar,
    PHIMode,
    RedactionPolicy,
    instrument_hl7,
    parse_hl7v2,
)

SAMPLE_ORU = (
    "MSH|^~\\&|LAB|HOSP-MAIN|AI-AGENT|VINDICARA|20260511120000||ORU^R01|MSG001|P|2.5\r"
    "PID|1||MRN-0042^^^HOSP-MAIN^MR||DOE^JANE||19850315|F\r"
    "OBR|1|ORD001|FIL001|14749-6^HbA1c^LN|||20260511\r"
    "OBX|1|NM|14749-6^HbA1c^LN||8.4|%|<7.0|H|||F\r"
    "OBX|2|NM|2345-7^Glucose^LN||186|mg/dL|74-106|H|||F\r"
    "OBX|3|ST|LOCAL001^Custom Test^LOCAL||Positive||||F\r"
)

UNAUTHORIZED_ORU = (
    "MSH|^~\\&|LAB|HOSP-MAIN|AI-AGENT|VINDICARA|20260511130000||ORU^R01|MSG002|P|2.5\r"
    "PID|1||MRN-9999^^^HOSP-MAIN^MR||SMITH^JOHN||19700101|M\r"
    "OBR|1|ORD002|FIL002|2345-7^Glucose^LN|||20260511\r"
    "OBX|1|NM|2345-7^Glucose^LN||95|mg/dL|74-106||||F\r"
)


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--live-fhir", help="FHIR server URL")
    parser.add_argument("--phi-raw", action="store_true")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as td:
        workdir = Path(td)
        chain_path = workdir / "clinical-chain.jsonl"

        phi_mode = PHIMode.RAW if args.phi_raw else PHIMode.REDACTED
        policy = RedactionPolicy(phi_mode=phi_mode)

        spec = IntentSpec(
            goal="Review patient MRN-0042 lab results",
            allowed_entities=["MRN-0042"],
            allowed_tools=["hl7v2_receive"],
        )
        rec = AIRRecorder(chain_path, intent_spec=spec)

        print("  HL7v2 + FHIR R4 Clinical Evidence Sidecar Demo\n")

        print("  STEP 1: Parse authorized ORU^R01 (MRN-0042)")
        sidecar = ClinicalSidecar(rec, redaction_policy=policy)
        result = await sidecar.process(SAMPLE_ORU)
        print(f"    message_type: {result.message_type}")
        print(f"    records_written: {result.records_written}")
        print(f"    fhir_resources: {result.fhir_resource_types}")
        print(f"    patient_mrn_hash: {result.patient_mrn_hash}")

        print("\n  STEP 2: Inject unauthorized ORU^R01 (MRN-9999)")
        result2 = await sidecar.process(UNAUTHORIZED_ORU)
        print(f"    message_type: {result2.message_type}")

        print("\n  STEP 3: Verify chain integrity")
        chain = load_chain(chain_path)
        vr = verify_chain(chain)
        print(f"    chain status: {vr.status.value}")
        print(f"    records verified: {vr.records_verified}")

        print("\n  STEP 4: Run structural verification")
        from airsdk.verification import verify_intent
        iv = verify_intent(chain, spec)
        print(f"    verdict: {iv.verdict.value}")
        if iv.violations:
            for v in iv.violations:
                print(f"    {v.check_id} {v.severity}: {v.title}")

        print(f"\n  Chain written to: {chain_path}")


if __name__ == "__main__":
    asyncio.run(main())
```

- [ ] **Step 2: Run the demo**

```bash
python packages/projectair-pro/scripts/e2e_hl7_fhir.py
```

Expected: completes in under 30 seconds, shows parsed ORU, FHIR resources, chain verification, and SV-ENTITY-01 firing on MRN-9999.

- [ ] **Step 3: Commit**

```bash
git add packages/projectair-pro/scripts/e2e_hl7_fhir.py
git commit -m "feat(hl7): add E2E demo script for clinical evidence sidecar"
```

---

### Task 12: Marketing site updates

**Files:**
- Modify: `site/src/routes/pricing/+page.svelte`
- Modify: `site/src/routes/solutions/healthcare/+page.svelte`

- [ ] **Step 1: Add HL7v2/FHIR to Enterprise tier on pricing page**

In `site/src/routes/pricing/+page.svelte`, find the Enterprise feature list and add:

```html
<li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">></span><span>HL7v2 + FHIR R4 clinical interop</span></li>
<li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">></span><span>Clinical evidence sidecar (SIEM gateway)</span></li>
```

In the feature comparison table, add a row:

```html
<tr style="border-bottom: 1px solid var(--border-subtle);">
  <td class="p-4">Clinical interop (HL7v2 / FHIR R4)</td>
  <td class="p-4 text-center">-</td>
  <td class="p-4 text-center">-</td>
  <td class="p-4 text-center">-</td>
  <td class="p-4 text-center text-brand-red">*</td>
</tr>
```

- [ ] **Step 2: Add capability cards to healthcare page**

In `site/src/routes/solutions/healthcare/+page.svelte`, add to the `capabilities` array:

```javascript
{ title: 'HL7v2 Clinical Evidence', description: 'Every ADT, ORM, ORU, MDM message your clinical AI agent handles is parsed and recorded as a signed capsule. PHI is redacted by default to minimize exposure; BAA required for all clinical deployments.' },
{ title: 'FHIR R4 Structured Evidence', description: 'HL7v2 segments are mapped to FHIR R4 resources (Patient, Observation, ServiceRequest, DiagnosticReport) using the HL7-published spec models. Auditors see structured clinical data with proper coding system attribution.' },
```

Add FAQ section before the closing `</section>`:

```html
<section class="pb-20 px-6">
  <div class="max-w-screen-lg mx-auto">
    <p class="text-brand-red text-sm font-semibold uppercase tracking-wider mb-4 font-mono">FAQ</p>
    <div class="glass-panel p-6">
      <h3 class="text-lg font-bold mb-2">What data leaves my network?</h3>
      <p class="text-sm leading-relaxed" style="color: var(--text-muted);">The only data that leaves your network is a BLAKE3 hash (32 bytes) submitted to Sigstore Rekor for timestamping. No PHI, no clinical content, no patient identifiers, no message payloads. The hash is a one-way cryptographic commitment that proves the chain existed at a point in time.</p>
    </div>
  </div>
</section>
```

- [ ] **Step 3: Run svelte-check**

```bash
cd site && npm run check
```

Expected: 0 errors

- [ ] **Step 4: Commit**

```bash
git add site/src/routes/pricing/+page.svelte site/src/routes/solutions/healthcare/+page.svelte
git commit -m "feat(site): add HL7v2 + FHIR R4 clinical interop to pricing and healthcare pages"
```

---

### Task 13: Run full test suite and verify

- [ ] **Step 1: Run the Pro test suite**

```bash
pytest packages/projectair-pro/tests/hl7/ -v --tb=short
```

Expected: all tests pass.

- [ ] **Step 2: Run the OSS test suite (verify no regressions)**

```bash
pytest packages/projectair/tests/ -x -q
```

Expected: 510+ passed, 14 skipped, 0 failures.

- [ ] **Step 3: Run svelte-check on site**

```bash
cd site && npm run check
```

Expected: 0 errors.

- [ ] **Step 4: Run the E2E demo**

```bash
python packages/projectair-pro/scripts/e2e_hl7_fhir.py
```

Expected: completes in under 30 seconds.

- [ ] **Step 5: Final commit if any fixes needed**

```bash
git add -A && git commit -m "fix: address test/lint issues from HL7v2 integration"
```

---

### Task 14: CLI subcommands (air hl7)

**Files:**
- Modify: `packages/projectair/src/projectair/cli.py`
- Create: `packages/projectair-pro/tests/hl7/test_cli.py`

- [ ] **Step 1: Write failing CLI tests**

Create `packages/projectair-pro/tests/hl7/test_cli.py`:

```python
"""Tests for air hl7 CLI subcommands."""
from __future__ import annotations

import tempfile
from pathlib import Path

from typer.testing import CliRunner

from projectair.cli import app

runner = CliRunner()

SAMPLE_ORU = (
    "MSH|^~\\&|LAB|HOSP-MAIN|AI-AGENT|VINDICARA|20260511120000||ORU^R01|MSG001|P|2.5\r"
    "PID|1||MRN-0042^^^HOSP-MAIN^MR||DOE^JANE||19850315|F\r"
    "OBX|1|NM|14749-6^HbA1c^LN||8.4|%|<7.0|H|||F\r"
)


def test_hl7_parse_displays_message(tmp_path: Path) -> None:
    hl7_file = tmp_path / "test.hl7"
    hl7_file.write_text(SAMPLE_ORU)
    result = runner.invoke(app, ["hl7", "parse", str(hl7_file)])
    assert result.exit_code == 0
    assert "ORU^R01" in result.stdout


def test_hl7_capture_writes_chain(tmp_path: Path) -> None:
    hl7_file = tmp_path / "test.hl7"
    hl7_file.write_text(SAMPLE_ORU)
    chain = tmp_path / "chain.jsonl"
    result = runner.invoke(app, ["hl7", "capture", str(hl7_file), "--chain", str(chain)])
    assert result.exit_code == 0
    assert chain.exists()
    assert chain.stat().st_size > 0
```

- [ ] **Step 2: Add `air hl7` subcommand group to cli.py**

In `packages/projectair/src/projectair/cli.py`, add a new Typer group:

```python
hl7_app = typer.Typer(help="HL7v2 + FHIR R4 clinical evidence tools (Pro).")
app.add_typer(hl7_app, name="hl7")


@hl7_app.command("parse")
def hl7_parse(
    file: Path = typer.Argument(..., help="Path to .hl7 file"),
) -> None:
    """Parse and display HL7v2 messages."""
    try:
        from airsdk_pro.hl7 import parse_hl7v2
    except ImportError:
        typer.echo("Error: HL7v2 support requires projectair-pro. See https://vindicara.io/pricing")
        raise typer.Exit(1)
    content = file.read_text()
    for chunk in content.split("MSH|"):
        if not chunk.strip():
            continue
        raw = "MSH|" + chunk
        msg = parse_hl7v2(raw)
        typer.echo(f"  Type: {msg.message_type}")
        typer.echo(f"  Facility: {msg.sending_facility}")
        typer.echo(f"  Timestamp: {msg.timestamp}")
        if msg.pid:
            typer.echo(f"  Patient MRN: {msg.pid.primary_mrn}")
        typer.echo(f"  OBX count: {len(msg.obx)}")
        typer.echo("")


@hl7_app.command("capture")
def hl7_capture(
    file: Path = typer.Argument(..., help="Path to .hl7 file"),
    chain: Path = typer.Option("hl7-chain.jsonl", help="Output chain path"),
) -> None:
    """Parse HL7v2, map to FHIR R4, write signed capsules."""
    try:
        from airsdk_pro.hl7 import RedactionPolicy, instrument_hl7
    except ImportError:
        typer.echo("Error: HL7v2 support requires projectair-pro. See https://vindicara.io/pricing")
        raise typer.Exit(1)
    from airsdk.recorder import AIRRecorder
    rec = AIRRecorder(chain)
    policy = RedactionPolicy()
    content = file.read_text()
    count = 0
    for chunk in content.split("MSH|"):
        if not chunk.strip():
            continue
        raw = "MSH|" + chunk
        instrument_hl7(rec, raw, redaction_policy=policy)
        count += 1
    typer.echo(f"  {count} message(s) captured to {chain}")
```

- [ ] **Step 3: Run CLI tests**

```bash
pytest packages/projectair-pro/tests/hl7/test_cli.py -v
```

- [ ] **Step 4: Commit**

```bash
git add packages/projectair/src/projectair/cli.py packages/projectair-pro/tests/hl7/test_cli.py
git commit -m "feat(cli): add air hl7 parse and capture subcommands (Pro)"
```

---

### Task 15: Integration tests

**Files:**
- Create: `packages/projectair-pro/tests/hl7/test_capture_integration.py`
- Create: `packages/projectair-pro/tests/hl7/test_sidecar_integration.py`
- Create: `packages/projectair-pro/tests/hl7/test_intent_scope.py`

- [ ] **Step 1: Write capture integration test**

Create `packages/projectair-pro/tests/hl7/test_capture_integration.py`:

```python
"""Integration: raw HL7v2 -> capture -> verified chain with redacted FHIR."""
from __future__ import annotations

from pathlib import Path

from airsdk.agdr import load_chain, verify_chain
from airsdk.recorder import AIRRecorder
from airsdk.types import VerificationStatus

from airsdk_pro.hl7.capture import instrument_hl7
from airsdk_pro.hl7.redaction import PHIMode, RedactionPolicy
from airsdk_pro.hl7.test_parser import SAMPLE_ORU_R01


def test_full_capture_to_verified_chain(tmp_path: Path) -> None:
    rec = AIRRecorder(tmp_path / "chain.jsonl")
    policy = RedactionPolicy()
    start, end = instrument_hl7(rec, SAMPLE_ORU_R01, redaction_policy=policy)
    chain = load_chain(tmp_path / "chain.jsonl")
    result = verify_chain(chain)
    assert result.status == VerificationStatus.OK
    assert result.records_verified == 2
    assert start.payload.fhir_resources is not None
    patient_res = [r for r in start.payload.fhir_resources if r.get("resourceType") == "Patient"]
    assert len(patient_res) == 1
    patient_ids = patient_res[0].get("identifier", [])
    for pid in patient_ids:
        assert pid.get("value") != "MRN-0042"


def test_raw_mode_preserves_mrn(tmp_path: Path) -> None:
    rec = AIRRecorder(tmp_path / "chain.jsonl")
    policy = RedactionPolicy(phi_mode=PHIMode.RAW)
    start, _ = instrument_hl7(rec, SAMPLE_ORU_R01, redaction_policy=policy)
    patient_res = [r for r in start.payload.fhir_resources if r.get("resourceType") == "Patient"]
    patient_ids = patient_res[0].get("identifier", [])
    mrn_values = [p["value"] for p in patient_ids]
    assert "MRN-0042" in mrn_values
```

- [ ] **Step 2: Write intent scope integration test**

Create `packages/projectair-pro/tests/hl7/test_intent_scope.py`:

```python
"""Integration: intent capsule scope + SV-ENTITY-01 on out-of-scope MRN."""
from __future__ import annotations

from pathlib import Path

from airsdk.agdr import load_chain
from airsdk.recorder import AIRRecorder
from airsdk.types import IntentSpec
from airsdk.verification import verify_intent
from airsdk.verification.types import IntentVerdict

from airsdk_pro.hl7.capture import instrument_hl7
from airsdk_pro.hl7.redaction import RedactionPolicy

AUTHORIZED_ORU = (
    "MSH|^~\\&|LAB|HOSP|AI|V|20260511||ORU^R01|M1|P|2.5\r"
    "PID|1||MRN-0042^^^HOSP^MR||DOE^JANE||19850315|F\r"
    "OBX|1|NM|14749-6^HbA1c^LN||8.4|%|<7.0|H|||F\r"
)

UNAUTHORIZED_ORU = (
    "MSH|^~\\&|LAB|HOSP|AI|V|20260511||ORU^R01|M2|P|2.5\r"
    "PID|1||MRN-9999^^^HOSP^MR||SMITH^JOHN||19700101|M\r"
    "OBX|1|NM|2345-7^Glucose^LN||95|mg/dL|74-106||||F\r"
)


def test_entity_violation_on_unauthorized_mrn(tmp_path: Path) -> None:
    spec = IntentSpec(
        goal="Review patient MRN-0042",
        allowed_entities=["MRN-0042"],
        allowed_tools=["hl7v2_receive"],
    )
    rec = AIRRecorder(tmp_path / "chain.jsonl", intent_spec=spec)
    policy = RedactionPolicy()
    instrument_hl7(rec, AUTHORIZED_ORU, redaction_policy=policy)
    instrument_hl7(rec, UNAUTHORIZED_ORU, redaction_policy=policy)
    chain = load_chain(tmp_path / "chain.jsonl")
    result = verify_intent(chain, spec)
    entity_violations = [v for v in result.violations if v.check_id == "SV-ENTITY-01"]
    assert len(entity_violations) >= 1
```

- [ ] **Step 3: Write sidecar integration test (mock Splunk HEC)**

Create `packages/projectair-pro/tests/hl7/test_sidecar_integration.py`:

```python
"""Integration: sidecar pipeline with mock SIEM target."""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from airsdk.recorder import AIRRecorder

from airsdk_pro.hl7.gateway import ClinicalSidecar
from airsdk_pro.hl7.redaction import RedactionPolicy
from airsdk_pro.hl7.test_parser import SAMPLE_ORU_R01


@pytest.mark.asyncio
async def test_sidecar_full_pipeline(tmp_path: Path) -> None:
    rec = AIRRecorder(tmp_path / "chain.jsonl")
    sidecar = ClinicalSidecar(rec, redaction_policy=RedactionPolicy())
    result = await sidecar.process(SAMPLE_ORU_R01)
    assert result.message_type == "ORU^R01"
    assert result.records_written == 2
    assert "Patient" in result.fhir_resource_types
    assert "Observation" in result.fhir_resource_types
    assert result.patient_mrn_hash is not None
    assert result.patient_mrn_hash != "MRN-0042"
```

- [ ] **Step 4: Run all integration tests**

```bash
pytest packages/projectair-pro/tests/hl7/test_capture_integration.py packages/projectair-pro/tests/hl7/test_intent_scope.py packages/projectair-pro/tests/hl7/test_sidecar_integration.py -v
```

- [ ] **Step 5: Commit**

```bash
git add packages/projectair-pro/tests/hl7/test_capture_integration.py packages/projectair-pro/tests/hl7/test_intent_scope.py packages/projectair-pro/tests/hl7/test_sidecar_integration.py
git commit -m "test(hl7): add integration tests for capture, intent scope, and sidecar"
```

---

### Task 16: OBX dispatch tests and types tests

**Files:**
- Create: `packages/projectair-pro/tests/hl7/test_obx_dispatch.py`
- Create: `packages/projectair-pro/tests/hl7/test_types.py`

- [ ] **Step 1: Write OBX dispatch tests**

Create `packages/projectair-pro/tests/hl7/test_obx_dispatch.py`:

```python
"""Tests for OBX-2 value type dispatch and OBX-3 code system normalization."""
from __future__ import annotations

import pytest

from airsdk_pro.hl7.parser import parse_hl7v2


def _make_obx_message(value_type: str, value: str, code_system: str = "LN") -> str:
    return (
        "MSH|^~\\&|LAB|HOSP|AI|V|20260511||ORU^R01|M1|P|2.5\r"
        "PID|1||MRN-0042^^^HOSP^MR||DOE^JANE||19850315|F\r"
        f"OBX|1|{value_type}|TEST-1^Test^{code_system}||{value}|units|||F\r"
    )


def test_obx_nm_numeric() -> None:
    msg = parse_hl7v2(_make_obx_message("NM", "8.4"))
    assert msg.obx[0].value_type == "NM"
    assert msg.obx[0].value_numeric == 8.4


def test_obx_st_string() -> None:
    msg = parse_hl7v2(_make_obx_message("ST", "Positive"))
    assert msg.obx[0].value_type == "ST"
    assert msg.obx[0].value_string == "Positive"


def test_obx_tx_text() -> None:
    msg = parse_hl7v2(_make_obx_message("TX", "Long text note here"))
    assert msg.obx[0].value_type == "TX"
    assert msg.obx[0].value_string == "Long text note here"


def test_obx_ft_formatted_text() -> None:
    msg = parse_hl7v2(_make_obx_message("FT", "Formatted text"))
    assert msg.obx[0].value_type == "FT"
    assert msg.obx[0].value_string == "Formatted text"


def test_obx_sn_structured_numeric() -> None:
    msg = parse_hl7v2(_make_obx_message("SN", "3.5"))
    assert msg.obx[0].value_type == "SN"
    assert msg.obx[0].value_numeric == 3.5


def test_obx_dt_date() -> None:
    msg = parse_hl7v2(_make_obx_message("DT", "20260511"))
    assert msg.obx[0].value_type == "DT"
    assert msg.obx[0].value_datetime == "20260511"


def test_obx_ts_timestamp() -> None:
    msg = parse_hl7v2(_make_obx_message("TS", "20260511120000"))
    assert msg.obx[0].value_type == "TS"
    assert msg.obx[0].value_datetime == "20260511120000"


def test_obx_cwe_coded() -> None:
    raw = (
        "MSH|^~\\&|LAB|HOSP|AI|V|20260511||ORU^R01|M1|P|2.5\r"
        "PID|1||MRN-0042^^^HOSP^MR||DOE^JANE||19850315|F\r"
        "OBX|1|CWE|TEST-1^Test^LN||260373001^Detected^SCT|||||F\r"
    )
    msg = parse_hl7v2(raw)
    assert msg.obx[0].value_type == "CWE"
    assert msg.obx[0].value_coded == "260373001"


def test_code_system_snomed() -> None:
    msg = parse_hl7v2(_make_obx_message("ST", "x", "SCT"))
    assert msg.obx[0].observation_id_system == "SCT"


def test_code_system_local() -> None:
    msg = parse_hl7v2(_make_obx_message("ST", "x", "MYLOCAL"))
    assert msg.obx[0].observation_id_system == "MYLOCAL"
```

- [ ] **Step 2: Write types tests**

Create `packages/projectair-pro/tests/hl7/test_types.py`:

```python
"""Tests for HL7v2 Pydantic model validation and serialization."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from airsdk_pro.hl7.types import (
    FHIRPushResult,
    HL7v2Message,
    MSHSegment,
    OBXSegment,
    PIDSegment,
    PatientIdentifier,
    SidecarResult,
)


def test_patient_identifier_round_trip() -> None:
    pi = PatientIdentifier(value="MRN-0042", type_code="MR", assigning_authority="HOSP")
    d = pi.model_dump()
    loaded = PatientIdentifier.model_validate(d)
    assert loaded.value == "MRN-0042"


def test_obx_segment_extra_forbid() -> None:
    with pytest.raises(ValidationError):
        OBXSegment(set_id=1, value_type="NM", observation_id="X", unexpected_field="bad")


def test_sidecar_result_defaults() -> None:
    r = SidecarResult(message_type="ORU^R01")
    assert r.records_written == 0
    assert r.fhir_resource_types == []


def test_fhir_push_result_serialization() -> None:
    r = FHIRPushResult(success=True, status_code=200, resources_created=3)
    d = r.model_dump()
    assert d["resources_created"] == 3
    loaded = FHIRPushResult.model_validate(d)
    assert loaded.success
```

- [ ] **Step 3: Run tests**

```bash
pytest packages/projectair-pro/tests/hl7/test_obx_dispatch.py packages/projectair-pro/tests/hl7/test_types.py -v
```

- [ ] **Step 4: Commit**

```bash
git add packages/projectair-pro/tests/hl7/test_obx_dispatch.py packages/projectair-pro/tests/hl7/test_types.py
git commit -m "test(hl7): add OBX dispatch and types validation tests"
```

---

### Task 17: README update

**Files:**
- Modify: `packages/projectair/README.md`

- [ ] **Step 1: Add HL7v2/FHIR to framework integrations table**

In `packages/projectair/README.md`, find the framework integrations table and add a new row:

```markdown
| HL7v2 / FHIR R4 | `instrument_hl7` (Pro) | 1.1.0 |
```

- [ ] **Step 2: Commit**

```bash
git add packages/projectair/README.md
git commit -m "docs: add HL7v2/FHIR R4 to framework integrations table in README"
```
