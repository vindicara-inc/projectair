"""HL7v2 parser wrapper over vendored hl7apy (Pro)."""
from __future__ import annotations

from airsdk_pro._vendor.hl7apy.parser import parse_message as _hl7_parse
from airsdk_pro._vendor.hl7apy.exceptions import ParserError
from airsdk_pro.hl7.types import (
    HL7v2Message,
    HL7v2ParseError,
    MSHSegment,
    OBRSegment,
    OBXSegment,
    PIDSegment,
    PV1Segment,
    PatientIdentifier,
)


def _field(segment: object, name: str) -> str:
    """Safely retrieve a field from a segment as a stripped string."""
    try:
        return str(getattr(segment, name).to_er7()).strip()
    except Exception:
        return ""


def _parse_timestamp(raw_ts: str) -> tuple[str, str]:
    """Convert HL7 timestamp to (iso8601, precision).

    Precision values: year, month, day, second, millisecond.
    Length 10 and 12 (hour/minute) map to 'second' precision
    since HL7v2 timestamps without seconds still represent time.
    """
    ts = raw_ts.strip()
    # Strip timezone offset for length measurement
    base = ts.split("+")[0].split("-")[0] if (
        "+" in ts or (ts.count("-") > 0 and len(ts) > 8)
    ) else ts
    # Remove subseconds decimal for base length
    core = base.split(".")[0]
    n = len(core)

    if n <= 4:
        year = core[:4]
        return year, "year"
    if n <= 6:
        year, month = core[:4], core[4:6]
        return f"{year}-{month}", "month"
    if n <= 8:
        year, month, day = core[:4], core[4:6], core[6:8]
        return f"{year}-{month}-{day}", "day"

    # 10 (YYYYMMDDHH), 12 (YYYYMMDDHHM M), 14+ (YYYYMMDDHHMMSS)
    year, month, day = core[:4], core[4:6], core[6:8]
    hour = core[8:10] if n >= 10 else "00"
    minute = core[10:12] if n >= 12 else "00"
    second = core[12:14] if n >= 14 else "00"

    subsec = ("." + base.split(".")[1]) if "." in base else ""
    tz_part = ""
    if "+" in ts:
        raw_tz = ts.split("+", 1)[1]
        tz_part = f"+{raw_tz[:2]}:{raw_tz[2:4]}" if len(raw_tz) >= 4 else f"+{raw_tz}"
    elif len(ts) > len(base) and ts[len(base)] == "-":
        raw_tz = ts[len(base) + 1:]
        tz_part = f"-{raw_tz[:2]}:{raw_tz[2:4]}" if len(raw_tz) >= 4 else f"-{raw_tz}"

    iso = f"{year}-{month}-{day}T{hour}:{minute}:{second}{subsec}{tz_part}"
    precision = "millisecond" if subsec else "second"
    return iso, precision


def _parse_msh(seg: object) -> MSHSegment:
    return MSHSegment(
        sending_application=_field(seg, "msh_3"),
        sending_facility=_field(seg, "msh_4"),
        receiving_application=_field(seg, "msh_5"),
        receiving_facility=_field(seg, "msh_6"),
        datetime=_field(seg, "msh_7"),
        message_type=_field(seg, "msh_9"),
        message_control_id=_field(seg, "msh_10"),
        processing_id=_field(seg, "msh_11"),
        version_id=_field(seg, "msh_12"),
    )


def _parse_pid(seg: object) -> PIDSegment:
    identifiers: list[PatientIdentifier] = []
    primary_mrn: str | None = None

    try:
        pid3_fields = list(seg.pid_3.list)  # type: ignore[attr-defined]
    except Exception:
        pid3_fields = []

    for cx_field in pid3_fields:
        try:
            cx_children = {
                c.name.rsplit("_", 1)[-1]: str(c.to_er7()).strip()
                for c in cx_field.children
            }
            id_value = cx_children.get("1", "")
            auth = cx_children.get("4", "")
            type_code = cx_children.get("5", "")
            if id_value:
                ident = PatientIdentifier(
                    value=id_value,
                    type_code=type_code,
                    assigning_authority=auth,
                )
                identifiers.append(ident)
                if type_code == "MR" and primary_mrn is None:
                    primary_mrn = id_value
        except Exception:
            pass

    pid5_raw = _field(seg, "pid_5")
    family_name: str | None = None
    given_name: str | None = None
    if pid5_raw:
        parts = pid5_raw.split("^")
        family_name = parts[0] if parts[0] else None
        given_name = parts[1] if len(parts) > 1 and parts[1] else None

    return PIDSegment(
        identifiers=identifiers,
        primary_mrn=primary_mrn,
        family_name=family_name,
        given_name=given_name,
        date_of_birth=_field(seg, "pid_7") or None,
        gender=_field(seg, "pid_8") or None,
    )


def _parse_pv1(seg: object) -> PV1Segment:
    return PV1Segment(
        patient_class=_field(seg, "pv1_2"),
        assigned_location=_field(seg, "pv1_3"),
        attending_doctor=_field(seg, "pv1_7"),
        visit_number=_field(seg, "pv1_19"),
    )


def _parse_obr(seg: object) -> OBRSegment:
    raw_id = _field(seg, "obr_4")
    svc_id = raw_id.split("^")[0] if raw_id else raw_id
    return OBRSegment(
        set_id=int(_field(seg, "obr_1") or "1"),
        placer_order_number=_field(seg, "obr_2"),
        filler_order_number=_field(seg, "obr_3"),
        universal_service_id=svc_id,
    )


def _parse_obx(seg: object) -> OBXSegment:
    set_id = int(_field(seg, "obx_1") or "0")
    value_type = _field(seg, "obx_2")
    obs_id_raw = _field(seg, "obx_3")
    obs_parts = obs_id_raw.split("^")
    obs_id = obs_parts[0] if obs_parts else obs_id_raw
    obs_text = obs_parts[1] if len(obs_parts) > 1 else ""
    obs_sys = obs_parts[2] if len(obs_parts) > 2 else ""

    raw_val = _field(seg, "obx_5")
    units = _field(seg, "obx_6") or None
    ref_range = _field(seg, "obx_7") or None
    abn_flags = _field(seg, "obx_8") or None
    obs_status = _field(seg, "obx_11") or None

    value_numeric: float | None = None
    value_string: str | None = None
    value_coded: str | None = None
    value_coded_system: str | None = None
    value_coded_text: str | None = None
    value_datetime: str | None = None

    if value_type == "NM":
        try:
            value_numeric = float(raw_val)
        except (ValueError, TypeError):
            value_string = raw_val
    elif value_type in ("ST", "TX", "FT"):
        value_string = raw_val or None
    elif value_type in ("CWE", "CE"):
        coded_parts = raw_val.split("^")
        value_coded = coded_parts[0] if coded_parts else raw_val
        value_coded_text = coded_parts[1] if len(coded_parts) > 1 else None
        value_coded_system = coded_parts[2] if len(coded_parts) > 2 else None
    elif value_type in ("TS", "DT"):
        value_datetime = raw_val or None
    elif value_type == "SN":
        # SN: structured numeric, e.g. ">8.4" or "8.4"
        numeric_str = raw_val.lstrip("><=~")
        try:
            value_numeric = float(numeric_str)
        except (ValueError, TypeError):
            value_string = raw_val
    else:
        value_string = raw_val or None

    return OBXSegment(
        set_id=set_id,
        value_type=value_type,
        observation_id=obs_id,
        observation_id_text=obs_text,
        observation_id_system=obs_sys,
        value_numeric=value_numeric,
        value_string=value_string,
        value_coded=value_coded,
        value_coded_system=value_coded_system,
        value_coded_text=value_coded_text,
        value_datetime=value_datetime,
        units=units,
        reference_range=ref_range,
        abnormal_flags=abn_flags,
        observation_status=obs_status,
    )


def _parse_z_segment(seg: object) -> list[str]:
    """Return list of field values for a Z-segment (excluding segment name)."""
    try:
        raw = str(seg.to_er7())  # type: ignore[attr-defined]
        parts = raw.split("|")
        return parts[1:]  # drop segment name
    except Exception:
        return []


def parse_hl7v2(raw: str) -> HL7v2Message:
    """Parse a raw HL7v2 pipe-delimited message.

    Delegates to vendored hl7apy for parsing.
    Raises HL7v2ParseError for malformed messages.
    """
    stripped = raw.lstrip()
    if not stripped.startswith("MSH"):
        raise HL7v2ParseError("Missing MSH segment: message must start with MSH")

    try:
        msg = _hl7_parse(stripped, find_groups=False)
    except (ParserError, Exception) as exc:
        raise HL7v2ParseError(f"Failed to parse HL7v2 message: {exc}") from exc

    segments = list(msg.children)
    seg_map: dict[str, list[object]] = {}
    for seg in segments:
        name: str = seg.name
        seg_map.setdefault(name, []).append(seg)

    if "MSH" not in seg_map:
        raise HL7v2ParseError("Missing MSH segment")

    msh_seg = seg_map["MSH"][0]
    msh = _parse_msh(msh_seg)
    ts_raw = msh.datetime
    timestamp, timestamp_precision = _parse_timestamp(ts_raw) if ts_raw else ("", "day")

    pid: PIDSegment | None = None
    if "PID" in seg_map:
        pid = _parse_pid(seg_map["PID"][0])

    pv1: PV1Segment | None = None
    if "PV1" in seg_map:
        pv1 = _parse_pv1(seg_map["PV1"][0])

    obr: OBRSegment | None = None
    if "OBR" in seg_map:
        obr = _parse_obr(seg_map["OBR"][0])

    obx_list = [_parse_obx(s) for s in seg_map.get("OBX", [])]

    z_segments: dict[str, list[list[str]]] = {}
    for name_key, seg_list in seg_map.items():
        if name_key.startswith("Z") and len(name_key) == 3:
            z_segments[name_key] = [_parse_z_segment(s) for s in seg_list]

    return HL7v2Message(
        raw=raw,
        message_type=msh.message_type,
        message_control_id=msh.message_control_id,
        timestamp=timestamp,
        timestamp_precision=timestamp_precision,
        sending_facility=msh.sending_facility,
        receiving_facility=msh.receiving_facility,
        msh=msh,
        pid=pid,
        pv1=pv1,
        obr=obr,
        obx=obx_list,
        z_segments=z_segments,
    )
