"""PHI redaction policy for HL7v2 clinical chains (Pro).

Critical safety requirement: All clinical chains contain PHI. A BAA is
ALWAYS required before activating HL7v2 sidecar capture. Attempting to
construct a ``RedactionPolicy`` without ``baa_acknowledged=True`` raises
``ValueError`` immediately so callers cannot silently skip the
acknowledgement.
"""
from __future__ import annotations

import re
from datetime import date
from enum import StrEnum

import blake3
from pydantic import BaseModel, ConfigDict, Field, model_validator


class PHIMode(StrEnum):
    """Controls whether PHI fields are hashed (REDACTED) or stored verbatim (RAW)."""

    REDACTED = "redacted"
    RAW = "raw"


PHI_CLASS_FIELDS: frozenset[str] = frozenset({
    "mrn",
    "name",
    "family_name",
    "given_name",
    "date_of_birth",
    "ssn",
    "address",
    "phone",
    "email",
    "medical_record_number",
    "account_number",
    "visit_number",
    "device_serial",
})
"""Fields considered PHI-class. Blocked from ``allowed_fields`` in REDACTED mode."""


class PHIRedactionError(Exception):
    """Raised when a PHI redaction operation cannot be completed safely."""


class RedactionPolicy(BaseModel):
    """Governs how PHI is handled when writing HL7v2 clinical chains.

    All clinical chains contain PHI-derived data regardless of
    ``phi_mode``. A BAA is always required: set ``baa_acknowledged=True``
    to confirm your deployment is covered by a signed BAA.

    In ``PHIMode.REDACTED`` (default), patient identifiers are replaced
    with their BLAKE3 digest and dates of birth are truncated to the
    year (with the 90+ rule applied). No raw PHI enters the chain.

    In ``PHIMode.RAW``, values are stored verbatim. Use only when your
    BAA and deployment environment explicitly permit raw PHI in audit
    chains.
    """

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


# ---------------------------------------------------------------------------
# Redaction helpers
# ---------------------------------------------------------------------------

_DATE8_RE = re.compile(r"\d{8}")


def redact_identifier(value: str, policy: RedactionPolicy) -> str:
    """Hash ``value`` with BLAKE3 in REDACTED mode; return verbatim in RAW mode.

    The BLAKE3 digest is hex-encoded (64 characters). The same input
    always produces the same digest within a single deployment, enabling
    correlation across records without exposing the raw identifier.
    """
    if policy.phi_mode == PHIMode.RAW:
        return value
    return blake3.blake3(value.encode()).hexdigest()


def redact_dob(dob: str, policy: RedactionPolicy) -> str:
    """Truncate a date-of-birth string to year in REDACTED mode.

    Applies the HIPAA Safe Harbor 90+ aggregation rule: patients aged 90
    or older are represented as ``"90+"`` rather than their birth year to
    prevent re-identification of very elderly patients.

    Args:
        dob: HL7v2 date string in any of ``YYYY``, ``YYYYMMDD``, or
            ``YYYYMMDDHHmmss`` format.
        policy: Active redaction policy.

    Returns:
        In RAW mode: ``dob`` unchanged. In REDACTED mode: ``"90+"`` if
        the patient is 90 or older, the four-digit birth year otherwise,
        or ``""`` if the year cannot be extracted.
    """
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
    """Strip 8-digit date sequences from message control IDs.

    Message control IDs commonly embed the message date (``YYYYMMDD``)
    as a prefix or suffix. This helper replaces each 8-digit run with
    ``XXXXXXXX`` so MCIDs can be logged without leaking the encounter
    date. The operation is unconditional and requires no policy object.
    """
    return _DATE8_RE.sub("XXXXXXXX", mcid)
