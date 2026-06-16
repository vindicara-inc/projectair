"""NIST AI RMF report generator (premium / Pro)."""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from airsdk.types import (
    AgDRPayload,
    AgDRRecord,
    Finding,
    ForensicReport,
    StepKind,
    VerificationResult,
    VerificationStatus,
)

from _helpers import requires_vendor_key
from airsdk_pro.license import (
    LicenseInvalidError,
    LicenseMissingError,
    install_license,
    load_license,
)
from airsdk_pro.report_nist_rmf import (
    NIST_RMF_FEATURE,
    generate_nist_rmf_report,
)

DUMMY_HASH = "0" * 64
DUMMY_SIG = "aa" * 64
DUMMY_KEY = "bb" * 32


def _record(
    kind: StepKind = StepKind.LLM_START,
    step_id: str = "test-step-1",
    timestamp: str = "2026-04-21T12:00:00Z",
    **payload_fields: object,
) -> AgDRRecord:
    return AgDRRecord(
        step_id=step_id,
        timestamp=timestamp,
        kind=kind,
        payload=AgDRPayload.model_validate(payload_fields),
        prev_hash=DUMMY_HASH,
        content_hash=DUMMY_HASH,
        signature=DUMMY_SIG,
        signer_key=DUMMY_KEY,
    )


def _report(
    findings: list[Finding] | None = None,
    verification_status: VerificationStatus = VerificationStatus.OK,
    verification_reason: str | None = None,
    verification_failed_step_id: str | None = None,
    records: int = 1,
) -> ForensicReport:
    return ForensicReport(
        air_version="0.7.1",
        report_id=str(uuid4()),
        source_log="/var/log/air/test-fixture.log",
        generated_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        records=records,
        conversations=1,
        verification=VerificationResult(
            status=verification_status,
            records_verified=records,
            reason=verification_reason,
            failed_step_id=verification_failed_step_id,
        ),
        findings=findings or [],
    )


def _finding(
    detector_id: str = "ASI01",
    severity: str = "high",
    step_id: str = "test-step-1",
    description: str = "test",
) -> Finding:
    return Finding(
        detector_id=detector_id,
        title=f"{detector_id} test",
        severity=severity,
        step_id=step_id,
        step_index=0,
        description=description,
    )


@pytest.fixture
def licensed(
    tmp_path: Path,
    issue_token: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    """Install a Pro license with the NIST RMF feature flag and route the gate to it."""
    token = issue_token(
        email="rmf-tests@vindicara.io",
        tier="individual",
        features=(NIST_RMF_FEATURE,),
    )
    license_path = tmp_path / "license.json"
    install_license(token, path=license_path)
    monkeypatch.setattr(
        "airsdk_pro.gate.load_license", lambda: load_license(license_path)
    )
    return license_path


@requires_vendor_key
def test_nist_rmf_renders_header_with_system_identity(licensed: Path) -> None:
    records = [_record()]
    report = _report(records=1)
    out = generate_nist_rmf_report(
        report,
        records,
        "sys-001",
        system_name="Coach Agent",
        operator_entity="Acme Operator",
        monitoring_period="2026-Q3",
    )
    assert "# NIST AI RMF Risk-Management Report" in out
    assert "**System:** Coach Agent" in out
    assert "**System ID:** `sys-001`" in out
    assert "**Operator:** Acme Operator" in out
    assert "**Reporting period:** 2026-Q3" in out


@requires_vendor_key
def test_nist_rmf_includes_disclaimer(licensed: Path) -> None:
    out = generate_nist_rmf_report(_report(), [_record()], "sys-001")
    assert "INFORMATIONAL TEMPLATE, NOT LEGAL OR AUDIT ADVICE" in out
    assert "NIST does not certify" in out


@requires_vendor_key
def test_nist_rmf_chain_ok_emits_ok_statement(licensed: Path) -> None:
    records = [_record()]
    out = generate_nist_rmf_report(
        _report(verification_status=VerificationStatus.OK, records=1),
        records,
        "sys-001",
    )
    assert "chain verified cleanly" in out.lower()
    assert "MEASURE 2.7" in out
    assert "MEASURE 2.8" in out


@requires_vendor_key
def test_nist_rmf_chain_tampered_emits_failure_warning(licensed: Path) -> None:
    out = generate_nist_rmf_report(
        _report(
            verification_status=VerificationStatus.TAMPERED,
            verification_reason="signature mismatch at step 3",
            verification_failed_step_id="test-step-3",
            records=1,
        ),
        [_record()],
        "sys-001",
    )
    assert "Chain verification did not complete successfully" in out
    assert "signature mismatch at step 3" in out
    assert "`test-step-3`" in out


@requires_vendor_key
def test_nist_rmf_renders_subcategory_crosswalk_table(licensed: Path) -> None:
    out = generate_nist_rmf_report(_report(), [_record()], "sys-001")
    assert "AI RMF Subcategory Crosswalk" in out
    for sub in ("GOVERN 1.5", "MAP 5.1", "MEASURE 1", "MEASURE 2.7", "MEASURE 2.8", "MANAGE 1.3", "MANAGE 4.1"):
        assert sub in out


@requires_vendor_key
def test_nist_rmf_critical_findings_in_section_9_1(licensed: Path) -> None:
    findings = [
        _finding(detector_id="ASI03", severity="critical", description="identity forgery"),
        _finding(detector_id="ASI02", severity="high", description="shell injection"),
    ]
    out = generate_nist_rmf_report(_report(findings=findings, records=1), [_record()], "sys-001")
    assert "9.1 Critical-severity findings" in out
    assert "9.2 High-severity findings" in out
    assert "ASI03" in out
    assert "identity forgery" in out
    assert "shell injection" in out


@requires_vendor_key
def test_nist_rmf_severity_rollup_counts(licensed: Path) -> None:
    findings = [
        _finding(severity="critical"),
        _finding(severity="critical"),
        _finding(severity="high"),
        _finding(severity="medium"),
    ]
    out = generate_nist_rmf_report(_report(findings=findings, records=1), [_record()], "sys-001")
    assert "**Findings of critical severity:** 2" in out
    assert "**Findings of high severity:** 1" in out
    assert "**Findings of medium severity:** 1" in out


@requires_vendor_key
def test_nist_rmf_attestation_references_air_version(licensed: Path) -> None:
    out = generate_nist_rmf_report(_report(), [_record()], "sys-001")
    assert "v0.7.1" in out


@requires_vendor_key
def test_nist_rmf_appendix_lists_every_finding(licensed: Path) -> None:
    findings = [_finding(step_id=f"s{i}", description=f"finding {i}") for i in range(3)]
    out = generate_nist_rmf_report(_report(findings=findings, records=3), [_record()], "sys-001")
    appendix = out.split("Appendix A")[-1]
    for i in range(3):
        assert f"finding {i}" in appendix


@requires_vendor_key
def test_nist_rmf_appendix_escapes_pipes_in_descriptions(licensed: Path) -> None:
    findings = [_finding(description="dangerous | pipe | content")]
    out = generate_nist_rmf_report(_report(findings=findings, records=1), [_record()], "sys-001")
    assert r"dangerous \| pipe \| content" in out


@requires_vendor_key
def test_nist_rmf_observed_time_range_reflects_first_and_last_record(licensed: Path) -> None:
    records = [
        _record(step_id="a", timestamp="2026-04-01T00:00:00Z"),
        _record(step_id="b", timestamp="2026-04-15T12:00:00Z"),
    ]
    out = generate_nist_rmf_report(_report(records=2), records, "sys-001")
    assert "2026-04-01T00:00:00Z to 2026-04-15T12:00:00Z" in out


@requires_vendor_key
def test_nist_rmf_signer_keys_truncated_in_header(licensed: Path) -> None:
    out = generate_nist_rmf_report(_report(records=1), [_record()], "sys-001")
    assert "`bbbbbbbbbbbbbbbb...`" in out


@requires_vendor_key
def test_nist_rmf_defaults_placeholders_for_missing_fields(licensed: Path) -> None:
    out = generate_nist_rmf_report(_report(), [_record()], "sys-001")
    assert "[AI system name]" in out
    assert "[Operator entity]" in out
    assert "[reporting period, e.g. 2026-Q3]" in out
    assert "AI RMF 1.0 (NIST AI 100-1)" in out


# -- Gate behaviour ------------------------------------------------------


def test_nist_rmf_blocks_when_no_license(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise() -> Any:
        raise LicenseMissingError("no license")

    monkeypatch.setattr("airsdk_pro.gate.load_license", _raise)
    with pytest.raises(LicenseMissingError):
        generate_nist_rmf_report(_report(), [_record()], "sys-001")


@requires_vendor_key
def test_nist_rmf_blocks_when_feature_not_in_license(
    tmp_path: Path,
    issue_token: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A valid license without the NIST RMF feature flag must still be rejected."""
    token = issue_token(
        email="other@vindicara.io",
        tier="individual",
        features=("air-cloud-client",),
    )
    license_path = tmp_path / "license.json"
    install_license(token, path=license_path)
    monkeypatch.setattr(
        "airsdk_pro.gate.load_license", lambda: load_license(license_path)
    )
    with pytest.raises(LicenseInvalidError):
        generate_nist_rmf_report(_report(), [_record()], "sys-001")
