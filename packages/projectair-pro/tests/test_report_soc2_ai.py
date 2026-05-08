"""SOC 2 AI evidence-template generator (premium / Pro)."""
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
from airsdk_pro.report_soc2_ai import (
    SOC2_AI_FEATURE,
    generate_soc2_ai_report,
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
    """Install a Pro license with the SOC 2 AI feature flag and route the gate to it."""
    token = issue_token(
        email="soc2-tests@vindicara.io",
        tier="individual",
        features=(SOC2_AI_FEATURE,),
    )
    license_path = tmp_path / "license.json"
    install_license(token, path=license_path)
    monkeypatch.setattr(
        "airsdk_pro.gate.load_license", lambda: load_license(license_path)
    )
    return license_path


@requires_vendor_key
def test_soc2_ai_renders_header_with_system_identity(licensed: Path) -> None:
    out = generate_soc2_ai_report(
        _report(),
        [_record()],
        "sys-001",
        service_organisation="Acme SaaS Co",
        system_name="Coach Agent",
        monitoring_period="2026-Q3",
    )
    assert "# SOC 2 AI System Control Evidence" in out
    assert "**Service organisation:** Acme SaaS Co" in out
    assert "**System:** Coach Agent" in out
    assert "**System ID:** `sys-001`" in out
    assert "**Reporting period:** 2026-Q3" in out


@requires_vendor_key
def test_soc2_ai_disclaimer_says_not_a_soc2_report(licensed: Path) -> None:
    out = generate_soc2_ai_report(_report(), [_record()], "sys-001")
    assert "NOT A SOC 2 REPORT" in out
    assert "independent CPA" in out
    assert "AT-C" in out


@requires_vendor_key
def test_soc2_ai_chain_ok_emits_ok_statement_with_cc7_cc8(licensed: Path) -> None:
    out = generate_soc2_ai_report(
        _report(verification_status=VerificationStatus.OK, records=1),
        [_record()],
        "sys-001",
    )
    assert "chain verified cleanly" in out.lower()
    assert "CC7" in out
    assert "CC8" in out


@requires_vendor_key
def test_soc2_ai_chain_tampered_emits_failure_warning(licensed: Path) -> None:
    out = generate_soc2_ai_report(
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
def test_soc2_ai_renders_tsc_crosswalk_table(licensed: Path) -> None:
    out = generate_soc2_ai_report(_report(), [_record()], "sys-001")
    assert "Trust Services Criteria Crosswalk" in out
    for criterion in ("CC2.1", "CC4.1", "CC6.1", "CC7.2", "CC7.4", "CC8.1", "PI1.4"):
        assert criterion in out


@requires_vendor_key
def test_soc2_ai_critical_findings_in_section_9_1(licensed: Path) -> None:
    findings = [
        _finding(detector_id="ASI03", severity="critical", description="identity forgery"),
        _finding(detector_id="ASI02", severity="high", description="shell injection"),
    ]
    out = generate_soc2_ai_report(_report(findings=findings, records=1), [_record()], "sys-001")
    assert "9.1 Critical-severity findings" in out
    assert "9.2 High-severity findings" in out
    assert "ASI03" in out
    assert "identity forgery" in out


@requires_vendor_key
def test_soc2_ai_severity_rollup_counts(licensed: Path) -> None:
    findings = [_finding(severity="critical"), _finding(severity="high"), _finding(severity="high")]
    out = generate_soc2_ai_report(_report(findings=findings, records=1), [_record()], "sys-001")
    assert "**Findings of critical severity:** 1" in out
    assert "**Findings of high severity:** 2" in out


@requires_vendor_key
def test_soc2_ai_attestation_references_air_version(licensed: Path) -> None:
    out = generate_soc2_ai_report(_report(), [_record()], "sys-001")
    assert "v0.7.1" in out


@requires_vendor_key
def test_soc2_ai_in_scope_categories_render(licensed: Path) -> None:
    out = generate_soc2_ai_report(
        _report(),
        [_record()],
        "sys-001",
        in_scope_categories=("Security",),
    )
    assert "**TSC categories in scope:** Security" in out


@requires_vendor_key
def test_soc2_ai_appendix_lists_every_finding(licensed: Path) -> None:
    findings = [_finding(step_id=f"s{i}", description=f"finding {i}") for i in range(3)]
    out = generate_soc2_ai_report(_report(findings=findings, records=3), [_record()], "sys-001")
    appendix = out.split("Appendix A")[-1]
    for i in range(3):
        assert f"finding {i}" in appendix


@requires_vendor_key
def test_soc2_ai_appendix_escapes_pipes_in_descriptions(licensed: Path) -> None:
    findings = [_finding(description="dangerous | pipe")]
    out = generate_soc2_ai_report(_report(findings=findings, records=1), [_record()], "sys-001")
    assert r"dangerous \| pipe" in out


@requires_vendor_key
def test_soc2_ai_signer_keys_truncated_in_header(licensed: Path) -> None:
    out = generate_soc2_ai_report(_report(records=1), [_record()], "sys-001")
    assert "`bbbbbbbbbbbbbbbb...`" in out


@requires_vendor_key
def test_soc2_ai_observed_time_range(licensed: Path) -> None:
    records = [
        _record(step_id="a", timestamp="2026-04-01T00:00:00Z"),
        _record(step_id="b", timestamp="2026-04-15T12:00:00Z"),
    ]
    out = generate_soc2_ai_report(_report(records=2), records, "sys-001")
    assert "2026-04-01T00:00:00Z to 2026-04-15T12:00:00Z" in out


@requires_vendor_key
def test_soc2_ai_defaults_placeholders_for_missing_fields(licensed: Path) -> None:
    out = generate_soc2_ai_report(_report(), [_record()], "sys-001")
    assert "[Service organisation]" in out
    assert "[AI system name]" in out
    assert "[reporting period, e.g. 2026-Q3]" in out


# -- Gate behaviour ------------------------------------------------------


def test_soc2_ai_blocks_when_no_license(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise() -> Any:
        raise LicenseMissingError("no license")

    monkeypatch.setattr("airsdk_pro.gate.load_license", _raise)
    with pytest.raises(LicenseMissingError):
        generate_soc2_ai_report(_report(), [_record()], "sys-001")


@requires_vendor_key
def test_soc2_ai_blocks_when_feature_not_in_license(
    tmp_path: Path,
    issue_token: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A valid license without the SOC 2 AI feature flag must still be rejected."""
    token = issue_token(
        email="other@vindicara.io",
        tier="individual",
        features=("report-nist-ai-rmf",),
    )
    license_path = tmp_path / "license.json"
    install_license(token, path=license_path)
    monkeypatch.setattr(
        "airsdk_pro.gate.load_license", lambda: load_license(license_path)
    )
    with pytest.raises(LicenseInvalidError):
        generate_soc2_ai_report(_report(), [_record()], "sys-001")
