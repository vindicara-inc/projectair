"""ALCOA+ data-integrity evidence report generator."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from uuid import uuid4

from airsdk._compat import UTC
from airsdk.agdr import load_chain, verify_chain
from airsdk.alcoa import generate_alcoa_report
from airsdk.recorder import AIRRecorder
from airsdk.types import DecisionProvenance, ForensicReport, VerificationResult, VerificationStatus


def _report(log: Path, records_len: int, verification: VerificationResult) -> ForensicReport:
    return ForensicReport(
        air_version="test",
        report_id=str(uuid4()),
        source_log=str(log),
        generated_at=datetime.now(UTC).isoformat(),
        records=records_len,
        conversations=1,
        verification=verification,
        findings=[],
    )


def _chain(tmp_path: Path) -> tuple[ForensicReport, list]:
    recorder = AIRRecorder(log_path=tmp_path / "r.log", user_intent="decide")
    recorder.llm_start(prompt="q")
    recorder.llm_end(response="a", provenance=DecisionProvenance(provider="openai", model="gpt-4o", temperature=0.7))
    records = load_chain(tmp_path / "r.log")
    return _report(tmp_path / "r.log", len(records), verify_chain(records)), records


def test_report_covers_all_nine_principles(tmp_path: Path) -> None:
    report, records = _chain(tmp_path)
    md = generate_alcoa_report(report, records)
    for name in ("Attributable", "Legible", "Contemporaneous", "Original", "Accurate",
                 "Complete", "Consistent", "Enduring", "Available"):
        assert name in md


def test_report_states_boundary_and_readiness(tmp_path: Path) -> None:
    report, records = _chain(tmp_path)
    md = generate_alcoa_report(report, records)
    # The honest boundary must be present and prominent.
    assert "validated" in md.lower()
    assert "necessary, not sufficient" in md
    assert "Readiness:** beta" in md
    assert "certificate of compliance" in md


def test_report_credits_provenance_evidence(tmp_path: Path) -> None:
    report, records = _chain(tmp_path)
    md = generate_alcoa_report(report, records)
    # One of two LLM records carries provenance.
    assert "1/2 LLM record(s) carry decision provenance" in md


def test_report_flags_missing_external_anchor(tmp_path: Path) -> None:
    report, records = _chain(tmp_path)
    md = generate_alcoa_report(report, records)
    # No anchor in this chain: Contemporaneous/Enduring must be downgraded, not overclaimed.
    assert "No external anchor" in md
    assert "Partial" in md


def test_broken_chain_downgrades_consistency(tmp_path: Path) -> None:
    report, records = _chain(tmp_path)
    broken = _report(tmp_path / "r.log", report.records,
                     VerificationResult(status=VerificationStatus.TAMPERED, records_verified=0))
    md = generate_alcoa_report(broken, records)
    assert "tampered" in md
    assert "Not evidenced" in md
