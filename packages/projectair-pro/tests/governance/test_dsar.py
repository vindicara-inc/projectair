"""Tests for the DSAR report generator."""
from __future__ import annotations

from airsdk_pro.governance.dsar import generate_dsar, render_dsar_markdown
from airsdk_pro.governance.types import GovernanceIndex


class TestDSAR:
    def test_generate_dsar(self, sample_index: GovernanceIndex) -> None:
        report = generate_dsar(sample_index, "patient-42", subject_type="patient", jurisdiction="HIPAA")
        assert report.total_accesses == 2
        assert report.subject.subject_id == "patient-42"
        assert report.subject.jurisdiction == "HIPAA"
        assert "45 CFR 164.528" in report.jurisdiction_notes

    def test_generate_dsar_no_results(self, sample_index: GovernanceIndex) -> None:
        report = generate_dsar(sample_index, "nonexistent")
        assert report.total_accesses == 0

    def test_render_markdown(self, sample_index: GovernanceIndex) -> None:
        report = generate_dsar(sample_index, "patient-42", jurisdiction="HIPAA")
        md = render_dsar_markdown(report)
        assert "# Data Subject Access Report" in md
        assert "patient-42" in md
        assert "query_patients" in md
        assert "HIPAA" in md

    def test_render_markdown_empty(self, sample_index: GovernanceIndex) -> None:
        report = generate_dsar(sample_index, "nonexistent")
        md = render_dsar_markdown(report)
        assert "No accesses found" in md

    def test_gdpr_jurisdiction(self, sample_index: GovernanceIndex) -> None:
        report = generate_dsar(sample_index, "patient-42", jurisdiction="GDPR")
        assert "Article 15" in report.jurisdiction_notes
