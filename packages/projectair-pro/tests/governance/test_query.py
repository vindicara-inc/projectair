"""Tests for the governance query engine."""
from __future__ import annotations

from airsdk_pro.governance.query import query, query_by_asset, query_by_subject
from airsdk_pro.governance.types import GovernanceIndex


class TestQuery:
    def test_query_by_subject(self, sample_index: GovernanceIndex) -> None:
        results = query_by_subject(sample_index, "patient-42")
        assert len(results) == 2

    def test_query_by_subject_not_found(self, sample_index: GovernanceIndex) -> None:
        results = query_by_subject(sample_index, "nonexistent")
        assert len(results) == 0

    def test_query_by_asset(self, sample_index: GovernanceIndex) -> None:
        results = query_by_asset(sample_index, "patients")
        assert len(results) == 1
        assert results[0].tool_name == "query_patients"

    def test_compound_query_subject_and_asset(self, sample_index: GovernanceIndex) -> None:
        results = query(sample_index, subject_id="patient-42", asset_id="patients")
        assert len(results) == 1

    def test_compound_query_no_filters(self, sample_index: GovernanceIndex) -> None:
        results = query(sample_index)
        assert len(results) == 2

    def test_compound_query_no_match(self, sample_index: GovernanceIndex) -> None:
        results = query(sample_index, subject_id="patient-42", asset_id="nonexistent")
        assert len(results) == 0
