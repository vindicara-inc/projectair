"""Tests for the governance chain indexer."""
from __future__ import annotations

from airsdk_pro.governance.indexer import index_chains
from airsdk_pro.governance.types import AccessType, GovernanceIndex


class TestIndexer:
    def test_index_extracts_tagged_records(self, sample_index: GovernanceIndex) -> None:
        assert len(sample_index.accesses) == 2

    def test_untagged_records_excluded(self, sample_index: GovernanceIndex) -> None:
        tool_names = [a.tool_name for a in sample_index.accesses]
        assert "ping" not in tool_names

    def test_by_subject_index(self, sample_index: GovernanceIndex) -> None:
        assert "patient-42" in sample_index.by_subject
        assert len(sample_index.by_subject["patient-42"]) == 2

    def test_by_asset_index(self, sample_index: GovernanceIndex) -> None:
        assert "patients" in sample_index.by_asset
        assert "appointments" in sample_index.by_asset

    def test_by_agent_index(self, sample_index: GovernanceIndex) -> None:
        assert len(sample_index.by_agent) == 1

    def test_access_type_inference_read(self, sample_index: GovernanceIndex) -> None:
        query_access = sample_index.accesses[0]
        assert query_access.access_type == AccessType.READ

    def test_access_type_inference_from_tool_name(self, sample_index: GovernanceIndex) -> None:
        read_access = sample_index.accesses[1]
        assert read_access.access_type == AccessType.READ

    def test_policy_decision_allowed(self, sample_index: GovernanceIndex) -> None:
        for access in sample_index.accesses:
            assert access.policy_decision == "allowed"

    def test_empty_chain(self) -> None:
        idx = index_chains([[]])
        assert len(idx.accesses) == 0

    def test_v05_chain_produces_empty_index(self, sample_tagged_chain: list) -> None:
        from airsdk.agdr import Signer
        from airsdk.types import StepKind

        signer = Signer.generate()
        old_chain = [
            signer.sign(StepKind.LLM_START, {"prompt": "hello"}),
            signer.sign(StepKind.LLM_END, {"response": "world"}),
        ]
        idx = index_chains([old_chain])
        assert len(idx.accesses) == 0
