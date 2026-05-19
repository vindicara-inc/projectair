"""Tests for v0.6 data governance schema extensions."""
from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from airsdk.agdr import Signer, load_chain, verify_chain
from airsdk.recorder import AIRRecorder
from airsdk.types import (
    AgDRPayload,
    DataAssetRef,
    DataSubjectRef,
    VerificationStatus,
)


class TestDataAssetRef:
    def test_valid(self) -> None:
        ref = DataAssetRef(asset_id="patients", asset_type="table")
        assert ref.asset_id == "patients"
        assert ref.asset_type == "table"
        assert ref.namespace == ""
        assert ref.sensitivity == ""

    def test_full(self) -> None:
        ref = DataAssetRef(
            asset_id="patients",
            asset_type="table",
            namespace="clinic_db",
            sensitivity="restricted",
        )
        assert ref.namespace == "clinic_db"
        assert ref.sensitivity == "restricted"

    def test_rejects_extra_fields(self) -> None:
        with pytest.raises(ValidationError):
            DataAssetRef(asset_id="x", asset_type="y", bogus="z")

    def test_requires_asset_id(self) -> None:
        with pytest.raises(ValidationError):
            DataAssetRef(asset_type="table")  # type: ignore[call-arg]


class TestDataSubjectRef:
    def test_valid(self) -> None:
        ref = DataSubjectRef(subject_id="patient-42")
        assert ref.subject_id == "patient-42"
        assert ref.subject_type == ""
        assert ref.jurisdiction == ""

    def test_full(self) -> None:
        ref = DataSubjectRef(
            subject_id="patient-42",
            subject_type="patient",
            jurisdiction="HIPAA",
        )
        assert ref.jurisdiction == "HIPAA"

    def test_rejects_extra_fields(self) -> None:
        with pytest.raises(ValidationError):
            DataSubjectRef(subject_id="x", bogus="z")


class TestPayloadGovernanceFields:
    def test_defaults_none(self) -> None:
        payload = AgDRPayload()
        assert payload.data_assets is None
        assert payload.data_subjects is None

    def test_populated(self) -> None:
        assets = [DataAssetRef(asset_id="t1", asset_type="table")]
        subjects = [DataSubjectRef(subject_id="s1")]
        payload = AgDRPayload(data_assets=assets, data_subjects=subjects)
        assert len(payload.data_assets) == 1
        assert payload.data_assets[0].asset_id == "t1"
        assert len(payload.data_subjects) == 1

    def test_roundtrip(self) -> None:
        assets = [DataAssetRef(asset_id="t1", asset_type="table", sensitivity="restricted")]
        payload = AgDRPayload(data_assets=assets, tool_name="read_db")
        dumped = payload.model_dump(exclude_none=True)
        restored = AgDRPayload.model_validate(dumped)
        assert restored.data_assets is not None
        assert restored.data_assets[0].asset_id == "t1"
        assert restored.data_assets[0].sensitivity == "restricted"


class TestChainBackwardCompat:
    def test_v05_chain_still_verifies(self) -> None:
        signer = Signer.generate()
        from airsdk.types import StepKind

        r1 = signer.sign(StepKind.LLM_START, {"prompt": "hello"})
        r2 = signer.sign(StepKind.LLM_END, {"response": "world"})
        result = verify_chain([r1, r2])
        assert result.status == VerificationStatus.OK

    def test_v06_tagged_record_verifies(self) -> None:
        signer = Signer.generate()
        from airsdk.types import StepKind

        payload = AgDRPayload(
            tool_name="query_patients",
            tool_args={"sql": "SELECT *"},
            data_assets=[DataAssetRef(asset_id="patients", asset_type="table")],
            data_subjects=[DataSubjectRef(subject_id="patient-42")],
        )
        r1 = signer.sign(StepKind.TOOL_START, payload)
        result = verify_chain([r1])
        assert result.status == VerificationStatus.OK


class TestRecorderGovernanceKwargs:
    def test_tool_start_with_governance(self, tmp_path: Path) -> None:
        log = tmp_path / "chain.jsonl"
        rec = AIRRecorder(log_path=log)
        assets = [DataAssetRef(asset_id="patients", asset_type="table")]
        subjects = [DataSubjectRef(subject_id="patient-42")]
        record = rec.tool_start(
            tool_name="query_db",
            data_assets=assets,
            data_subjects=subjects,
        )
        assert record.payload.data_assets is not None
        assert len(record.payload.data_assets) == 1
        assert record.payload.data_assets[0].asset_id == "patients"
        assert record.payload.data_subjects is not None
        assert record.payload.data_subjects[0].subject_id == "patient-42"

        chain = load_chain(log)
        assert chain[0].payload.data_assets is not None

    def test_llm_start_with_governance(self, tmp_path: Path) -> None:
        log = tmp_path / "chain.jsonl"
        rec = AIRRecorder(log_path=log)
        assets = [DataAssetRef(asset_id="docs", asset_type="file")]
        record = rec.llm_start(
            prompt="summarize the document",
            data_assets=assets,
        )
        assert record.payload.data_assets is not None
        assert record.payload.data_assets[0].asset_id == "docs"

    def test_tool_start_without_governance(self, tmp_path: Path) -> None:
        log = tmp_path / "chain.jsonl"
        rec = AIRRecorder(log_path=log)
        record = rec.tool_start(tool_name="ping")
        assert record.payload.data_assets is None
        assert record.payload.data_subjects is None
