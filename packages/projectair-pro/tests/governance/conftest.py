"""Shared fixtures for governance tests."""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from airsdk.agdr import Signer
from airsdk.recorder import AIRRecorder
from airsdk.types import DataAssetRef, DataSubjectRef, StepKind

from airsdk_pro.governance.indexer import index_chains
from airsdk_pro.governance.registry import AssetDefinition, DataAssetRegistry
from airsdk_pro.governance.types import GovernanceIndex


@pytest.fixture()
def sample_tagged_chain() -> list:
    """Build a short chain with governance-tagged tool_start records."""
    from airsdk.agdr import load_chain

    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        log_path = Path(f.name)

    rec = AIRRecorder(log_path=log_path)
    rec.llm_start(prompt="Fetch patient records")
    rec.llm_end(response="I will query the patients table.")
    rec.tool_start(
        tool_name="query_patients",
        tool_args={"sql": "SELECT * FROM patients WHERE id = 42"},
        data_assets=[DataAssetRef(asset_id="patients", asset_type="table", namespace="clinic_db", sensitivity="restricted")],
        data_subjects=[DataSubjectRef(subject_id="patient-42", subject_type="patient", jurisdiction="HIPAA")],
    )
    rec.tool_end(tool_name="query_patients", tool_output='[{"name": "Jane Doe"}]')
    rec.tool_start(
        tool_name="read_appointments",
        tool_args={"patient_id": "42"},
        data_assets=[DataAssetRef(asset_id="appointments", asset_type="table", namespace="clinic_db")],
        data_subjects=[DataSubjectRef(subject_id="patient-42", subject_type="patient")],
    )
    rec.tool_end(tool_name="read_appointments", tool_output="[]")
    rec.tool_start(tool_name="ping", tool_args={})
    rec.tool_end(tool_name="ping", tool_output="pong")
    rec.agent_finish(final_output="Done.")

    return load_chain(log_path)


@pytest.fixture()
def sample_registry() -> DataAssetRegistry:
    return DataAssetRegistry([
        AssetDefinition(id="patients", type="table", namespace="clinic_db", sensitivity="restricted", regulations=["HIPAA"], retention_days=2555),
        AssetDefinition(id="appointments", type="table", namespace="clinic_db", sensitivity="confidential"),
        AssetDefinition(id="logs", type="file", namespace="ops"),
    ])


@pytest.fixture()
def sample_index(sample_tagged_chain: list, sample_registry: DataAssetRegistry) -> GovernanceIndex:
    return index_chains([sample_tagged_chain], registry=sample_registry)
