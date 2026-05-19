"""Data governance types for AIR Pro."""
from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from airsdk.types import DataAssetRef, DataSubjectRef, HumanApproval

GOVERNANCE_FEATURE = "data_governance"


class AccessType(StrEnum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    TRANSFORM = "transform"
    UNKNOWN = "unknown"


class DataAccessRecord(BaseModel):
    """Flattened view of one agent data access, derived from AgDR records."""

    model_config = ConfigDict(extra="forbid")

    step_id: str
    timestamp: str
    agent_id: str | None
    tool_name: str
    access_type: AccessType
    data_assets: list[DataAssetRef]
    data_subjects: list[DataSubjectRef]
    identity_proof: str | None
    policy_decision: str | None
    approval: HumanApproval | None


class GovernanceIndex(BaseModel):
    """In-memory index of data accesses across one or more chains."""

    model_config = ConfigDict(extra="forbid")

    accesses: list[DataAccessRecord]
    by_subject: dict[str, list[int]]
    by_asset: dict[str, list[int]]
    by_agent: dict[str, list[int]]


class SubjectAccessReport(BaseModel):
    """DSAR response: all agent actions touching a specific data subject."""

    model_config = ConfigDict(extra="forbid")

    subject: DataSubjectRef
    generated_at: str
    total_accesses: int
    accesses: list[DataAccessRecord]
    chains_searched: int
    jurisdiction_notes: str


class GovernanceReport(BaseModel):
    """Full governance report across multiple chains."""

    model_config = ConfigDict(extra="forbid")

    generated_at: str
    total_chains: int
    total_accesses: int
    assets_accessed: list[str]
    subjects_affected: list[str]
    policy_enforcements: int
    violations: int
