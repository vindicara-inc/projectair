"""Compliance summary route for AIR Cloud."""
from __future__ import annotations

from typing import TYPE_CHECKING

from airsdk.types import StepKind
from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict

from vindicara.cloud.roles import Capability, require
from vindicara.compliance.frameworks import FRAMEWORKS
from vindicara.compliance.models import EvidenceType

if TYPE_CHECKING:
    from vindicara.cloud.capsule_store import CapsuleStore, StoredCapsule

router = APIRouter(tags=["compliance"])

# Map capsule StepKind values to EvidenceType counters.
# MCP_SCAN evidence does not originate from signed capsule records;
# it comes from the MCP scanner and will always show 0 in this view.
_KIND_TO_EVIDENCE: dict[StepKind, EvidenceType] = {
    StepKind.LLM_START: EvidenceType.GUARD_EVALUATION,
    StepKind.LLM_END: EvidenceType.GUARD_EVALUATION,
    StepKind.TOOL_START: EvidenceType.AGENT_ACTION,
    StepKind.TOOL_END: EvidenceType.AGENT_ACTION,
    StepKind.AGENT_FINISH: EvidenceType.AGENT_ACTION,
    StepKind.AGENT_MESSAGE: EvidenceType.AGENT_ACTION,
    StepKind.HUMAN_APPROVAL: EvidenceType.AGENT_SUSPENSION,
}
if hasattr(StepKind, "INTENT_DECLARATION"):
    _KIND_TO_EVIDENCE[StepKind.INTENT_DECLARATION] = EvidenceType.POLICY_CHANGE


class ControlScore(BaseModel):
    """Per-control compliance score."""

    model_config = ConfigDict(extra="forbid")

    control_id: str
    control_name: str
    evidence_count: int
    required: int
    met: bool


class FrameworkScore(BaseModel):
    """Aggregate compliance score for one framework."""

    model_config = ConfigDict(extra="forbid")

    framework_id: str
    name: str
    total_controls: int
    met_controls: int
    coverage_pct: float
    controls: list[ControlScore]


class ComplianceSummary(BaseModel):
    """Full compliance summary across all frameworks."""

    model_config = ConfigDict(extra="forbid")

    frameworks: list[FrameworkScore]


def _tally_evidence(capsules: list[StoredCapsule]) -> dict[EvidenceType, int]:
    """Count evidence type occurrences from workspace capsule records."""
    counts: dict[EvidenceType, int] = dict.fromkeys(EvidenceType, 0)
    for capsule in capsules:
        evidence_type = _KIND_TO_EVIDENCE.get(capsule.record.kind)
        if evidence_type is not None:
            counts[evidence_type] += 1
    return counts


def _score_framework(
    fw_id: object,
    evidence_counts: dict[EvidenceType, int],
) -> FrameworkScore:
    """Score one framework definition against collected evidence counts."""

    fw_def = FRAMEWORKS[fw_id]  # type: ignore[index]
    control_scores: list[ControlScore] = []

    for ctrl in fw_def.controls:
        # A control is met when ALL required evidence types each reach
        # min_evidence_count. If multiple types are required the
        # minimum across them must satisfy the threshold.
        if ctrl.required_evidence_types:
            min_count = min(
                evidence_counts.get(et, 0)
                for et in ctrl.required_evidence_types
            )
        else:
            min_count = 0

        met = min_count >= ctrl.min_evidence_count
        control_scores.append(
            ControlScore(
                control_id=ctrl.control_id,
                control_name=ctrl.control_name,
                evidence_count=min_count,
                required=ctrl.min_evidence_count,
                met=met,
            )
        )

    total = len(control_scores)
    met_count = sum(1 for cs in control_scores if cs.met)
    coverage = (met_count / total * 100.0) if total > 0 else 0.0

    return FrameworkScore(
        framework_id=fw_def.framework_id.value,
        name=fw_def.name,
        total_controls=total,
        met_controls=met_count,
        coverage_pct=round(coverage, 2),
        controls=control_scores,
    )


@router.get(
    "/v1/compliance/summary",
    response_model=ComplianceSummary,
    summary="Per-framework compliance scores for the calling workspace",
)
async def get_compliance_summary(request: Request) -> ComplianceSummary:
    """Return compliance coverage scores derived from workspace capsule records.

    Requires admin or owner role. Evidence counts are derived from the
    signed Intent Capsules stored for the workspace; each StepKind maps
    to one EvidenceType bucket. MCP_SCAN evidence is not derived from
    capsule records and will always read 0 in this view.
    """
    require(request, Capability.LIST_KEYS)

    store: CapsuleStore = request.app.state.capsule_store
    workspace_id: str = request.state.workspace_id
    capsules = store.for_workspace(workspace_id)

    evidence_counts = _tally_evidence(capsules)

    framework_scores = [
        _score_framework(fw_id, evidence_counts)
        for fw_id in FRAMEWORKS
    ]

    return ComplianceSummary(frameworks=framework_scores)


__all__ = ["ComplianceSummary", "ControlScore", "FrameworkScore", "router"]
