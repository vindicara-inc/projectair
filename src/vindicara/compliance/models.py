"""Compliance data models."""

from enum import StrEnum

from pydantic import BaseModel, Field


class ComplianceFramework(StrEnum):
    EU_AI_ACT_ARTICLE_72 = "eu-ai-act-article-72"
    NIST_AI_RMF = "nist-ai-rmf"
    SOC2_AI = "soc2-ai"


class EvidenceType(StrEnum):
    GUARD_EVALUATION = "guard_evaluation"
    AGENT_ACTION = "agent_action"
    MCP_SCAN = "mcp_scan"
    POLICY_CHANGE = "policy_change"
    AGENT_SUSPENSION = "agent_suspension"


class ControlStatus(StrEnum):
    MET = "met"
    PARTIAL = "partial"
    NOT_MET = "not_met"
    NOT_APPLICABLE = "not_applicable"


class ControlEvidence(BaseModel):
    """Evidence collected for a single compliance control."""

    control_id: str
    control_name: str
    status: ControlStatus
    evidence_count: int = 0
    evidence_types: list[EvidenceType] = Field(default_factory=list)
    summary: str = ""
    last_evidence_at: str = ""


class FrameworkInfo(BaseModel):
    """Metadata about a compliance framework."""

    framework_id: ComplianceFramework
    name: str
    description: str = ""
    control_count: int = 0
    version: str = "1.0"


class ComplianceReport(BaseModel):
    """Generated compliance report with per-control evidence."""

    report_id: str
    framework: ComplianceFramework
    system_id: str
    period: str
    generated_at: str
    total_controls: int = 0
    met_controls: int = 0
    partial_controls: int = 0
    not_met_controls: int = 0
    coverage_pct: float = 0.0
    controls: list[ControlEvidence] = Field(default_factory=list)
    summary: str = ""


class GenerateReportRequest(BaseModel):
    """Request to generate a compliance report."""

    framework: ComplianceFramework
    system_id: str
    period: str = ""
