"""Tests for compliance models."""

from vindicara.compliance.models import (
    ComplianceFramework,
    ComplianceReport,
    ControlEvidence,
    ControlStatus,
    EvidenceType,
    GenerateReportRequest,
)


class TestComplianceFramework:
    def test_enum_values(self) -> None:
        assert ComplianceFramework.EU_AI_ACT_ARTICLE_72 == "eu-ai-act-article-72"
        assert ComplianceFramework.NIST_AI_RMF == "nist-ai-rmf"
        assert ComplianceFramework.SOC2_AI == "soc2-ai"


class TestEvidenceType:
    def test_enum_values(self) -> None:
        assert EvidenceType.GUARD_EVALUATION == "guard_evaluation"
        assert EvidenceType.AGENT_ACTION == "agent_action"
        assert EvidenceType.MCP_SCAN == "mcp_scan"


class TestControlEvidence:
    def test_create(self) -> None:
        ce = ControlEvidence(
            control_id="ART72-1",
            control_name="System Performance Monitoring",
            status=ControlStatus.MET,
            evidence_count=15,
            evidence_types=[EvidenceType.GUARD_EVALUATION],
        )
        assert ce.control_id == "ART72-1"
        assert ce.status == ControlStatus.MET
        assert ce.evidence_count == 15


class TestComplianceReport:
    def test_defaults(self) -> None:
        report = ComplianceReport(
            report_id="rpt_test",
            framework=ComplianceFramework.EU_AI_ACT_ARTICLE_72,
            system_id="test-system",
            period="2026-Q1",
            generated_at="2026-04-01T00:00:00Z",
        )
        assert report.total_controls == 0
        assert report.coverage_pct == 0.0
        assert report.controls == []


class TestGenerateReportRequest:
    def test_create(self) -> None:
        req = GenerateReportRequest(
            framework=ComplianceFramework.NIST_AI_RMF,
            system_id="sales-bot",
        )
        assert req.framework == ComplianceFramework.NIST_AI_RMF
        assert req.period == ""
