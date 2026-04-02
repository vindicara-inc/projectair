"""Tests for compliance report generator."""

import time

from vindicara.audit.logger import AuditEvent
from vindicara.compliance.collector import EvidenceCollector
from vindicara.compliance.models import ComplianceFramework, ControlStatus
from vindicara.compliance.reporter import ComplianceReporter
from vindicara.config.constants import (
    AUDIT_EVENT_AGENT_ACTION,
    AUDIT_EVENT_AGENT_SUSPENDED,
    AUDIT_EVENT_GUARD,
    AUDIT_EVENT_MCP_SCAN,
    AUDIT_EVENT_POLICY_CREATE,
)


class TestComplianceReporter:
    def test_empty_evidence_all_not_met(self) -> None:
        collector = EvidenceCollector()
        reporter = ComplianceReporter(collector)
        report = reporter.generate(
            framework=ComplianceFramework.EU_AI_ACT_ARTICLE_72,
            system_id="test",
        )
        assert report.total_controls == 8
        assert report.met_controls == 0
        assert report.coverage_pct == 0.0
        for ctrl in report.controls:
            assert ctrl.status == ControlStatus.NOT_MET

    def test_partial_evidence(self) -> None:
        collector = EvidenceCollector()
        now = time.time()
        for _ in range(3):
            collector.record(AuditEvent(event_type=AUDIT_EVENT_GUARD, timestamp=now))

        reporter = ComplianceReporter(collector)
        report = reporter.generate(
            framework=ComplianceFramework.EU_AI_ACT_ARTICLE_72,
            system_id="test",
        )
        assert report.met_controls < report.total_controls
        assert report.coverage_pct > 0.0

    def test_full_evidence_high_coverage(self) -> None:
        collector = EvidenceCollector()
        now = time.time()
        for _ in range(20):
            collector.record(AuditEvent(event_type=AUDIT_EVENT_GUARD, timestamp=now))
        for _ in range(5):
            collector.record(AuditEvent(event_type=AUDIT_EVENT_AGENT_ACTION, timestamp=now))
        collector.record(AuditEvent(event_type=AUDIT_EVENT_MCP_SCAN, timestamp=now))
        collector.record(AuditEvent(event_type=AUDIT_EVENT_AGENT_SUSPENDED, timestamp=now))
        collector.record(AuditEvent(event_type=AUDIT_EVENT_POLICY_CREATE, timestamp=now))

        reporter = ComplianceReporter(collector)
        report = reporter.generate(
            framework=ComplianceFramework.EU_AI_ACT_ARTICLE_72,
            system_id="test",
        )
        assert report.met_controls > 0
        assert report.coverage_pct > 50.0
        assert report.report_id.startswith("rpt_")

    def test_report_has_correct_framework(self) -> None:
        collector = EvidenceCollector()
        reporter = ComplianceReporter(collector)
        report = reporter.generate(
            framework=ComplianceFramework.NIST_AI_RMF,
            system_id="test",
            period="2026-Q1",
        )
        assert report.framework == ComplianceFramework.NIST_AI_RMF
        assert report.system_id == "test"
        assert report.period == "2026-Q1"

    def test_soc2_report(self) -> None:
        collector = EvidenceCollector()
        reporter = ComplianceReporter(collector)
        report = reporter.generate(
            framework=ComplianceFramework.SOC2_AI,
            system_id="test",
        )
        assert report.total_controls == 8
