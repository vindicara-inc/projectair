"""Tests for SDK response types."""

from vindicara.sdk.types import (
    GuardResult,
    PolicyInfo,
    RuleResult,
    Severity,
    Verdict,
)


class TestGuardResult:
    def test_allowed_result(self) -> None:
        result = GuardResult(
            verdict=Verdict.ALLOWED,
            policy_id="content-safety",
            rules=[],
            latency_ms=1.5,
        )
        assert result.is_allowed
        assert not result.is_blocked
        assert result.verdict == Verdict.ALLOWED

    def test_blocked_result(self) -> None:
        rule = RuleResult(
            rule_id="pii-ssn",
            triggered=True,
            severity=Severity.CRITICAL,
            message="SSN detected in output",
        )
        result = GuardResult(
            verdict=Verdict.BLOCKED,
            policy_id="pii-filter",
            rules=[rule],
            latency_ms=0.8,
        )
        assert result.is_blocked
        assert not result.is_allowed
        assert len(result.triggered_rules) == 1
        assert result.triggered_rules[0].rule_id == "pii-ssn"

    def test_flagged_result(self) -> None:
        result = GuardResult(
            verdict=Verdict.FLAGGED,
            policy_id="content-safety",
            rules=[],
            latency_ms=2.0,
        )
        assert not result.is_allowed
        assert not result.is_blocked
        assert result.verdict == Verdict.FLAGGED


class TestPolicyInfo:
    def test_policy_info(self) -> None:
        info = PolicyInfo(
            policy_id="pii-filter",
            name="PII Filter",
            description="Detects and blocks PII in outputs",
            version=1,
            enabled=True,
        )
        assert info.policy_id == "pii-filter"
        assert info.version == 1
