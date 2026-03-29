"""Composite rule chains: AND/OR/NOT logic."""

from dataclasses import dataclass

from vindicara.engine.rules.base import Rule
from vindicara.sdk.types import RuleResult, Severity


@dataclass(frozen=True)
class AnyOfRule:
    """Triggers if ANY child rule triggers (OR logic)."""

    rule_id: str
    rules: list[Rule]
    severity: Severity

    def evaluate(self, text: str) -> RuleResult:
        for rule in self.rules:
            result = rule.evaluate(text)
            if result.triggered:
                return RuleResult(
                    rule_id=self.rule_id,
                    triggered=True,
                    severity=self.severity,
                    message=f"Triggered by {result.rule_id}: {result.message}",
                )
        return RuleResult(
            rule_id=self.rule_id,
            triggered=False,
            severity=self.severity,
        )


@dataclass(frozen=True)
class AllOfRule:
    """Triggers only if ALL child rules trigger (AND logic)."""

    rule_id: str
    rules: list[Rule]
    severity: Severity

    def evaluate(self, text: str) -> RuleResult:
        messages: list[str] = []
        for rule in self.rules:
            result = rule.evaluate(text)
            if not result.triggered:
                return RuleResult(
                    rule_id=self.rule_id,
                    triggered=False,
                    severity=self.severity,
                )
            messages.append(f"{result.rule_id}: {result.message}")
        return RuleResult(
            rule_id=self.rule_id,
            triggered=True,
            severity=self.severity,
            message=f"All conditions met: {'; '.join(messages)}",
        )


@dataclass(frozen=True)
class NotRule:
    """Triggers if the inner rule does NOT trigger (NOT logic)."""

    rule_id: str
    inner: Rule
    severity: Severity

    def evaluate(self, text: str) -> RuleResult:
        result = self.inner.evaluate(text)
        return RuleResult(
            rule_id=self.rule_id,
            triggered=not result.triggered,
            severity=self.severity,
            message=f"Negation of {self.inner.rule_id}" if not result.triggered else "",
        )
