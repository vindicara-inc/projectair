"""Base protocol for policy rules."""

from typing import Protocol

from vindicara.sdk.types import RuleResult


class Rule(Protocol):
    """Protocol that all policy rules must implement."""

    rule_id: str

    def evaluate(self, text: str) -> RuleResult:
        """Evaluate text against this rule and return a result."""
        ...
