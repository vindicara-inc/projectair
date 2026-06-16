"""Base protocol for policy rules."""

from typing import Protocol

from vindicara.sdk.types import RuleResult


class Rule(Protocol):
    """Protocol that all policy rules must implement.

    ``rule_id`` is declared as a read-only property so that concrete rules
    exposing it as a frozen/read-only attribute (the common case) satisfy
    the protocol. A plain ``rule_id: str`` annotation would require a
    settable attribute and reject read-only implementations.
    """

    @property
    def rule_id(self) -> str: ...

    def evaluate(self, text: str) -> RuleResult:
        """Evaluate text against this rule and return a result."""
        ...
