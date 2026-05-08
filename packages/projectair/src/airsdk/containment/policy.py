"""Declarative containment policy.

Operators describe what the agent IS NOT allowed to do, plus what
requires human approval. The recorder consults the policy on every
tool_start, before any side effect happens. Three decisions:

- ``ALLOW``: rule says nothing about this action; proceed normally
- ``BLOCK``: a deny rule trips; raise ``BlockedActionError``
- ``STEP_UP``: a step-up rule trips; raise ``StepUpRequiredError``
  with a fresh challenge id for the approval flow

Rule precedence: deny rules override step-up rules. If the same action
matches both a ``deny_tools`` entry and a ``step_up_for_actions`` entry,
it is blocked, never queued for approval. This keeps "absolutely never"
absolute even when an operator forgets to remove the step-up rule.
"""
from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from airsdk.types import Finding


class Decision(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    STEP_UP = "step_up"


@dataclass(frozen=True)
class PolicyVerdict:
    decision: Decision
    reason: str = ""
    challenge_id: str | None = None


@dataclass
class ContainmentPolicy:
    """Declarative containment ruleset.

    Parameters
    ----------
    deny_tools:
        Tool names that are always blocked. Use for tools that have no
        legitimate use case from this agent (``shell_exec`` from a
        customer-support bot, ``billing_api.charge`` from a docs
        assistant).
    deny_arg_patterns:
        Map of tool_name -> {arg_name: regex_pattern}. The regex must
        match for the action to be denied. Use for "shell_exec is fine
        but never with rm -rf" or "http_post is fine but never to
        attacker domains".
    block_on_findings:
        Detector ids (``ASI01``, ``AIR-02``, etc.) that, when present
        in the chain so far, block any further tool calls. Use to halt
        an agent the moment a guard detector fires.
    step_up_for_actions:
        List of dicts. Each dict is a set of equality matches against
        the action description (``{"tool": "stripe_charge"}`` or
        ``{"tool": "send_email", "to_domain": "external"}``). When all
        keys match, the action requires human approval.

    All four lists default to empty; an empty policy is permissive.
    """

    deny_tools: list[str] = field(default_factory=list)
    deny_arg_patterns: dict[str, dict[str, str]] = field(default_factory=dict)
    block_on_findings: list[str] = field(default_factory=list)
    step_up_for_actions: list[dict[str, Any]] = field(default_factory=list)

    def evaluate(
        self,
        tool_name: str,
        tool_args: dict[str, Any] | None = None,
        prior_findings: list[Finding] | None = None,
    ) -> PolicyVerdict:
        """Decide whether ``tool_name`` with ``tool_args`` is allowed.

        The recorder calls this synchronously before writing TOOL_START.
        Return value is consumed verbatim; side effects (chain writes,
        challenge issuance) live on the recorder, not here.
        """
        args = tool_args or {}
        findings = prior_findings or []

        # 1. Hard block: tool name explicitly denied.
        if tool_name in self.deny_tools:
            return PolicyVerdict(
                decision=Decision.BLOCK,
                reason=f"tool {tool_name!r} is in deny_tools",
            )

        # 2. Hard block: argument pattern matches a deny rule.
        arg_rules = self.deny_arg_patterns.get(tool_name, {})
        for arg_name, pattern in arg_rules.items():
            value = _stringify(args.get(arg_name))
            if value is not None and re.search(pattern, value):
                return PolicyVerdict(
                    decision=Decision.BLOCK,
                    reason=(
                        f"tool {tool_name!r} arg {arg_name!r} matches deny "
                        f"pattern {pattern!r}: {_truncate(value, 64)!r}"
                    ),
                )

        # 3. Hard block: a guard detector has fired earlier in the chain.
        for finding in findings:
            if finding.detector_id in self.block_on_findings:
                return PolicyVerdict(
                    decision=Decision.BLOCK,
                    reason=(
                        f"detector {finding.detector_id} fired earlier "
                        f"in chain ({finding.title}); refusing further actions"
                    ),
                )

        # 4. Step-up: explicit human approval required for this action.
        action = {"tool": tool_name, **args}
        for rule in self.step_up_for_actions:
            if _action_matches(action, rule):
                return PolicyVerdict(
                    decision=Decision.STEP_UP,
                    reason=f"action {action!r} matches step-up rule {rule!r}",
                    challenge_id=_new_challenge_id(),
                )

        return PolicyVerdict(decision=Decision.ALLOW)


def _stringify(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, dict | list | tuple):
        # A tool arg might be a nested dict (http_post body, openapi spec).
        # Stringify so a regex can scan it; this is a best-effort surface,
        # not a security boundary - critical args should be flat strings.
        return str(value)
    return str(value)


def _action_matches(action: dict[str, Any], rule: dict[str, Any]) -> bool:
    return all(action.get(key) == expected for key, expected in rule.items())


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "..."


def _new_challenge_id() -> str:
    """Cryptographically-random challenge id for step-up approval flows.

    Used as the JWT subject the approver authenticates against and as
    the chain-side reference linking the TOOL_START to the eventual
    HUMAN_APPROVAL record. 128 bits of entropy is overkill for an
    approval session token but trivially cheap.
    """
    return secrets.token_urlsafe(16)
