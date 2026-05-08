"""Containment policy tests."""
from __future__ import annotations

from airsdk.containment.policy import ContainmentPolicy, Decision
from airsdk.types import Finding


def test_empty_policy_is_permissive() -> None:
    policy = ContainmentPolicy()
    verdict = policy.evaluate("anything", {"x": 1})
    assert verdict.decision == Decision.ALLOW


def test_deny_tools_blocks_by_name() -> None:
    policy = ContainmentPolicy(deny_tools=["shell_exec"])
    verdict = policy.evaluate("shell_exec", {"cmd": "ls"})
    assert verdict.decision == Decision.BLOCK
    assert "shell_exec" in verdict.reason


def test_deny_tools_does_not_block_unrelated_tools() -> None:
    policy = ContainmentPolicy(deny_tools=["shell_exec"])
    verdict = policy.evaluate("read_file", {"path": "/etc/hosts"})
    assert verdict.decision == Decision.ALLOW


def test_deny_arg_pattern_blocks_dangerous_command() -> None:
    policy = ContainmentPolicy(
        deny_arg_patterns={"shell_exec": {"cmd": r"rm\s+-rf"}},
    )
    verdict = policy.evaluate("shell_exec", {"cmd": "rm -rf /"})
    assert verdict.decision == Decision.BLOCK


def test_deny_arg_pattern_allows_safe_command() -> None:
    policy = ContainmentPolicy(
        deny_arg_patterns={"shell_exec": {"cmd": r"rm\s+-rf"}},
    )
    verdict = policy.evaluate("shell_exec", {"cmd": "ls -la"})
    assert verdict.decision == Decision.ALLOW


def test_deny_arg_pattern_searches_nested_dict_via_str() -> None:
    """Tool args are sometimes nested dicts (http_post body). The policy
    stringifies them so the regex finds patterns inside."""
    policy = ContainmentPolicy(
        deny_arg_patterns={"http_post": {"body": r"attacker\.example"}},
    )
    verdict = policy.evaluate(
        "http_post",
        {"url": "http://example.com", "body": {"target": "attacker.example.com"}},
    )
    assert verdict.decision == Decision.BLOCK


def test_block_on_findings_halts_after_detector_fires() -> None:
    policy = ContainmentPolicy(block_on_findings=["AIR-01"])
    finding = Finding(
        detector_id="AIR-01",
        title="Prompt Injection Detected",
        severity="high",
        step_id="step-uuid",
        step_index=3,
        description="injection in tool output",
    )
    verdict = policy.evaluate("read_file", {"path": "/x"}, prior_findings=[finding])
    assert verdict.decision == Decision.BLOCK
    assert "AIR-01" in verdict.reason


def test_block_on_findings_ignores_unrelated_detectors() -> None:
    policy = ContainmentPolicy(block_on_findings=["AIR-01"])
    finding = Finding(
        detector_id="ASI06",
        title="Memory Poisoning",
        severity="medium",
        step_id="step-uuid",
        step_index=2,
        description="...",
    )
    verdict = policy.evaluate("read_file", {"path": "/x"}, prior_findings=[finding])
    assert verdict.decision == Decision.ALLOW


def test_step_up_required_returns_challenge_id() -> None:
    policy = ContainmentPolicy(
        step_up_for_actions=[{"tool": "stripe_charge"}],
    )
    verdict = policy.evaluate("stripe_charge", {"amount_cents": 9999})
    assert verdict.decision == Decision.STEP_UP
    assert verdict.challenge_id is not None
    assert len(verdict.challenge_id) >= 16  # urlsafe_b64encode(16 bytes) > 16 chars


def test_step_up_each_call_gets_fresh_challenge() -> None:
    policy = ContainmentPolicy(step_up_for_actions=[{"tool": "send_email"}])
    a = policy.evaluate("send_email", {"to": "x@y.com"})
    b = policy.evaluate("send_email", {"to": "x@y.com"})
    assert a.challenge_id != b.challenge_id


def test_deny_overrides_step_up() -> None:
    """If an operator forgets to remove a step-up rule when adding a deny
    rule for the same tool, the deny wins. 'absolutely never' must stay
    absolute."""
    policy = ContainmentPolicy(
        deny_tools=["shell_exec"],
        step_up_for_actions=[{"tool": "shell_exec"}],
    )
    verdict = policy.evaluate("shell_exec", {})
    assert verdict.decision == Decision.BLOCK
