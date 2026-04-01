"""Tests for agent identity models."""

from vindicara.identity.models import AgentIdentity, AgentStatus, CheckResult


class TestAgentIdentity:
    def test_active_by_default(self) -> None:
        agent = AgentIdentity(agent_id="a1", name="test-agent")
        assert agent.is_active
        assert not agent.is_suspended

    def test_suspended_agent(self) -> None:
        agent = AgentIdentity(
            agent_id="a1", name="test-agent",
            status=AgentStatus.SUSPENDED, suspended_reason="Anomalous behavior",
        )
        assert agent.is_suspended
        assert not agent.is_active

    def test_agent_with_permissions(self) -> None:
        agent = AgentIdentity(
            agent_id="a1", name="sales-bot",
            permitted_tools=["crm_read", "email_send"],
            data_scope=["accounts.sales"],
            limits={"max_actions_per_minute": 60},
        )
        assert len(agent.permitted_tools) == 2
        assert agent.limits["max_actions_per_minute"] == 60


class TestCheckResult:
    def test_allowed(self) -> None:
        result = CheckResult(agent_id="a1", tool="crm_read", allowed=True)
        assert result.allowed

    def test_denied(self) -> None:
        result = CheckResult(agent_id="a1", tool="admin_delete", allowed=False, reason="Tool not in permitted list")
        assert not result.allowed
