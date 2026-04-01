"""Tests for permission checking engine."""

from vindicara.identity.authz import AuthzEngine
from vindicara.identity.registry import AgentRegistry


class TestToolPermissions:
    def test_allowed_tool(self) -> None:
        registry = AgentRegistry()
        agent = registry.register(name="bot", permitted_tools=["crm_read", "email_send"])
        engine = AuthzEngine(registry)
        result = engine.check_tool(agent.agent_id, "crm_read")
        assert result.allowed

    def test_denied_tool(self) -> None:
        registry = AgentRegistry()
        agent = registry.register(name="bot", permitted_tools=["crm_read"])
        engine = AuthzEngine(registry)
        result = engine.check_tool(agent.agent_id, "admin_delete")
        assert not result.allowed
        assert "not in permitted" in result.reason

    def test_no_restrictions_allows_all(self) -> None:
        registry = AgentRegistry()
        agent = registry.register(name="bot", permitted_tools=[])
        engine = AuthzEngine(registry)
        result = engine.check_tool(agent.agent_id, "anything")
        assert result.allowed

    def test_suspended_agent_denied(self) -> None:
        registry = AgentRegistry()
        agent = registry.register(name="bot", permitted_tools=["crm_read"])
        registry.suspend(agent.agent_id, reason="Rogue")
        engine = AuthzEngine(registry)
        result = engine.check_tool(agent.agent_id, "crm_read")
        assert not result.allowed
        assert "suspended" in result.reason.lower()


class TestDataScopePermissions:
    def test_allowed_scope(self) -> None:
        registry = AgentRegistry()
        agent = registry.register(name="bot", data_scope=["accounts.sales"])
        engine = AuthzEngine(registry)
        result = engine.check_data_scope(agent.agent_id, "accounts.sales.pipeline")
        assert result.allowed

    def test_denied_scope(self) -> None:
        registry = AgentRegistry()
        agent = registry.register(name="bot", data_scope=["accounts.sales"])
        engine = AuthzEngine(registry)
        result = engine.check_data_scope(agent.agent_id, "accounts.hr.payroll")
        assert not result.allowed

    def test_no_scope_restrictions(self) -> None:
        registry = AgentRegistry()
        agent = registry.register(name="bot", data_scope=[])
        engine = AuthzEngine(registry)
        result = engine.check_data_scope(agent.agent_id, "anything")
        assert result.allowed

    def test_suspended_denies_scope(self) -> None:
        registry = AgentRegistry()
        agent = registry.register(name="bot", data_scope=["accounts"])
        registry.suspend(agent.agent_id)
        engine = AuthzEngine(registry)
        result = engine.check_data_scope(agent.agent_id, "accounts")
        assert not result.allowed
