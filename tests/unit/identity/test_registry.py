"""Tests for agent registry."""

import pytest

from vindicara.identity.registry import AgentNotFoundError, AgentRegistry


class TestAgentRegistry:
    def test_register_agent(self) -> None:
        registry = AgentRegistry()
        agent = registry.register(
            name="sales-bot",
            permitted_tools=["crm_read"],
            data_scope=["accounts"],
            limits={"max_actions_per_minute": 60},
        )
        assert agent.name == "sales-bot"
        assert agent.agent_id.startswith("agent_")
        assert agent.is_active

    def test_get_agent(self) -> None:
        registry = AgentRegistry()
        created = registry.register(name="test")
        fetched = registry.get(created.agent_id)
        assert fetched.agent_id == created.agent_id

    def test_get_missing_raises(self) -> None:
        registry = AgentRegistry()
        with pytest.raises(AgentNotFoundError):
            registry.get("nonexistent")

    def test_list_agents(self) -> None:
        registry = AgentRegistry()
        registry.register(name="a")
        registry.register(name="b")
        assert len(registry.list_agents()) == 2

    def test_suspend_agent(self) -> None:
        registry = AgentRegistry()
        agent = registry.register(name="test")
        suspended = registry.suspend(agent.agent_id, reason="Rogue behavior")
        assert suspended.is_suspended
        assert suspended.suspended_reason == "Rogue behavior"

    def test_reactivate_agent(self) -> None:
        registry = AgentRegistry()
        agent = registry.register(name="test")
        registry.suspend(agent.agent_id)
        reactivated = registry.reactivate(agent.agent_id)
        assert reactivated.is_active

    def test_delete_agent(self) -> None:
        registry = AgentRegistry()
        agent = registry.register(name="test")
        registry.delete(agent.agent_id)
        with pytest.raises(AgentNotFoundError):
            registry.get(agent.agent_id)

    def test_delete_missing_raises(self) -> None:
        registry = AgentRegistry()
        with pytest.raises(AgentNotFoundError):
            registry.delete("nonexistent")
