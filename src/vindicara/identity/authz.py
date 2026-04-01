"""Permission checking engine for agent tool calls."""

import structlog

from vindicara.identity.models import CheckResult
from vindicara.identity.registry import AgentRegistry

logger = structlog.get_logger()


class AuthzEngine:
    def __init__(self, registry: AgentRegistry) -> None:
        self._registry = registry

    def check_tool(self, agent_id: str, tool: str) -> CheckResult:
        agent = self._registry.get(agent_id)

        if agent.is_suspended:
            logger.warning("authz.denied.suspended", agent_id=agent_id, tool=tool)
            return CheckResult(
                agent_id=agent_id,
                tool=tool,
                allowed=False,
                reason=f"Agent is suspended: {agent.suspended_reason}",
            )

        if not agent.permitted_tools:
            return CheckResult(agent_id=agent_id, tool=tool, allowed=True, reason="No tool restrictions")

        if tool in agent.permitted_tools:
            return CheckResult(agent_id=agent_id, tool=tool, allowed=True)

        return CheckResult(
            agent_id=agent_id,
            tool=tool,
            allowed=False,
            reason=f"Tool '{tool}' not in permitted list: {agent.permitted_tools}",
        )

    def check_data_scope(self, agent_id: str, scope: str) -> CheckResult:
        agent = self._registry.get(agent_id)

        if agent.is_suspended:
            return CheckResult(
                agent_id=agent_id,
                tool=scope,
                allowed=False,
                reason=f"Agent is suspended: {agent.suspended_reason}",
            )

        if not agent.data_scope:
            return CheckResult(agent_id=agent_id, tool=scope, allowed=True, reason="No data scope restrictions")

        for allowed_scope in agent.data_scope:
            if scope.startswith(allowed_scope):
                return CheckResult(agent_id=agent_id, tool=scope, allowed=True)

        return CheckResult(
            agent_id=agent_id,
            tool=scope,
            allowed=False,
            reason=f"Data scope '{scope}' not within permitted scopes: {agent.data_scope}",
        )
