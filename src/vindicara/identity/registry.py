"""In-memory agent registry."""

import uuid
from datetime import UTC, datetime

import structlog

from vindicara.identity.models import AgentIdentity, AgentStatus
from vindicara.sdk.exceptions import VindicaraError

logger = structlog.get_logger()


class AgentNotFoundError(VindicaraError):
    """Raised when an agent ID is not found in the registry."""


class AgentSuspendedError(VindicaraError):
    """Raised when an operation is attempted on a suspended agent."""


class AgentRegistry:
    def __init__(self) -> None:
        self._agents: dict[str, AgentIdentity] = {}

    def register(
        self,
        name: str,
        permitted_tools: list[str] | None = None,
        data_scope: list[str] | None = None,
        limits: dict[str, int] | None = None,
    ) -> AgentIdentity:
        agent_id = f"agent_{uuid.uuid4().hex[:12]}"
        agent = AgentIdentity(
            agent_id=agent_id,
            name=name,
            permitted_tools=permitted_tools or [],
            data_scope=data_scope or [],
            limits=limits or {},
            status=AgentStatus.ACTIVE,
            created_at=datetime.now(UTC).isoformat(),
        )
        self._agents[agent_id] = agent
        logger.info("agent.registered", agent_id=agent_id, name=name)
        return agent

    def get(self, agent_id: str) -> AgentIdentity:
        agent = self._agents.get(agent_id)
        if not agent:
            raise AgentNotFoundError(f"Agent '{agent_id}' not found")
        return agent

    def list_agents(self) -> list[AgentIdentity]:
        return list(self._agents.values())

    def suspend(self, agent_id: str, reason: str = "Manual suspension") -> AgentIdentity:
        agent = self.get(agent_id)
        updated = agent.model_copy(update={"status": AgentStatus.SUSPENDED, "suspended_reason": reason})
        self._agents[agent_id] = updated
        logger.warning("agent.suspended", agent_id=agent_id, reason=reason)
        return updated

    def reactivate(self, agent_id: str) -> AgentIdentity:
        agent = self.get(agent_id)
        updated = agent.model_copy(update={"status": AgentStatus.ACTIVE, "suspended_reason": ""})
        self._agents[agent_id] = updated
        logger.info("agent.reactivated", agent_id=agent_id)
        return updated

    def delete(self, agent_id: str) -> None:
        if agent_id not in self._agents:
            raise AgentNotFoundError(f"Agent '{agent_id}' not found")
        del self._agents[agent_id]
        logger.info("agent.deleted", agent_id=agent_id)
