"""Agent identity data models."""

from enum import StrEnum

from pydantic import BaseModel, Field


class AgentStatus(StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"


class AgentIdentity(BaseModel):
    agent_id: str
    name: str
    permitted_tools: list[str] = Field(default_factory=list)
    data_scope: list[str] = Field(default_factory=list)
    limits: dict[str, int] = Field(default_factory=dict)
    status: AgentStatus = AgentStatus.ACTIVE
    suspended_reason: str = ""
    created_at: str = ""

    @property
    def is_active(self) -> bool:
        return self.status == AgentStatus.ACTIVE

    @property
    def is_suspended(self) -> bool:
        return self.status == AgentStatus.SUSPENDED


class RegisterAgentRequest(BaseModel):
    name: str
    permitted_tools: list[str] = Field(default_factory=list)
    data_scope: list[str] = Field(default_factory=list)
    limits: dict[str, int] = Field(default_factory=dict)


class CheckRequest(BaseModel):
    tool: str
    data_scope: str = ""


class CheckResult(BaseModel):
    agent_id: str
    tool: str
    allowed: bool
    reason: str = ""


class SuspendRequest(BaseModel):
    reason: str = "Manual suspension"
