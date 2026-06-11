"""Per-org persistence for Flightdeck console workspace state.

The console's mutable state (revoked delegations, resolved findings, evidence
transport toggles, carrier consents, connected plugins) is workspace-scoped and
must survive restarts and be shared across API instances. This module defines the
state model and two backends: an in-memory store for local/dev/test, and a
DynamoDB store (table ``vindicara-flightdeck``) for production.

Keyed per org (one workspace per Auth0 organization).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Protocol

import structlog

from vindicara.config.constants import TABLE_NAME_FLIGHTDECK

logger = structlog.get_logger()

_ENV_TABLE = "AIR_FLIGHTDECK_TABLE"

DEFAULT_TRANSPORT: dict[str, bool] = {
    "Signed evidence pack": True,
    "Posture feed": True,
    "Incident reconstruction": True,
    "Raw PHI / payloads": False,
}


@dataclass
class WorkspaceState:
    """Mutable, persisted state for a single console workspace (org)."""

    revoked_agents: set[str] = field(default_factory=set)
    resolved_findings: set[str] = field(default_factory=set)
    transport: dict[str, bool] = field(default_factory=lambda: dict(DEFAULT_TRANSPORT))
    consents: list[dict[str, str]] = field(default_factory=list)
    plugin_connected: set[str] = field(default_factory=set)

    def to_item(self) -> dict[str, object]:
        """Serialize to a JSON-safe dict (sets become sorted lists)."""
        return {
            "revoked_agents": sorted(self.revoked_agents),
            "resolved_findings": sorted(self.resolved_findings),
            "transport": self.transport,
            "consents": self.consents,
            "plugin_connected": sorted(self.plugin_connected),
        }

    @classmethod
    def from_item(cls, item: dict[str, object]) -> WorkspaceState:
        transport = dict(DEFAULT_TRANSPORT)
        raw_transport = item.get("transport")
        if isinstance(raw_transport, dict):
            transport.update({str(k): bool(v) for k, v in raw_transport.items()})
        consents_raw = item.get("consents")
        consents = consents_raw if isinstance(consents_raw, list) else []
        return cls(
            revoked_agents=set(_str_list(item.get("revoked_agents"))),
            resolved_findings=set(_str_list(item.get("resolved_findings"))),
            transport=transport,
            consents=[c for c in consents if isinstance(c, dict)],
            plugin_connected=set(_str_list(item.get("plugin_connected"))),
        )


def _str_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value]
    return []


class WorkspaceStore(Protocol):
    """Loads and saves :class:`WorkspaceState` keyed by workspace (org) id."""

    def load(self, workspace_id: str) -> WorkspaceState: ...

    def save(self, workspace_id: str, state: WorkspaceState) -> None: ...


class InMemoryWorkspaceStore:
    """Process-local store. Default for local dev and tests."""

    def __init__(self) -> None:
        self._states: dict[str, WorkspaceState] = {}

    def load(self, workspace_id: str) -> WorkspaceState:
        return self._states.setdefault(workspace_id, WorkspaceState())

    def save(self, workspace_id: str, state: WorkspaceState) -> None:
        self._states[workspace_id] = state


class DynamoWorkspaceStore:
    """DynamoDB-backed store. One item per workspace (pk=ws#<id>, sk=state)."""

    def __init__(self, table_name: str | None = None) -> None:
        import boto3  # lazy: keeps boto3 off the import path for local/test

        self._table = boto3.resource("dynamodb").Table(table_name or TABLE_NAME_FLIGHTDECK)

    def load(self, workspace_id: str) -> WorkspaceState:
        response = self._table.get_item(Key={"pk": f"ws#{workspace_id}", "sk": "state"})
        item = response.get("Item")
        if not item:
            return WorkspaceState()
        raw = item.get("state")
        if isinstance(raw, str):
            return WorkspaceState.from_item(json.loads(raw))
        return WorkspaceState()

    def save(self, workspace_id: str, state: WorkspaceState) -> None:
        self._table.put_item(
            Item={
                "pk": f"ws#{workspace_id}",
                "sk": "state",
                "state": json.dumps(state.to_item()),
            }
        )


def build_workspace_store() -> WorkspaceStore:
    """Return the DynamoDB store when configured, else the in-memory store."""
    table_name = os.environ.get(_ENV_TABLE)
    if table_name:
        logger.info("flightdeck.store.dynamodb", table=table_name)
        return DynamoWorkspaceStore(table_name)
    logger.info("flightdeck.store.in_memory")
    return InMemoryWorkspaceStore()
