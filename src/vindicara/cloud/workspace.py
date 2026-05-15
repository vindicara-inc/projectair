"""Workspace + API-key model for AIR Cloud multi-tenancy.

A workspace is the unit of tenancy: every ingested capsule belongs to
exactly one workspace, and every API key authenticates the bearer as
acting on behalf of one specific workspace.

The protocols here are the persistence boundary; ``InMemory*`` impls
ship for tests and local dev. A DynamoDB-backed pair lands when the
hosted service deploys to AWS.
"""
from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

API_KEY_PREFIX = "air_"
"""Prefix on every issued API key. Never used for workspace IDs."""


def _now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def generate_api_key() -> str:
    """Generate a fresh API key. Format: ``air_<32 hex chars>``."""
    return API_KEY_PREFIX + secrets.token_hex(16)


@dataclass(frozen=True)
class Workspace:
    """A single tenant on AIR Cloud."""

    workspace_id: str
    name: str
    owner_email: str
    created_at: str = field(default_factory=_now_iso)


@dataclass(frozen=True)
class ApiKey:
    """An API key bound to a workspace.

    The key string is the secret; ``key_id`` is a public identifier the
    dashboard uses to display / revoke keys without surfacing the secret
    again. ``role`` is set by the workspace owner when issuing the key
    and is consulted by future authorization checks (read-only viewers
    vs ingestion-only writers etc.). Today every key has full access to
    its workspace; the ``role`` field is captured so we can tighten
    later without breaking the wire format.
    """

    key_id: str
    workspace_id: str
    key: str
    role: str = "owner"
    name: str | None = None
    created_at: str = field(default_factory=_now_iso)
    revoked_at: str | None = None


@runtime_checkable
class WorkspaceStore(Protocol):
    def create(self, workspace: Workspace) -> None: ...
    def get(self, workspace_id: str) -> Workspace | None: ...
    def list(self) -> list[Workspace]: ...


@runtime_checkable
class ApiKeyStore(Protocol):
    def issue(self, api_key: ApiKey) -> None: ...
    def lookup(self, key: str) -> ApiKey | None: ...
    def for_workspace(self, workspace_id: str) -> list[ApiKey]: ...
    def revoke(self, key_id: str) -> bool: ...
    def update_role(self, key_id: str, role: str) -> ApiKey | None: ...


class InMemoryWorkspaceStore:
    """Thread-safe dict-backed workspace store. Tests and local dev only."""

    def __init__(self) -> None:
        self._items: dict[str, Workspace] = {}
        self._lock = threading.Lock()

    def create(self, workspace: Workspace) -> None:
        with self._lock:
            if workspace.workspace_id in self._items:
                raise ValueError(f"workspace {workspace.workspace_id!r} already exists")
            self._items[workspace.workspace_id] = workspace

    def get(self, workspace_id: str) -> Workspace | None:
        with self._lock:
            return self._items.get(workspace_id)

    def list(self) -> list[Workspace]:
        with self._lock:
            return sorted(self._items.values(), key=lambda w: w.created_at)


class InMemoryApiKeyStore:
    """Thread-safe API-key store. Tests and local dev only."""

    def __init__(self) -> None:
        self._by_key: dict[str, ApiKey] = {}
        self._by_id: dict[str, ApiKey] = {}
        self._lock = threading.Lock()

    def issue(self, api_key: ApiKey) -> None:
        with self._lock:
            if api_key.key_id in self._by_id:
                raise ValueError(f"api key id {api_key.key_id!r} already exists")
            if api_key.key in self._by_key:
                raise ValueError("api key collision (regenerate)")
            self._by_id[api_key.key_id] = api_key
            self._by_key[api_key.key] = api_key

    def lookup(self, key: str) -> ApiKey | None:
        with self._lock:
            entry = self._by_key.get(key)
            if entry is None or entry.revoked_at is not None:
                return None
            return entry

    def for_workspace(self, workspace_id: str) -> list[ApiKey]:
        with self._lock:
            return [
                k for k in self._by_id.values()
                if k.workspace_id == workspace_id
            ]

    def revoke(self, key_id: str) -> bool:
        with self._lock:
            existing = self._by_id.get(key_id)
            if existing is None or existing.revoked_at is not None:
                return False
            revoked = ApiKey(
                key_id=existing.key_id,
                workspace_id=existing.workspace_id,
                key=existing.key,
                role=existing.role,
                name=existing.name,
                created_at=existing.created_at,
                revoked_at=_now_iso(),
            )
            self._by_id[key_id] = revoked
            self._by_key[revoked.key] = revoked
            return True

    def update_role(self, key_id: str, role: str) -> ApiKey | None:
        with self._lock:
            existing = self._by_id.get(key_id)
            if existing is None or existing.revoked_at is not None:
                return None
            updated = ApiKey(
                key_id=existing.key_id,
                workspace_id=existing.workspace_id,
                key=existing.key,
                role=role,
                name=existing.name,
                created_at=existing.created_at,
                revoked_at=existing.revoked_at,
            )
            self._by_id[key_id] = updated
            self._by_key[existing.key] = updated
            return updated


__all__ = [
    "API_KEY_PREFIX",
    "ApiKey",
    "ApiKeyStore",
    "InMemoryApiKeyStore",
    "InMemoryWorkspaceStore",
    "Workspace",
    "WorkspaceStore",
    "generate_api_key",
]
