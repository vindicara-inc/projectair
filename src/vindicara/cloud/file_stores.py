"""Filesystem-backed workspace + API-key stores for self-hosted units.

The AIR Cloud factory falls back to in-memory stores when no DynamoDB tables
are configured. That is correct for tests, but for the self-hosted / air-gapped
Enterprise unit (which has no AWS DynamoDB) in-memory means every tenant and
API key is forgotten on restart. These JSON-file-backed stores are the durable
substitute: they satisfy the same :class:`WorkspaceStore` / :class:`ApiKeyStore`
protocols and persist under a single data directory alongside the
:class:`~vindicara.cloud.capsule_store.JSONLCapsuleStore` capsule log.

Single-node by design: every mutation is a read-modify-write under a process
lock with an atomic ``os.replace``. Workspaces and keys are low-volume and
change rarely, so this is adequate for one container. A multi-node deployment
uses the DynamoDB-backed stores instead.
"""

from __future__ import annotations

import json
import threading
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from vindicara.cloud.workspace import ApiKey, Workspace


def _now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class JSONWorkspaceStore:
    """Single-file JSON workspace store. Survives restarts.

    Persists all workspaces to ``<root>/workspaces.json`` as a mapping keyed by
    ``workspace_id``. Satisfies the :class:`WorkspaceStore` protocol.
    """

    def __init__(self, root: str | Path) -> None:
        self._path = Path(root).expanduser() / "workspaces.json"
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _read(self) -> dict[str, Workspace]:
        if not self._path.exists():
            return {}
        raw = json.loads(self._path.read_text(encoding="utf-8"))
        return {wid: Workspace(**data) for wid, data in raw.items()}

    def _write(self, items: dict[str, Workspace]) -> None:
        payload = {wid: asdict(ws) for wid, ws in items.items()}
        tmp = self._path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp.replace(self._path)

    def create(self, workspace: Workspace) -> None:
        with self._lock:
            items = self._read()
            if workspace.workspace_id in items:
                raise ValueError(f"workspace {workspace.workspace_id!r} already exists")
            items[workspace.workspace_id] = workspace
            self._write(items)

    def get(self, workspace_id: str) -> Workspace | None:
        with self._lock:
            return self._read().get(workspace_id)

    def list(self) -> list[Workspace]:
        with self._lock:
            return sorted(self._read().values(), key=lambda w: w.created_at)


class JSONApiKeyStore:
    """Single-file JSON API-key store. Survives restarts.

    Persists all keys to ``<root>/api_keys.json`` as a list of key records.
    Revocation and role changes are durable. Satisfies the :class:`ApiKeyStore`
    protocol.
    """

    def __init__(self, root: str | Path) -> None:
        self._path = Path(root).expanduser() / "api_keys.json"
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _read(self) -> list[ApiKey]:
        if not self._path.exists():
            return []
        raw = json.loads(self._path.read_text(encoding="utf-8"))
        return [ApiKey(**data) for data in raw]

    def _write(self, items: list[ApiKey]) -> None:
        tmp = self._path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps([asdict(k) for k in items], indent=2), encoding="utf-8")
        tmp.replace(self._path)

    def issue(self, api_key: ApiKey) -> None:
        with self._lock:
            items = self._read()
            if any(k.key_id == api_key.key_id for k in items):
                raise ValueError(f"api key id {api_key.key_id!r} already exists")
            if any(k.key == api_key.key for k in items):
                raise ValueError("api key collision (regenerate)")
            items.append(api_key)
            self._write(items)

    def lookup(self, key: str) -> ApiKey | None:
        with self._lock:
            for entry in self._read():
                if entry.key == key:
                    return None if entry.revoked_at is not None else entry
            return None

    def for_workspace(self, workspace_id: str) -> list[ApiKey]:
        with self._lock:
            return [k for k in self._read() if k.workspace_id == workspace_id]

    def revoke(self, key_id: str) -> bool:
        with self._lock:
            items = self._read()
            for i, existing in enumerate(items):
                if existing.key_id == key_id:
                    if existing.revoked_at is not None:
                        return False
                    items[i] = ApiKey(
                        key_id=existing.key_id,
                        workspace_id=existing.workspace_id,
                        key=existing.key,
                        role=existing.role,
                        name=existing.name,
                        created_at=existing.created_at,
                        revoked_at=_now_iso(),
                    )
                    self._write(items)
                    return True
            return False

    def update_role(self, key_id: str, role: str) -> ApiKey | None:
        with self._lock:
            items = self._read()
            for i, existing in enumerate(items):
                if existing.key_id == key_id:
                    if existing.revoked_at is not None:
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
                    items[i] = updated
                    self._write(items)
                    return updated
            return None


__all__ = ["JSONApiKeyStore", "JSONWorkspaceStore"]
