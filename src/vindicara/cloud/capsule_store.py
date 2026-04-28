"""Storage backends for Signed Intent Capsules received by AIR Cloud.

A :class:`CapsuleStore` is the persistence boundary on the server side:
the ``/v1/capsules`` route hands every verified record to it, and the
dashboard / report generators read records back out of it. Two
implementations ship today:

- :class:`InMemoryCapsuleStore` for unit tests and local development.
- :class:`JSONLCapsuleStore` for single-host AIR Enterprise deployments
  and the air-gapped tier where filesystem persistence is enough.

A DynamoDB-backed implementation lands when AIR Cloud actually deploys to
AWS; the contract here is the abstraction it will satisfy.
"""
from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from airsdk.types import AgDRRecord

if TYPE_CHECKING:
    from collections.abc import Iterable


@dataclass(frozen=True)
class StoredCapsule:
    """A capsule together with the workspace it was received under.

    AIR Cloud is multi-tenant: every record is scoped to the workspace of
    the API key that POSTed it. Phase 1.5 multi-tenancy adds workspace
    isolation in the storage backend; for now the field is captured at
    ingestion and stored alongside the record.
    """

    workspace_id: str
    record: AgDRRecord


@runtime_checkable
class CapsuleStore(Protocol):
    """Persistence boundary for received capsules."""

    def append(self, capsule: StoredCapsule) -> None:
        """Persist one capsule. Must be safe to call from any request thread."""
        ...

    def for_workspace(self, workspace_id: str) -> list[StoredCapsule]:
        """Return capsules for ``workspace_id`` in insertion order."""
        ...

    def count(self, workspace_id: str | None = None) -> int:
        """Return capsule count for ``workspace_id``, or all if ``None``."""
        ...


class InMemoryCapsuleStore:
    """Thread-safe list-backed store for tests and local dev."""

    def __init__(self) -> None:
        self._items: list[StoredCapsule] = []
        self._lock = threading.Lock()

    def append(self, capsule: StoredCapsule) -> None:
        with self._lock:
            self._items.append(capsule)

    def for_workspace(self, workspace_id: str) -> list[StoredCapsule]:
        with self._lock:
            return [c for c in self._items if c.workspace_id == workspace_id]

    def count(self, workspace_id: str | None = None) -> int:
        with self._lock:
            if workspace_id is None:
                return len(self._items)
            return sum(1 for c in self._items if c.workspace_id == workspace_id)

    def all(self) -> list[StoredCapsule]:
        """Test-only accessor returning every capsule across workspaces."""
        with self._lock:
            return list(self._items)


class JSONLCapsuleStore:
    """Append-only JSONL store keyed by directory.

    One file per workspace at ``<root>/<workspace_id>.jsonl``. The on-disk
    format is one JSON object per line with the shape ``{"workspace_id":
    "...", "record": <AgDRRecord JSON>}``. Reads stream the file from disk
    so a long history does not need to fit in memory; writes are append-only
    so torn writes can only damage the tail of one workspace's stream.
    """

    def __init__(self, root: str | Path) -> None:
        self._root = Path(root).expanduser()
        self._root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _path_for(self, workspace_id: str) -> Path:
        return self._root / f"{workspace_id}.jsonl"

    def append(self, capsule: StoredCapsule) -> None:
        line = json.dumps({
            "workspace_id": capsule.workspace_id,
            "record": json.loads(capsule.record.model_dump_json(exclude_none=True)),
        }, separators=(",", ":"))
        with self._lock, self._path_for(capsule.workspace_id).open("a", encoding="utf-8") as handle:
            handle.write(line)
            handle.write("\n")

    def for_workspace(self, workspace_id: str) -> list[StoredCapsule]:
        path = self._path_for(workspace_id)
        if not path.exists():
            return []
        out: list[StoredCapsule] = []
        with self._lock, path.open(encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                record = AgDRRecord.model_validate(obj["record"])
                out.append(StoredCapsule(workspace_id=obj["workspace_id"], record=record))
        return out

    def count(self, workspace_id: str | None = None) -> int:
        if workspace_id is not None:
            return len(self.for_workspace(workspace_id))
        return sum(self._workspace_counts())

    def _workspace_counts(self) -> Iterable[int]:
        for path in self._root.glob("*.jsonl"):
            with path.open(encoding="utf-8") as handle:
                yield sum(1 for line in handle if line.strip())
