"""Tests for the AIR Cloud capsule storage backends."""
from __future__ import annotations

from typing import TYPE_CHECKING

from airsdk.agdr import Signer
from airsdk.types import AgDRPayload, StepKind

if TYPE_CHECKING:
    from pathlib import Path

from vindicara.cloud.capsule_store import (
    InMemoryCapsuleStore,
    JSONLCapsuleStore,
    StoredCapsule,
)


def _signed_record(prompt: str = "hello"):
    signer = Signer.generate()
    return signer.sign(StepKind.LLM_START, AgDRPayload.model_validate({"prompt": prompt}))


def test_in_memory_store_appends_and_lists() -> None:
    store = InMemoryCapsuleStore()
    record = _signed_record()

    store.append(StoredCapsule(workspace_id="ws-a", record=record))

    items = store.for_workspace("ws-a")
    assert len(items) == 1
    assert items[0].record.step_id == record.step_id


def test_in_memory_store_isolates_workspaces() -> None:
    store = InMemoryCapsuleStore()
    store.append(StoredCapsule(workspace_id="ws-a", record=_signed_record("a")))
    store.append(StoredCapsule(workspace_id="ws-b", record=_signed_record("b")))
    store.append(StoredCapsule(workspace_id="ws-a", record=_signed_record("a2")))

    assert store.count("ws-a") == 2
    assert store.count("ws-b") == 1
    assert store.count() == 3
    assert [c.record.payload.prompt for c in store.for_workspace("ws-a")] == ["a", "a2"]
    assert [c.record.payload.prompt for c in store.for_workspace("ws-b")] == ["b"]


def test_jsonl_store_round_trips_records(tmp_path: Path) -> None:
    store = JSONLCapsuleStore(tmp_path)
    record = _signed_record("durable")

    store.append(StoredCapsule(workspace_id="ws-a", record=record))

    items = store.for_workspace("ws-a")
    assert len(items) == 1
    assert items[0].record.step_id == record.step_id
    assert items[0].record.signature == record.signature
    assert items[0].record.payload.prompt == "durable"


def test_jsonl_store_persists_across_instances(tmp_path: Path) -> None:
    JSONLCapsuleStore(tmp_path).append(
        StoredCapsule(workspace_id="ws-a", record=_signed_record("first"))
    )
    JSONLCapsuleStore(tmp_path).append(
        StoredCapsule(workspace_id="ws-a", record=_signed_record("second"))
    )

    fresh = JSONLCapsuleStore(tmp_path)
    items = fresh.for_workspace("ws-a")
    assert [c.record.payload.prompt for c in items] == ["first", "second"]


def test_jsonl_store_count_aggregates_across_workspaces(tmp_path: Path) -> None:
    store = JSONLCapsuleStore(tmp_path)
    store.append(StoredCapsule(workspace_id="ws-a", record=_signed_record("x")))
    store.append(StoredCapsule(workspace_id="ws-b", record=_signed_record("y")))
    store.append(StoredCapsule(workspace_id="ws-b", record=_signed_record("z")))

    assert store.count("ws-a") == 1
    assert store.count("ws-b") == 2
    assert store.count() == 3


def test_jsonl_store_returns_empty_for_unknown_workspace(tmp_path: Path) -> None:
    store = JSONLCapsuleStore(tmp_path)
    assert store.for_workspace("never-existed") == []
    assert store.count("never-existed") == 0
