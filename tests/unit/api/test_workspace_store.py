"""Unit tests for the Flightdeck workspace persistence layer."""

from __future__ import annotations

from vindicara.api.console.workspace_store import (
    DEFAULT_TRANSPORT,
    InMemoryWorkspaceStore,
    WorkspaceState,
)


def test_default_state_is_empty_and_honest() -> None:
    state = WorkspaceState()
    assert state.revoked_agents == set()
    assert state.resolved_findings == set()
    assert state.consents == []
    assert state.plugin_connected == set()
    # Transport defaults are config, not fabricated data; PHI stays off.
    assert state.transport == DEFAULT_TRANSPORT
    assert state.transport["Raw PHI / payloads"] is False


def test_to_item_is_json_safe_and_sorted() -> None:
    state = WorkspaceState(
        revoked_agents={"b", "a"},
        plugin_connected={"datadog", "auth0"},
    )
    item = state.to_item()
    assert item["revoked_agents"] == ["a", "b"]
    assert item["plugin_connected"] == ["auth0", "datadog"]
    assert isinstance(item["consents"], list)


def test_from_item_round_trips() -> None:
    original = WorkspaceState(
        revoked_agents={"agent-1"},
        resolved_findings={"f-1", "f-2"},
        transport={"Posture feed": False},
        consents=[{"carrier": "acme", "status": "active"}],
        plugin_connected={"splunk"},
    )
    restored = WorkspaceState.from_item(original.to_item())
    assert restored.revoked_agents == {"agent-1"}
    assert restored.resolved_findings == {"f-1", "f-2"}
    assert restored.consents == [{"carrier": "acme", "status": "active"}]
    assert restored.plugin_connected == {"splunk"}
    # Missing transport keys fall back to defaults; provided key is overridden.
    assert restored.transport["Posture feed"] is False
    assert restored.transport["Signed evidence pack"] is True


def test_from_item_tolerates_garbage() -> None:
    state = WorkspaceState.from_item({"revoked_agents": "not-a-list", "consents": [1, "x", {"k": "v"}]})
    assert state.revoked_agents == set()
    assert state.consents == [{"k": "v"}]


def test_in_memory_store_persists_per_workspace() -> None:
    store = InMemoryWorkspaceStore()
    a = store.load("org-a")
    a.plugin_connected.add("datadog")
    store.save("org-a", a)

    # A different workspace is isolated.
    assert store.load("org-b").plugin_connected == set()
    # The saved workspace round-trips.
    assert store.load("org-a").plugin_connected == {"datadog"}
