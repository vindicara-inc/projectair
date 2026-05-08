"""Workspace + ApiKey model and in-memory stores."""
from __future__ import annotations

import pytest

from vindicara.cloud.workspace import (
    API_KEY_PREFIX,
    ApiKey,
    InMemoryApiKeyStore,
    InMemoryWorkspaceStore,
    Workspace,
    generate_api_key,
)


def test_generate_api_key_prefix_and_length() -> None:
    key = generate_api_key()
    assert key.startswith(API_KEY_PREFIX)
    assert len(key) == len(API_KEY_PREFIX) + 32  # token_hex(16) -> 32 chars


def test_generate_api_key_uniqueness() -> None:
    seen = {generate_api_key() for _ in range(100)}
    assert len(seen) == 100


def test_workspace_store_roundtrip() -> None:
    store = InMemoryWorkspaceStore()
    ws = Workspace(workspace_id="acme", name="Acme", owner_email="ops@acme.io")
    store.create(ws)
    assert store.get("acme") == ws
    assert store.get("missing") is None
    assert store.list() == [ws]


def test_workspace_store_rejects_duplicate() -> None:
    store = InMemoryWorkspaceStore()
    store.create(Workspace(workspace_id="acme", name="A", owner_email="e@a"))
    with pytest.raises(ValueError, match="already exists"):
        store.create(Workspace(workspace_id="acme", name="B", owner_email="f@a"))


def test_api_key_store_lookup_by_secret() -> None:
    store = InMemoryApiKeyStore()
    key = ApiKey(key_id="key_1", workspace_id="acme", key="air_abc123")
    store.issue(key)
    assert store.lookup("air_abc123") == key
    assert store.lookup("air_wrong") is None


def test_api_key_store_revoke_flow() -> None:
    store = InMemoryApiKeyStore()
    key = ApiKey(key_id="key_1", workspace_id="acme", key="air_secret")
    store.issue(key)
    assert store.revoke("key_1") is True
    # post-revocation, lookup returns None
    assert store.lookup("air_secret") is None
    # revoke is idempotent: returns False the second time
    assert store.revoke("key_1") is False


def test_api_key_store_for_workspace_filters_by_tenant() -> None:
    store = InMemoryApiKeyStore()
    store.issue(ApiKey(key_id="k_a1", workspace_id="acme", key="air_a1"))
    store.issue(ApiKey(key_id="k_a2", workspace_id="acme", key="air_a2"))
    store.issue(ApiKey(key_id="k_b1", workspace_id="beta", key="air_b1"))
    acme_keys = {k.key_id for k in store.for_workspace("acme")}
    assert acme_keys == {"k_a1", "k_a2"}
    beta_keys = {k.key_id for k in store.for_workspace("beta")}
    assert beta_keys == {"k_b1"}


def test_api_key_store_revoke_unknown_returns_false() -> None:
    store = InMemoryApiKeyStore()
    assert store.revoke("nonexistent") is False
