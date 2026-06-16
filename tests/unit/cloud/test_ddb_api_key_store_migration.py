"""Keyed-HMAC API-key hashing + backward-compatible dual-read (DDBApiKeyStore).

Uses a minimal in-memory fake for the DynamoDB Table calls the store makes
(no new dependency / no moto), proving:
  * new keys are stored as a keyed HMAC-SHA256, not a plain SHA-256;
  * pre-migration keys (plain SHA-256) still validate;
  * a legacy key is lazily re-hashed to the keyed form on first lookup.
"""

from __future__ import annotations

from typing import Any

from vindicara.cloud.ddb_api_key_store import DDBApiKeyStore, _hash_key, _legacy_hash_key
from vindicara.cloud.workspace import ApiKey


class FakeTable:
    """In-memory stand-in for the few boto3 Table calls the store uses."""

    def __init__(self) -> None:
        self.items: dict[str, dict[str, str]] = {}

    def put_item(self, *, Item: dict[str, str], **_: Any) -> None:  # noqa: N803
        self.items[Item["key_id"]] = dict(Item)

    def query(self, *, ExpressionAttributeValues: dict[str, str], Limit: int | None = None, **_: Any) -> dict[str, Any]:  # noqa: N803
        kh = ExpressionAttributeValues[":kh"]
        hits = [dict(i) for i in self.items.values() if i.get("key_hash") == kh]
        return {"Items": hits[:Limit] if Limit else hits}

    def update_item(self, *, Key: dict[str, str], ExpressionAttributeValues: dict[str, str], **_: Any) -> None:  # noqa: N803
        self.items[Key["key_id"]]["key_hash"] = ExpressionAttributeValues[":kh"]


def _api_key(key: str = "air_secret_token_value", key_id: str = "key_1") -> ApiKey:
    return ApiKey(key_id=key_id, workspace_id="ws_1", key=key, role="owner", created_at="2026-01-01T00:00:00Z")


def test_keyed_and_legacy_hashes_differ() -> None:
    assert _hash_key("air_x") != _legacy_hash_key("air_x")


def test_issue_stores_keyed_hash() -> None:
    table = FakeTable()
    ak = _api_key()
    DDBApiKeyStore(table).issue(ak)
    assert table.items["key_1"]["key_hash"] == _hash_key(ak.key)
    assert table.items["key_1"]["key_hash"] != _legacy_hash_key(ak.key)


def test_lookup_finds_keyed_key() -> None:
    table = FakeTable()
    store = DDBApiKeyStore(table)
    ak = _api_key()
    store.issue(ak)
    found = store.lookup(ak.key)
    assert found is not None
    assert found.key_id == "key_1"
    assert found.workspace_id == "ws_1"


def test_legacy_key_validates_and_is_migrated() -> None:
    table = FakeTable()
    store = DDBApiKeyStore(table)
    secret = "air_legacy_token"
    # Pre-migration row: key_hash stored as a plain SHA-256 digest.
    table.items["key_legacy"] = {
        "key_id": "key_legacy",
        "workspace_id": "ws_2",
        "key_hash": _legacy_hash_key(secret),
        "role": "owner",
        "name": "",
        "created_at": "2026-01-01T00:00:00Z",
        "revoked_at": "",
    }
    found = store.lookup(secret)
    assert found is not None
    assert found.key_id == "key_legacy"
    # lazily re-hashed to the keyed form
    assert table.items["key_legacy"]["key_hash"] == _hash_key(secret)
    # second lookup now hits the keyed hash directly
    assert store.lookup(secret) is not None


def test_lookup_unknown_returns_none() -> None:
    assert DDBApiKeyStore(FakeTable()).lookup("air_nope") is None


def test_lookup_revoked_returns_none() -> None:
    table = FakeTable()
    store = DDBApiKeyStore(table)
    ak = _api_key()
    store.issue(ak)
    table.items["key_1"]["revoked_at"] = "2026-02-01T00:00:00Z"
    assert store.lookup(ak.key) is None
