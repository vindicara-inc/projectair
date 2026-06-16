"""DynamoDB-backed API key store for AIR Cloud.

Table schema:
    pk: key_id (String)
    GSI 'by_key_hash': pk key_hash (String) for O(1) lookup by secret
    attrs: workspace_id (String), key_hash (String), role (String),
           name (String | null), created_at (String), revoked_at (String | null)

The raw API key is hashed with SHA-256 before storage; the plaintext is
returned exactly once at issuance time and never persisted. Lookup by
raw key re-hashes and queries the GSI.

Implements the ``ApiKeyStore`` protocol from ``workspace.py``.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast

from vindicara.cloud.workspace import ApiKey

if TYPE_CHECKING:
    from mypy_boto3_dynamodb.service_resource import Table

_log = logging.getLogger(__name__)

GSI_NAME = "by_key_hash"

# Keyed HMAC-SHA256: a leaked table can't be brute-forced offline without the server
# secret. Deterministic, so the by_key_hash GSI O(1) lookup is preserved (a salted
# password KDF would break it). Shares the API-key HMAC secret with the request-auth
# middleware (vindicara.api.middleware.auth).
_HMAC_SECRET = os.environ.get(
    "VINDICARA_API_KEY_HMAC_SECRET",
    "vindicara-dev-hmac-secret-change-in-prod",
).encode("utf-8")


def _hash_key(raw: str) -> str:
    return hmac.new(_HMAC_SECRET, raw.encode("utf-8"), hashlib.sha256).hexdigest()


def _legacy_hash_key(raw: str) -> str:
    # Pre-migration keys were stored as a plain SHA-256 digest. Retained only for
    # backward-compatible dual-read lookup; such keys are re-hashed to the keyed
    # form on first use (see DDBApiKeyStore.lookup).
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class DDBApiKeyStore:
    """DynamoDB-backed API key store for production AIR Cloud."""

    def __init__(self, table: Table) -> None:
        self._table = table

    def issue(self, api_key: ApiKey) -> None:
        self._table.put_item(
            Item={
                "key_id": api_key.key_id,
                "workspace_id": api_key.workspace_id,
                "key_hash": _hash_key(api_key.key),
                "role": api_key.role,
                "name": api_key.name or "",
                "created_at": api_key.created_at,
                "revoked_at": api_key.revoked_at or "",
            },
            ConditionExpression="attribute_not_exists(key_id)",
        )

    def lookup(self, key: str) -> ApiKey | None:
        # Dual-read: try the keyed HMAC hash first; fall back to the legacy plain
        # SHA-256 hash so pre-migration keys keep validating. A key found via the
        # legacy hash is lazily re-hashed to the keyed form so it migrates on use.
        item = self._query_by_hash(_hash_key(key))
        migrate = False
        if item is None:
            item = self._query_by_hash(_legacy_hash_key(key))
            migrate = item is not None
        if item is None or item.get("revoked_at", ""):
            return None
        if migrate:
            self._migrate_hash(item["key_id"], _hash_key(key))
        return ApiKey(
            key_id=item["key_id"],
            workspace_id=item["workspace_id"],
            key=key,
            role=item["role"],
            name=item.get("name") or None,
            created_at=item["created_at"],
            revoked_at=None,
        )

    def _query_by_hash(self, key_hash: str) -> dict[str, str] | None:
        resp = self._table.query(
            IndexName=GSI_NAME,
            KeyConditionExpression="key_hash = :kh",
            ExpressionAttributeValues={":kh": key_hash},
            Limit=1,
        )
        items = cast("list[dict[str, str]]", resp.get("Items", []))
        return items[0] if items else None

    def _migrate_hash(self, key_id: str, new_hash: str) -> None:
        # Best-effort lazy migration of a legacy-hashed key to the keyed form; a
        # failure simply defers migration and never blocks authentication.
        try:
            self._table.update_item(
                Key={"key_id": key_id},
                UpdateExpression="SET key_hash = :kh",
                ExpressionAttributeValues={":kh": new_hash},
            )
        except Exception:
            _log.warning("api_key.hash_migration_failed", extra={"key_id": key_id})

    def for_workspace(self, workspace_id: str) -> list[ApiKey]:
        items: list[dict[str, str]] = []
        resp = self._table.scan(
            FilterExpression="workspace_id = :ws",
            ExpressionAttributeValues={":ws": workspace_id},
        )
        items.extend(cast("list[dict[str, str]]", resp.get("Items", [])))
        last_key = resp.get("LastEvaluatedKey")
        while last_key:
            resp = self._table.scan(
                FilterExpression="workspace_id = :ws",
                ExpressionAttributeValues={":ws": workspace_id},
                ExclusiveStartKey=last_key,
            )
            items.extend(cast("list[dict[str, str]]", resp.get("Items", [])))
            last_key = resp.get("LastEvaluatedKey")

        return [
            ApiKey(
                key_id=item["key_id"],
                workspace_id=item["workspace_id"],
                key="",
                role=item["role"],
                name=item.get("name") or None,
                created_at=item["created_at"],
                revoked_at=item.get("revoked_at") or None,
            )
            for item in items
        ]

    def revoke(self, key_id: str) -> bool:
        try:
            self._table.update_item(
                Key={"key_id": key_id},
                UpdateExpression="SET revoked_at = :ra",
                ExpressionAttributeValues={":ra": _now_iso(), ":empty": ""},
                ConditionExpression=(
                    "attribute_exists(key_id) AND (attribute_not_exists(revoked_at) OR revoked_at = :empty)"
                ),
            )
        except self._table.meta.client.exceptions.ConditionalCheckFailedException:
            return False
        return True

    def update_role(self, key_id: str, role: str) -> ApiKey | None:
        # "role" is a DynamoDB reserved word, so it is aliased via
        # ExpressionAttributeNames. A revoked or missing key is not updated.
        try:
            resp = self._table.update_item(
                Key={"key_id": key_id},
                UpdateExpression="SET #r = :role",
                ExpressionAttributeNames={"#r": "role"},
                ExpressionAttributeValues={":role": role, ":empty": ""},
                ConditionExpression=(
                    "attribute_exists(key_id) AND (attribute_not_exists(revoked_at) OR revoked_at = :empty)"
                ),
                ReturnValues="ALL_NEW",
            )
        except self._table.meta.client.exceptions.ConditionalCheckFailedException:
            return None
        attrs = cast("dict[str, str]", resp.get("Attributes", {}))
        if not attrs:
            return None
        return ApiKey(
            key_id=attrs["key_id"],
            workspace_id=attrs["workspace_id"],
            key="",
            role=attrs["role"],
            name=attrs.get("name") or None,
            created_at=attrs["created_at"],
            revoked_at=attrs.get("revoked_at") or None,
        )
