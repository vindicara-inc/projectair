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
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from vindicara.cloud.workspace import ApiKey

if TYPE_CHECKING:
    from mypy_boto3_dynamodb.service_resource import Table

_log = logging.getLogger(__name__)

GSI_NAME = "by_key_hash"


def _hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


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
        key_hash = _hash_key(key)
        resp = self._table.query(
            IndexName=GSI_NAME,
            KeyConditionExpression="key_hash = :kh",
            ExpressionAttributeValues={":kh": key_hash},
            Limit=1,
        )
        items = resp.get("Items", [])
        if not items:
            return None
        item = items[0]
        revoked = item.get("revoked_at", "")
        if revoked:
            return None
        return ApiKey(
            key_id=item["key_id"],
            workspace_id=item["workspace_id"],
            key=key,
            role=item["role"],
            name=item.get("name") or None,
            created_at=item["created_at"],
            revoked_at=None,
        )

    def for_workspace(self, workspace_id: str) -> list[ApiKey]:
        items: list[dict[str, str]] = []
        kwargs: dict[str, object] = {
            "FilterExpression": "workspace_id = :ws",
            "ExpressionAttributeValues": {":ws": workspace_id},
        }
        while True:
            resp = self._table.scan(**kwargs)
            items.extend(resp.get("Items", []))
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
            kwargs["ExclusiveStartKey"] = last_key

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
                ExpressionAttributeValues={":ra": _now_iso()},
                ConditionExpression=(
                    "attribute_exists(key_id) AND "
                    "(revoked_at = :empty OR attribute_not_exists(revoked_at))"
                ),
                ExpressionAttributeNames={},
            )
        except self._table.meta.client.exceptions.ConditionalCheckFailedException:
            return False
        return True
