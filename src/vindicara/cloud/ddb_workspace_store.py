"""DynamoDB-backed workspace store for AIR Cloud.

Table schema:
    pk: workspace_id (String)
    attrs: name (String), owner_email (String), created_at (String)

Implements the ``WorkspaceStore`` protocol from ``workspace.py``.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from vindicara.cloud.workspace import Workspace

if TYPE_CHECKING:
    from mypy_boto3_dynamodb.service_resource import Table

_log = logging.getLogger(__name__)


class DDBWorkspaceStore:
    """DynamoDB-backed workspace store for production AIR Cloud."""

    def __init__(self, table: Table) -> None:
        self._table = table

    def create(self, workspace: Workspace) -> None:
        self._table.put_item(
            Item={
                "workspace_id": workspace.workspace_id,
                "name": workspace.name,
                "owner_email": workspace.owner_email,
                "created_at": workspace.created_at,
            },
            ConditionExpression="attribute_not_exists(workspace_id)",
        )

    def get(self, workspace_id: str) -> Workspace | None:
        resp = self._table.get_item(Key={"workspace_id": workspace_id})
        item = resp.get("Item")
        if item is None:
            return None
        return Workspace(
            workspace_id=item["workspace_id"],
            name=item["name"],
            owner_email=item["owner_email"],
            created_at=item["created_at"],
        )

    def list(self) -> list[Workspace]:
        items: list[dict[str, str]] = []
        kwargs: dict[str, object] = {}
        while True:
            resp = self._table.scan(**kwargs)
            items.extend(resp.get("Items", []))
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
            kwargs["ExclusiveStartKey"] = last_key

        workspaces = [
            Workspace(
                workspace_id=item["workspace_id"],
                name=item["name"],
                owner_email=item["owner_email"],
                created_at=item["created_at"],
            )
            for item in items
        ]
        return sorted(workspaces, key=lambda w: w.created_at)
