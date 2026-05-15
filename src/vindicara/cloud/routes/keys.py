"""Workspace-scoped API-key management routes."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict

from vindicara.cloud.roles import Capability, Role, is_valid_role, require
from vindicara.cloud.workspace import (
    ApiKey,
    ApiKeyStore,
    generate_api_key,
)

router = APIRouter()


class IssueKeyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = None
    role: str = "member"


class RedactedKey(BaseModel):
    """Public view of a key. Omits the secret entirely."""

    model_config = ConfigDict(extra="forbid")
    key_id: str
    workspace_id: str
    role: str
    name: str | None = None
    created_at: str
    revoked_at: str | None = None


def _redact(api_key: ApiKey) -> RedactedKey:
    return RedactedKey(
        key_id=api_key.key_id,
        workspace_id=api_key.workspace_id,
        role=api_key.role,
        name=api_key.name,
        created_at=api_key.created_at,
        revoked_at=api_key.revoked_at,
    )


@router.get(
    "/v1/keys",
    response_model=list[RedactedKey],
    summary="List API keys in the calling key's workspace (secrets redacted).",
)
async def list_keys(request: Request) -> list[RedactedKey]:
    require(request, Capability.LIST_KEYS)
    store: ApiKeyStore = request.app.state.cloud_api_keys
    workspace_id: str = request.state.workspace_id
    return [_redact(k) for k in store.for_workspace(workspace_id)]


@router.post(
    "/v1/keys",
    response_model=ApiKey,
    status_code=status.HTTP_201_CREATED,
    summary="Issue a fresh API key in the calling key's workspace.",
)
async def issue_key(request: Request, payload: IssueKeyRequest) -> ApiKey:
    """Issue a new API key. The full key (with secret) is returned exactly
    once; subsequent listings will redact it. Treat the response body as
    secret material at the receiving side."""
    require(request, Capability.ISSUE_KEY)
    if not is_valid_role(payload.role):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"role {payload.role!r} is not a valid workspace role",
        )
    store: ApiKeyStore = request.app.state.cloud_api_keys
    workspace_id: str = request.state.workspace_id
    existing = len(store.for_workspace(workspace_id))
    api_key = ApiKey(
        key_id=f"key_{workspace_id}_{existing + 1:04d}",
        workspace_id=workspace_id,
        key=generate_api_key(),
        role=payload.role,
        name=payload.name,
    )
    store.issue(api_key)
    return api_key


class UpdateKeyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: str


@router.patch(
    "/v1/keys/{key_id}",
    summary="Update the role on an existing API key.",
)
async def update_key_role(
    key_id: str, body: UpdateKeyRequest, request: Request
) -> dict[str, str]:
    require(request, Capability.ISSUE_KEY)

    if not is_valid_role(body.role):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"role {body.role!r} is not a valid workspace role",
        )

    caller_role = Role(request.state.role)
    target_role = Role(body.role)

    # Only owner can assign admin or owner roles
    if target_role in (Role.OWNER, Role.ADMIN) and caller_role != Role.OWNER:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="only workspace owner can assign admin/owner role",
        )

    store: ApiKeyStore = request.app.state.cloud_api_keys
    updated = store.update_role(key_id, body.role)
    if updated is None:
        raise HTTPException(status_code=404, detail="key not found or revoked")

    return {"key_id": key_id, "role": body.role}


@router.delete(
    "/v1/keys/{key_id}",
    summary="Revoke an API key in the calling key's workspace.",
)
async def revoke_key(request: Request, key_id: str) -> dict[str, str | bool]:
    require(request, Capability.REVOKE_KEY)
    store: ApiKeyStore = request.app.state.cloud_api_keys
    workspace_id: str = request.state.workspace_id
    matching = [k for k in store.for_workspace(workspace_id) if k.key_id == key_id]
    if not matching:
        raise HTTPException(status_code=404, detail=f"key {key_id!r} not found in workspace")
    if matching[0].revoked_at is not None:
        return {"key_id": key_id, "revoked": False, "detail": "already revoked"}
    revoked = store.revoke(key_id)
    return {"key_id": key_id, "revoked": revoked}
