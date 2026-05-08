"""Workspace introspection + creation + member invite routes for AIR Cloud."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict

from vindicara.cloud.roles import Capability, is_valid_role, require
from vindicara.cloud.workspace import (
    ApiKey,
    ApiKeyStore,
    Workspace,
    WorkspaceStore,
    generate_api_key,
)

router = APIRouter()


class WorkspaceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    workspace_id: str
    name: str
    owner_email: str


class WorkspaceCreated(BaseModel):
    """Response on successful workspace creation. Returns the bootstrap API key once."""

    model_config = ConfigDict(extra="forbid")
    workspace: Workspace
    bootstrap_api_key: ApiKey


@router.get(
    "/v1/workspaces/me",
    response_model=Workspace,
    summary="Return the workspace the calling API key belongs to.",
)
async def whoami(request: Request) -> Workspace:
    require(request, Capability.READ_WORKSPACE)
    store: WorkspaceStore = request.app.state.cloud_workspaces
    workspace_id: str = request.state.workspace_id
    workspace = store.get(workspace_id)
    if workspace is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"workspace {workspace_id!r} no longer exists",
        )
    return workspace


@router.post(
    "/v1/workspaces",
    response_model=WorkspaceCreated,
    status_code=status.HTTP_201_CREATED,
    summary="Create a workspace and issue its bootstrap API key.",
)
async def create_workspace(request: Request, payload: WorkspaceCreate) -> WorkspaceCreated:
    """Bootstrap a new tenant. Returns the first API key inline; the caller
    is responsible for storing it (it cannot be retrieved later).

    NOTE: this route is part of the public API surface but real
    deployments should gate it behind an admin-only path or an OIDC
    login (W3.10) before exposing it. The default deployment binds it
    to ``/v1`` like every other route, so the bootstrap key created at
    deploy time is the only credential that can call it for now.
    """
    workspace_store: WorkspaceStore = request.app.state.cloud_workspaces
    api_key_store: ApiKeyStore = request.app.state.cloud_api_keys

    workspace = Workspace(
        workspace_id=payload.workspace_id,
        name=payload.name,
        owner_email=payload.owner_email,
    )
    try:
        workspace_store.create(workspace)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    api_key = ApiKey(
        key_id=f"key_{payload.workspace_id}_owner",
        workspace_id=payload.workspace_id,
        key=generate_api_key(),
        role="owner",
        name="bootstrap key",
    )
    api_key_store.issue(api_key)
    return WorkspaceCreated(workspace=workspace, bootstrap_api_key=api_key)


class MemberInvite(BaseModel):
    """Inputs for inviting a teammate into the calling workspace."""

    model_config = ConfigDict(extra="forbid")
    email: str
    role: str = "member"
    name: str | None = None


class MemberInvited(BaseModel):
    """Result of an invite. Returns the freshly minted API key inline."""

    model_config = ConfigDict(extra="forbid")
    workspace_id: str
    invited_email: str
    api_key: ApiKey


@router.post(
    "/v1/workspaces/me/members",
    response_model=MemberInvited,
    status_code=status.HTTP_201_CREATED,
    summary="Invite a teammate by email; returns a freshly minted API key.",
)
async def invite_member(request: Request, payload: MemberInvite) -> MemberInvited:
    """Issue a workspace-bound API key on behalf of a teammate.

    Today this is the "shared keys" flow: an owner or admin POSTs an
    email + role; the response carries a fresh API key the inviter
    delivers out-of-band (email link / Slack DM / wherever). The full
    key is returned exactly once and not retrievable later. The teammate's
    name and email are recorded on the key for audit; the email is NOT
    used for any automated authentication today.
    """
    require(request, Capability.INVITE_MEMBER)
    if not is_valid_role(payload.role):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"role {payload.role!r} is not a valid workspace role",
        )
    if payload.role == "owner":
        # Owners get bootstrapped at workspace creation; inviting an
        # additional owner via this route would dilute the owner audit
        # trail. Owners can be created by an existing owner via POST
        # /v1/keys with role=owner, where the intent is unambiguous.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="role 'owner' cannot be granted via the invite flow; use POST /v1/keys",
        )

    api_key_store: ApiKeyStore = request.app.state.cloud_api_keys
    workspace_id: str = request.state.workspace_id
    existing = len(api_key_store.for_workspace(workspace_id))
    api_key = ApiKey(
        key_id=f"key_{workspace_id}_{existing + 1:04d}",
        workspace_id=workspace_id,
        key=generate_api_key(),
        role=payload.role,
        name=payload.name or payload.email,
    )
    api_key_store.issue(api_key)
    return MemberInvited(
        workspace_id=workspace_id,
        invited_email=payload.email,
        api_key=api_key,
    )
