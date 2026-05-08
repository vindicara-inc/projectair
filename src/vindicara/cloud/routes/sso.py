"""Enterprise SSO routes.

- ``PUT /v1/sso/config``  (owner-only) set/replace the workspace's SSO config.
- ``GET /v1/sso/config``  (admin+)     read the workspace's SSO config.
- ``POST /v1/sso/login``  **unauthed** by design; this IS the auth flow.

The login route is intentionally exempt from the API-key middleware:
the dashboard cannot have a key yet at the moment of first SSO login.
The middleware lists ``/v1/sso/login`` in ``UNAUTHED_PATHS``.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict

from vindicara.cloud.roles import Capability, is_valid_role, require
from vindicara.cloud.sso import (
    InMemorySsoConfigStore,
    SsoConfig,
    SsoConfigError,
    SsoConfigStore,
    SsoVerificationError,
    verify_oidc_token,
)
from vindicara.cloud.workspace import (
    ApiKey,
    ApiKeyStore,
    WorkspaceStore,
    generate_api_key,
)

router = APIRouter()


class SsoConfigPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    issuer: str
    audience: str
    default_role: str = "member"
    jwks_uri: str | None = None
    allowed_email_domains: tuple[str, ...] = ()


class SsoLoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    workspace_id: str
    token: str


class SsoLoginResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    workspace_id: str
    api_key: ApiKey
    sub: str
    email: str | None = None


def _sso_store(request: Request) -> SsoConfigStore:
    """Read the SSO config store from app.state, falling back to an in-memory one."""
    store: SsoConfigStore | None = getattr(request.app.state, "cloud_sso_configs", None)
    if store is None:
        store = InMemorySsoConfigStore()
        request.app.state.cloud_sso_configs = store
    return store


@router.put(
    "/v1/sso/config",
    response_model=SsoConfig,
    summary="Set or replace the SSO configuration for the calling workspace.",
)
async def put_sso_config(request: Request, payload: SsoConfigPayload) -> SsoConfig:
    require(request, Capability.ISSUE_KEY)  # owner/admin only — same privilege as minting keys
    if not is_valid_role(payload.default_role):
        raise HTTPException(status_code=400, detail=f"default_role {payload.default_role!r} is invalid")
    if payload.default_role == "owner":
        raise HTTPException(status_code=400, detail="default_role 'owner' cannot be JIT-provisioned via SSO")
    if not payload.issuer or not payload.audience:
        raise HTTPException(status_code=400, detail="issuer and audience are required")
    store = _sso_store(request)
    config = SsoConfig(
        workspace_id=request.state.workspace_id,
        issuer=payload.issuer,
        audience=payload.audience,
        default_role=payload.default_role,
        jwks_uri=payload.jwks_uri,
        allowed_email_domains=payload.allowed_email_domains,
    )
    store.put(config)
    return config


@router.get(
    "/v1/sso/config",
    response_model=SsoConfig,
    summary="Read the SSO configuration for the calling workspace.",
)
async def get_sso_config(request: Request) -> SsoConfig:
    require(request, Capability.LIST_KEYS)  # admin+; same audience as listing keys
    store = _sso_store(request)
    config = store.get(request.state.workspace_id)
    if config is None:
        raise HTTPException(status_code=404, detail="no SSO config set for this workspace")
    return config


@router.post(
    "/v1/sso/login",
    response_model=SsoLoginResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Trade a verified OIDC ID token for a workspace API key (JIT provisioning).",
)
async def sso_login(request: Request, payload: SsoLoginRequest) -> SsoLoginResponse:
    """Exchange a JWT minted by the workspace's configured OIDC issuer for
    an API key.

    This route is unauthenticated by design (it IS the auth flow). The
    workspace must already exist and have an SSO config; the JWT must
    verify against that config's issuer + audience + JWKS.

    First-time logins for a given ``(iss, sub)`` mint a fresh API key
    at the workspace's ``default_role``. Repeated logins for the same
    ``(iss, sub)`` return the same active key (a stable session, not a
    fresh credential per login). Revoked keys force re-provisioning at
    the next login.
    """
    workspace_store: WorkspaceStore = request.app.state.cloud_workspaces
    if workspace_store.get(payload.workspace_id) is None:
        raise HTTPException(status_code=404, detail=f"workspace {payload.workspace_id!r} not found")
    sso_store = _sso_store(request)
    config = sso_store.get(payload.workspace_id)
    if config is None:
        raise HTTPException(status_code=400, detail="workspace has no SSO config set")

    try:
        claims = verify_oidc_token(payload.token, config=config)
    except SsoVerificationError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except SsoConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    sub = str(claims["sub"])
    email = claims.get("email")
    if email is not None and not isinstance(email, str):
        email = None

    api_key_store: ApiKeyStore = request.app.state.cloud_api_keys
    sso_key_id = _sso_key_id(payload.workspace_id, config.issuer, sub)

    existing = next(
        (k for k in api_key_store.for_workspace(payload.workspace_id) if k.key_id == sso_key_id and k.revoked_at is None),
        None,
    )
    if existing is not None:
        return SsoLoginResponse(
            workspace_id=payload.workspace_id,
            api_key=existing,
            sub=sub,
            email=email if isinstance(email, str) else None,
        )

    new_key = ApiKey(
        key_id=sso_key_id,
        workspace_id=payload.workspace_id,
        key=generate_api_key(),
        role=config.default_role,
        name=email if isinstance(email, str) else f"sso:{sub[:24]}",
    )
    api_key_store.issue(new_key)
    return SsoLoginResponse(
        workspace_id=payload.workspace_id,
        api_key=new_key,
        sub=sub,
        email=email if isinstance(email, str) else None,
    )


def _sso_key_id(workspace_id: str, issuer: str, sub: str) -> str:
    """Stable per-(workspace, issuer, sub) key id.

    Hashed to keep the persisted key id under the standard secondary-index
    limits and to avoid leaking the OIDC subject on the wire when admins
    list keys; the human-readable owner is in ``ApiKey.name``.
    """
    import hashlib
    digest = hashlib.sha256(f"{issuer}|{sub}".encode()).hexdigest()[:24]
    return f"key_{workspace_id}_sso_{digest}"
