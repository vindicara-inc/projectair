# Team-Tier Workspace Management Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add team workspace management to the AIR Cloud dashboard: Auth0 SSO auto-provisioning, role-gated views, 4 admin screens (Team, Activity, Compliance, Analytics), left sidebar navigation, zero local storage.

**Architecture:** Backend already has workspace CRUD, RBAC, SSO login, member invite, key management. We add short-lived session JWTs for the dashboard (replacing long-lived API keys on the client), capsule scoping by role, and 2 new aggregate endpoints. Frontend gets route restructuring under `/dashboard/`, a sidebar, and 4 new admin screens. The browser is a stateless view layer: Auth0 owns the session, backend owns the data.

**Tech Stack:** Python 3.12+ / FastAPI / Pydantic v2 (backend), SvelteKit 2 / Svelte 5 / Tailwind 4 (frontend), Auth0 SPA SDK, PyJWT (session tokens)

**Spec:** `docs/superpowers/specs/2026-05-14-team-workspace-management-design.md`

---

## Task 1: Backend - Session Token Module

Create short-lived JWT session tokens signed by the backend. Dashboard uses these instead of raw API keys.

**Files:**
- Create: `src/vindicara/cloud/session_token.py`
- Test: `tests/unit/cloud/test_session_token.py`

- [ ] **Step 1: Write failing tests**

```python
"""tests/unit/cloud/test_session_token.py"""
from __future__ import annotations

import os
import time

import pytest

os.environ.setdefault("VINDICARA_SESSION_SECRET", "test_secret_for_unit_tests_only_0000")

from vindicara.cloud.session_token import (
    SessionClaims,
    create_session_token,
    verify_session_token,
    SessionTokenError,
)


def test_roundtrip() -> None:
    claims = SessionClaims(
        workspace_id="ws_001",
        role="member",
        sub="auth0|abc123",
        key_id="key_ws_001_sso_aabbcc",
    )
    token = create_session_token(claims, ttl_seconds=900)
    verified = verify_session_token(token)
    assert verified.workspace_id == "ws_001"
    assert verified.role == "member"
    assert verified.sub == "auth0|abc123"
    assert verified.key_id == "key_ws_001_sso_aabbcc"


def test_expired_token() -> None:
    claims = SessionClaims(
        workspace_id="ws_001",
        role="member",
        sub="auth0|abc123",
        key_id="key_001",
    )
    token = create_session_token(claims, ttl_seconds=-1)
    with pytest.raises(SessionTokenError, match="expired"):
        verify_session_token(token)


def test_tampered_token() -> None:
    claims = SessionClaims(
        workspace_id="ws_001",
        role="member",
        sub="auth0|abc123",
        key_id="key_001",
    )
    token = create_session_token(claims, ttl_seconds=900)
    tampered = token[:-4] + "XXXX"
    with pytest.raises(SessionTokenError):
        verify_session_token(tampered)


def test_missing_claims() -> None:
    with pytest.raises(SessionTokenError):
        verify_session_token("not.a.jwt")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/cloud/test_session_token.py -v`
Expected: FAIL (module not found)

- [ ] **Step 3: Implement session token module**

```python
"""src/vindicara/cloud/session_token.py
Short-lived JWT session tokens for dashboard auth.

The backend signs these with an HMAC key derived from
VINDICARA_SESSION_SECRET (or a random secret per process).
Dashboard holds these in memory only. 15-minute default TTL.
"""
from __future__ import annotations

import os
import secrets
import time
from dataclasses import dataclass

import jwt

_ALGORITHM = "HS256"
_ISSUER = "air-cloud"
DEFAULT_TTL_SECONDS = 900  # 15 minutes


def _load_secret() -> str:
    secret = os.environ.get("VINDICARA_SESSION_SECRET")
    if secret is None:
        raise RuntimeError(
            "VINDICARA_SESSION_SECRET env var is required. "
            "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    return secret


class SessionTokenError(Exception):
    pass


@dataclass(frozen=True)
class SessionClaims:
    workspace_id: str
    role: str
    sub: str
    key_id: str


def create_session_token(
    claims: SessionClaims,
    *,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    secret: str | None = None,
) -> str:
    secret = secret or _load_secret()
    now = int(time.time())
    payload = {
        "workspace_id": claims.workspace_id,
        "role": claims.role,
        "sub": claims.sub,
        "key_id": claims.key_id,
        "iss": _ISSUER,
        "iat": now,
        "exp": now + ttl_seconds,
    }
    return jwt.encode(payload, secret, algorithm=_ALGORITHM)


def verify_session_token(
    token: str,
    *,
    secret: str | None = None,
) -> SessionClaims:
    secret = secret or _load_secret()
    try:
        payload = jwt.decode(
            token,
            secret,
            algorithms=[_ALGORITHM],
            issuer=_ISSUER,
            options={"require": ["workspace_id", "role", "sub", "key_id", "exp"]},
        )
    except jwt.ExpiredSignatureError:
        raise SessionTokenError("session token expired")
    except jwt.InvalidTokenError as exc:
        raise SessionTokenError(f"invalid session token: {exc}")
    return SessionClaims(
        workspace_id=payload["workspace_id"],
        role=payload["role"],
        sub=payload["sub"],
        key_id=payload["key_id"],
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/unit/cloud/test_session_token.py -v`
Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add src/vindicara/cloud/session_token.py tests/unit/cloud/test_session_token.py
git commit -m "feat(cloud): short-lived JWT session token module"
```

---

## Task 2: Backend - Dual-Auth Middleware

Modify `AirCloudAuthMiddleware` to accept both `X-API-Key` (SDK/agent ingestion) and `Authorization: Bearer` (dashboard session tokens).

**Files:**
- Modify: `src/vindicara/cloud/middleware.py`
- Test: `tests/unit/cloud/test_middleware.py`

- [ ] **Step 1: Write failing tests for Bearer auth**

```python
"""tests/unit/cloud/test_middleware.py"""
from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from vindicara.cloud.factory import create_air_cloud_app
from vindicara.cloud.session_token import SessionClaims, create_session_token
from vindicara.cloud.workspace import (
    ApiKey,
    InMemoryApiKeyStore,
    InMemoryWorkspaceStore,
    Workspace,
)


@pytest.fixture()
def stores() -> tuple[InMemoryWorkspaceStore, InMemoryApiKeyStore]:
    ws_store = InMemoryWorkspaceStore()
    key_store = InMemoryApiKeyStore()
    ws = Workspace(workspace_id="ws_test", name="Test", owner_email="a@b.com")
    ws_store.create(ws)
    key = ApiKey(
        key_id="key_test",
        workspace_id="ws_test",
        key="air_deadbeef1234567890abcdef12345678",
        role="owner",
        name="test",
    )
    key_store.issue(key)
    return ws_store, key_store


@pytest.fixture()
def app(stores: tuple[InMemoryWorkspaceStore, InMemoryApiKeyStore]):  # type: ignore[type-arg]
    ws_store, key_store = stores
    return create_air_cloud_app(
        workspace_store=ws_store,
        api_key_store=key_store,
    )


@pytest.mark.anyio()
async def test_bearer_token_auth(app) -> None:  # type: ignore[no-untyped-def]
    claims = SessionClaims(
        workspace_id="ws_test", role="owner", sub="auth0|x", key_id="key_test"
    )
    token = create_session_token(claims)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get(
            "/v1/workspaces/me",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert resp.status_code == 200
    assert resp.json()["workspace_id"] == "ws_test"


@pytest.mark.anyio()
async def test_expired_bearer_returns_401(app) -> None:  # type: ignore[no-untyped-def]
    claims = SessionClaims(
        workspace_id="ws_test", role="owner", sub="auth0|x", key_id="key_test"
    )
    token = create_session_token(claims, ttl_seconds=-1)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get(
            "/v1/workspaces/me",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert resp.status_code == 401


@pytest.mark.anyio()
async def test_api_key_still_works(app, stores) -> None:  # type: ignore[no-untyped-def]
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get(
            "/v1/workspaces/me",
            headers={"X-API-Key": "air_deadbeef1234567890abcdef12345678"},
        )
    assert resp.status_code == 200


@pytest.mark.anyio()
async def test_no_auth_returns_401(app) -> None:  # type: ignore[no-untyped-def]
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/v1/workspaces/me")
    assert resp.status_code == 401
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/cloud/test_middleware.py -v`
Expected: `test_bearer_token_auth` and `test_expired_bearer_returns_401` FAIL

- [ ] **Step 3: Update middleware to accept Bearer tokens**

In `src/vindicara/cloud/middleware.py`, update the `dispatch` method. After the existing `X-API-Key` check, add a fallback to `Authorization: Bearer`:

```python
# After the existing X-API-Key lookup block, before the 401 response:

from vindicara.cloud.session_token import (
    SessionClaims,
    SessionTokenError,
    verify_session_token,
)

# In dispatch(), replace the header extraction block with:

api_key_header = request.headers.get("X-API-Key")
bearer_header = request.headers.get("Authorization", "")

if api_key_header:
    api_key = store.lookup(api_key_header)
    if api_key is None:
        return JSONResponse(
            {"detail": "invalid or revoked api key"}, status_code=401
        )
    request.state.workspace_id = api_key.workspace_id
    request.state.api_key_id = api_key.key_id
    request.state.role = api_key.role
elif bearer_header.startswith("Bearer "):
    raw_token = bearer_header[7:]
    try:
        claims = verify_session_token(raw_token)
    except SessionTokenError:
        return JSONResponse(
            {"detail": "invalid or expired session token"}, status_code=401
        )
    request.state.workspace_id = claims.workspace_id
    request.state.api_key_id = claims.key_id
    request.state.role = claims.role
else:
    return JSONResponse(
        {"detail": "missing X-API-Key or Authorization header"},
        status_code=401,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/unit/cloud/test_middleware.py -v`
Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add src/vindicara/cloud/middleware.py tests/unit/cloud/test_middleware.py
git commit -m "feat(cloud): dual-auth middleware (API key + Bearer session token)"
```

---

## Task 3: Backend - SSO Login Returns Session Token

Modify SSO login to return a short-lived session token instead of the raw API key.

**Files:**
- Modify: `src/vindicara/cloud/routes/sso.py`
- Test: `tests/unit/cloud/test_sso_session.py`

- [ ] **Step 1: Write failing test**

```python
"""tests/unit/cloud/test_sso_session.py"""
from __future__ import annotations

from unittest.mock import patch

import pytest
from httpx import ASGITransport, AsyncClient

from vindicara.cloud.factory import create_air_cloud_app
from vindicara.cloud.session_token import verify_session_token
from vindicara.cloud.sso import SsoConfig
from vindicara.cloud.workspace import (
    InMemoryApiKeyStore,
    InMemoryWorkspaceStore,
    Workspace,
)


@pytest.fixture()
def app_with_sso():  # type: ignore[no-untyped-def]
    ws_store = InMemoryWorkspaceStore()
    key_store = InMemoryApiKeyStore()
    ws = Workspace(workspace_id="ws_sso", name="SSO Test", owner_email="o@b.com")
    ws_store.create(ws)

    from vindicara.cloud.sso import InMemorySsoConfigStore

    sso_store = InMemorySsoConfigStore()
    sso_store.put(
        SsoConfig(
            workspace_id="ws_sso",
            issuer="https://auth.example.com/",
            audience="air-cloud",
            default_role="member",
        )
    )

    app = create_air_cloud_app(
        workspace_store=ws_store,
        api_key_store=key_store,
        sso_config_store=sso_store,
    )
    return app, key_store


@pytest.mark.anyio()
async def test_sso_login_returns_session_token(app_with_sso) -> None:  # type: ignore[no-untyped-def]
    app, key_store = app_with_sso

    fake_claims = {
        "sub": "auth0|user1",
        "iss": "https://auth.example.com/",
        "aud": "air-cloud",
        "email": "user@b.com",
    }

    with patch(
        "vindicara.cloud.routes.sso.verify_oidc_token", return_value=fake_claims
    ):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/v1/sso/login",
                json={"workspace_id": "ws_sso", "token": "fake.jwt.here"},
            )

    assert resp.status_code == 201
    body = resp.json()
    assert "session_token" in body
    assert "api_key" not in body  # raw key no longer returned
    assert body["workspace_id"] == "ws_sso"
    assert body["role"] == "member"

    # Verify the session token is valid
    claims = verify_session_token(body["session_token"])
    assert claims.workspace_id == "ws_sso"
    assert claims.role == "member"
    assert claims.sub == "auth0|user1"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/cloud/test_sso_session.py -v`
Expected: FAIL (response still returns api_key, not session_token)

- [ ] **Step 3: Modify SSO login route**

In `src/vindicara/cloud/routes/sso.py`:

1. Add import: `from vindicara.cloud.session_token import SessionClaims, create_session_token`
2. Add new response model:
```python
class SsoSessionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    workspace_id: str
    session_token: str
    role: str
    sub: str
    email: str | None = None
```
3. In the `POST /v1/sso/login` handler, after JIT provisioning or existing key lookup, replace the return with:
```python
session_claims = SessionClaims(
    workspace_id=workspace_id,
    role=api_key.role,
    sub=claims["sub"],
    key_id=api_key.key_id,
)
session_token = create_session_token(session_claims)
return SsoSessionResponse(
    workspace_id=workspace_id,
    session_token=session_token,
    role=api_key.role,
    sub=claims["sub"],
    email=claims.get("email"),
)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/unit/cloud/test_sso_session.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/vindicara/cloud/routes/sso.py tests/unit/cloud/test_sso_session.py
git commit -m "feat(cloud): SSO login returns short-lived session token"
```

---

## Task 4: Backend - Capsule Scoping by Role

Member/viewer roles see only capsules ingested under their API key. Owner/admin sees all workspace capsules.

**Files:**
- Modify: `src/vindicara/cloud/capsule_store.py`
- Modify: `src/vindicara/cloud/routes/capsules.py`
- Test: `tests/unit/cloud/test_capsule_scoping.py`

- [ ] **Step 1: Create test helper**

```python
"""tests/unit/cloud/helpers.py"""
from __future__ import annotations

import json

from airsdk.agdr import Signer, sign_record
from airsdk.types import AgDRPayload, StepKind


def make_signed_record(signer: Signer, *, step_id: str = "step_1") -> str:
    payload = AgDRPayload(model="test", prompt="test", response="test")
    record = sign_record(
        signer=signer,
        kind=StepKind.LLM_CALL,
        payload=payload,
        step_id=step_id,
    )
    return record.model_dump_json()
```

- [ ] **Step 2: Write failing tests**

```python
"""tests/unit/cloud/test_capsule_scoping.py"""
from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from vindicara.cloud.factory import create_air_cloud_app
from vindicara.cloud.workspace import (
    ApiKey,
    InMemoryApiKeyStore,
    InMemoryWorkspaceStore,
    Workspace,
)


@pytest.fixture()
def scoped_app():  # type: ignore[no-untyped-def]
    ws_store = InMemoryWorkspaceStore()
    key_store = InMemoryApiKeyStore()
    ws = Workspace(workspace_id="ws_scope", name="Scope", owner_email="o@b.com")
    ws_store.create(ws)

    owner_key = ApiKey(
        key_id="key_owner",
        workspace_id="ws_scope",
        key="air_owner_00000000000000000000000000",
        role="owner",
    )
    member_key = ApiKey(
        key_id="key_member",
        workspace_id="ws_scope",
        key="air_member_000000000000000000000000000",
        role="member",
    )
    key_store.issue(owner_key)
    key_store.issue(member_key)

    app = create_air_cloud_app(
        workspace_store=ws_store,
        api_key_store=key_store,
    )
    return app


@pytest.mark.anyio()
async def test_member_sees_only_own_capsules(scoped_app) -> None:  # type: ignore[no-untyped-def]
    async with AsyncClient(
        transport=ASGITransport(app=scoped_app), base_url="http://test"
    ) as client:
        # Ingest as member
        from airsdk.agdr import Signer

        signer = Signer.generate()
        from tests.unit.cloud.helpers import make_signed_record

        rec_member = make_signed_record(signer, step_id="step_m1")
        await client.post(
            "/v1/capsules",
            content=rec_member,
            headers={
                "X-API-Key": "air_member_000000000000000000000000000",
                "Content-Type": "application/json",
            },
        )

        # Ingest as owner
        rec_owner = make_signed_record(signer, step_id="step_o1")
        await client.post(
            "/v1/capsules",
            content=rec_owner,
            headers={
                "X-API-Key": "air_owner_00000000000000000000000000",
                "Content-Type": "application/json",
            },
        )

        # Member sees only their capsule
        resp = await client.get(
            "/v1/capsules",
            headers={"X-API-Key": "air_member_000000000000000000000000000"},
        )
        assert resp.status_code == 200
        records = resp.json()["records"]
        step_ids = [r["step_id"] for r in records]
        assert "step_m1" in step_ids
        assert "step_o1" not in step_ids

        # Owner sees all capsules
        resp = await client.get(
            "/v1/capsules",
            headers={"X-API-Key": "air_owner_00000000000000000000000000"},
        )
        records = resp.json()["records"]
        step_ids = [r["step_id"] for r in records]
        assert "step_m1" in step_ids
        assert "step_o1" in step_ids
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/cloud/test_capsule_scoping.py -v`
Expected: FAIL (member currently sees all capsules)

- [ ] **Step 3: Add api_key_id to capsule storage**

In `src/vindicara/cloud/capsule_store.py`, add `api_key_id: str` to `StoredCapsule` and add a `for_key` method to the `CapsuleStore` protocol:

```python
@runtime_checkable
class CapsuleStore(Protocol):
    def append(self, capsule: StoredCapsule) -> None: ...
    def for_workspace(
        self, workspace_id: str, *, limit: int = 100, offset: int = 0
    ) -> list[StoredCapsule]: ...
    def for_key(
        self, workspace_id: str, api_key_id: str, *, limit: int = 100, offset: int = 0
    ) -> list[StoredCapsule]: ...
    def count(self, workspace_id: str | None = None) -> int: ...
```

Implement `for_key` in `InMemoryCapsuleStore` to filter by `api_key_id`.

- [ ] **Step 4: Pass api_key_id through capsule ingest route**

In `src/vindicara/cloud/routes/capsules.py`, when creating `StoredCapsule` in `POST /v1/capsules`, include `api_key_id=request.state.api_key_id`.

- [ ] **Step 5: Scope GET /v1/capsules by role**

In `src/vindicara/cloud/routes/capsules.py`, update `GET /v1/capsules`:

```python
from vindicara.cloud.roles import Role

role = request.state.role
if role in (Role.MEMBER, Role.VIEWER):
    capsules = store.for_key(
        request.state.workspace_id,
        request.state.api_key_id,
        limit=limit,
        offset=offset,
    )
else:
    capsules = store.for_workspace(
        request.state.workspace_id, limit=limit, offset=offset
    )
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `pytest tests/unit/cloud/test_capsule_scoping.py -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add src/vindicara/cloud/capsule_store.py src/vindicara/cloud/routes/capsules.py tests/unit/cloud/test_capsule_scoping.py tests/unit/cloud/helpers.py
git commit -m "feat(cloud): capsule scoping by api_key_id for member/viewer roles"
```

---

## Task 5: Backend - PATCH Keys Endpoint

Allow owner/admin to change a key's role.

**Files:**
- Modify: `src/vindicara/cloud/routes/keys.py`
- Modify: `src/vindicara/cloud/workspace.py` (add `update_role` to protocol)
- Test: `tests/unit/cloud/test_patch_key.py`

- [ ] **Step 1: Write failing tests**

```python
"""tests/unit/cloud/test_patch_key.py"""
from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from vindicara.cloud.factory import create_air_cloud_app
from vindicara.cloud.workspace import (
    ApiKey,
    InMemoryApiKeyStore,
    InMemoryWorkspaceStore,
    Workspace,
)


@pytest.fixture()
def patch_app():  # type: ignore[no-untyped-def]
    ws_store = InMemoryWorkspaceStore()
    key_store = InMemoryApiKeyStore()
    ws = Workspace(workspace_id="ws_p", name="Patch", owner_email="o@b.com")
    ws_store.create(ws)
    owner = ApiKey(key_id="k_own", workspace_id="ws_p", key="air_own_00000000000000000000000000000", role="owner")
    member = ApiKey(key_id="k_mem", workspace_id="ws_p", key="air_mem_00000000000000000000000000000", role="member")
    key_store.issue(owner)
    key_store.issue(member)
    return create_air_cloud_app(workspace_store=ws_store, api_key_store=key_store)


@pytest.mark.anyio()
async def test_owner_promotes_member_to_admin(patch_app) -> None:  # type: ignore[no-untyped-def]
    async with AsyncClient(transport=ASGITransport(app=patch_app), base_url="http://test") as c:
        resp = await c.patch(
            "/v1/keys/k_mem",
            json={"role": "admin"},
            headers={"X-API-Key": "air_own_00000000000000000000000000000"},
        )
    assert resp.status_code == 200
    assert resp.json()["role"] == "admin"


@pytest.mark.anyio()
async def test_admin_cannot_promote_to_owner(patch_app) -> None:  # type: ignore[no-untyped-def]
    # First promote member to admin
    async with AsyncClient(transport=ASGITransport(app=patch_app), base_url="http://test") as c:
        await c.patch(
            "/v1/keys/k_mem",
            json={"role": "admin"},
            headers={"X-API-Key": "air_own_00000000000000000000000000000"},
        )
        # Now admin tries to promote self to owner
        resp = await c.patch(
            "/v1/keys/k_mem",
            json={"role": "owner"},
            headers={"X-API-Key": "air_mem_00000000000000000000000000000"},
        )
    assert resp.status_code == 403


@pytest.mark.anyio()
async def test_member_cannot_patch(patch_app) -> None:  # type: ignore[no-untyped-def]
    async with AsyncClient(transport=ASGITransport(app=patch_app), base_url="http://test") as c:
        resp = await c.patch(
            "/v1/keys/k_mem",
            json={"role": "admin"},
            headers={"X-API-Key": "air_mem_00000000000000000000000000000"},
        )
    assert resp.status_code == 403
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/cloud/test_patch_key.py -v`
Expected: FAIL (endpoint does not exist)

- [ ] **Step 3: Add update_role to ApiKeyStore**

In `src/vindicara/cloud/workspace.py`, add to `ApiKeyStore` protocol:
```python
def update_role(self, key_id: str, role: str) -> ApiKey | None: ...
```

Implement in `InMemoryApiKeyStore`:
```python
def update_role(self, key_id: str, role: str) -> ApiKey | None:
    with self._lock:
        existing = self._by_id.get(key_id)
        if existing is None or existing.revoked_at is not None:
            return None
        updated = ApiKey(
            key_id=existing.key_id,
            workspace_id=existing.workspace_id,
            key=existing.key,
            role=role,
            name=existing.name,
            created_at=existing.created_at,
            revoked_at=existing.revoked_at,
        )
        self._by_id[key_id] = updated
        self._by_key[existing.key] = updated
        return updated
```

- [ ] **Step 4: Add PATCH route**

In `src/vindicara/cloud/routes/keys.py`:

```python
class UpdateKeyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: str


@router.patch("/v1/keys/{key_id}")
async def update_key_role(
    key_id: str, body: UpdateKeyRequest, request: Request
) -> dict[str, str]:
    require(request, Capability.ISSUE_KEY)

    if body.role not in VALID_ROLES:
        raise HTTPException(400, f"invalid role: {body.role}")

    caller_role = Role(request.state.role)
    target_role = Role(body.role)

    # Only owner can set admin or owner
    if target_role in (Role.OWNER, Role.ADMIN) and caller_role != Role.OWNER:
        raise HTTPException(403, "only workspace owner can assign admin/owner role")

    store: ApiKeyStore = request.app.state.cloud_api_keys
    updated = store.update_role(key_id, body.role)
    if updated is None:
        raise HTTPException(404, "key not found or revoked")

    return {"key_id": key_id, "role": body.role}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/unit/cloud/test_patch_key.py -v`
Expected: 3 passed

- [ ] **Step 6: Commit**

```bash
git add src/vindicara/cloud/workspace.py src/vindicara/cloud/routes/keys.py tests/unit/cloud/test_patch_key.py
git commit -m "feat(cloud): PATCH /v1/keys/{key_id} for role updates"
```

---

## Task 6: Backend - Compliance Summary Endpoint

**Files:**
- Create: `src/vindicara/cloud/routes/compliance.py`
- Modify: `src/vindicara/cloud/factory.py` (register route)
- Test: `tests/unit/cloud/test_compliance_route.py`

- [ ] **Step 1: Write failing test**

```python
"""tests/unit/cloud/test_compliance_route.py"""
from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from vindicara.cloud.factory import create_air_cloud_app
from vindicara.cloud.workspace import (
    ApiKey,
    InMemoryApiKeyStore,
    InMemoryWorkspaceStore,
    Workspace,
)


@pytest.fixture()
def compliance_app():  # type: ignore[no-untyped-def]
    ws_store = InMemoryWorkspaceStore()
    key_store = InMemoryApiKeyStore()
    ws = Workspace(workspace_id="ws_c", name="Comp", owner_email="o@b.com")
    ws_store.create(ws)
    owner = ApiKey(key_id="k_o", workspace_id="ws_c", key="air_comp_owner_000000000000000000000", role="owner")
    member = ApiKey(key_id="k_m", workspace_id="ws_c", key="air_comp_memb_0000000000000000000000", role="member")
    key_store.issue(owner)
    key_store.issue(member)
    return create_air_cloud_app(workspace_store=ws_store, api_key_store=key_store)


@pytest.mark.anyio()
async def test_owner_gets_compliance_summary(compliance_app) -> None:  # type: ignore[no-untyped-def]
    async with AsyncClient(transport=ASGITransport(app=compliance_app), base_url="http://test") as c:
        resp = await c.get(
            "/v1/compliance/summary",
            headers={"X-API-Key": "air_comp_owner_000000000000000000000"},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert "frameworks" in body
    assert len(body["frameworks"]) == 4


@pytest.mark.anyio()
async def test_member_forbidden(compliance_app) -> None:  # type: ignore[no-untyped-def]
    async with AsyncClient(transport=ASGITransport(app=compliance_app), base_url="http://test") as c:
        resp = await c.get(
            "/v1/compliance/summary",
            headers={"X-API-Key": "air_comp_memb_0000000000000000000000"},
        )
    assert resp.status_code == 403
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/cloud/test_compliance_route.py -v`
Expected: FAIL (404, route not found)

- [ ] **Step 3: Implement compliance summary route**

```python
"""src/vindicara/cloud/routes/compliance.py"""
from __future__ import annotations

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict

from vindicara.cloud.capsule_store import CapsuleStore
from vindicara.cloud.roles import Capability, Role, require
from vindicara.compliance.frameworks import FRAMEWORKS
from vindicara.compliance.models import EvidenceType

router = APIRouter(tags=["compliance"])


class ControlScore(BaseModel):
    model_config = ConfigDict(extra="forbid")
    control_id: str
    control_name: str
    evidence_count: int
    required: int
    met: bool


class FrameworkScore(BaseModel):
    model_config = ConfigDict(extra="forbid")
    framework_id: str
    name: str
    total_controls: int
    met_controls: int
    coverage_pct: float
    controls: list[ControlScore]


class ComplianceSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")
    frameworks: list[FrameworkScore]


@router.get("/v1/compliance/summary")
async def compliance_summary(request: Request) -> ComplianceSummary:
    require(request, Capability.LIST_KEYS)  # admin+ only

    store: CapsuleStore = request.app.state.capsule_store
    workspace_id: str = request.state.workspace_id
    capsules = store.for_workspace(workspace_id, limit=1000, offset=0)

    # Count evidence types from capsule records
    evidence_counts: dict[str, int] = {}
    for capsule in capsules:
        kind = capsule.record.kind if hasattr(capsule, "record") else ""
        evidence_counts[kind] = evidence_counts.get(kind, 0) + 1

    frameworks: list[FrameworkScore] = []
    for fw_id, fw_def in FRAMEWORKS.items():
        control_scores: list[ControlScore] = []
        met = 0
        for ctrl in fw_def.controls:
            count = sum(
                evidence_counts.get(et.value, 0)
                for et in ctrl.required_evidence_types
            )
            is_met = count >= ctrl.min_evidence_count
            if is_met:
                met += 1
            control_scores.append(
                ControlScore(
                    control_id=ctrl.control_id,
                    control_name=ctrl.control_name,
                    evidence_count=count,
                    required=ctrl.min_evidence_count,
                    met=is_met,
                )
            )
        total = len(fw_def.controls)
        frameworks.append(
            FrameworkScore(
                framework_id=fw_id.value,
                name=fw_def.name,
                total_controls=total,
                met_controls=met,
                coverage_pct=round(met / total * 100, 1) if total else 0.0,
                controls=control_scores,
            )
        )

    return ComplianceSummary(frameworks=frameworks)
```

- [ ] **Step 4: Register route in factory.py**

In `src/vindicara/cloud/factory.py`, add:
```python
from vindicara.cloud.routes import compliance
app.include_router(compliance.router)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/unit/cloud/test_compliance_route.py -v`
Expected: 2 passed

- [ ] **Step 6: Commit**

```bash
git add src/vindicara/cloud/routes/compliance.py src/vindicara/cloud/factory.py tests/unit/cloud/test_compliance_route.py
git commit -m "feat(cloud): GET /v1/compliance/summary endpoint"
```

---

## Task 7: Backend - Analytics Summary Endpoint

**Files:**
- Create: `src/vindicara/cloud/routes/analytics.py`
- Modify: `src/vindicara/cloud/factory.py` (register route)
- Test: `tests/unit/cloud/test_analytics_route.py`

- [ ] **Step 1: Write failing test**

```python
"""tests/unit/cloud/test_analytics_route.py"""
from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from vindicara.cloud.factory import create_air_cloud_app
from vindicara.cloud.workspace import (
    ApiKey,
    InMemoryApiKeyStore,
    InMemoryWorkspaceStore,
    Workspace,
)


@pytest.fixture()
def analytics_app():  # type: ignore[no-untyped-def]
    ws_store = InMemoryWorkspaceStore()
    key_store = InMemoryApiKeyStore()
    ws = Workspace(workspace_id="ws_a", name="Analytics", owner_email="o@b.com")
    ws_store.create(ws)
    owner = ApiKey(key_id="k_o", workspace_id="ws_a", key="air_analytics_own_0000000000000000000", role="owner")
    key_store.issue(owner)
    return create_air_cloud_app(workspace_store=ws_store, api_key_store=key_store)


@pytest.mark.anyio()
async def test_analytics_summary_shape(analytics_app) -> None:  # type: ignore[no-untyped-def]
    async with AsyncClient(transport=ASGITransport(app=analytics_app), base_url="http://test") as c:
        resp = await c.get(
            "/v1/analytics/summary",
            headers={"X-API-Key": "air_analytics_own_0000000000000000000"},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert "total_capsules" in body
    assert "capsules_this_week" in body
    assert "unique_agents" in body
    assert "active_members" in body
    assert "detector_counts" in body
    assert "chain_health" in body
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/cloud/test_analytics_route.py -v`
Expected: FAIL (404)

- [ ] **Step 3: Implement analytics route**

```python
"""src/vindicara/cloud/routes/analytics.py"""
from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict

from vindicara.cloud.capsule_store import CapsuleStore
from vindicara.cloud.roles import Capability, require
from vindicara.cloud.workspace import ApiKeyStore

router = APIRouter(tags=["analytics"])


class ChainHealth(BaseModel):
    model_config = ConfigDict(extra="forbid")
    verified: int
    tampered: int
    broken_link: int


class DailyCount(BaseModel):
    model_config = ConfigDict(extra="forbid")
    date: str
    count: int


class AnalyticsSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")
    total_capsules: int
    capsules_this_week: int
    unique_agents: int
    active_members: int
    detector_counts: dict[str, int]
    chain_health: ChainHealth
    daily_ingestion: list[DailyCount]


@router.get("/v1/analytics/summary")
async def analytics_summary(request: Request) -> AnalyticsSummary:
    require(request, Capability.LIST_KEYS)

    capsule_store: CapsuleStore = request.app.state.capsule_store
    key_store: ApiKeyStore = request.app.state.cloud_api_keys
    workspace_id: str = request.state.workspace_id

    capsules = capsule_store.for_workspace(workspace_id, limit=10000, offset=0)
    keys = key_store.for_workspace(workspace_id)

    now = datetime.now(UTC)
    week_ago = now - timedelta(days=7)
    week_ago_iso = week_ago.isoformat()

    agents: set[str] = set()
    active_key_ids: set[str] = set()
    detector_counts: Counter[str] = Counter()
    daily: Counter[str] = Counter()
    weekly = 0

    for cap in capsules:
        rec = cap.record
        if hasattr(rec, "agent_id") and rec.agent_id:
            agents.add(rec.agent_id)
        if hasattr(cap, "api_key_id") and cap.api_key_id:
            active_key_ids.add(cap.api_key_id)

        ts = rec.timestamp if hasattr(rec, "timestamp") else cap.created_at
        if ts and ts >= week_ago_iso:
            weekly += 1
        if ts:
            daily[ts[:10]] += 1

        if hasattr(rec, "findings") and rec.findings:
            for f in rec.findings:
                detector_counts[f.detector_id] += 1

    # Sort daily by date descending, last 30 days
    thirty_days_ago = (now - timedelta(days=30)).strftime("%Y-%m-%d")
    daily_list = sorted(
        [DailyCount(date=d, count=c) for d, c in daily.items() if d >= thirty_days_ago],
        key=lambda x: x.date,
        reverse=True,
    )

    active_members = len(
        [k for k in keys if k.revoked_at is None and k.key_id in active_key_ids]
    )

    return AnalyticsSummary(
        total_capsules=len(capsules),
        capsules_this_week=weekly,
        unique_agents=len(agents),
        active_members=active_members,
        detector_counts=dict(detector_counts),
        chain_health=ChainHealth(verified=len(capsules), tampered=0, broken_link=0),
        daily_ingestion=daily_list,
    )
```

- [ ] **Step 4: Register route in factory.py**

In `src/vindicara/cloud/factory.py`, add:
```python
from vindicara.cloud.routes import analytics
app.include_router(analytics.router)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/unit/cloud/test_analytics_route.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/vindicara/cloud/routes/analytics.py src/vindicara/cloud/factory.py tests/unit/cloud/test_analytics_route.py
git commit -m "feat(cloud): GET /v1/analytics/summary endpoint"
```

---

## Task 8: Frontend - Transport Layer Updates

Add Bearer token auth and new endpoint methods to the cloud client.

**Files:**
- Modify: `packages/air-dashboard/src/lib/transport/air_cloud_client.ts`
- Test: `packages/air-dashboard/tests/transport/air_cloud_client.test.ts`

- [ ] **Step 1: Write failing tests**

```typescript
// packages/air-dashboard/tests/transport/air_cloud_client.test.ts
import { describe, it, expect } from 'vitest';
import { AirCloudClient } from '$lib/transport/air_cloud_client';

describe('AirCloudClient bearer auth', () => {
  it('sends Authorization header when sessionToken is set', () => {
    const client = new AirCloudClient({
      baseUrl: 'https://test.example.com',
      sessionToken: 'jwt.token.here',
    });
    // The client should use Bearer auth, not X-API-Key
    expect(client.authMode).toBe('bearer');
  });

  it('sends X-API-Key header when apiKey is set', () => {
    const client = new AirCloudClient({
      baseUrl: 'https://test.example.com',
      apiKey: 'air_test123',
    });
    expect(client.authMode).toBe('api-key');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/air-dashboard && npm run test -- tests/transport/air_cloud_client.test.ts`
Expected: FAIL

- [ ] **Step 3: Update AirCloudClient**

Modify `packages/air-dashboard/src/lib/transport/air_cloud_client.ts`:

1. Change constructor to accept either `apiKey` or `sessionToken`:
```typescript
export interface CloudClientConfig {
  baseUrl: string;
  apiKey?: string;
  sessionToken?: string;
}

export class AirCloudClient {
  private baseUrl: string;
  private apiKey?: string;
  private sessionToken?: string;

  get authMode(): 'bearer' | 'api-key' {
    return this.sessionToken ? 'bearer' : 'api-key';
  }

  private get headers(): Record<string, string> {
    if (this.sessionToken) {
      return { 'Authorization': `Bearer ${this.sessionToken}` };
    }
    return { 'X-API-Key': this.apiKey ?? '' };
  }
```

2. Add new endpoint methods:
```typescript
async ssoLogin(token: string, workspaceId?: string): Promise<SsoSessionResponse> {
  const body: Record<string, string> = { token };
  if (workspaceId) body.workspace_id = workspaceId;
  const resp = await fetch(`${this.baseUrl}/v1/sso/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!resp.ok) throw new AirCloudHttpError(resp.status, await resp.text());
  return resp.json();
}

async complianceSummary(): Promise<ComplianceSummary> {
  const resp = await fetch(`${this.baseUrl}/v1/compliance/summary`, {
    headers: this.headers,
  });
  if (!resp.ok) throw new AirCloudHttpError(resp.status, await resp.text());
  return resp.json();
}

async analyticsSummary(): Promise<AnalyticsSummary> {
  const resp = await fetch(`${this.baseUrl}/v1/analytics/summary`, {
    headers: this.headers,
  });
  if (!resp.ok) throw new AirCloudHttpError(resp.status, await resp.text());
  return resp.json();
}

async listMembers(): Promise<RedactedKey[]> {
  return this.listKeys();  // same endpoint, admin-only
}

async inviteMember(email: string, role: string = 'member'): Promise<MemberInvited> {
  const resp = await fetch(`${this.baseUrl}/v1/workspaces/me/members`, {
    method: 'POST',
    headers: { ...this.headers, 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, role }),
  });
  if (!resp.ok) throw new AirCloudHttpError(resp.status, await resp.text());
  return resp.json();
}

async updateKeyRole(keyId: string, role: string): Promise<{ key_id: string; role: string }> {
  const resp = await fetch(`${this.baseUrl}/v1/keys/${keyId}`, {
    method: 'PATCH',
    headers: { ...this.headers, 'Content-Type': 'application/json' },
    body: JSON.stringify({ role }),
  });
  if (!resp.ok) throw new AirCloudHttpError(resp.status, await resp.text());
  return resp.json();
}

async revokeKey(keyId: string): Promise<{ key_id: string; revoked: boolean }> {
  const resp = await fetch(`${this.baseUrl}/v1/keys/${keyId}`, {
    method: 'DELETE',
    headers: this.headers,
  });
  if (!resp.ok) throw new AirCloudHttpError(resp.status, await resp.text());
  return resp.json();
}
```

3. Add TypeScript interfaces for new response types:
```typescript
export interface SsoSessionResponse {
  workspace_id: string;
  session_token: string;
  role: string;
  sub: string;
  email: string | null;
}

export interface ComplianceSummary {
  frameworks: FrameworkScore[];
}

export interface FrameworkScore {
  framework_id: string;
  name: string;
  total_controls: number;
  met_controls: number;
  coverage_pct: number;
  controls: ControlScore[];
}

export interface ControlScore {
  control_id: string;
  control_name: string;
  evidence_count: number;
  required: number;
  met: boolean;
}

export interface AnalyticsSummary {
  total_capsules: number;
  capsules_this_week: number;
  unique_agents: number;
  active_members: number;
  detector_counts: Record<string, number>;
  chain_health: { verified: number; tampered: number; broken_link: number };
  daily_ingestion: { date: string; count: number }[];
}

export interface MemberInvited {
  workspace_id: string;
  invited_email: string;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/air-dashboard && npm run test -- tests/transport/air_cloud_client.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add packages/air-dashboard/src/lib/transport/air_cloud_client.ts packages/air-dashboard/tests/transport/air_cloud_client.test.ts
git commit -m "feat(dashboard): transport layer with Bearer auth + team/compliance/analytics endpoints"
```

---

## Task 9: Frontend - Auth Flow Rewrite (Zero Local Storage)

Remove localStorage persistence. Wire Auth0 login to SSO auto-provisioning.

**Files:**
- Modify: `packages/air-dashboard/src/lib/stores/cloud_session.svelte.ts`
- Modify: `packages/air-dashboard/src/lib/stores/auth.svelte.ts`
- Create: `packages/air-dashboard/src/lib/stores/role.svelte.ts`

- [ ] **Step 1: Create role store**

```typescript
// packages/air-dashboard/src/lib/stores/role.svelte.ts
import { type Role } from './types';

class RoleStore {
  current = $state<Role>('viewer');
  sub = $state<string>('');
  email = $state<string | null>(null);

  get isAdmin(): boolean {
    return this.current === 'owner' || this.current === 'admin';
  }

  get isOwner(): boolean {
    return this.current === 'owner';
  }

  set(role: Role, sub: string, email: string | null): void {
    this.current = role;
    this.sub = sub;
    this.email = email;
  }

  clear(): void {
    this.current = 'viewer';
    this.sub = '';
    this.email = null;
  }
}

export type Role = 'owner' | 'admin' | 'member' | 'viewer';
export const roleStore = new RoleStore();
```

- [ ] **Step 2: Rewrite cloud_session store (remove all localStorage)**

Strip all `localStorage.getItem/setItem/removeItem` calls. The `connect()` method now accepts a session token (from SSO exchange) instead of a raw API key. Add an `ssoConnect()` method that takes the Auth0 JWT, calls `POST /v1/sso/login`, and connects with the returned session token.

Key changes:
- Remove `_STORAGE_KEY` constant
- Remove `restore()` method (no persistence to restore)
- Remove all `localStorage` references
- `connect(baseUrl, sessionToken)` uses Bearer auth
- `ssoConnect(baseUrl, workspaceId, auth0Token)` does the full SSO exchange
- Session token stored in memory only

```typescript
// Key method:
async ssoConnect(baseUrl: string, auth0Token: string): Promise<void> {
  this.status = 'connecting';
  try {
    const client = new AirCloudClient({ baseUrl });
    // workspace_id is optional; backend discovers it from Auth0 issuer match
    const resp = await client.ssoLogin(auth0Token);
    this.sessionToken = resp.session_token;
    this.client = new AirCloudClient({ baseUrl, sessionToken: resp.session_token });
    this.workspace = await this.client.whoami();
    this.baseUrl = baseUrl;
    roleStore.set(resp.role as Role, resp.sub, resp.email);
    this.status = 'connected';
  } catch (err) {
    this.status = 'error';
    this.errorMessage = err instanceof Error ? err.message : String(err);
  }
}
```

Also add a 401-interceptor that triggers silent Auth0 re-auth when the session token expires:

```typescript
// In cloud_session store, wrap every API call:
async withAutoRefresh<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (err) {
    if (err instanceof AirCloudHttpError && err.status === 401 && authStore.client) {
      // Session token expired. Silent re-auth via Auth0 + re-exchange.
      const freshToken = await authStore.client.getTokenSilently();
      const baseUrl = this.baseUrl ?? 'https://cloud.vindicara.io';
      const resp = await new AirCloudClient({ baseUrl }).ssoLogin(freshToken);
      this.sessionToken = resp.session_token;
      this.client = new AirCloudClient({ baseUrl, sessionToken: resp.session_token });
      roleStore.set(resp.role as Role, resp.sub, resp.email);
      return await fn();  // retry with fresh token
    }
    throw err;
  }
}
```

All store methods (`loadCurrentChain`, `listMembers`, etc.) should call through `withAutoRefresh`.

- [ ] **Step 3: Update auth store to auto-provision on callback**

In `auth.svelte.ts`, after handling the Auth0 redirect callback and getting the user, automatically trigger the SSO connection:

```typescript
// After successful Auth0 authentication:
// No VITE_WORKSPACE_ID needed. Backend discovers workspace from Auth0 issuer.
const token = await this.client.getTokenSilently();
await cloudSession.ssoConnect(
  import.meta.env.VITE_AIR_CLOUD_URL ?? 'https://cloud.vindicara.io',
  token,
);
this.phase = 'authenticated';
```

- [ ] **Step 4: Run check to verify no TypeScript errors**

Run: `cd packages/air-dashboard && npm run check`
Expected: 0 errors

- [ ] **Step 5: Verify zero localStorage usage**

Run: `grep -r "localStorage" packages/air-dashboard/src/ --include="*.ts" --include="*.svelte"`
Expected: No matches

- [ ] **Step 6: Commit**

```bash
git add packages/air-dashboard/src/lib/stores/
git commit -m "feat(dashboard): zero localStorage auth flow with SSO auto-provisioning"
```

---

## Task 10: Frontend - Route Restructuring + Sidebar

Move the dashboard to `/dashboard/` routes. Add left sidebar with role-gated navigation.

**Files:**
- Create: `packages/air-dashboard/src/routes/dashboard/+layout.svelte`
- Create: `packages/air-dashboard/src/routes/dashboard/+page.svelte` (move from root)
- Create: `packages/air-dashboard/src/routes/dashboard/+page.ts`
- Create: `packages/air-dashboard/src/routes/dashboard/team/+page.svelte` (placeholder)
- Create: `packages/air-dashboard/src/routes/dashboard/team/+page.ts`
- Create: `packages/air-dashboard/src/routes/dashboard/activity/+page.svelte` (placeholder)
- Create: `packages/air-dashboard/src/routes/dashboard/activity/+page.ts`
- Create: `packages/air-dashboard/src/routes/dashboard/compliance/+page.svelte` (placeholder)
- Create: `packages/air-dashboard/src/routes/dashboard/compliance/+page.ts`
- Create: `packages/air-dashboard/src/routes/dashboard/analytics/+page.svelte` (placeholder)
- Create: `packages/air-dashboard/src/routes/dashboard/analytics/+page.ts`
- Create: `packages/air-dashboard/src/lib/panels/Sidebar.svelte`
- Modify: `packages/air-dashboard/src/routes/+page.svelte` (redirect to /dashboard/)
- Modify: `packages/air-dashboard/src/routes/+layout.svelte` (remove auth gate, moved to dashboard layout)

- [ ] **Step 1: Create Sidebar component**

```svelte
<!-- packages/air-dashboard/src/lib/panels/Sidebar.svelte -->
<script lang="ts">
  import { page } from '$app/stores';
  import { roleStore } from '$lib/stores/role.svelte';
  import { cloudSession } from '$lib/stores/cloud_session.svelte';

  let expanded = $state(false);

  const navItems = [
    { href: '/dashboard/', label: 'Chain', icon: '⬡', adminOnly: false },
    { href: '/dashboard/team', label: 'Team', icon: '◈', adminOnly: true },
    { href: '/dashboard/activity', label: 'Activity', icon: '◉', adminOnly: true },
    { href: '/dashboard/compliance', label: 'Compliance', icon: '⬢', adminOnly: true },
    { href: '/dashboard/analytics', label: 'Analytics', icon: '△', adminOnly: true },
  ];

  const visibleItems = $derived(
    navItems.filter((item) => !item.adminOnly || roleStore.isAdmin)
  );
</script>

<nav
  class="fixed left-0 top-0 h-full bg-zinc-950/90 border-r border-zinc-800 z-50 transition-all duration-200 flex flex-col"
  class:w-14={!expanded}
  class:w-52={expanded}
  onmouseenter={() => (expanded = true)}
  onmouseleave={() => (expanded = false)}
>
  <div class="flex-1 pt-4">
    {#each visibleItems as item}
      <a
        href={item.href}
        class="flex items-center gap-3 px-4 py-3 text-sm transition-colors"
        class:text-red-500={$page.url.pathname === item.href}
        class:text-zinc-400={$page.url.pathname !== item.href}
        class:hover:text-white={true}
      >
        <span class="text-lg w-6 text-center font-mono">{item.icon}</span>
        {#if expanded}
          <span class="font-mono text-xs tracking-wider uppercase">{item.label}</span>
        {/if}
      </a>
    {/each}
  </div>

  <div class="border-t border-zinc-800 p-3">
    {#if expanded}
      <p class="text-xs text-zinc-500 font-mono truncate">{cloudSession.workspace?.name ?? ''}</p>
      <p class="text-xs text-zinc-600 font-mono truncate">{roleStore.email ?? ''}</p>
      <span class="inline-block mt-1 px-2 py-0.5 text-[10px] font-mono uppercase tracking-wider rounded
        {roleStore.current === 'owner' ? 'bg-red-900/50 text-red-400' :
         roleStore.current === 'admin' ? 'bg-amber-900/50 text-amber-400' :
         'bg-zinc-800 text-zinc-400'}">
        {roleStore.current}
      </span>
    {/if}
  </div>
</nav>
```

- [ ] **Step 2: Create dashboard layout with auth gate + sidebar**

```svelte
<!-- packages/air-dashboard/src/routes/dashboard/+layout.svelte -->
<script lang="ts">
  import { goto } from '$app/navigation';
  import { page } from '$app/stores';
  import { authStore } from '$lib/stores/auth.svelte';
  import { roleStore } from '$lib/stores/role.svelte';
  import Sidebar from '$lib/panels/Sidebar.svelte';
  import { onMount } from 'svelte';

  const adminRoutes = ['/dashboard/team', '/dashboard/activity', '/dashboard/compliance', '/dashboard/analytics'];

  onMount(() => {
    authStore.init();
  });

  // Role guard: redirect non-admins away from admin routes
  $effect(() => {
    const path = $page.url.pathname;
    if (adminRoutes.some((r) => path.startsWith(r)) && !roleStore.isAdmin) {
      goto('/dashboard/');
    }
  });
</script>

{#if authStore.phase === 'loading'}
  <div class="flex items-center justify-center h-screen bg-zinc-950 text-zinc-500 font-mono">
    Authenticating...
  </div>
{:else if authStore.phase === 'gate'}
  <div class="flex items-center justify-center h-screen bg-zinc-950">
    <button
      onclick={() => authStore.login()}
      class="px-6 py-3 bg-red-600 text-white font-mono text-sm uppercase tracking-wider hover:bg-red-500 transition-colors"
    >
      Sign in with Auth0
    </button>
  </div>
{:else}
  <Sidebar />
  <main class="ml-14">
    <slot />
  </main>
{/if}
```

- [ ] **Step 3: Move existing dashboard page**

Copy the contents of `src/routes/+page.svelte` (the current forensic chain view) to `src/routes/dashboard/+page.svelte`. Remove the auth gate logic (now in the layout). Keep all the forensic chain, replay, detector, and panel logic.

Create `src/routes/dashboard/+page.ts`:
```typescript
export const prerender = true;
export const ssr = false;
```

- [ ] **Step 4: Create placeholder admin route pages**

Each admin route gets a minimal page that will be implemented in Tasks 11-14:

```svelte
<!-- packages/air-dashboard/src/routes/dashboard/team/+page.svelte -->
<script lang="ts">
  import TeamTable from '$lib/panels/TeamTable.svelte';
</script>

<TeamTable />
```

(Same pattern for activity, compliance, analytics, importing their respective panel components. Create matching `+page.ts` files with `prerender = true; ssr = false;`)

- [ ] **Step 5: Update root page to redirect**

```svelte
<!-- packages/air-dashboard/src/routes/+page.svelte -->
<script lang="ts">
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  onMount(() => goto('/dashboard/'));
</script>
```

- [ ] **Step 6: Strip auth gate from root layout**

Update `src/routes/+layout.svelte` to just render the slot with global CSS, no auth logic.

- [ ] **Step 7: Run checks**

Run: `cd packages/air-dashboard && npm run check`
Expected: 0 errors

- [ ] **Step 8: Commit**

```bash
git add packages/air-dashboard/src/
git commit -m "feat(dashboard): route restructuring under /dashboard/ with sidebar navigation"
```

---

## Task 11: Frontend - Team Management Screen

**Files:**
- Create: `packages/air-dashboard/src/lib/panels/TeamTable.svelte`
- Create: `packages/air-dashboard/src/lib/stores/team.svelte.ts`

- [ ] **Step 1: Create team store**

```typescript
// packages/air-dashboard/src/lib/stores/team.svelte.ts
import type { RedactedKey } from '$lib/transport/air_cloud_client';
import { cloudSession } from '$lib/stores/cloud_session.svelte';

class TeamStore {
  members = $state<RedactedKey[]>([]);
  loading = $state(false);
  error = $state<string | null>(null);

  async load(): Promise<void> {
    if (!cloudSession.client) return;
    this.loading = true;
    this.error = null;
    try {
      this.members = await cloudSession.client.listMembers();
    } catch (err) {
      this.error = err instanceof Error ? err.message : String(err);
    } finally {
      this.loading = false;
    }
  }

  async invite(email: string, role: string): Promise<boolean> {
    if (!cloudSession.client) return false;
    try {
      await cloudSession.client.inviteMember(email, role);
      await this.load();
      return true;
    } catch (err) {
      this.error = err instanceof Error ? err.message : String(err);
      return false;
    }
  }

  async changeRole(keyId: string, role: string): Promise<boolean> {
    if (!cloudSession.client) return false;
    try {
      await cloudSession.client.updateKeyRole(keyId, role);
      await this.load();
      return true;
    } catch (err) {
      this.error = err instanceof Error ? err.message : String(err);
      return false;
    }
  }

  async revoke(keyId: string): Promise<boolean> {
    if (!cloudSession.client) return false;
    try {
      await cloudSession.client.revokeKey(keyId);
      await this.load();
      return true;
    } catch (err) {
      this.error = err instanceof Error ? err.message : String(err);
      return false;
    }
  }
}

export const teamStore = new TeamStore();
```

- [ ] **Step 2: Create TeamTable component**

```svelte
<!-- packages/air-dashboard/src/lib/panels/TeamTable.svelte -->
<script lang="ts">
  import { onMount } from 'svelte';
  import { teamStore } from '$lib/stores/team.svelte';
  import { roleStore } from '$lib/stores/role.svelte';

  let inviteEmail = $state('');
  let inviteRole = $state('member');
  let confirmRevoke = $state<string | null>(null);

  onMount(() => { teamStore.load(); });

  async function handleInvite() {
    if (!inviteEmail.trim()) return;
    const ok = await teamStore.invite(inviteEmail.trim(), inviteRole);
    if (ok) { inviteEmail = ''; inviteRole = 'member'; }
  }

  async function handleRevoke(keyId: string) {
    await teamStore.revoke(keyId);
    confirmRevoke = null;
  }
</script>

<div class="p-6 max-w-4xl mx-auto">
  <h1 class="text-xl font-mono font-bold text-white mb-6 tracking-wider uppercase">Team Members</h1>

  {#if roleStore.isAdmin}
    <form onsubmit={(e) => { e.preventDefault(); handleInvite(); }} class="flex gap-3 mb-8">
      <input
        type="email"
        bind:value={inviteEmail}
        placeholder="email@example.com"
        class="flex-1 bg-zinc-900 border border-zinc-700 text-white text-sm font-mono px-3 py-2 focus:border-red-500 focus:outline-none"
      />
      <select bind:value={inviteRole} class="bg-zinc-900 border border-zinc-700 text-white text-sm font-mono px-3 py-2">
        <option value="member">Member</option>
        {#if roleStore.isOwner}
          <option value="admin">Admin</option>
        {/if}
      </select>
      <button type="submit" class="px-4 py-2 bg-red-600 text-white text-sm font-mono uppercase tracking-wider hover:bg-red-500">
        Invite
      </button>
    </form>
  {/if}

  {#if teamStore.error}
    <p class="text-red-400 text-sm font-mono mb-4">{teamStore.error}</p>
  {/if}

  <table class="w-full text-sm font-mono">
    <thead>
      <tr class="text-zinc-500 text-xs uppercase tracking-wider border-b border-zinc-800">
        <th class="text-left py-2 px-3">Email / Name</th>
        <th class="text-left py-2 px-3">Role</th>
        <th class="text-left py-2 px-3">Status</th>
        <th class="text-left py-2 px-3">Key ID</th>
        <th class="text-right py-2 px-3">Actions</th>
      </tr>
    </thead>
    <tbody>
      {#each teamStore.members as member}
        <tr class="border-b border-zinc-800/50 hover:bg-zinc-900/50">
          <td class="py-3 px-3 text-white">{member.name ?? 'unnamed'}</td>
          <td class="py-3 px-3">
            {#if roleStore.isOwner && member.role !== 'owner'}
              <select
                value={member.role}
                onchange={(e) => teamStore.changeRole(member.key_id, e.currentTarget.value)}
                class="bg-zinc-900 border border-zinc-700 text-white text-xs px-2 py-1"
              >
                <option value="admin">admin</option>
                <option value="member">member</option>
                <option value="viewer">viewer</option>
              </select>
            {:else}
              <span class="px-2 py-0.5 text-xs rounded
                {member.role === 'owner' ? 'bg-red-900/50 text-red-400' :
                 member.role === 'admin' ? 'bg-amber-900/50 text-amber-400' :
                 'bg-zinc-800 text-zinc-400'}">
                {member.role}
              </span>
            {/if}
          </td>
          <td class="py-3 px-3">
            <span class="text-xs {member.revoked_at ? 'text-red-400' : 'text-green-400'}">
              {member.revoked_at ? 'revoked' : 'active'}
            </span>
          </td>
          <td class="py-3 px-3 text-zinc-500">{member.key_id.slice(0, 8)}</td>
          <td class="py-3 px-3 text-right">
            {#if roleStore.isAdmin && member.role !== 'owner' && !member.revoked_at}
              {#if confirmRevoke === member.key_id}
                <button onclick={() => handleRevoke(member.key_id)} class="text-red-400 text-xs hover:text-red-300 mr-2">confirm</button>
                <button onclick={() => (confirmRevoke = null)} class="text-zinc-500 text-xs hover:text-zinc-300">cancel</button>
              {:else}
                <button onclick={() => (confirmRevoke = member.key_id)} class="text-zinc-500 text-xs hover:text-red-400">revoke</button>
              {/if}
            {/if}
          </td>
        </tr>
      {/each}
    </tbody>
  </table>

  {#if teamStore.loading}
    <p class="text-zinc-500 text-sm font-mono mt-4">Loading...</p>
  {/if}
</div>
```

- [ ] **Step 3: Run check**

Run: `cd packages/air-dashboard && npm run check`
Expected: 0 errors

- [ ] **Step 4: Commit**

```bash
git add packages/air-dashboard/src/lib/panels/TeamTable.svelte packages/air-dashboard/src/lib/stores/team.svelte.ts
git commit -m "feat(dashboard): team management screen with invite, role change, revoke"
```

---

## Task 12: Frontend - Activity Overview Screen

**Files:**
- Create: `packages/air-dashboard/src/lib/panels/ActivityFeed.svelte`

- [ ] **Step 1: Implement ActivityFeed component**

```svelte
<!-- packages/air-dashboard/src/lib/panels/ActivityFeed.svelte -->
<script lang="ts">
  import { onMount } from 'svelte';
  import { cloudSession } from '$lib/stores/cloud_session.svelte';
  import type { AgDRRecord } from '$lib/agdr/types';

  let records = $state<AgDRRecord[]>([]);
  let loading = $state(true);
  let filterMember = $state('all');
  let filterSeverity = $state('all');

  onMount(async () => {
    if (!cloudSession.client) return;
    try {
      const page = await cloudSession.client.listCapsules(1000, 0);
      records = page.records.reverse();
    } finally {
      loading = false;
    }
  });

  const filtered = $derived(
    records.filter((r) => {
      if (filterMember !== 'all' && r.agent_id !== filterMember) return false;
      return true;
    })
  );

  const uniqueAgents = $derived([...new Set(records.map((r) => r.agent_id).filter(Boolean))]);
</script>

<div class="p-6 max-w-5xl mx-auto">
  <h1 class="text-xl font-mono font-bold text-white mb-6 tracking-wider uppercase">Activity</h1>

  <div class="flex gap-3 mb-6">
    <select bind:value={filterMember} class="bg-zinc-900 border border-zinc-700 text-white text-sm font-mono px-3 py-2">
      <option value="all">All agents</option>
      {#each uniqueAgents as agent}
        <option value={agent}>{agent}</option>
      {/each}
    </select>
  </div>

  {#if loading}
    <p class="text-zinc-500 text-sm font-mono">Loading activity...</p>
  {:else}
    <div class="space-y-1">
      {#each filtered as record}
        <div class="flex items-center gap-4 py-2 px-3 border-b border-zinc-800/50 hover:bg-zinc-900/30 text-sm font-mono">
          <span class="text-zinc-600 text-xs w-40 shrink-0">{record.timestamp?.slice(0, 19) ?? ''}</span>
          <span class="text-zinc-400 w-24 shrink-0">{record.agent_id ?? 'unknown'}</span>
          <span class="px-2 py-0.5 text-xs rounded bg-zinc-800 text-zinc-300 shrink-0">{record.kind}</span>
          <span class="text-zinc-500 flex-1 truncate">{record.payload?.prompt?.slice(0, 80) ?? ''}</span>
          {#if record.findings && record.findings.length > 0}
            <span class="px-2 py-0.5 text-xs rounded bg-red-900/50 text-red-400">
              {record.findings.length} finding{record.findings.length > 1 ? 's' : ''}
            </span>
          {/if}
        </div>
      {/each}
    </div>
  {/if}
</div>
```

- [ ] **Step 2: Wire into route page**

Update `packages/air-dashboard/src/routes/dashboard/activity/+page.svelte`:
```svelte
<script lang="ts">
  import ActivityFeed from '$lib/panels/ActivityFeed.svelte';
</script>
<ActivityFeed />
```

- [ ] **Step 3: Run check**

Run: `cd packages/air-dashboard && npm run check`
Expected: 0 errors

- [ ] **Step 4: Commit**

```bash
git add packages/air-dashboard/src/lib/panels/ActivityFeed.svelte packages/air-dashboard/src/routes/dashboard/activity/
git commit -m "feat(dashboard): activity overview screen with agent filter"
```

---

## Task 13: Frontend - Compliance Dashboard Screen

**Files:**
- Create: `packages/air-dashboard/src/lib/panels/ComplianceCard.svelte`
- Create: `packages/air-dashboard/src/lib/panels/ComplianceDashboard.svelte`

- [ ] **Step 1: Create ComplianceCard component**

```svelte
<!-- packages/air-dashboard/src/lib/panels/ComplianceCard.svelte -->
<script lang="ts">
  import type { FrameworkScore } from '$lib/transport/air_cloud_client';

  let { framework }: { framework: FrameworkScore } = $props();
  let expanded = $state(false);

  const statusColor = $derived(
    framework.coverage_pct >= 80 ? 'text-green-400 bg-green-900/30' :
    framework.coverage_pct >= 50 ? 'text-amber-400 bg-amber-900/30' :
    'text-red-400 bg-red-900/30'
  );

  const statusLabel = $derived(
    framework.coverage_pct >= 80 ? 'compliant' :
    framework.coverage_pct >= 50 ? 'partial' :
    'insufficient'
  );
</script>

<div class="border border-zinc-800 bg-zinc-950/80 p-4">
  <button onclick={() => (expanded = !expanded)} class="w-full text-left">
    <div class="flex items-center justify-between mb-2">
      <h3 class="text-sm font-mono font-bold text-white tracking-wider">{framework.name}</h3>
      <span class="px-2 py-0.5 text-[10px] font-mono uppercase tracking-wider rounded {statusColor}">
        {statusLabel}
      </span>
    </div>
    <div class="flex items-center gap-4 text-xs font-mono text-zinc-400">
      <span>{framework.met_controls}/{framework.total_controls} controls met</span>
      <span>{framework.coverage_pct}%</span>
    </div>
  </button>

  {#if expanded}
    <div class="mt-4 border-t border-zinc-800 pt-3 space-y-2">
      {#each framework.controls as ctrl}
        <div class="flex items-center justify-between text-xs font-mono py-1">
          <div class="flex items-center gap-2">
            <span class="w-2 h-2 rounded-full {ctrl.met ? 'bg-green-500' : 'bg-red-500'}"></span>
            <span class="text-zinc-400">{ctrl.control_id}</span>
            <span class="text-zinc-300">{ctrl.control_name}</span>
          </div>
          <span class="text-zinc-500">{ctrl.evidence_count}/{ctrl.required}</span>
        </div>
      {/each}
    </div>
  {/if}
</div>
```

- [ ] **Step 2: Create ComplianceDashboard container**

```svelte
<!-- packages/air-dashboard/src/lib/panels/ComplianceDashboard.svelte -->
<script lang="ts">
  import { onMount } from 'svelte';
  import { cloudSession } from '$lib/stores/cloud_session.svelte';
  import type { ComplianceSummary } from '$lib/transport/air_cloud_client';
  import ComplianceCard from './ComplianceCard.svelte';

  let summary = $state<ComplianceSummary | null>(null);
  let loading = $state(true);
  let error = $state<string | null>(null);

  onMount(async () => {
    if (!cloudSession.client) return;
    try {
      summary = await cloudSession.client.complianceSummary();
    } catch (err) {
      error = err instanceof Error ? err.message : String(err);
    } finally {
      loading = false;
    }
  });
</script>

<div class="p-6 max-w-4xl mx-auto">
  <h1 class="text-xl font-mono font-bold text-white mb-6 tracking-wider uppercase">Compliance</h1>

  {#if loading}
    <p class="text-zinc-500 text-sm font-mono">Loading compliance data...</p>
  {:else if error}
    <p class="text-red-400 text-sm font-mono">{error}</p>
  {:else if summary}
    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
      {#each summary.frameworks as framework}
        <ComplianceCard {framework} />
      {/each}
    </div>
  {/if}
</div>
```

- [ ] **Step 3: Wire into route page**

Update `packages/air-dashboard/src/routes/dashboard/compliance/+page.svelte`:
```svelte
<script lang="ts">
  import ComplianceDashboard from '$lib/panels/ComplianceDashboard.svelte';
</script>
<ComplianceDashboard />
```

- [ ] **Step 4: Run check**

Run: `cd packages/air-dashboard && npm run check`
Expected: 0 errors

- [ ] **Step 5: Commit**

```bash
git add packages/air-dashboard/src/lib/panels/ComplianceCard.svelte packages/air-dashboard/src/lib/panels/ComplianceDashboard.svelte packages/air-dashboard/src/routes/dashboard/compliance/
git commit -m "feat(dashboard): compliance dashboard with 4 framework cards"
```

---

## Task 14: Frontend - Analytics Screen

**Files:**
- Create: `packages/air-dashboard/src/lib/panels/AnalyticsDashboard.svelte`

- [ ] **Step 1: Implement AnalyticsDashboard**

```svelte
<!-- packages/air-dashboard/src/lib/panels/AnalyticsDashboard.svelte -->
<script lang="ts">
  import { onMount } from 'svelte';
  import { cloudSession } from '$lib/stores/cloud_session.svelte';
  import type { AnalyticsSummary } from '$lib/transport/air_cloud_client';

  let data = $state<AnalyticsSummary | null>(null);
  let loading = $state(true);
  let error = $state<string | null>(null);

  onMount(async () => {
    if (!cloudSession.client) return;
    try {
      data = await cloudSession.client.analyticsSummary();
    } catch (err) {
      error = err instanceof Error ? err.message : String(err);
    } finally {
      loading = false;
    }
  });

  const sortedDetectors = $derived(
    data ? Object.entries(data.detector_counts).sort((a, b) => b[1] - a[1]) : []
  );

  const maxDetectorCount = $derived(
    sortedDetectors.length > 0 ? sortedDetectors[0][1] : 1
  );

  const healthTotal = $derived(
    data ? data.chain_health.verified + data.chain_health.tampered + data.chain_health.broken_link : 1
  );
</script>

<div class="p-6 max-w-5xl mx-auto">
  <h1 class="text-xl font-mono font-bold text-white mb-6 tracking-wider uppercase">Analytics</h1>

  {#if loading}
    <p class="text-zinc-500 text-sm font-mono">Loading analytics...</p>
  {:else if error}
    <p class="text-red-400 text-sm font-mono">{error}</p>
  {:else if data}
    <!-- Headline stats -->
    <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
      {#each [
        { label: 'Total Capsules', value: data.total_capsules.toLocaleString() },
        { label: 'This Week', value: data.capsules_this_week.toLocaleString() },
        { label: 'Unique Agents', value: data.unique_agents.toString() },
        { label: 'Active Members', value: data.active_members.toString() },
      ] as stat}
        <div class="border border-zinc-800 bg-zinc-950/80 p-4">
          <p class="text-xs font-mono text-zinc-500 uppercase tracking-wider">{stat.label}</p>
          <p class="text-2xl font-mono font-bold text-white mt-1">{stat.value}</p>
        </div>
      {/each}
    </div>

    <!-- Detector triggers -->
    <h2 class="text-sm font-mono font-bold text-white mb-3 tracking-wider uppercase">Detector Triggers</h2>
    <div class="space-y-2 mb-8">
      {#each sortedDetectors as [detector, count]}
        <div class="flex items-center gap-3">
          <span class="text-xs font-mono text-zinc-400 w-16 shrink-0">{detector}</span>
          <div class="flex-1 h-5 bg-zinc-900 relative">
            <div
              class="h-full bg-red-600/70"
              style="width: {(count / maxDetectorCount) * 100}%"
            ></div>
          </div>
          <span class="text-xs font-mono text-zinc-500 w-12 text-right">{count}</span>
        </div>
      {/each}
    </div>

    <!-- Chain health -->
    <h2 class="text-sm font-mono font-bold text-white mb-3 tracking-wider uppercase">Chain Health</h2>
    <div class="flex gap-4 mb-8">
      <div class="flex items-center gap-2">
        <span class="w-3 h-3 rounded-full bg-green-500"></span>
        <span class="text-xs font-mono text-zinc-400">Verified: {data.chain_health.verified} ({Math.round(data.chain_health.verified / healthTotal * 100)}%)</span>
      </div>
      <div class="flex items-center gap-2">
        <span class="w-3 h-3 rounded-full bg-red-500"></span>
        <span class="text-xs font-mono text-zinc-400">Tampered: {data.chain_health.tampered}</span>
      </div>
      <div class="flex items-center gap-2">
        <span class="w-3 h-3 rounded-full bg-amber-500"></span>
        <span class="text-xs font-mono text-zinc-400">Broken: {data.chain_health.broken_link}</span>
      </div>
    </div>

    <!-- Daily ingestion -->
    <h2 class="text-sm font-mono font-bold text-white mb-3 tracking-wider uppercase">Daily Ingestion (30d)</h2>
    <div class="flex items-end gap-1 h-32">
      {#each data.daily_ingestion.slice().reverse() as day}
        {@const maxDay = Math.max(...data.daily_ingestion.map((d) => d.count), 1)}
        <div class="flex-1 flex flex-col items-center justify-end">
          <div
            class="w-full bg-red-600/50 min-h-[2px]"
            style="height: {(day.count / maxDay) * 100}%"
            title="{day.date}: {day.count}"
          ></div>
        </div>
      {/each}
    </div>
  {/if}
</div>
```

- [ ] **Step 2: Wire into route page**

Update `packages/air-dashboard/src/routes/dashboard/analytics/+page.svelte`:
```svelte
<script lang="ts">
  import AnalyticsDashboard from '$lib/panels/AnalyticsDashboard.svelte';
</script>
<AnalyticsDashboard />
```

- [ ] **Step 3: Run check**

Run: `cd packages/air-dashboard && npm run check`
Expected: 0 errors

- [ ] **Step 4: Run full CI**

Run: `cd packages/air-dashboard && npm run ci`
Expected: check + test + build + bundle:check all pass

- [ ] **Step 5: Commit**

```bash
git add packages/air-dashboard/src/lib/panels/AnalyticsDashboard.svelte packages/air-dashboard/src/routes/dashboard/analytics/
git commit -m "feat(dashboard): analytics screen with stats, detector chart, chain health, ingestion trend"
```

---

## Task 15: Integration Verification

End-to-end smoke test and final checks.

**Files:** None (verification only)

- [ ] **Step 1: Run backend tests**

Run: `pytest tests/unit/cloud/ -v`
Expected: All tests pass

- [ ] **Step 2: Run dashboard CI**

Run: `cd packages/air-dashboard && npm run ci`
Expected: check + test + build + bundle:check pass

- [ ] **Step 3: Verify zero localStorage**

Run: `grep -r "localStorage\|sessionStorage\|indexedDB" packages/air-dashboard/src/ --include="*.ts" --include="*.svelte"`
Expected: No matches

- [ ] **Step 4: Run lint**

Run: `./scripts/lint.sh`
Expected: Clean (ruff + mypy)

- [ ] **Step 5: Final commit if any fixups needed**

```bash
git commit -m "chore: integration verification and fixups for team workspace management"
```
