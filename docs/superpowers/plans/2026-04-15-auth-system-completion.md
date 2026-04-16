# Auth System Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish the Vindicara dashboard auth system to spec-complete (Option B from brainstorming): stable JWT secret, refresh flow, unified API key store, email verification via SES (with dev fallback), key rotation grace enforcement, DynamoDB persistence, MFA setup page, and full test coverage.

**Architecture:** The existing auth surface (signup, login, JWT cookies, MFA helpers, CSRF middleware, API key manager) stays. This plan adds the missing operational pieces and fixes three critical bugs (regenerating JWT secret, non-enforced rotation grace, duplicate API key stores). Store layer gets a `UserStoreBackend` protocol with `InMemoryBackend` and `DynamoBackend` implementations so dev/test keep in-memory and prod gets DynamoDB via a new `vindicara-users` table. Email verification uses a `Mailer` interface with `SESMailer` and `LoggingMailer` implementations, factory-picked by `VINDICARA_STAGE`. Refresh flow lives inside the existing dashboard middleware and mints a new access cookie transparently on expired-access-valid-refresh.

**Tech Stack:** Python 3.12, FastAPI, Pydantic v2, bcrypt, PyJWT, pyotp, structlog, boto3 (DynamoDB + SES), moto (test-only, new), AWS CDK, pytest + pytest-asyncio + hypothesis.

**Reference spec:** `docs/superpowers/specs/2026-04-09-auth-system-design.md` (including the 2026-04-15 Production Readiness addendum).

**Preconditions:**
- Run from repo root `/Users/km/Desktop/vindicara`
- Python venv at `.venv/` (use `.venv/bin/pytest`, `.venv/bin/ruff`, `.venv/bin/mypy`)
- All 219 existing tests must pass before Task 1 begins. Run `.venv/bin/pytest -q` to confirm.
- `VINDICARA_STAGE` unset (defaults to `dev`)

---

## File Map

**Create:**
- `src/vindicara/dashboard/auth/backends.py` — `UserStoreBackend` protocol, `InMemoryUserBackend`, `DynamoUserBackend`
- `src/vindicara/dashboard/auth/mailer.py` — `Mailer` protocol, `LoggingMailer`, `SESMailer`, `get_mailer()` factory
- `src/vindicara/dashboard/keys/backends.py` — `KeyStoreBackend` protocol, `InMemoryKeyBackend`, `DynamoKeyBackend`
- `src/vindicara/dashboard/templates/pages/verify_pending.html` — "check your email" page
- `src/vindicara/dashboard/templates/pages/mfa_setup.html` — MFA enrollment page
- `tests/unit/dashboard/__init__.py`
- `tests/unit/dashboard/auth/__init__.py`
- `tests/unit/dashboard/auth/test_passwords.py`
- `tests/unit/dashboard/auth/test_tokens.py`
- `tests/unit/dashboard/auth/test_mfa.py`
- `tests/unit/dashboard/auth/test_store.py`
- `tests/unit/dashboard/auth/test_backends_dynamo.py`
- `tests/unit/dashboard/auth/test_mailer.py`
- `tests/unit/dashboard/keys/__init__.py`
- `tests/unit/dashboard/keys/test_manager.py`
- `tests/unit/dashboard/keys/test_backends_dynamo.py`
- `tests/integration/dashboard/test_auth_flow.py`
- `tests/integration/dashboard/test_refresh.py`
- `tests/integration/dashboard/test_keys_api.py`
- `tests/integration/dashboard/test_mfa_setup_page.py`
- `tests/integration/api/test_public_api_scope.py`

**Modify:**
- `src/vindicara/config/settings.py` — add `jwt_secret`, `users_table`, `verify_base_url`, `ses_sender`
- `src/vindicara/dashboard/auth/tokens.py` — read secret via `_get_secret()` with process-level cache
- `src/vindicara/dashboard/auth/models.py` — add `VerificationToken`
- `src/vindicara/dashboard/auth/store.py` — accept backend, delegate persistence, add verification token methods
- `src/vindicara/dashboard/auth/api.py` — signup sends verification, login blocks unverified, add resend and MFA disable
- `src/vindicara/dashboard/auth/middleware.py` — add refresh flow, add public paths for verify
- `src/vindicara/dashboard/routes.py` — add GET `/verify`, GET `/verify-pending`, GET `/settings/mfa`
- `src/vindicara/dashboard/keys/manager.py` — grace enforcement in `validate_key`, pluggable backend, add `register_dev_key`, fix rotation to return new raw key
- `src/vindicara/api/middleware/auth.py` — delete `APIKeyStore`, delegate to `APIKeyManager`, add scope enforcement
- `src/vindicara/api/app.py` — pass `dev_api_keys` to `APIKeyManager` instead of `APIKeyStore`
- `src/vindicara/infra/stacks/data_stack.py` — add `users_table`
- `src/vindicara/infra/stacks/api_stack.py` — grant users_table, inject env vars
- `src/vindicara/infra/app.py` — pass `users_table` to `APIStack`
- `tests/conftest.py` — set env vars at module top, update `authed_cookies` to full verify+login flow
- `pyproject.toml` — add `moto[dynamodb]>=5.0,<6.0` to `dev` extras

---

## Scope Map (spec → task)

| Spec section | Task(s) |
|---|---|
| JWT Secret Management (addendum) | 1 |
| In-memory store (main) + backend protocol | 2 |
| DynamoDB Storage (addendum) | 11, 13 |
| API Key Store Unification (addendum) | 9 |
| SES with dev fallback (addendum) | 3, 4 |
| Refresh Token Flow (addendum) | 7 |
| Key Rotation Grace Enforcement (addendum) | 8 |
| MFA Setup Page (addendum) | 10 |
| Signup + email verification (main) | 4, 5 |
| Login blocks unverified (main + addendum) | 6 |
| Test Matrix (addendum) | 14, 15 |
| CDK resources (addendum) | 13 |
| Hard rules (existing tests must pass) | every task |

---

## Task 1: Stable JWT Secret + Hardened Test Conftest

**Rationale:** `dashboard/auth/tokens.py:11` currently calls `secrets.token_hex(32)` at module import time. Every Lambda cold start regenerates the signing key, invalidating every outstanding JWT. Fix: read the secret from `VindicaraSettings` once via a process-level cached helper, with a per-process random fallback for local dev. Tests set a fixed secret at the top of `conftest.py` before any vindicara module is imported.

**Files:**
- Modify: `src/vindicara/config/settings.py`
- Modify: `src/vindicara/dashboard/auth/tokens.py`
- Modify: `tests/conftest.py`
- Test: `tests/unit/dashboard/auth/test_tokens.py` (create)

- [ ] **Step 1: Add settings fields**

In `src/vindicara/config/settings.py`, inside `VindicaraSettings`, add four new fields after `rate_limit_window_seconds`:

```python
    jwt_secret: str = Field(
        default="",
        description="JWT signing secret. Empty means generate a random per-process secret.",
    )
    users_table: str = Field(
        default="",
        description="DynamoDB table name for user/session/key storage. Empty means in-memory.",
    )
    verify_base_url: str = Field(
        default="http://localhost:8000",
        description="Base URL for email verification links.",
    )
    ses_sender: str = Field(
        default="noreply@vindicara.io",
        description="Verified SES sender identity for outbound email.",
    )
```

- [ ] **Step 2: Rewrite tokens.py to use cached secret**

Replace the contents of `src/vindicara/dashboard/auth/tokens.py` with:

```python
"""JWT token creation, validation, and CSRF."""

import secrets
from datetime import UTC, datetime, timedelta

import jwt
import structlog

from vindicara.config.settings import VindicaraSettings

logger = structlog.get_logger()

ALGORITHM = "HS256"
ACCESS_TOKEN_MINUTES = 15
REFRESH_TOKEN_DAYS = 7
CSRF_TOKEN_BYTES = 32

_SECRET: str | None = None


def _get_secret() -> str:
    """Resolve the JWT signing secret once per process.

    Reads from `VINDICARA_JWT_SECRET` via settings. If empty, generates a
    random per-process secret so local dev works without configuration.
    """
    global _SECRET
    if _SECRET is None:
        settings = VindicaraSettings()
        _SECRET = settings.jwt_secret if settings.jwt_secret else secrets.token_hex(32)
    return _SECRET


def _reset_secret_for_tests() -> None:
    """Test hook: clear the cached secret so the next call re-reads settings."""
    global _SECRET
    _SECRET = None


def create_access_token(user_id: str, email: str) -> str:
    """Create a short-lived access token (15 min)."""
    payload = {
        "sub": user_id,
        "email": email,
        "type": "access",
        "exp": datetime.now(UTC) + timedelta(minutes=ACCESS_TOKEN_MINUTES),
        "iat": datetime.now(UTC),
    }
    return jwt.encode(payload, _get_secret(), algorithm=ALGORITHM)


def create_refresh_token(user_id: str, session_id: str) -> str:
    """Create a long-lived refresh token (7 days)."""
    payload = {
        "sub": user_id,
        "sid": session_id,
        "type": "refresh",
        "exp": datetime.now(UTC) + timedelta(days=REFRESH_TOKEN_DAYS),
        "iat": datetime.now(UTC),
    }
    return jwt.encode(payload, _get_secret(), algorithm=ALGORITHM)


def create_csrf_token() -> str:
    """Create a random CSRF token."""
    return secrets.token_hex(CSRF_TOKEN_BYTES)


def decode_token(token: str) -> dict[str, str]:
    """Decode and validate a JWT token. Returns payload or empty dict on failure."""
    if not token:
        return {}
    try:
        payload: dict[str, str] = jwt.decode(token, _get_secret(), algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        logger.info("auth.token.expired")
        return {}
    except jwt.InvalidTokenError as exc:
        logger.warning("auth.token.invalid", error=str(exc))
        return {}


def verify_csrf(cookie_token: str, header_token: str) -> bool:
    """Verify CSRF token from cookie matches header. Constant-time compare."""
    if not cookie_token or not header_token:
        return False
    return secrets.compare_digest(cookie_token, header_token)
```

- [ ] **Step 3: Set env vars at top of conftest**

Replace the first four lines of `tests/conftest.py` (the docstring and first blank line) so env vars are set BEFORE any vindicara import:

```python
"""Shared test fixtures."""

import os

os.environ.setdefault("VINDICARA_JWT_SECRET", "test-jwt-secret-do-not-use-in-production-0123456789abcdef")
os.environ.setdefault("VINDICARA_STAGE", "test")

import uuid

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from vindicara.api.app import create_app

TEST_API_KEY = "vnd_test"
TEST_PASSWORD = "TestPassword123"  # noqa: S105


@pytest.fixture
def app() -> FastAPI:
    """Create a test app with a pre-registered dev API key."""
    return create_app(dev_api_keys=[TEST_API_KEY])


@pytest.fixture
async def authed_cookies(app: FastAPI) -> dict[str, str]:
    """Sign up a unique test user and return auth cookies."""
    email = f"test-{uuid.uuid4().hex[:8]}@vindicara.io"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", follow_redirects=False) as client:
        resp = await client.post(
            "/dashboard/api/auth/signup",
            data={"email": email, "password": TEST_PASSWORD, "confirm_password": TEST_PASSWORD},
        )
        return dict(resp.cookies)
```

Note: the `authed_cookies` fixture body is unchanged in this task. Task 4 updates it to do the full verify+login flow.

- [ ] **Step 4: Create tests/unit/dashboard tree**

Create these four empty init files:

```bash
touch tests/unit/dashboard/__init__.py
touch tests/unit/dashboard/auth/__init__.py
touch tests/unit/dashboard/keys/__init__.py
```

- [ ] **Step 5: Write failing tests for token stability and round-trip**

Create `tests/unit/dashboard/auth/test_tokens.py`:

```python
"""Unit tests for JWT token module."""

import time
from datetime import UTC, datetime, timedelta

import jwt
import pytest

from vindicara.dashboard.auth import tokens


@pytest.fixture(autouse=True)
def reset_secret_cache() -> None:
    tokens._reset_secret_for_tests()


def test_secret_is_stable_across_calls() -> None:
    first = tokens._get_secret()
    second = tokens._get_secret()
    assert first == second
    assert len(first) >= 32


def test_access_token_round_trip() -> None:
    token = tokens.create_access_token("user_abc", "x@example.com")
    payload = tokens.decode_token(token)
    assert payload["sub"] == "user_abc"
    assert payload["email"] == "x@example.com"
    assert payload["type"] == "access"


def test_refresh_token_round_trip() -> None:
    token = tokens.create_refresh_token("user_abc", "sess_xyz")
    payload = tokens.decode_token(token)
    assert payload["sub"] == "user_abc"
    assert payload["sid"] == "sess_xyz"
    assert payload["type"] == "refresh"


def test_decode_empty_token_returns_empty_dict() -> None:
    assert tokens.decode_token("") == {}


def test_decode_invalid_token_returns_empty_dict() -> None:
    assert tokens.decode_token("not-a-real-jwt") == {}


def test_decode_expired_token_returns_empty_dict() -> None:
    payload = {
        "sub": "user_abc",
        "email": "x@example.com",
        "type": "access",
        "exp": datetime.now(UTC) - timedelta(seconds=1),
        "iat": datetime.now(UTC) - timedelta(hours=1),
    }
    expired = jwt.encode(payload, tokens._get_secret(), algorithm=tokens.ALGORITHM)
    assert tokens.decode_token(expired) == {}


def test_csrf_verify_requires_match() -> None:
    token = tokens.create_csrf_token()
    assert tokens.verify_csrf(token, token) is True
    assert tokens.verify_csrf(token, "other") is False
    assert tokens.verify_csrf("", token) is False
    assert tokens.verify_csrf(token, "") is False


def test_csrf_tokens_are_unique() -> None:
    assert tokens.create_csrf_token() != tokens.create_csrf_token()
```

- [ ] **Step 6: Run the new tests**

Run: `.venv/bin/pytest tests/unit/dashboard/auth/test_tokens.py -v`
Expected: 8 PASS.

- [ ] **Step 7: Run the full existing suite**

Run: `.venv/bin/pytest -q`
Expected: 219 + 8 = 227 PASS (or more if your baseline is higher).

- [ ] **Step 8: Commit**

```bash
git add src/vindicara/config/settings.py src/vindicara/dashboard/auth/tokens.py tests/conftest.py tests/unit/dashboard/
git commit -m "feat(auth): stable JWT secret and token unit tests"
```

---

## Task 2: UserStoreBackend Protocol + Verification Token CRUD

**Rationale:** The current `UserStore` owns three in-memory dicts directly. To swap in DynamoDB later (Task 11) without rewriting the logic, extract persistence into a `UserStoreBackend` protocol and have `UserStore` delegate. Also add verification token methods for the email-verification flow (Task 4+).

**Files:**
- Create: `src/vindicara/dashboard/auth/backends.py`
- Modify: `src/vindicara/dashboard/auth/models.py`
- Modify: `src/vindicara/dashboard/auth/store.py`
- Test: `tests/unit/dashboard/auth/test_store.py` (create)

- [ ] **Step 1: Add VerificationToken model**

Append to `src/vindicara/dashboard/auth/models.py`:

```python
class VerificationToken(BaseModel):
    token: str
    user_id: str
    expires_at: str
```

- [ ] **Step 2: Create backends.py with protocol + in-memory implementation**

Create `src/vindicara/dashboard/auth/backends.py`:

```python
"""Pluggable persistence backends for the user store."""

from typing import Protocol

from vindicara.dashboard.auth.models import Session, User, VerificationToken


class UserStoreBackend(Protocol):
    """Storage operations the UserStore depends on."""

    def put_user(self, user: User) -> None: ...
    def get_user_by_id(self, user_id: str) -> User | None: ...
    def get_user_by_email(self, email: str) -> User | None: ...

    def put_session(self, session: Session) -> None: ...
    def get_session(self, session_id: str) -> Session | None: ...

    def put_verification_token(self, record: VerificationToken) -> None: ...
    def consume_verification_token(self, token: str) -> str | None: ...


class InMemoryUserBackend:
    """Default in-memory backend used for dev and tests."""

    def __init__(self) -> None:
        self._users: dict[str, User] = {}
        self._email_index: dict[str, str] = {}
        self._sessions: dict[str, Session] = {}
        self._verify_tokens: dict[str, VerificationToken] = {}

    def put_user(self, user: User) -> None:
        self._users[user.user_id] = user
        self._email_index[user.email.lower()] = user.user_id

    def get_user_by_id(self, user_id: str) -> User | None:
        return self._users.get(user_id)

    def get_user_by_email(self, email: str) -> User | None:
        user_id = self._email_index.get(email.lower())
        if user_id is None:
            return None
        return self._users.get(user_id)

    def put_session(self, session: Session) -> None:
        self._sessions[session.session_id] = session

    def get_session(self, session_id: str) -> Session | None:
        return self._sessions.get(session_id)

    def put_verification_token(self, record: VerificationToken) -> None:
        self._verify_tokens[record.token] = record

    def consume_verification_token(self, token: str) -> str | None:
        from datetime import UTC, datetime

        record = self._verify_tokens.pop(token, None)
        if record is None:
            return None
        if datetime.now(UTC) > datetime.fromisoformat(record.expires_at):
            return None
        return record.user_id
```

- [ ] **Step 3: Refactor store.py to use backend**

Replace the contents of `src/vindicara/dashboard/auth/store.py` with:

```python
"""User store. Orchestration layer over a UserStoreBackend."""

import secrets
import uuid
from datetime import UTC, datetime, timedelta

import structlog

from vindicara.dashboard.auth.backends import InMemoryUserBackend, UserStoreBackend
from vindicara.dashboard.auth.models import Session, User, VerificationToken
from vindicara.dashboard.auth.passwords import hash_password, verify_password

logger = structlog.get_logger()

LOCKOUT_THRESHOLD = 5
LOCKOUT_MINUTES = 15
VERIFY_TOKEN_HOURS = 24
SESSION_DAYS = 7


class UserStore:
    """User account, session, and verification-token orchestration."""

    def __init__(self, backend: UserStoreBackend) -> None:
        self._backend = backend

    def create_user(self, email: str, password: str) -> User:
        """Create a new, unverified user. Caller must issue a verification token separately."""
        if self._backend.get_user_by_email(email):
            raise ValueError("Email already registered")
        user_id = f"user_{uuid.uuid4().hex[:12]}"
        user = User(
            user_id=user_id,
            email=email.lower(),
            password_hash=hash_password(password),
            created_at=datetime.now(UTC).isoformat(),
            verified=False,
        )
        self._backend.put_user(user)
        logger.info("auth.user.created", user_id=user_id, email=email)
        return user

    def get_by_email(self, email: str) -> User | None:
        return self._backend.get_user_by_email(email)

    def get_by_id(self, user_id: str) -> User | None:
        return self._backend.get_user_by_id(user_id)

    def update_user(self, user: User) -> None:
        self._backend.put_user(user)

    def mark_verified(self, user_id: str) -> bool:
        user = self._backend.get_user_by_id(user_id)
        if user is None:
            return False
        self._backend.put_user(user.model_copy(update={"verified": True}))
        return True

    def check_lockout(self, email: str) -> bool:
        user = self.get_by_email(email)
        if user is None or not user.locked_until:
            return False
        locked = datetime.fromisoformat(user.locked_until)
        if datetime.now(UTC) < locked:
            return True
        self.update_user(user.model_copy(update={"failed_login_attempts": 0, "locked_until": ""}))
        return False

    def record_failed_login(self, email: str) -> None:
        user = self.get_by_email(email)
        if user is None:
            return
        attempts = user.failed_login_attempts + 1
        updates: dict[str, object] = {"failed_login_attempts": attempts}
        if attempts >= LOCKOUT_THRESHOLD:
            updates["locked_until"] = (datetime.now(UTC) + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
            logger.warning("auth.account.locked", email=email, attempts=attempts)
        self.update_user(user.model_copy(update=updates))

    def clear_failed_logins(self, email: str) -> None:
        user = self.get_by_email(email)
        if user is None:
            return
        self.update_user(user.model_copy(update={"failed_login_attempts": 0, "locked_until": ""}))

    def authenticate(self, email: str, password: str) -> User | None:
        if self.check_lockout(email):
            return None
        user = self.get_by_email(email)
        if user is None:
            self.record_failed_login(email)
            return None
        if not verify_password(password, user.password_hash):
            self.record_failed_login(email)
            return None
        self.clear_failed_logins(email)
        return user

    def create_session(self, user_id: str) -> Session:
        session_id = f"sess_{uuid.uuid4().hex[:16]}"
        session = Session(
            session_id=session_id,
            user_id=user_id,
            created_at=datetime.now(UTC).isoformat(),
            expires_at=(datetime.now(UTC) + timedelta(days=SESSION_DAYS)).isoformat(),
        )
        self._backend.put_session(session)
        return session

    def get_session(self, session_id: str) -> Session | None:
        session = self._backend.get_session(session_id)
        if session is None or session.revoked:
            return None
        return session

    def revoke_session(self, session_id: str) -> None:
        session = self._backend.get_session(session_id)
        if session:
            self._backend.put_session(session.model_copy(update={"revoked": True}))

    def issue_verification_token(self, user_id: str) -> str:
        token = secrets.token_urlsafe(32)
        record = VerificationToken(
            token=token,
            user_id=user_id,
            expires_at=(datetime.now(UTC) + timedelta(hours=VERIFY_TOKEN_HOURS)).isoformat(),
        )
        self._backend.put_verification_token(record)
        return token

    def consume_verification_token(self, token: str) -> str | None:
        return self._backend.consume_verification_token(token)


_store: UserStore | None = None


def get_user_store() -> UserStore:
    """Return the singleton user store. In-memory for now; DynamoDB wiring lands in Task 11."""
    global _store
    if _store is None:
        _store = UserStore(backend=InMemoryUserBackend())
    return _store


def _reset_store_for_tests() -> None:
    """Test hook: drop the singleton so the next call rebuilds it with a fresh backend."""
    global _store
    _store = None
```

- [ ] **Step 4: Write failing tests for the store**

Create `tests/unit/dashboard/auth/test_store.py`:

```python
"""Unit tests for UserStore orchestration."""

import time
from datetime import UTC, datetime, timedelta

import pytest

from vindicara.dashboard.auth.backends import InMemoryUserBackend
from vindicara.dashboard.auth.store import LOCKOUT_THRESHOLD, UserStore


@pytest.fixture
def store() -> UserStore:
    return UserStore(backend=InMemoryUserBackend())


def test_create_user_is_unverified(store: UserStore) -> None:
    user = store.create_user("alice@example.com", "StrongPass123!!")
    assert user.verified is False
    assert user.email == "alice@example.com"
    assert user.password_hash != "StrongPass123!!"


def test_create_duplicate_email_raises(store: UserStore) -> None:
    store.create_user("alice@example.com", "StrongPass123!!")
    with pytest.raises(ValueError, match="already registered"):
        store.create_user("alice@example.com", "OtherPass456!!")


def test_get_by_email_is_case_insensitive(store: UserStore) -> None:
    store.create_user("Alice@Example.com", "StrongPass123!!")
    assert store.get_by_email("ALICE@example.com") is not None


def test_mark_verified_flips_flag(store: UserStore) -> None:
    user = store.create_user("alice@example.com", "StrongPass123!!")
    assert store.mark_verified(user.user_id) is True
    reloaded = store.get_by_id(user.user_id)
    assert reloaded is not None
    assert reloaded.verified is True


def test_authenticate_returns_none_for_wrong_password(store: UserStore) -> None:
    store.create_user("alice@example.com", "StrongPass123!!")
    assert store.authenticate("alice@example.com", "wrong") is None


def test_authenticate_returns_user_for_correct_password(store: UserStore) -> None:
    store.create_user("alice@example.com", "StrongPass123!!")
    result = store.authenticate("alice@example.com", "StrongPass123!!")
    assert result is not None
    assert result.email == "alice@example.com"


def test_lockout_after_threshold_failures(store: UserStore) -> None:
    store.create_user("alice@example.com", "StrongPass123!!")
    for _ in range(LOCKOUT_THRESHOLD):
        store.authenticate("alice@example.com", "wrong")
    assert store.check_lockout("alice@example.com") is True


def test_successful_login_clears_failures(store: UserStore) -> None:
    store.create_user("alice@example.com", "StrongPass123!!")
    for _ in range(LOCKOUT_THRESHOLD - 1):
        store.authenticate("alice@example.com", "wrong")
    store.authenticate("alice@example.com", "StrongPass123!!")
    user = store.get_by_email("alice@example.com")
    assert user is not None
    assert user.failed_login_attempts == 0


def test_verification_token_round_trip(store: UserStore) -> None:
    user = store.create_user("alice@example.com", "StrongPass123!!")
    token = store.issue_verification_token(user.user_id)
    assert store.consume_verification_token(token) == user.user_id
    # Second consume fails (single-use)
    assert store.consume_verification_token(token) is None


def test_verification_token_expires(store: UserStore) -> None:
    from vindicara.dashboard.auth.models import VerificationToken

    user = store.create_user("alice@example.com", "StrongPass123!!")
    # Craft an already-expired token directly against the backend
    expired = VerificationToken(
        token="expired-token-1234",
        user_id=user.user_id,
        expires_at=(datetime.now(UTC) - timedelta(hours=1)).isoformat(),
    )
    store._backend.put_verification_token(expired)
    assert store.consume_verification_token("expired-token-1234") is None


def test_session_create_and_revoke(store: UserStore) -> None:
    user = store.create_user("alice@example.com", "StrongPass123!!")
    session = store.create_session(user.user_id)
    assert store.get_session(session.session_id) is not None
    store.revoke_session(session.session_id)
    assert store.get_session(session.session_id) is None
```

- [ ] **Step 5: Run the new tests**

Run: `.venv/bin/pytest tests/unit/dashboard/auth/test_store.py -v`
Expected: 11 PASS.

- [ ] **Step 6: Run the full suite**

Run: `.venv/bin/pytest -q`
Expected: all previous tests still pass (signup was previously auto-verifying; existing signup integration will now hit an unverified user, but the integration fixture `authed_cookies` still reads cookies from the signup redirect which no longer sets them — the breakage gets fixed in Task 4, not here).

Important: after this task, some dashboard integration tests that depend on `authed_cookies` will FAIL because signup no longer auto-verifies users. **That is expected and is fixed in Task 4.** Do not try to fix it here.

Use this command to confirm only the expected tests fail:

```bash
.venv/bin/pytest -q --co-only || true
.venv/bin/pytest tests/unit/dashboard/auth/ tests/integration/mcp/ tests/integration/api/ -q
```

The `tests/unit/` and non-dashboard integration tests must all pass. Dashboard integration failures are deferred to Task 4.

- [ ] **Step 7: Commit**

```bash
git add src/vindicara/dashboard/auth/backends.py src/vindicara/dashboard/auth/models.py src/vindicara/dashboard/auth/store.py tests/unit/dashboard/auth/test_store.py
git commit -m "refactor(auth): extract UserStoreBackend protocol and add verification tokens"
```

---

## Task 3: Mailer Module with SES and Logging Implementations

**Rationale:** Signup needs to send a verification email. In dev/test we log the link; in prod we hit SES. Abstract behind a `Mailer` protocol so the signup code doesn't branch on stage itself.

**Files:**
- Create: `src/vindicara/dashboard/auth/mailer.py`
- Test: `tests/unit/dashboard/auth/test_mailer.py` (create)

- [ ] **Step 1: Write failing mailer tests**

Create `tests/unit/dashboard/auth/test_mailer.py`:

```python
"""Unit tests for the Mailer factory and implementations."""

import os
from unittest.mock import MagicMock

import pytest

from vindicara.dashboard.auth import mailer


def test_logging_mailer_does_not_raise(caplog: pytest.LogCaptureFixture) -> None:
    m = mailer.LoggingMailer()
    m.send_verification_email(to="alice@example.com", token="tok123", base_url="http://test")
    # Smoke check: no exception, logger was called. We don't assert log contents
    # because structlog routes through its own processor chain.


def test_factory_returns_logging_mailer_in_test_stage(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VINDICARA_STAGE", "test")
    assert isinstance(mailer.get_mailer(), mailer.LoggingMailer)


def test_factory_returns_logging_mailer_in_dev_stage(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VINDICARA_STAGE", "dev")
    assert isinstance(mailer.get_mailer(), mailer.LoggingMailer)


def test_factory_returns_ses_mailer_in_prod_stage(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VINDICARA_STAGE", "prod")
    # Avoid real boto3 initialization by patching the constructor
    monkeypatch.setattr(mailer.SESMailer, "__init__", lambda self, region, sender: None)
    result = mailer.get_mailer()
    assert isinstance(result, mailer.SESMailer)


def test_ses_mailer_calls_boto_client(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_client = MagicMock()
    fake_boto = MagicMock()
    fake_boto.client.return_value = fake_client

    monkeypatch.setattr(mailer, "_boto3_module", lambda: fake_boto)

    m = mailer.SESMailer(region="us-east-1", sender="noreply@example.com")
    m.send_verification_email(to="alice@example.com", token="tok123", base_url="http://test")

    fake_client.send_email.assert_called_once()
    call_kwargs = fake_client.send_email.call_args.kwargs
    assert call_kwargs["Source"] == "noreply@example.com"
    assert call_kwargs["Destination"]["ToAddresses"] == ["alice@example.com"]
    assert "tok123" in str(call_kwargs["Message"])
```

- [ ] **Step 2: Run test, expect failure**

Run: `.venv/bin/pytest tests/unit/dashboard/auth/test_mailer.py -v`
Expected: FAIL (`vindicara.dashboard.auth.mailer` does not exist).

- [ ] **Step 3: Create the mailer module**

Create `src/vindicara/dashboard/auth/mailer.py`:

```python
"""Email delivery: SES in prod, structlog in dev/test."""

from typing import Any, Protocol

import structlog

from vindicara.config.settings import VindicaraSettings

logger = structlog.get_logger()


class Mailer(Protocol):
    """Outbound mailer interface."""

    def send_verification_email(self, to: str, token: str, base_url: str) -> None: ...


class LoggingMailer:
    """Dev/test mailer. Logs the verification link instead of sending an email."""

    def send_verification_email(self, to: str, token: str, base_url: str) -> None:
        link = f"{base_url}/dashboard/verify?token={token}"
        logger.info("mailer.verification", to=to, link=link)


def _boto3_module() -> Any:
    """Import boto3 lazily so tests can monkeypatch without incurring the import cost."""
    import boto3

    return boto3


class SESMailer:
    """Production mailer. Sends via AWS SES."""

    def __init__(self, region: str, sender: str) -> None:
        self._client = _boto3_module().client("ses", region_name=region)
        self._sender = sender

    def send_verification_email(self, to: str, token: str, base_url: str) -> None:
        link = f"{base_url}/dashboard/verify?token={token}"
        self._client.send_email(
            Source=self._sender,
            Destination={"ToAddresses": [to]},
            Message={
                "Subject": {"Data": "Verify your Vindicara account"},
                "Body": {
                    "Html": {
                        "Data": (
                            f"<p>Welcome to Vindicara.</p>"
                            f'<p><a href="{link}">Verify your email</a></p>'
                            f"<p>This link expires in 24 hours.</p>"
                        ),
                    },
                    "Text": {"Data": f"Welcome to Vindicara. Verify your email: {link}\nThis link expires in 24 hours."},
                },
            },
        )
        logger.info("mailer.sent", to=to)


def get_mailer() -> Mailer:
    """Factory: LoggingMailer in dev/test, SESMailer in prod."""
    settings = VindicaraSettings()
    if settings.stage in ("dev", "test"):
        return LoggingMailer()
    return SESMailer(region=settings.aws_region, sender=settings.ses_sender)
```

- [ ] **Step 4: Run the test, expect pass**

Run: `.venv/bin/pytest tests/unit/dashboard/auth/test_mailer.py -v`
Expected: 5 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/vindicara/dashboard/auth/mailer.py tests/unit/dashboard/auth/test_mailer.py
git commit -m "feat(auth): add Mailer interface with SES and logging implementations"
```

---

## Task 4: Signup Sends Verification Email + Fix authed_cookies Fixture

**Rationale:** Signup must now (a) create an unverified user, (b) issue a verification token, (c) call `mailer.send_verification_email`, and (d) redirect to a "check your email" page instead of straight into the dashboard. The test fixture needs to compensate by consuming the token and logging in.

**Files:**
- Modify: `src/vindicara/dashboard/auth/api.py`
- Modify: `tests/conftest.py`
- Test: (integration tests covered in Task 5 once the verify endpoint exists)

- [ ] **Step 1: Rewrite the signup endpoint**

In `src/vindicara/dashboard/auth/api.py`, replace the `signup` function (currently ~line 27-55) with:

```python
@router.post("/signup")
async def signup(
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
) -> Response:
    if password != confirm_password:
        return HTMLResponse('<div style="color:#E63946;padding:8px;">Passwords do not match</div>')

    validation = validate_password(password)
    if not validation.valid:
        errors = "<br>".join(validation.errors)
        return HTMLResponse(f'<div style="color:#E63946;padding:8px;">{errors}</div>')

    store = get_user_store()
    try:
        user = store.create_user(email, password)
    except ValueError as exc:
        return HTMLResponse(f'<div style="color:#E63946;padding:8px;">{exc}</div>')

    token = store.issue_verification_token(user.user_id)
    settings = VindicaraSettings()
    mailer = get_mailer()
    mailer.send_verification_email(to=user.email, token=token, base_url=settings.verify_base_url)

    logger.info("auth.signup.pending_verification", user_id=user.user_id, email=email)
    return RedirectResponse(url="/dashboard/verify-pending", status_code=303)
```

Also add the two new imports at the top of `api.py` (next to the existing imports):

```python
from vindicara.dashboard.auth.mailer import get_mailer
```

(`VindicaraSettings` is already imported.)

- [ ] **Step 2: Update the authed_cookies fixture to do full verify + login**

Replace the `authed_cookies` fixture in `tests/conftest.py` with:

```python
@pytest.fixture
async def authed_cookies(app: FastAPI) -> dict[str, str]:
    """Sign up a unique test user, consume the verification token, log in, return cookies."""
    from vindicara.dashboard.auth.store import get_user_store

    email = f"test-{uuid.uuid4().hex[:8]}@vindicara.io"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", follow_redirects=False) as client:
        signup_resp = await client.post(
            "/dashboard/api/auth/signup",
            data={"email": email, "password": TEST_PASSWORD, "confirm_password": TEST_PASSWORD},
        )
        assert signup_resp.status_code == 303, f"signup failed: {signup_resp.status_code} {signup_resp.text}"

        # Grab the verification token directly from the store (dev/test shortcut, no email to read)
        store = get_user_store()
        user = store.get_by_email(email)
        assert user is not None, "signup did not create user"
        # Retrieve the most recently issued token for this user via the backend
        backend = store._backend  # type: ignore[attr-defined]
        token = next(
            (rec.token for rec in backend._verify_tokens.values() if rec.user_id == user.user_id),  # type: ignore[attr-defined]
            None,
        )
        assert token is not None, "signup did not issue verification token"

        # Consume the token via the verify endpoint (lands once Task 5 is done;
        # for this task we bypass the endpoint and mark verified directly)
        store.mark_verified(user.user_id)

        # Log in to get cookies
        login_resp = await client.post(
            "/dashboard/api/auth/login",
            data={"email": email, "password": TEST_PASSWORD},
        )
        assert login_resp.status_code == 303, f"login failed: {login_resp.status_code} {login_resp.text}"
        return dict(login_resp.cookies)
```

Note: This fixture uses `store.mark_verified` as a shortcut because the verify endpoint doesn't exist yet (Task 5). After Task 5 lands, this fixture still works — the shortcut is harmless because `mark_verified` is idempotent.

- [ ] **Step 3: Run the dashboard integration tests**

Run: `.venv/bin/pytest tests/integration/dashboard/ -q`
Expected: all PASS (fixture now completes signup + verify + login).

- [ ] **Step 4: Run the full test suite**

Run: `.venv/bin/pytest -q`
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/vindicara/dashboard/auth/api.py tests/conftest.py
git commit -m "feat(auth): signup sends verification email and redirects to pending page"
```

---

## Task 5: Verify Route + Resend Endpoint + verify-pending Page

**Rationale:** User clicks the verification link from the email → lands on `GET /dashboard/verify?token=<token>` → token is consumed → user is marked verified → redirect to login with a success flash. Also: a `POST /dashboard/api/auth/resend-verification` endpoint so users who lost the email can re-trigger it, and a `verify-pending.html` page to show after signup.

**Files:**
- Create: `src/vindicara/dashboard/templates/pages/verify_pending.html`
- Modify: `src/vindicara/dashboard/routes.py`
- Modify: `src/vindicara/dashboard/auth/api.py`
- Modify: `src/vindicara/dashboard/auth/middleware.py`
- Test: `tests/integration/dashboard/test_auth_flow.py` (create here; expanded in Task 15)

- [ ] **Step 1: Write a failing integration test for the full signup → verify → login flow**

Create `tests/integration/dashboard/test_auth_flow.py`:

```python
"""Integration tests for the end-to-end auth flow."""

import uuid

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from tests.conftest import TEST_PASSWORD


@pytest.mark.asyncio
async def test_signup_redirects_to_verify_pending(app: FastAPI) -> None:
    email = f"flow-{uuid.uuid4().hex[:8]}@example.com"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", follow_redirects=False) as client:
        resp = await client.post(
            "/dashboard/api/auth/signup",
            data={"email": email, "password": TEST_PASSWORD, "confirm_password": TEST_PASSWORD},
        )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/dashboard/verify-pending"


@pytest.mark.asyncio
async def test_verify_pending_page_renders(app: FastAPI) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/dashboard/verify-pending")
    assert resp.status_code == 200
    assert "Check your email" in resp.text


@pytest.mark.asyncio
async def test_verify_link_marks_user_verified(app: FastAPI) -> None:
    from vindicara.dashboard.auth.store import get_user_store

    email = f"flow-{uuid.uuid4().hex[:8]}@example.com"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", follow_redirects=False) as client:
        await client.post(
            "/dashboard/api/auth/signup",
            data={"email": email, "password": TEST_PASSWORD, "confirm_password": TEST_PASSWORD},
        )
        store = get_user_store()
        user = store.get_by_email(email)
        assert user is not None
        assert user.verified is False

        backend = store._backend  # type: ignore[attr-defined]
        token = next(rec.token for rec in backend._verify_tokens.values() if rec.user_id == user.user_id)  # type: ignore[attr-defined]

        resp = await client.get(f"/dashboard/verify?token={token}")
        assert resp.status_code == 302
        assert "/dashboard/login" in resp.headers["location"]

        refreshed = store.get_by_email(email)
        assert refreshed is not None
        assert refreshed.verified is True


@pytest.mark.asyncio
async def test_verify_invalid_token_returns_error(app: FastAPI) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", follow_redirects=False) as client:
        resp = await client.get("/dashboard/verify?token=not-a-real-token")
    assert resp.status_code == 302
    assert "verify-failed" in resp.headers["location"]


@pytest.mark.asyncio
async def test_resend_verification_issues_new_token(app: FastAPI) -> None:
    from vindicara.dashboard.auth.store import get_user_store

    email = f"flow-{uuid.uuid4().hex[:8]}@example.com"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", follow_redirects=False) as client:
        await client.post(
            "/dashboard/api/auth/signup",
            data={"email": email, "password": TEST_PASSWORD, "confirm_password": TEST_PASSWORD},
        )

        store = get_user_store()
        backend = store._backend  # type: ignore[attr-defined]
        initial_tokens = {rec.token for rec in backend._verify_tokens.values()}  # type: ignore[attr-defined]

        resp = await client.post(
            "/dashboard/api/auth/resend-verification",
            data={"email": email},
        )
        assert resp.status_code == 200

        refreshed_tokens = {rec.token for rec in backend._verify_tokens.values()}  # type: ignore[attr-defined]
        assert refreshed_tokens - initial_tokens, "resend did not issue a new token"
```

- [ ] **Step 2: Run test, expect failure**

Run: `.venv/bin/pytest tests/integration/dashboard/test_auth_flow.py -v`
Expected: all FAIL (routes and template do not exist).

- [ ] **Step 3: Create the verify-pending page template**

Create `src/vindicara/dashboard/templates/pages/verify_pending.html`:

```html
{% extends "base.html" %}
{% block title %}Check your email - Vindicara{% endblock %}
{% block content %}
<div style="display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:70vh;gap:16px;">
  <div style="width:56px;height:56px;background:rgba(96,165,250,0.1);display:flex;align-items:center;justify-content:center;">
    <svg width="28" height="28" viewBox="0 0 24 24" fill="none">
      <path d="M3 7l9 6 9-6M3 7v10a2 2 0 002 2h14a2 2 0 002-2V7M3 7l9-5 9 5" stroke="#60A5FA" stroke-width="2"/>
    </svg>
  </div>
  <h1 style="color:#EFEFEF;font-size:20px;font-weight:600;margin:0;">Check your email</h1>
  <p style="color:#9090A8;font-size:14px;max-width:440px;text-align:center;margin:0;">
    We sent a verification link to the address you signed up with. Click the link to activate your account. The link expires in 24 hours.
  </p>
  <div class="card" style="padding:16px;width:100%;max-width:440px;">
    <div style="font-size:11px;color:#444458;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px;">Didn't get the email?</div>
    <form action="/dashboard/api/auth/resend-verification" method="post" style="display:flex;gap:8px;">
      <input type="email" name="email" placeholder="you@example.com" required style="flex:1;">
      <button type="submit" class="btn-outline" style="padding:8px 16px;">Resend</button>
    </form>
  </div>
  <a href="/dashboard/login" style="font-size:12px;color:#9090A8;">Back to login</a>
</div>
{% endblock %}
```

- [ ] **Step 4: Add the verify and verify-pending routes**

In `src/vindicara/dashboard/routes.py`, add two new route handlers immediately after the existing `signup_page` handler:

```python
@router.get("/verify-pending", response_class=HTMLResponse)
async def verify_pending_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(name="pages/verify_pending.html", request=request, context={"active_page": "verify"})


@router.get("/verify")
async def verify_token(request: Request) -> Response:
    from fastapi.responses import RedirectResponse

    from vindicara.dashboard.auth.store import get_user_store

    token = request.query_params.get("token", "")
    if not token:
        return RedirectResponse(url="/dashboard/login?verify-failed=1", status_code=302)

    store = get_user_store()
    user_id = store.consume_verification_token(token)
    if user_id is None:
        return RedirectResponse(url="/dashboard/login?verify-failed=1", status_code=302)

    store.mark_verified(user_id)
    return RedirectResponse(url="/dashboard/login?verified=1", status_code=302)
```

Add `from starlette.responses import Response` to the imports at the top of `routes.py`.

- [ ] **Step 5: Add the resend endpoint**

In `src/vindicara/dashboard/auth/api.py`, add a new endpoint after the existing `/mfa/verify` endpoint:

```python
@router.post("/resend-verification")
async def resend_verification(email: str = Form(...)) -> HTMLResponse:
    """Re-issue a verification token and email it. Always returns success to avoid account enumeration."""
    store = get_user_store()
    user = store.get_by_email(email)
    if user is not None and not user.verified:
        token = store.issue_verification_token(user.user_id)
        settings = VindicaraSettings()
        mailer = get_mailer()
        mailer.send_verification_email(to=user.email, token=token, base_url=settings.verify_base_url)
        logger.info("auth.verification.resent", user_id=user.user_id, email=email)
    # Intentionally always returns 200 to avoid leaking which emails are registered
    return HTMLResponse('<div style="color:#4ADE80;padding:8px;">If that email is registered, a new verification link has been sent.</div>')
```

- [ ] **Step 6: Add public paths to auth middleware**

In `src/vindicara/dashboard/auth/middleware.py`, add the new paths to `_PUBLIC_PATHS`:

```python
_PUBLIC_PATHS = {
    "/dashboard/login",
    "/dashboard/signup",
    "/dashboard/verify",
    "/dashboard/verify-pending",
    "/dashboard/api/auth/signup",
    "/dashboard/api/auth/login",
    "/dashboard/api/auth/resend-verification",
    "/dashboard/demo",
    "/dashboard/api/demo/start",
    "/dashboard/api/demo/status",
}
```

Note: `/dashboard/verify` requires special handling because it has a query param. Starlette's `request.url.path` strips the query string, so the plain path match still works.

- [ ] **Step 7: Run the new tests**

Run: `.venv/bin/pytest tests/integration/dashboard/test_auth_flow.py -v`
Expected: all 5 PASS.

- [ ] **Step 8: Run full suite**

Run: `.venv/bin/pytest -q`
Expected: all pass.

- [ ] **Step 9: Commit**

```bash
git add src/vindicara/dashboard/templates/pages/verify_pending.html src/vindicara/dashboard/routes.py src/vindicara/dashboard/auth/api.py src/vindicara/dashboard/auth/middleware.py tests/integration/dashboard/test_auth_flow.py
git commit -m "feat(auth): add email verification endpoint, resend, and pending page"
```

---

## Task 6: Login Blocks Unverified Users

**Rationale:** Per the main spec, unverified users cannot log in. The current login handler issues tokens regardless of `user.verified`.

**Files:**
- Modify: `src/vindicara/dashboard/auth/api.py`
- Modify: `tests/integration/dashboard/test_auth_flow.py`

- [ ] **Step 1: Write failing tests**

Append to `tests/integration/dashboard/test_auth_flow.py`:

```python
@pytest.mark.asyncio
async def test_unverified_user_cannot_login(app: FastAPI) -> None:
    email = f"unver-{uuid.uuid4().hex[:8]}@example.com"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", follow_redirects=False) as client:
        await client.post(
            "/dashboard/api/auth/signup",
            data={"email": email, "password": TEST_PASSWORD, "confirm_password": TEST_PASSWORD},
        )
        resp = await client.post(
            "/dashboard/api/auth/login",
            data={"email": email, "password": TEST_PASSWORD},
        )
    assert resp.status_code == 200
    assert "verify" in resp.text.lower()


@pytest.mark.asyncio
async def test_verified_user_can_login(app: FastAPI) -> None:
    from vindicara.dashboard.auth.store import get_user_store

    email = f"ver-{uuid.uuid4().hex[:8]}@example.com"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", follow_redirects=False) as client:
        await client.post(
            "/dashboard/api/auth/signup",
            data={"email": email, "password": TEST_PASSWORD, "confirm_password": TEST_PASSWORD},
        )
        store = get_user_store()
        user = store.get_by_email(email)
        assert user is not None
        store.mark_verified(user.user_id)

        resp = await client.post(
            "/dashboard/api/auth/login",
            data={"email": email, "password": TEST_PASSWORD},
        )
    assert resp.status_code == 303
    assert "vnd_access" in resp.cookies
```

- [ ] **Step 2: Run test, expect failure**

Run: `.venv/bin/pytest tests/integration/dashboard/test_auth_flow.py::test_unverified_user_cannot_login -v`
Expected: FAIL (login issues tokens regardless of verified status).

- [ ] **Step 3: Update login to block unverified users**

In `src/vindicara/dashboard/auth/api.py`, replace the body of the `login` function immediately after the `authenticate` call (currently right after the `if user is None: return ...` line) with:

```python
    if user is None:
        return HTMLResponse('<div style="color:#E63946;padding:8px;">Invalid email or password</div>')

    if not user.verified:
        return HTMLResponse(
            '<div style="color:#EF9F27;padding:8px;">'
            'Please verify your email before logging in. '
            '<a href="/dashboard/verify-pending" style="color:#60A5FA;">Resend verification</a>'
            '</div>'
        )

    if user.mfa_enabled:
```

The diff is: insert the four-line `if not user.verified:` block between the existing `if user is None` check and the `if user.mfa_enabled` check. Leave everything else as-is.

- [ ] **Step 4: Run the tests**

Run: `.venv/bin/pytest tests/integration/dashboard/test_auth_flow.py -v`
Expected: all PASS.

- [ ] **Step 5: Run full suite**

Run: `.venv/bin/pytest -q`
Expected: all pass (the `authed_cookies` fixture calls `store.mark_verified` before login, so it still works).

- [ ] **Step 6: Commit**

```bash
git add src/vindicara/dashboard/auth/api.py tests/integration/dashboard/test_auth_flow.py
git commit -m "feat(auth): block unverified users from logging in"
```

---

## Task 7: Refresh Token Flow in Middleware

**Rationale:** 15-minute access tokens with no refresh flow boots users every 15 minutes. Middleware must: on expired access token, check `vnd_refresh`, verify the session is not revoked, mint a new access token, and attach it to the outgoing response cookie. The user never sees a login prompt until the refresh token itself expires (7 days).

**Files:**
- Modify: `src/vindicara/dashboard/auth/middleware.py`
- Test: `tests/integration/dashboard/test_refresh.py` (create)

- [ ] **Step 1: Write failing refresh test**

Create `tests/integration/dashboard/test_refresh.py`:

```python
"""Integration tests for the refresh token flow."""

import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from tests.conftest import TEST_PASSWORD
from vindicara.dashboard.auth import tokens


def _expired_access(user_id: str, email: str) -> str:
    payload = {
        "sub": user_id,
        "email": email,
        "type": "access",
        "exp": datetime.now(UTC) - timedelta(seconds=1),
        "iat": datetime.now(UTC) - timedelta(hours=1),
    }
    return jwt.encode(payload, tokens._get_secret(), algorithm=tokens.ALGORITHM)


@pytest.mark.asyncio
async def test_expired_access_with_valid_refresh_issues_new_access(app: FastAPI) -> None:
    from vindicara.dashboard.auth.store import get_user_store

    email = f"refresh-{uuid.uuid4().hex[:8]}@example.com"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", follow_redirects=False) as client:
        await client.post(
            "/dashboard/api/auth/signup",
            data={"email": email, "password": TEST_PASSWORD, "confirm_password": TEST_PASSWORD},
        )
        store = get_user_store()
        user = store.get_by_email(email)
        assert user is not None
        store.mark_verified(user.user_id)
        login_resp = await client.post(
            "/dashboard/api/auth/login",
            data={"email": email, "password": TEST_PASSWORD},
        )
        refresh_cookie = login_resp.cookies["vnd_refresh"]

        # Replace the access cookie with an expired one; keep the valid refresh
        expired = _expired_access(user.user_id, user.email)
        client.cookies.clear()
        client.cookies.set("vnd_access", expired)
        client.cookies.set("vnd_refresh", refresh_cookie)

        resp = await client.get("/dashboard/")

    assert resp.status_code == 200
    # Middleware should have set a fresh access cookie on the response
    assert "vnd_access" in resp.cookies
    new_access = resp.cookies["vnd_access"]
    assert new_access != expired
    assert tokens.decode_token(new_access).get("sub") == user.user_id


@pytest.mark.asyncio
async def test_revoked_session_cannot_refresh(app: FastAPI) -> None:
    from vindicara.dashboard.auth.store import get_user_store

    email = f"revoke-{uuid.uuid4().hex[:8]}@example.com"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", follow_redirects=False) as client:
        await client.post(
            "/dashboard/api/auth/signup",
            data={"email": email, "password": TEST_PASSWORD, "confirm_password": TEST_PASSWORD},
        )
        store = get_user_store()
        user = store.get_by_email(email)
        assert user is not None
        store.mark_verified(user.user_id)
        login_resp = await client.post(
            "/dashboard/api/auth/login",
            data={"email": email, "password": TEST_PASSWORD},
        )
        refresh_cookie = login_resp.cookies["vnd_refresh"]
        # Decode the refresh to find sid, then revoke
        payload = tokens.decode_token(refresh_cookie)
        sid = payload["sid"]
        store.revoke_session(sid)

        expired = _expired_access(user.user_id, user.email)
        client.cookies.clear()
        client.cookies.set("vnd_access", expired)
        client.cookies.set("vnd_refresh", refresh_cookie)

        resp = await client.get("/dashboard/")

    assert resp.status_code == 302
    assert "/dashboard/login" in resp.headers["location"]


@pytest.mark.asyncio
async def test_no_tokens_at_all_redirects_to_login(app: FastAPI) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", follow_redirects=False) as client:
        resp = await client.get("/dashboard/")
    assert resp.status_code == 302
    assert "/dashboard/login" in resp.headers["location"]
```

- [ ] **Step 2: Run test, expect failure**

Run: `.venv/bin/pytest tests/integration/dashboard/test_refresh.py -v`
Expected: `test_expired_access_with_valid_refresh_issues_new_access` FAILS (middleware currently redirects on expired access without consulting refresh).

- [ ] **Step 3: Rewrite middleware to handle refresh**

Replace the contents of `src/vindicara/dashboard/auth/middleware.py` with:

```python
"""Auth middleware for dashboard routes: JWT cookie auth, CSRF, transparent refresh."""

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from vindicara.config.settings import VindicaraSettings
from vindicara.dashboard.auth.store import get_user_store
from vindicara.dashboard.auth.tokens import (
    ACCESS_TOKEN_MINUTES,
    create_access_token,
    decode_token,
    verify_csrf,
)

_PUBLIC_PATHS = {
    "/dashboard/login",
    "/dashboard/signup",
    "/dashboard/verify",
    "/dashboard/verify-pending",
    "/dashboard/api/auth/signup",
    "/dashboard/api/auth/login",
    "/dashboard/api/auth/resend-verification",
    "/dashboard/demo",
    "/dashboard/api/demo/start",
    "/dashboard/api/demo/status",
}


class DashboardAuthMiddleware(BaseHTTPMiddleware):
    """Protects dashboard routes. Auto-refreshes expired access tokens."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        path = request.url.path

        if not path.startswith("/dashboard"):
            return await call_next(request)

        if path in _PUBLIC_PATHS:
            return await call_next(request)

        access_token = request.cookies.get("vnd_access", "")
        payload = decode_token(access_token)
        new_access_cookie: str | None = None

        # If access is missing/expired/invalid, try to refresh via vnd_refresh
        if not payload or payload.get("type") != "access":
            refresh_token = request.cookies.get("vnd_refresh", "")
            refresh_payload = decode_token(refresh_token)
            if refresh_payload and refresh_payload.get("type") == "refresh":
                session_id = str(refresh_payload.get("sid", ""))
                user_id = str(refresh_payload.get("sub", ""))
                store = get_user_store()
                session = store.get_session(session_id)
                if session and not session.revoked:
                    user = store.get_by_id(user_id)
                    if user is not None and user.verified:
                        new_access_cookie = create_access_token(user.user_id, user.email)
                        payload = decode_token(new_access_cookie)

        if not payload or payload.get("type") != "access":
            if path.startswith("/dashboard/api/"):
                return Response(status_code=401, content="Unauthorized")
            return RedirectResponse(url="/dashboard/login", status_code=302)

        if (
            request.method in ("POST", "PUT", "DELETE")
            and path.startswith("/dashboard/api/")
            and not path.startswith("/dashboard/api/auth/")
        ):
            csrf_cookie = request.cookies.get("vnd_csrf", "")
            csrf_header = request.headers.get("X-CSRF-Token", "")
            if not verify_csrf(csrf_cookie, csrf_header):
                csrf_form = ""
                if request.headers.get("content-type", "").startswith("application/x-www-form-urlencoded"):
                    form = await request.form()
                    csrf_form = str(form.get("_csrf", ""))
                if not verify_csrf(csrf_cookie, csrf_form):
                    return Response(status_code=403, content="CSRF validation failed")

        request.state.user_id = str(payload.get("sub", ""))
        request.state.email = str(payload.get("email", ""))

        response = await call_next(request)

        if new_access_cookie is not None:
            settings = VindicaraSettings()
            secure = settings.stage not in ("dev", "test")
            response.set_cookie(
                "vnd_access",
                new_access_cookie,
                httponly=True,
                secure=secure,
                samesite="strict",
                max_age=ACCESS_TOKEN_MINUTES * 60,
            )

        return response
```

- [ ] **Step 4: Run the new tests**

Run: `.venv/bin/pytest tests/integration/dashboard/test_refresh.py -v`
Expected: all 3 PASS.

- [ ] **Step 5: Run full suite**

Run: `.venv/bin/pytest -q`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add src/vindicara/dashboard/auth/middleware.py tests/integration/dashboard/test_refresh.py
git commit -m "feat(auth): transparent refresh of expired access tokens"
```

---

## Task 8: Key Rotation Grace Enforcement

**Rationale:** `APIKeyManager.rotate_key` sets `grace_expires` on the old record but `validate_key` never checks it, so the rotated-out key stays valid forever. Fix `validate_key` to treat a key past its grace deadline as revoked.

**Files:**
- Modify: `src/vindicara/dashboard/keys/manager.py`
- Test: `tests/unit/dashboard/keys/test_manager.py` (create)

- [ ] **Step 1: Write failing test**

Create `tests/unit/dashboard/keys/test_manager.py`:

```python
"""Unit tests for APIKeyManager."""

from datetime import UTC, datetime, timedelta

import pytest

from vindicara.dashboard.keys.manager import APIKeyManager, VALID_SCOPES


@pytest.fixture
def manager() -> APIKeyManager:
    return APIKeyManager()


def test_create_key_returns_raw_and_record(manager: APIKeyManager) -> None:
    raw, record = manager.create_key(user_id="u1", name="test", scopes=["guard"])
    assert raw.startswith("vnd_live_")
    assert record.scopes == ["guard"]
    assert record.key_prefix.startswith("vnd_live_")


def test_create_key_defaults_to_all_scopes_when_none_provided(manager: APIKeyManager) -> None:
    _, record = manager.create_key(user_id="u1", name="test", scopes=None)
    assert set(record.scopes) == VALID_SCOPES


def test_validate_key_returns_record(manager: APIKeyManager) -> None:
    raw, record = manager.create_key(user_id="u1", name="test")
    result = manager.validate_key(raw)
    assert result is not None
    assert result.key_id == record.key_id


def test_validate_unknown_key_returns_none(manager: APIKeyManager) -> None:
    assert manager.validate_key("vnd_live_notarealkey") is None


def test_revoke_key_removes_it(manager: APIKeyManager) -> None:
    raw, record = manager.create_key(user_id="u1", name="test")
    assert manager.revoke_key(record.key_id, "u1") is True
    assert manager.validate_key(raw) is None


def test_rotate_key_returns_new_raw_and_old_still_valid_during_grace(manager: APIKeyManager) -> None:
    old_raw, old_record = manager.create_key(user_id="u1", name="test")
    result = manager.rotate_key(old_record.key_id, "u1")
    assert result is not None
    new_raw, new_record = result
    assert new_raw != old_raw
    assert manager.validate_key(new_raw) is not None
    # Old key still works during grace period
    assert manager.validate_key(old_raw) is not None


def test_rotate_key_expires_old_key_after_grace(manager: APIKeyManager) -> None:
    old_raw, old_record = manager.create_key(user_id="u1", name="test")
    manager.rotate_key(old_record.key_id, "u1")

    # Manually set grace_expires to the past
    expired_record = manager._keys[old_record.key_id].model_copy(  # type: ignore[attr-defined]
        update={"grace_expires": (datetime.now(UTC) - timedelta(seconds=1)).isoformat()},
    )
    manager._keys[old_record.key_id] = expired_record  # type: ignore[attr-defined]

    assert manager.validate_key(old_raw) is None


def test_revoked_key_returns_none(manager: APIKeyManager) -> None:
    raw, record = manager.create_key(user_id="u1", name="test")
    manager.revoke_key(record.key_id, "u1")
    assert manager.validate_key(raw) is None


def test_list_keys_filters_revoked(manager: APIKeyManager) -> None:
    _, k1 = manager.create_key(user_id="u1", name="keep")
    _, k2 = manager.create_key(user_id="u1", name="gone")
    manager.revoke_key(k2.key_id, "u1")
    ids = [k.key_id for k in manager.list_keys("u1")]
    assert k1.key_id in ids
    assert k2.key_id not in ids


def test_scope_filtering_on_create(manager: APIKeyManager) -> None:
    _, record = manager.create_key(user_id="u1", name="test", scopes=["guard", "not-a-real-scope"])
    assert record.scopes == ["guard"]
```

- [ ] **Step 2: Run test, expect failures**

Run: `.venv/bin/pytest tests/unit/dashboard/keys/test_manager.py -v`
Expected: `test_rotate_key_expires_old_key_after_grace` FAILS.

- [ ] **Step 3: Fix validate_key in manager.py**

In `src/vindicara/dashboard/keys/manager.py`, replace the `validate_key` method with:

```python
    def validate_key(self, raw_key: str) -> APIKeyRecord | None:
        """Validate a raw API key. Returns record if valid (not revoked, not past grace)."""
        key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
        key_id = self._hash_index.get(key_hash)
        if key_id is None:
            return None
        record = self._keys.get(key_id)
        if record is None or record.revoked:
            return None
        if record.grace_expires:
            try:
                deadline = datetime.fromisoformat(record.grace_expires)
            except ValueError:
                return None
            if datetime.now(UTC) > deadline:
                return None
        return record
```

- [ ] **Step 4: Run tests**

Run: `.venv/bin/pytest tests/unit/dashboard/keys/test_manager.py -v`
Expected: all 10 PASS.

- [ ] **Step 5: Run full suite**

Run: `.venv/bin/pytest -q`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add src/vindicara/dashboard/keys/manager.py tests/unit/dashboard/keys/test_manager.py
git commit -m "fix(keys): enforce rotation grace period in validate_key"
```

---

## Task 9: API Key Store Unification + Public API Scope Enforcement

**Rationale:** Two independent in-memory key stores exist: `api/middleware/auth.py::APIKeyStore` (used by the public API) and `dashboard/keys/manager.py::APIKeyManager` (used by the dashboard). Keys created in the dashboard never reach the public API. Unify: delete `APIKeyStore`, make `APIKeyAuthMiddleware` consult `APIKeyManager`, and add scope enforcement per route prefix.

**Files:**
- Modify: `src/vindicara/api/middleware/auth.py`
- Modify: `src/vindicara/api/app.py`
- Modify: `src/vindicara/dashboard/keys/manager.py`
- Test: `tests/integration/api/test_public_api_scope.py` (create)

- [ ] **Step 1: Write failing integration test**

Create `tests/integration/api/test_public_api_scope.py`:

```python
"""Integration tests for scope enforcement on the public API."""

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from tests.conftest import TEST_API_KEY


@pytest.mark.asyncio
async def test_dev_key_has_all_scopes(app: FastAPI) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/v1/guard",
            headers={"X-Vindicara-Key": TEST_API_KEY},
            json={"input": "hello", "output": "world", "policy": "content-safety"},
        )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_dashboard_created_key_works_for_public_api(app: FastAPI) -> None:
    from vindicara.dashboard.keys.manager import get_key_manager

    manager = get_key_manager()
    raw_key, _ = manager.create_key(user_id="u1", name="sdk-test", scopes=["guard"])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/v1/guard",
            headers={"X-Vindicara-Key": raw_key},
            json={"input": "hello", "output": "world", "policy": "content-safety"},
        )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_wrong_scope_returns_403(app: FastAPI) -> None:
    from vindicara.dashboard.keys.manager import get_key_manager

    manager = get_key_manager()
    raw_key, _ = manager.create_key(user_id="u1", name="scanner-only", scopes=["mcp"])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/v1/guard",
            headers={"X-Vindicara-Key": raw_key},
            json={"input": "hello", "output": "world", "policy": "content-safety"},
        )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_invalid_key_returns_401(app: FastAPI) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/v1/guard",
            headers={"X-Vindicara-Key": "vnd_live_totally_fake"},
            json={"input": "hello", "output": "world", "policy": "content-safety"},
        )
    assert resp.status_code == 401
```

- [ ] **Step 2: Run test, expect failures**

Run: `.venv/bin/pytest tests/integration/api/test_public_api_scope.py -v`
Expected: `test_dashboard_created_key_works_for_public_api` and `test_wrong_scope_returns_403` FAIL (public middleware uses the separate APIKeyStore and has no scope check).

- [ ] **Step 3: Add register_dev_key to APIKeyManager**

In `src/vindicara/dashboard/keys/manager.py`, add a method to the `APIKeyManager` class right after `validate_key`:

```python
    def register_dev_key(self, raw_key: str, owner_id: str = "dev") -> APIKeyRecord:
        """Register a pre-existing raw key with full scopes. For tests and dev seed only."""
        import hashlib

        key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
        key_id = f"devkey_{secrets.token_hex(4)}"
        record = APIKeyRecord(
            key_id=key_id,
            user_id=owner_id,
            name=f"dev-{owner_id}",
            key_hash=key_hash,
            key_prefix=raw_key[:12] + "..." + raw_key[-4:] if len(raw_key) > 16 else raw_key,
            scopes=list(VALID_SCOPES),
            created_at=datetime.now(UTC).isoformat(),
        )
        self._keys[key_id] = record
        self._hash_index[key_hash] = key_id
        logger.info("keys.dev_registered", owner_id=owner_id)
        return record
```

- [ ] **Step 4: Replace api/middleware/auth.py with scope-aware middleware**

Replace the contents of `src/vindicara/api/middleware/auth.py` with:

```python
"""API key authentication and scope enforcement for the public API."""

import structlog
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from vindicara.config.constants import API_KEY_HEADER

logger = structlog.get_logger()

_PUBLIC_PATHS = {"/health", "/ready", "/docs", "/openapi.json", "/redoc"}

# Route prefix → required scope
_SCOPE_MAP: tuple[tuple[str, str], ...] = (
    ("/v1/guard", "guard"),
    ("/v1/scans", "mcp"),
    ("/v1/agents", "agents"),
    ("/v1/monitor", "monitor"),
    ("/v1/reports", "compliance"),
    ("/v1/policies", "guard"),
)


def _required_scope(path: str) -> str | None:
    """Return the scope required for the given path, or None if no scope is required."""
    for prefix, scope in _SCOPE_MAP:
        if path.startswith(prefix):
            return scope
    return None


class APIKeyAuthMiddleware(BaseHTTPMiddleware):
    """Validates X-Vindicara-Key against the unified APIKeyManager and enforces scopes."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        path = request.url.path

        if path in _PUBLIC_PATHS or path.startswith("/dashboard"):
            return await call_next(request)

        api_key = request.headers.get(API_KEY_HEADER, "")

        # Import lazily to avoid a circular import when the manager module is being initialized.
        from vindicara.dashboard.keys.manager import get_key_manager

        manager = get_key_manager()
        record = manager.validate_key(api_key)

        if record is None:
            return JSONResponse(
                status_code=401,
                content={"detail": f"Invalid API key. Provide a valid key via {API_KEY_HEADER} header."},
            )

        required = _required_scope(path)
        if required is not None and required not in record.scopes:
            return JSONResponse(
                status_code=403,
                content={"detail": f"API key missing required scope: {required}"},
            )

        request.state.api_key = api_key
        request.state.owner_id = record.user_id
        request.state.key_id = record.key_id
        return await call_next(request)
```

- [ ] **Step 5: Update create_app to seed dev keys via APIKeyManager**

In `src/vindicara/api/app.py`, replace the `key_store = APIKeyStore()` block (and the `app.state.key_store = key_store` line) with:

```python
    from vindicara.dashboard.keys.manager import get_key_manager

    key_manager = get_key_manager()
    if dev_api_keys:
        for key in dev_api_keys:
            key_manager.register_dev_key(key, owner_id="dev")
```

Remove the `APIKeyStore` import at the top of `app.py`. The `APIKeyAuthMiddleware` import stays.

- [ ] **Step 6: Run the new tests**

Run: `.venv/bin/pytest tests/integration/api/test_public_api_scope.py -v`
Expected: all 4 PASS.

- [ ] **Step 7: Run full suite**

Run: `.venv/bin/pytest -q`
Expected: all pass.

Note: if any existing integration test creates a key via the old `APIKeyStore` API (e.g. `app.state.key_store.register_key(...)`), it will fail. Search for and update: `.venv/bin/pytest -q -k "not integration" || true; grep -rn "app.state.key_store" src tests`. Replace any such calls with `get_key_manager().register_dev_key(...)`.

- [ ] **Step 8: Commit**

```bash
git add src/vindicara/api/middleware/auth.py src/vindicara/api/app.py src/vindicara/dashboard/keys/manager.py tests/integration/api/test_public_api_scope.py
git commit -m "feat(auth): unify API key stores and enforce scopes on public API"
```

---

## Task 10: MFA Setup Page + Disable Endpoint

**Rationale:** `/dashboard/settings/mfa` has no page today. Add a settings page that renders current MFA status, offers enable (reusing existing `/api/auth/mfa/setup` endpoint), and provides a disable endpoint that requires the current TOTP code.

**Files:**
- Create: `src/vindicara/dashboard/templates/pages/mfa_setup.html`
- Modify: `src/vindicara/dashboard/routes.py`
- Modify: `src/vindicara/dashboard/auth/api.py`
- Test: `tests/integration/dashboard/test_mfa_setup_page.py` (create)

- [ ] **Step 1: Write failing test**

Create `tests/integration/dashboard/test_mfa_setup_page.py`:

```python
"""Tests for the MFA setup page and disable endpoint."""

import pyotp
import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient


@pytest.mark.asyncio
async def test_mfa_setup_page_renders_for_authed_user(app: FastAPI, authed_cookies: dict[str, str]) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", cookies=authed_cookies) as client:
        resp = await client.get("/dashboard/settings/mfa")
    assert resp.status_code == 200
    assert "Two-Factor" in resp.text or "MFA" in resp.text


@pytest.mark.asyncio
async def test_mfa_setup_page_redirects_unauthed(app: FastAPI) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", follow_redirects=False) as client:
        resp = await client.get("/dashboard/settings/mfa")
    assert resp.status_code == 302
    assert "/dashboard/login" in resp.headers["location"]


@pytest.mark.asyncio
async def test_mfa_disable_requires_current_totp(app: FastAPI, authed_cookies: dict[str, str]) -> None:
    from vindicara.dashboard.auth.store import get_user_store

    store = get_user_store()
    # Find the user created by the fixture via email in cookie JWT
    from vindicara.dashboard.auth.tokens import decode_token

    payload = decode_token(authed_cookies["vnd_access"])
    user_id = payload["sub"]

    user = store.get_by_id(user_id)
    assert user is not None
    secret = pyotp.random_base32()
    store.update_user(user.model_copy(update={"mfa_secret": secret, "mfa_enabled": True}))

    csrf = authed_cookies["vnd_csrf"]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", cookies=authed_cookies) as client:
        # Wrong code fails
        resp = await client.post(
            "/dashboard/api/auth/mfa/disable",
            data={"code": "000000"},
            headers={"X-CSRF-Token": csrf},
        )
        assert resp.status_code == 200
        assert "Invalid" in resp.text

        # Correct code succeeds
        correct = pyotp.TOTP(secret).now()
        resp = await client.post(
            "/dashboard/api/auth/mfa/disable",
            data={"code": correct},
            headers={"X-CSRF-Token": csrf},
        )
        assert resp.status_code == 200
        assert "disabled" in resp.text.lower()

    refreshed = store.get_by_id(user_id)
    assert refreshed is not None
    assert refreshed.mfa_enabled is False
```

- [ ] **Step 2: Run tests, expect failure**

Run: `.venv/bin/pytest tests/integration/dashboard/test_mfa_setup_page.py -v`
Expected: FAIL (route and endpoint do not exist).

- [ ] **Step 3: Create MFA setup template**

Create `src/vindicara/dashboard/templates/pages/mfa_setup.html`:

```html
{% extends "base.html" %}
{% block title %}Two-Factor Authentication - Vindicara{% endblock %}
{% block content %}
<div style="margin-bottom:24px;">
  <h1 style="font-size:20px;font-weight:600;color:#EFEFEF;">Two-Factor Authentication</h1>
  <p style="color:#9090A8;font-size:13px;margin-top:4px;">Protect your account with a TOTP authenticator app</p>
</div>

<div class="card" style="padding:16px;max-width:560px;">
  <div style="font-size:13px;font-weight:600;color:#EFEFEF;margin-bottom:12px;">Status</div>
  {% if user.mfa_enabled %}
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:16px;">
      <span class="dot-active"></span>
      <span style="color:#4ADE80;font-weight:600;">Enabled</span>
    </div>
    <form hx-post="/dashboard/api/auth/mfa/disable" hx-target="#mfa-result" hx-swap="innerHTML" hx-headers='{"X-CSRF-Token": "{{ csrf_token }}"}'>
      <label style="font-size:11px;color:#444458;display:block;margin-bottom:4px;">CURRENT TOTP CODE</label>
      <div style="display:flex;gap:8px;">
        <input type="text" name="code" placeholder="000000" required style="width:140px;">
        <button type="submit" class="btn-outline" style="border-color:#E63946;color:#E63946;">Disable MFA</button>
      </div>
    </form>
  {% else %}
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:16px;">
      <span class="dot-idle"></span>
      <span style="color:#9090A8;">Not enabled</span>
    </div>
    <button hx-post="/dashboard/api/auth/mfa/setup" hx-target="#mfa-result" hx-swap="innerHTML" hx-headers='{"X-CSRF-Token": "{{ csrf_token }}"}' class="btn-red">Enable MFA</button>
  {% endif %}
  <div id="mfa-result" style="margin-top:16px;"></div>
</div>
{% endblock %}
```

- [ ] **Step 4: Add the MFA settings route**

In `src/vindicara/dashboard/routes.py`, add a new route after the existing `api_keys_page`:

```python
@router.get("/settings/mfa", response_class=HTMLResponse)
async def mfa_setup_page(request: Request) -> HTMLResponse:
    from vindicara.dashboard.auth.store import get_user_store

    user_id = getattr(request.state, "user_id", "")
    store = get_user_store()
    user = store.get_by_id(user_id)
    csrf_token = request.cookies.get("vnd_csrf", "")
    return templates.TemplateResponse(
        name="pages/mfa_setup.html",
        request=request,
        context={"active_page": "mfa", "user": user, "csrf_token": csrf_token},
    )
```

- [ ] **Step 5: Add the MFA disable endpoint**

In `src/vindicara/dashboard/auth/api.py`, add after the existing `mfa_verify` endpoint:

```python
@router.post("/mfa/disable")
async def mfa_disable(request: Request, code: str = Form(...)) -> HTMLResponse:
    store = get_user_store()
    user_id = getattr(request.state, "user_id", "")
    user = store.get_by_id(user_id)
    if not user or not user.mfa_enabled:
        return HTMLResponse('<div style="color:#E63946;">MFA is not enabled</div>')

    if not verify_totp(user.mfa_secret, code):
        return HTMLResponse('<div style="color:#E63946;padding:8px;">Invalid code</div>')

    store.update_user(user.model_copy(update={"mfa_enabled": False, "mfa_secret": ""}))
    logger.info("auth.mfa.disabled", user_id=user_id)
    return HTMLResponse('<div style="color:#4ADE80;padding:8px;">Two-factor authentication disabled</div>')
```

- [ ] **Step 6: Run tests**

Run: `.venv/bin/pytest tests/integration/dashboard/test_mfa_setup_page.py -v`
Expected: all 3 PASS.

- [ ] **Step 7: Run full suite**

Run: `.venv/bin/pytest -q`
Expected: all pass.

- [ ] **Step 8: Commit**

```bash
git add src/vindicara/dashboard/templates/pages/mfa_setup.html src/vindicara/dashboard/routes.py src/vindicara/dashboard/auth/api.py tests/integration/dashboard/test_mfa_setup_page.py
git commit -m "feat(auth): add MFA settings page and disable endpoint"
```

---

## Task 11: DynamoDB Backend for UserStoreBackend

**Rationale:** Production requires persistent user/session/verification storage shared across Lambda invocations. Implement `DynamoUserBackend` against the `vindicara-users` table (Task 13 creates the table in CDK; this task is pure application code + moto tests).

**Files:**
- Modify: `src/vindicara/dashboard/auth/backends.py`
- Modify: `src/vindicara/dashboard/auth/store.py`
- Modify: `pyproject.toml`
- Test: `tests/unit/dashboard/auth/test_backends_dynamo.py` (create)

- [ ] **Step 1: Add moto dev dependency**

In `pyproject.toml`, under `[project.optional-dependencies].dev`, add:

```toml
    "moto[dynamodb]>=5.0.0,<6.0",
```

Then install:

```bash
.venv/bin/pip install -e ".[api,dev]"
```

- [ ] **Step 2: Write failing test for DynamoUserBackend**

Create `tests/unit/dashboard/auth/test_backends_dynamo.py`:

```python
"""Integration tests for DynamoUserBackend using moto."""

from datetime import UTC, datetime, timedelta

import boto3
import pytest
from moto import mock_aws

from vindicara.dashboard.auth.backends import DynamoUserBackend
from vindicara.dashboard.auth.models import Session, User, VerificationToken

TABLE_NAME = "vindicara-users-test"


@pytest.fixture
def ddb_backend():  # type: ignore[no-untyped-def]
    with mock_aws():
        client = boto3.client("dynamodb", region_name="us-east-1")
        client.create_table(
            TableName=TABLE_NAME,
            KeySchema=[
                {"AttributeName": "PK", "KeyType": "HASH"},
                {"AttributeName": "SK", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "PK", "AttributeType": "S"},
                {"AttributeName": "SK", "AttributeType": "S"},
                {"AttributeName": "GSI1PK", "AttributeType": "S"},
                {"AttributeName": "GSI1SK", "AttributeType": "S"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "GSI1",
                    "KeySchema": [
                        {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                        {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        yield DynamoUserBackend(table_name=TABLE_NAME)


def test_put_and_get_user_by_id(ddb_backend: DynamoUserBackend) -> None:
    user = User(user_id="u1", email="alice@example.com", password_hash="hash", created_at=datetime.now(UTC).isoformat(), verified=False)
    ddb_backend.put_user(user)
    result = ddb_backend.get_user_by_id("u1")
    assert result is not None
    assert result.email == "alice@example.com"


def test_get_user_by_email_uses_gsi1(ddb_backend: DynamoUserBackend) -> None:
    user = User(user_id="u1", email="alice@example.com", password_hash="hash", created_at=datetime.now(UTC).isoformat(), verified=False)
    ddb_backend.put_user(user)
    result = ddb_backend.get_user_by_email("alice@example.com")
    assert result is not None
    assert result.user_id == "u1"


def test_get_user_by_email_case_insensitive(ddb_backend: DynamoUserBackend) -> None:
    user = User(user_id="u1", email="alice@example.com", password_hash="hash", created_at=datetime.now(UTC).isoformat(), verified=False)
    ddb_backend.put_user(user)
    assert ddb_backend.get_user_by_email("ALICE@example.com") is not None


def test_put_and_get_session(ddb_backend: DynamoUserBackend) -> None:
    session = Session(
        session_id="s1",
        user_id="u1",
        created_at=datetime.now(UTC).isoformat(),
        expires_at=(datetime.now(UTC) + timedelta(days=7)).isoformat(),
    )
    ddb_backend.put_session(session)
    result = ddb_backend.get_session("s1")
    assert result is not None
    assert result.user_id == "u1"


def test_verification_token_round_trip(ddb_backend: DynamoUserBackend) -> None:
    record = VerificationToken(
        token="tok123",
        user_id="u1",
        expires_at=(datetime.now(UTC) + timedelta(hours=24)).isoformat(),
    )
    ddb_backend.put_verification_token(record)
    assert ddb_backend.consume_verification_token("tok123") == "u1"
    # Single-use: second consume returns None
    assert ddb_backend.consume_verification_token("tok123") is None


def test_expired_verification_token_returns_none(ddb_backend: DynamoUserBackend) -> None:
    record = VerificationToken(
        token="expired",
        user_id="u1",
        expires_at=(datetime.now(UTC) - timedelta(hours=1)).isoformat(),
    )
    ddb_backend.put_verification_token(record)
    assert ddb_backend.consume_verification_token("expired") is None
```

- [ ] **Step 3: Run test, expect failure**

Run: `.venv/bin/pytest tests/unit/dashboard/auth/test_backends_dynamo.py -v`
Expected: FAIL (`DynamoUserBackend` does not exist).

- [ ] **Step 4: Add DynamoUserBackend implementation**

Append to `src/vindicara/dashboard/auth/backends.py`:

```python
class DynamoUserBackend:
    """DynamoDB-backed user store. Single-table design on vindicara-users."""

    def __init__(self, table_name: str) -> None:
        import boto3

        self._table = boto3.resource("dynamodb").Table(table_name)

    def put_user(self, user: User) -> None:
        item = user.model_dump()
        item.update(
            {
                "PK": f"USER#{user.user_id}",
                "SK": "PROFILE",
                "GSI1PK": f"EMAIL#{user.email.lower()}",
                "GSI1SK": f"USER#{user.user_id}",
            }
        )
        self._table.put_item(Item=item)

    def get_user_by_id(self, user_id: str) -> User | None:
        resp = self._table.get_item(Key={"PK": f"USER#{user_id}", "SK": "PROFILE"})
        item = resp.get("Item")
        if item is None:
            return None
        return _item_to_user(item)

    def get_user_by_email(self, email: str) -> User | None:
        from boto3.dynamodb.conditions import Key

        resp = self._table.query(
            IndexName="GSI1",
            KeyConditionExpression=Key("GSI1PK").eq(f"EMAIL#{email.lower()}"),
        )
        for item in resp.get("Items", []):
            if item.get("SK") == "PROFILE":
                return _item_to_user(item)
        return None

    def put_session(self, session: Session) -> None:
        from datetime import UTC, datetime

        expires_unix = int(datetime.fromisoformat(session.expires_at).timestamp())
        item = session.model_dump()
        item.update(
            {
                "PK": f"USER#{session.user_id}",
                "SK": f"SESSION#{session.session_id}",
                "ttl": expires_unix,
                "session_lookup_pk": f"SESSION#{session.session_id}",
            }
        )
        self._table.put_item(Item=item)
        # Also write a lookup record so get_session by id works without knowing user_id
        self._table.put_item(
            Item={
                "PK": f"SESSION#{session.session_id}",
                "SK": "INDEX",
                "user_id": session.user_id,
                "session_id": session.session_id,
                "ttl": expires_unix,
            }
        )

    def get_session(self, session_id: str) -> Session | None:
        lookup = self._table.get_item(Key={"PK": f"SESSION#{session_id}", "SK": "INDEX"}).get("Item")
        if lookup is None:
            return None
        user_id = lookup["user_id"]
        resp = self._table.get_item(Key={"PK": f"USER#{user_id}", "SK": f"SESSION#{session_id}"})
        item = resp.get("Item")
        if item is None:
            return None
        return _item_to_session(item)

    def put_verification_token(self, record: VerificationToken) -> None:
        from datetime import datetime

        expires_unix = int(datetime.fromisoformat(record.expires_at).timestamp())
        self._table.put_item(
            Item={
                "PK": f"USER#{record.user_id}",
                "SK": f"VERIFY#{record.token}",
                "token_lookup_pk": f"VERIFY#{record.token}",
                "user_id": record.user_id,
                "expires_at": record.expires_at,
                "ttl": expires_unix,
            }
        )
        self._table.put_item(
            Item={
                "PK": f"VERIFY#{record.token}",
                "SK": "INDEX",
                "user_id": record.user_id,
                "expires_at": record.expires_at,
                "ttl": expires_unix,
            }
        )

    def consume_verification_token(self, token: str) -> str | None:
        from datetime import UTC, datetime

        lookup = self._table.get_item(Key={"PK": f"VERIFY#{token}", "SK": "INDEX"}).get("Item")
        if lookup is None:
            return None
        if datetime.now(UTC) > datetime.fromisoformat(str(lookup["expires_at"])):
            return None
        user_id = str(lookup["user_id"])
        # Single-use: delete both records
        self._table.delete_item(Key={"PK": f"VERIFY#{token}", "SK": "INDEX"})
        self._table.delete_item(Key={"PK": f"USER#{user_id}", "SK": f"VERIFY#{token}"})
        return user_id


def _item_to_user(item: dict[str, object]) -> User:
    return User(**{k: v for k, v in item.items() if k in User.model_fields})


def _item_to_session(item: dict[str, object]) -> Session:
    return Session(**{k: v for k, v in item.items() if k in Session.model_fields})
```

- [ ] **Step 5: Update get_user_store factory to pick DynamoBackend in production**

In `src/vindicara/dashboard/auth/store.py`, replace the `get_user_store` function with:

```python
def get_user_store() -> UserStore:
    """Return the singleton user store. In-memory in dev/test, DynamoDB in prod."""
    global _store
    if _store is None:
        from vindicara.config.settings import VindicaraSettings
        from vindicara.dashboard.auth.backends import DynamoUserBackend, InMemoryUserBackend

        settings = VindicaraSettings()
        if settings.users_table and settings.stage == "prod":
            _store = UserStore(backend=DynamoUserBackend(table_name=settings.users_table))
        else:
            _store = UserStore(backend=InMemoryUserBackend())
    return _store
```

Remove the now-unused `InMemoryUserBackend` import from the top of `store.py` (keep only in the factory).

Actually, fix: keep the top import so existing usage in tests still works. Don't delete it.

- [ ] **Step 6: Run tests**

Run: `.venv/bin/pytest tests/unit/dashboard/auth/test_backends_dynamo.py -v`
Expected: 6 PASS.

- [ ] **Step 7: Run full suite**

Run: `.venv/bin/pytest -q`
Expected: all pass (in-memory backend is still used in tests because `stage=test`).

- [ ] **Step 8: Commit**

```bash
git add src/vindicara/dashboard/auth/backends.py src/vindicara/dashboard/auth/store.py pyproject.toml tests/unit/dashboard/auth/test_backends_dynamo.py
git commit -m "feat(auth): DynamoDB backend for UserStoreBackend"
```

---

## Task 12: DynamoDB Backend for APIKeyManager

**Rationale:** Same reason as Task 11. Unify key storage across Lambda invocations by giving `APIKeyManager` a pluggable backend that reads from the same `vindicara-users` table (KEY# SK + GSI2 for hash lookup).

**Files:**
- Create: `src/vindicara/dashboard/keys/backends.py`
- Modify: `src/vindicara/dashboard/keys/manager.py`
- Test: `tests/unit/dashboard/keys/test_backends_dynamo.py` (create)

- [ ] **Step 1: Write failing test**

Create `tests/unit/dashboard/keys/test_backends_dynamo.py`:

```python
"""DynamoDB backend tests for APIKeyManager."""

import boto3
import pytest
from moto import mock_aws

from vindicara.dashboard.keys.backends import DynamoKeyBackend
from vindicara.dashboard.keys.manager import APIKeyManager, APIKeyRecord

TABLE_NAME = "vindicara-users-test"


@pytest.fixture
def manager():  # type: ignore[no-untyped-def]
    with mock_aws():
        client = boto3.client("dynamodb", region_name="us-east-1")
        client.create_table(
            TableName=TABLE_NAME,
            KeySchema=[
                {"AttributeName": "PK", "KeyType": "HASH"},
                {"AttributeName": "SK", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "PK", "AttributeType": "S"},
                {"AttributeName": "SK", "AttributeType": "S"},
                {"AttributeName": "GSI2PK", "AttributeType": "S"},
                {"AttributeName": "GSI2SK", "AttributeType": "S"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "GSI2",
                    "KeySchema": [
                        {"AttributeName": "GSI2PK", "KeyType": "HASH"},
                        {"AttributeName": "GSI2SK", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        yield APIKeyManager(backend=DynamoKeyBackend(table_name=TABLE_NAME))


def test_create_and_validate_roundtrip(manager: APIKeyManager) -> None:
    raw, record = manager.create_key(user_id="u1", name="test", scopes=["guard"])
    result = manager.validate_key(raw)
    assert result is not None
    assert result.key_id == record.key_id


def test_list_keys_returns_active_only(manager: APIKeyManager) -> None:
    _, k1 = manager.create_key(user_id="u1", name="keep")
    _, k2 = manager.create_key(user_id="u1", name="gone")
    manager.revoke_key(k2.key_id, "u1")
    ids = {k.key_id for k in manager.list_keys("u1")}
    assert k1.key_id in ids
    assert k2.key_id not in ids


def test_revoke_invalidates_key(manager: APIKeyManager) -> None:
    raw, record = manager.create_key(user_id="u1", name="test")
    manager.revoke_key(record.key_id, "u1")
    assert manager.validate_key(raw) is None
```

- [ ] **Step 2: Run test, expect failure**

Run: `.venv/bin/pytest tests/unit/dashboard/keys/test_backends_dynamo.py -v`
Expected: FAIL (`DynamoKeyBackend` does not exist, `APIKeyManager` does not accept a `backend` parameter).

- [ ] **Step 3: Create backends.py for keys**

Create `src/vindicara/dashboard/keys/backends.py`:

```python
"""Pluggable persistence backends for APIKeyManager."""

from typing import Protocol

from vindicara.dashboard.keys.manager import APIKeyRecord


class KeyStoreBackend(Protocol):
    def put_key(self, record: APIKeyRecord) -> None: ...
    def get_key_by_id(self, key_id: str) -> APIKeyRecord | None: ...
    def get_key_by_hash(self, key_hash: str) -> APIKeyRecord | None: ...
    def list_keys_by_user(self, user_id: str) -> list[APIKeyRecord]: ...
    def delete_key_hash(self, key_hash: str) -> None: ...


class InMemoryKeyBackend:
    def __init__(self) -> None:
        self._keys: dict[str, APIKeyRecord] = {}
        self._hash_index: dict[str, str] = {}

    def put_key(self, record: APIKeyRecord) -> None:
        self._keys[record.key_id] = record
        if not record.revoked:
            self._hash_index[record.key_hash] = record.key_id

    def get_key_by_id(self, key_id: str) -> APIKeyRecord | None:
        return self._keys.get(key_id)

    def get_key_by_hash(self, key_hash: str) -> APIKeyRecord | None:
        key_id = self._hash_index.get(key_hash)
        if key_id is None:
            return None
        return self._keys.get(key_id)

    def list_keys_by_user(self, user_id: str) -> list[APIKeyRecord]:
        return [k for k in self._keys.values() if k.user_id == user_id and not k.revoked]

    def delete_key_hash(self, key_hash: str) -> None:
        self._hash_index.pop(key_hash, None)


class DynamoKeyBackend:
    def __init__(self, table_name: str) -> None:
        import boto3

        self._table = boto3.resource("dynamodb").Table(table_name)

    def put_key(self, record: APIKeyRecord) -> None:
        item = record.model_dump()
        item.update(
            {
                "PK": f"USER#{record.user_id}",
                "SK": f"KEY#{record.key_id}",
                "GSI2PK": f"APIKEY#{record.key_hash}",
                "GSI2SK": f"USER#{record.user_id}",
            }
        )
        self._table.put_item(Item=item)

    def get_key_by_id(self, key_id: str) -> APIKeyRecord | None:
        from boto3.dynamodb.conditions import Key

        # Scan by SK suffix — no direct lookup without user_id. Fall through to GSI2 where possible.
        resp = self._table.scan(
            FilterExpression=Key("SK").eq(f"KEY#{key_id}"),
        )
        items = resp.get("Items", [])
        if not items:
            return None
        return _item_to_record(items[0])

    def get_key_by_hash(self, key_hash: str) -> APIKeyRecord | None:
        from boto3.dynamodb.conditions import Key

        resp = self._table.query(
            IndexName="GSI2",
            KeyConditionExpression=Key("GSI2PK").eq(f"APIKEY#{key_hash}"),
        )
        for item in resp.get("Items", []):
            record = _item_to_record(item)
            if not record.revoked:
                return record
        return None

    def list_keys_by_user(self, user_id: str) -> list[APIKeyRecord]:
        from boto3.dynamodb.conditions import Key

        resp = self._table.query(
            KeyConditionExpression=Key("PK").eq(f"USER#{user_id}") & Key("SK").begins_with("KEY#"),
        )
        return [_item_to_record(i) for i in resp.get("Items", []) if not i.get("revoked", False)]

    def delete_key_hash(self, key_hash: str) -> None:
        # No-op for DynamoDB: revoked flag on the record is enough. GSI2 still has the record.
        pass


def _item_to_record(item: dict[str, object]) -> APIKeyRecord:
    return APIKeyRecord(**{k: v for k, v in item.items() if k in APIKeyRecord.model_fields})
```

- [ ] **Step 4: Refactor APIKeyManager to use backend**

In `src/vindicara/dashboard/keys/manager.py`, replace the `APIKeyManager` class with:

```python
class APIKeyManager:
    """API key orchestration over a pluggable backend."""

    def __init__(self, backend: "KeyStoreBackend | None" = None) -> None:
        if backend is None:
            from vindicara.dashboard.keys.backends import InMemoryKeyBackend

            backend = InMemoryKeyBackend()
        self._backend = backend

    # Exposed for test shortcuts
    @property
    def _keys(self) -> "dict[str, APIKeyRecord]":  # type: ignore[override]
        from vindicara.dashboard.keys.backends import InMemoryKeyBackend

        if isinstance(self._backend, InMemoryKeyBackend):
            return self._backend._keys
        return {}

    @property
    def _hash_index(self) -> "dict[str, str]":
        from vindicara.dashboard.keys.backends import InMemoryKeyBackend

        if isinstance(self._backend, InMemoryKeyBackend):
            return self._backend._hash_index
        return {}

    def create_key(
        self,
        user_id: str,
        name: str,
        scopes: list[str] | None = None,
    ) -> tuple[str, APIKeyRecord]:
        raw_key = f"vnd_live_{secrets.token_hex(32)}"
        key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
        key_id = f"key_{secrets.token_hex(8)}"
        validated_scopes = [s for s in (scopes or []) if s in VALID_SCOPES]

        record = APIKeyRecord(
            key_id=key_id,
            user_id=user_id,
            name=name,
            key_hash=key_hash,
            key_prefix=raw_key[:12] + "..." + raw_key[-4:],
            scopes=validated_scopes if validated_scopes else list(VALID_SCOPES),
            created_at=datetime.now(UTC).isoformat(),
        )
        self._backend.put_key(record)
        logger.info("keys.created", key_id=key_id, user_id=user_id, name=name)
        return raw_key, record

    def register_dev_key(self, raw_key: str, owner_id: str = "dev") -> APIKeyRecord:
        key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
        key_id = f"devkey_{secrets.token_hex(4)}"
        record = APIKeyRecord(
            key_id=key_id,
            user_id=owner_id,
            name=f"dev-{owner_id}",
            key_hash=key_hash,
            key_prefix=raw_key[:12] + "..." + raw_key[-4:] if len(raw_key) > 16 else raw_key,
            scopes=list(VALID_SCOPES),
            created_at=datetime.now(UTC).isoformat(),
        )
        self._backend.put_key(record)
        logger.info("keys.dev_registered", owner_id=owner_id)
        return record

    def list_keys(self, user_id: str) -> list[APIKeyRecord]:
        return self._backend.list_keys_by_user(user_id)

    def revoke_key(self, key_id: str, user_id: str) -> bool:
        record = self._backend.get_key_by_id(key_id)
        if record is None or record.user_id != user_id:
            return False
        self._backend.put_key(record.model_copy(update={"revoked": True}))
        self._backend.delete_key_hash(record.key_hash)
        logger.info("keys.revoked", key_id=key_id)
        return True

    def rotate_key(self, key_id: str, user_id: str) -> tuple[str, APIKeyRecord] | None:
        old = self._backend.get_key_by_id(key_id)
        if old is None or old.user_id != user_id or old.revoked:
            return None

        grace = (datetime.now(UTC) + timedelta(hours=GRACE_PERIOD_HOURS)).isoformat()
        self._backend.put_key(old.model_copy(update={"grace_expires": grace}))

        raw_key, new_record = self.create_key(user_id, old.name, old.scopes)
        self._backend.put_key(new_record.model_copy(update={"rotated_from": key_id}))
        logger.info("keys.rotated", old_key_id=key_id, new_key_id=new_record.key_id)
        return raw_key, new_record

    def validate_key(self, raw_key: str) -> APIKeyRecord | None:
        key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
        record = self._backend.get_key_by_hash(key_hash)
        if record is None or record.revoked:
            return None
        if record.grace_expires:
            try:
                deadline = datetime.fromisoformat(record.grace_expires)
            except ValueError:
                return None
            if datetime.now(UTC) > deadline:
                return None
        return record


_manager: APIKeyManager | None = None


def get_key_manager() -> APIKeyManager:
    """Return the singleton manager. DynamoDB in prod, in-memory otherwise."""
    global _manager
    if _manager is None:
        from vindicara.config.settings import VindicaraSettings
        from vindicara.dashboard.keys.backends import DynamoKeyBackend, InMemoryKeyBackend

        settings = VindicaraSettings()
        if settings.users_table and settings.stage == "prod":
            _manager = APIKeyManager(backend=DynamoKeyBackend(table_name=settings.users_table))
        else:
            _manager = APIKeyManager(backend=InMemoryKeyBackend())
    return _manager


def _reset_manager_for_tests() -> None:
    global _manager
    _manager = None
```

Note: the `_keys` / `_hash_index` properties at the top of the class preserve backward compatibility for tests that access these directly (Task 8 tests did so).

- [ ] **Step 5: Run tests**

Run: `.venv/bin/pytest tests/unit/dashboard/keys/ -v`
Expected: all PASS (manager tests from Task 8 still work against `InMemoryKeyBackend`, new DDB tests pass).

- [ ] **Step 6: Run full suite**

Run: `.venv/bin/pytest -q`
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add src/vindicara/dashboard/keys/backends.py src/vindicara/dashboard/keys/manager.py tests/unit/dashboard/keys/test_backends_dynamo.py
git commit -m "feat(keys): DynamoDB backend for APIKeyManager"
```

---

## Task 13: CDK Resources for Users Table + Env Vars

**Rationale:** Create the `vindicara-users` DynamoDB table in CDK with the single-table schema (GSI1, GSI2, TTL), grant Lambda read/write, and inject `VINDICARA_USERS_TABLE`, `VINDICARA_JWT_SECRET`, `VINDICARA_VERIFY_BASE_URL`, and `VINDICARA_STAGE=prod` as Lambda environment variables.

**Files:**
- Modify: `src/vindicara/infra/stacks/data_stack.py`
- Modify: `src/vindicara/infra/stacks/api_stack.py`
- Modify: `src/vindicara/infra/app.py`

- [ ] **Step 1: Read the current DataStack to see how existing tables are declared**

Run: `.venv/bin/python -c "from pathlib import Path; print(Path('src/vindicara/infra/stacks/data_stack.py').read_text())"`

Note the existing pattern (imports, table construction, GSI addition). Match it.

- [ ] **Step 2: Add the users table**

In `src/vindicara/infra/stacks/data_stack.py`, after the existing table declarations in `DataStack.__init__`, add:

```python
        self.users_table = dynamodb.Table(
            self,
            "UsersTable",
            table_name="vindicara-users",
            partition_key=dynamodb.Attribute(name="PK", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="SK", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            time_to_live_attribute="ttl",
            removal_policy=cdk.RemovalPolicy.RETAIN,
            point_in_time_recovery=True,
        )
        self.users_table.add_global_secondary_index(
            index_name="GSI1",
            partition_key=dynamodb.Attribute(name="GSI1PK", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="GSI1SK", type=dynamodb.AttributeType.STRING),
        )
        self.users_table.add_global_secondary_index(
            index_name="GSI2",
            partition_key=dynamodb.Attribute(name="GSI2PK", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="GSI2SK", type=dynamodb.AttributeType.STRING),
        )
```

Ensure `dynamodb` and `cdk` imports are present at the top of `data_stack.py` (they should be; existing tables use them).

- [ ] **Step 3: Thread users_table through infra/app.py**

In `src/vindicara/infra/app.py`, update the `APIStack` constructor call to pass the users table:

```python
APIStack(
    app,
    "VindicaraAPI",
    policies_table=data.policies_table,
    evaluations_table=data.evaluations_table,
    api_keys_table=data.api_keys_table,
    users_table=data.users_table,
    audit_bucket=data.audit_bucket,
    event_bus=events_stack.event_bus,
    env=env,
)
```

- [ ] **Step 4: Update APIStack to accept and use users_table**

In `src/vindicara/infra/stacks/api_stack.py`:

1. Add `users_table: dynamodb.Table` to the `__init__` signature.
2. Add `users_table.grant_read_write_data(self.api_fn)` where the other grants are.
3. Add these environment variables on the Lambda function (match the existing `add_environment` calls):

```python
        self.api_fn.add_environment("VINDICARA_USERS_TABLE", users_table.table_name)
        self.api_fn.add_environment("VINDICARA_STAGE", "prod")
        self.api_fn.add_environment("VINDICARA_VERIFY_BASE_URL", "https://api.vindicara.io")
```

4. Add the JWT secret injection. At the top of `api_stack.py`, add:

```python
from aws_cdk import aws_secretsmanager as secretsmanager
```

In `__init__`, after the Lambda function is constructed:

```python
        jwt_secret = secretsmanager.Secret.from_secret_name_v2(
            self, "VindicaraJwtSecret", "vindicara/jwt-secret",
        )
        self.api_fn.add_environment(
            "VINDICARA_JWT_SECRET",
            jwt_secret.secret_value.unsafe_unwrap(),
        )
```

Note: `unsafe_unwrap()` embeds the secret value in the CloudFormation template. This is acceptable because the CFN template lives in the same AWS account. Upgrade path (documented, not implemented): have Lambda fetch via `boto3.client("secretsmanager")` on cold start. Add a comment in the code:

```python
        # Note: unsafe_unwrap embeds the secret in CFN. For higher-assurance deployments,
        # switch to fetching via boto3 on Lambda cold start.
```

- [ ] **Step 5: Verify CDK synthesis**

Run: `cdk synth VindicaraData VindicaraAPI 2>&1 | tail -60`

Expected: no errors. The synthesized template should include `vindicara-users` with `GSI1` and `GSI2`, and the Lambda function should have the new env vars.

Note: you must first create the JWT secret out of band. Run once:

```bash
aws secretsmanager create-secret \
  --name "vindicara/jwt-secret" \
  --secret-string "$(openssl rand -hex 32)" \
  --region us-east-1
```

Document this in a comment at the top of `api_stack.py`:

```python
"""API Stack.

One-time prerequisite: create the JWT signing secret in Secrets Manager:

    aws secretsmanager create-secret \\
        --name vindicara/jwt-secret \\
        --secret-string "$(openssl rand -hex 32)" \\
        --region us-east-1
"""
```

- [ ] **Step 6: Run the full test suite**

Run: `.venv/bin/pytest -q`
Expected: all pass. CDK changes don't affect runtime tests because tests use in-memory backends.

- [ ] **Step 7: Commit**

```bash
git add src/vindicara/infra/stacks/data_stack.py src/vindicara/infra/stacks/api_stack.py src/vindicara/infra/app.py
git commit -m "feat(infra): add vindicara-users table and auth env vars"
```

---

## Task 14: Retroactive Unit Tests for Existing Auth Code

**Rationale:** Passwords, MFA, and basic key manager behavior are exercised only indirectly through integration tests today. Add dedicated unit tests for each module so a regression shows up at the unit layer first.

**Files:**
- Create: `tests/unit/dashboard/auth/test_passwords.py`
- Create: `tests/unit/dashboard/auth/test_mfa.py`

- [ ] **Step 1: Write passwords unit tests**

Create `tests/unit/dashboard/auth/test_passwords.py`:

```python
"""Unit tests for password hashing and complexity validation."""

import pytest

from vindicara.dashboard.auth.passwords import (
    MIN_PASSWORD_LENGTH,
    hash_password,
    validate_password,
    verify_password,
)


def test_hash_password_produces_bcrypt_string() -> None:
    result = hash_password("StrongPass123")
    assert result.startswith("$2")


def test_hash_is_unique_per_call() -> None:
    a = hash_password("StrongPass123")
    b = hash_password("StrongPass123")
    assert a != b


def test_verify_password_returns_true_for_correct() -> None:
    h = hash_password("StrongPass123")
    assert verify_password("StrongPass123", h) is True


def test_verify_password_returns_false_for_wrong() -> None:
    h = hash_password("StrongPass123")
    assert verify_password("WrongPass456", h) is False


def test_valid_password_passes_all_rules() -> None:
    result = validate_password("StrongPass123")
    assert result.valid is True
    assert result.errors == []


def test_short_password_reports_length_error() -> None:
    result = validate_password("Short1")
    assert result.valid is False
    assert any("characters" in e for e in result.errors)


def test_missing_upper_reports_error() -> None:
    result = validate_password("alllowercase123")
    assert result.valid is False
    assert any("uppercase" in e for e in result.errors)


def test_missing_lower_reports_error() -> None:
    result = validate_password("ALLUPPERCASE123")
    assert result.valid is False
    assert any("lowercase" in e for e in result.errors)


def test_missing_digit_reports_error() -> None:
    result = validate_password("NoDigitsPassword")
    assert result.valid is False
    assert any("digit" in e for e in result.errors)


def test_min_length_constant_is_12() -> None:
    assert MIN_PASSWORD_LENGTH == 12
```

- [ ] **Step 2: Write MFA unit tests**

Create `tests/unit/dashboard/auth/test_mfa.py`:

```python
"""Unit tests for TOTP MFA helpers."""

import base64

import pyotp

from vindicara.dashboard.auth.mfa import (
    generate_qr_base64,
    generate_secret,
    get_provisioning_uri,
    verify_totp,
)


def test_generate_secret_returns_base32() -> None:
    secret = generate_secret()
    # pyotp returns a 32-char base32 string by default
    assert len(secret) >= 16
    # Base32 alphabet check
    import string

    assert all(c in string.ascii_uppercase + "234567" for c in secret)


def test_provisioning_uri_includes_issuer() -> None:
    secret = generate_secret()
    uri = get_provisioning_uri(secret, "alice@example.com")
    assert "Vindicara" in uri
    assert "alice@example.com" in uri


def test_qr_base64_is_valid_base64() -> None:
    uri = get_provisioning_uri(generate_secret(), "alice@example.com")
    b64 = generate_qr_base64(uri)
    decoded = base64.b64decode(b64)
    # PNG header
    assert decoded[:8] == b"\x89PNG\r\n\x1a\n"


def test_verify_totp_accepts_correct_code() -> None:
    secret = generate_secret()
    code = pyotp.TOTP(secret).now()
    assert verify_totp(secret, code) is True


def test_verify_totp_rejects_wrong_code() -> None:
    secret = generate_secret()
    assert verify_totp(secret, "000000") is False


def test_verify_totp_rejects_gibberish() -> None:
    secret = generate_secret()
    assert verify_totp(secret, "not-a-code") is False
```

- [ ] **Step 3: Run tests**

Run: `.venv/bin/pytest tests/unit/dashboard/auth/test_passwords.py tests/unit/dashboard/auth/test_mfa.py -v`
Expected: all PASS.

- [ ] **Step 4: Run full suite**

Run: `.venv/bin/pytest -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add tests/unit/dashboard/auth/test_passwords.py tests/unit/dashboard/auth/test_mfa.py
git commit -m "test(auth): retroactive unit tests for passwords and MFA"
```

---

## Task 15: Integration Test Suite Completion

**Rationale:** Fill the last test-matrix gaps: an explicit keys API test exercising create/revoke/rotate over HTTP, and lockout behavior tests. Covers the edge cases not yet reached.

**Files:**
- Create: `tests/integration/dashboard/test_keys_api.py`
- Modify: `tests/integration/dashboard/test_auth_flow.py`

- [ ] **Step 1: Write keys API integration tests**

Create `tests/integration/dashboard/test_keys_api.py`:

```python
"""Integration tests for dashboard API key CRUD endpoints."""

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient


@pytest.mark.asyncio
async def test_create_key_returns_redirect_with_raw_key(app: FastAPI, authed_cookies: dict[str, str]) -> None:
    csrf = authed_cookies["vnd_csrf"]
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", cookies=authed_cookies, follow_redirects=False) as client:
        resp = await client.post(
            "/dashboard/api/keys",
            data={"name": "test-key", "scopes": "guard,mcp", "_csrf": csrf},
        )
    assert resp.status_code == 303
    assert "new_key=vnd_live_" in resp.headers["location"]


@pytest.mark.asyncio
async def test_list_keys_page_renders_created_key(app: FastAPI, authed_cookies: dict[str, str]) -> None:
    csrf = authed_cookies["vnd_csrf"]
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", cookies=authed_cookies, follow_redirects=True) as client:
        await client.post(
            "/dashboard/api/keys",
            data={"name": "listed-key", "scopes": "guard", "_csrf": csrf},
        )
        resp = await client.get("/dashboard/api-keys")
    assert resp.status_code == 200
    assert "listed-key" in resp.text


@pytest.mark.asyncio
async def test_revoke_key_removes_it_from_list(app: FastAPI, authed_cookies: dict[str, str]) -> None:
    from vindicara.dashboard.auth.tokens import decode_token
    from vindicara.dashboard.keys.manager import get_key_manager

    user_id = decode_token(authed_cookies["vnd_access"])["sub"]
    manager = get_key_manager()
    _, record = manager.create_key(user_id=user_id, name="doomed", scopes=["guard"])

    csrf = authed_cookies["vnd_csrf"]
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", cookies=authed_cookies, follow_redirects=False) as client:
        resp = await client.post(
            f"/dashboard/api/keys/{record.key_id}/revoke",
            data={"_csrf": csrf},
        )
    assert resp.status_code == 303
    assert record.key_id not in {k.key_id for k in manager.list_keys(user_id)}


@pytest.mark.asyncio
async def test_rotate_key_issues_new_key(app: FastAPI, authed_cookies: dict[str, str]) -> None:
    from vindicara.dashboard.auth.tokens import decode_token
    from vindicara.dashboard.keys.manager import get_key_manager

    user_id = decode_token(authed_cookies["vnd_access"])["sub"]
    manager = get_key_manager()
    _, original = manager.create_key(user_id=user_id, name="rotating", scopes=["guard"])

    csrf = authed_cookies["vnd_csrf"]
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", cookies=authed_cookies, follow_redirects=False) as client:
        resp = await client.post(
            f"/dashboard/api/keys/{original.key_id}/rotate",
            data={"_csrf": csrf},
        )
    assert resp.status_code == 303
    assert "new_key=vnd_live_" in resp.headers["location"]


@pytest.mark.asyncio
async def test_missing_csrf_blocks_key_creation(app: FastAPI, authed_cookies: dict[str, str]) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", cookies=authed_cookies, follow_redirects=False) as client:
        resp = await client.post(
            "/dashboard/api/keys",
            data={"name": "no-csrf", "scopes": "guard"},
        )
    assert resp.status_code == 403
```

- [ ] **Step 2: Add lockout tests to auth flow file**

Append to `tests/integration/dashboard/test_auth_flow.py`:

```python
@pytest.mark.asyncio
async def test_five_failed_logins_locks_account(app: FastAPI) -> None:
    from vindicara.dashboard.auth.store import get_user_store

    email = f"lock-{uuid.uuid4().hex[:8]}@example.com"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", follow_redirects=False) as client:
        await client.post(
            "/dashboard/api/auth/signup",
            data={"email": email, "password": TEST_PASSWORD, "confirm_password": TEST_PASSWORD},
        )
        store = get_user_store()
        user = store.get_by_email(email)
        assert user is not None
        store.mark_verified(user.user_id)

        for _ in range(5):
            await client.post(
                "/dashboard/api/auth/login",
                data={"email": email, "password": "WrongPassword123"},
            )

        # Even correct password now fails (locked)
        resp = await client.post(
            "/dashboard/api/auth/login",
            data={"email": email, "password": TEST_PASSWORD},
        )

    assert resp.status_code == 200
    assert "locked" in resp.text.lower()


@pytest.mark.asyncio
async def test_logout_revokes_session(app: FastAPI) -> None:
    from vindicara.dashboard.auth.store import get_user_store
    from vindicara.dashboard.auth.tokens import decode_token

    email = f"out-{uuid.uuid4().hex[:8]}@example.com"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", follow_redirects=False) as client:
        await client.post(
            "/dashboard/api/auth/signup",
            data={"email": email, "password": TEST_PASSWORD, "confirm_password": TEST_PASSWORD},
        )
        store = get_user_store()
        user = store.get_by_email(email)
        assert user is not None
        store.mark_verified(user.user_id)
        login = await client.post(
            "/dashboard/api/auth/login",
            data={"email": email, "password": TEST_PASSWORD},
        )
        refresh = login.cookies["vnd_refresh"]
        sid = decode_token(refresh)["sid"]

        logout = await client.post("/dashboard/api/auth/logout", cookies=dict(login.cookies))
        assert logout.status_code == 303

    assert store.get_session(sid) is None
```

- [ ] **Step 3: Run new tests**

Run: `.venv/bin/pytest tests/integration/dashboard/test_keys_api.py tests/integration/dashboard/test_auth_flow.py -v`
Expected: all PASS.

- [ ] **Step 4: Run full suite**

Run: `.venv/bin/pytest -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add tests/integration/dashboard/test_keys_api.py tests/integration/dashboard/test_auth_flow.py
git commit -m "test(auth): integration tests for keys API, lockout, and logout"
```

---

## Task 16: Final QA — Lint, Type Check, Full Suite, Coverage Check

**Rationale:** Verify the whole system is clean before the plan is considered done. Ruff, mypy strict, full test run, coverage threshold.

**Files:** none (verification only)

- [ ] **Step 1: Run ruff check**

Run: `.venv/bin/ruff check src/ tests/`
Expected: no issues. If any arise from the tasks above, fix them inline and move on.

- [ ] **Step 2: Run ruff format check**

Run: `.venv/bin/ruff format --check src/ tests/`
Expected: no issues. If any, run `.venv/bin/ruff format src/ tests/` and commit the formatting changes separately:

```bash
git add -u
git commit -m "style: ruff format"
```

- [ ] **Step 3: Run mypy strict**

Run: `.venv/bin/mypy src/`
Expected: no errors. Common issues and fixes:
- If `_backend` access in `APIKeyManager` properties triggers untyped-attribute errors, add `# type: ignore[attr-defined]` targeted at the offending line.
- If `store._backend._verify_tokens` access in `conftest.py` triggers errors, the `# type: ignore[attr-defined]` comments included in Task 4 should suppress them. Confirm they're present.

- [ ] **Step 4: Run full test suite with coverage**

Run: `.venv/bin/pytest --cov=vindicara --cov-report=term-missing -q`
Expected: all tests pass; coverage >= 80% (the pyproject threshold). If below 80%, inspect `term-missing` output and add targeted tests for the uncovered lines in the auth modules.

- [ ] **Step 5: Run the CDK synth to confirm infra still builds**

Run: `cdk synth 2>&1 | tail -20`
Expected: clean synth (or whatever the baseline warnings are — no new errors).

- [ ] **Step 6: Make sure no lingering references to the deleted APIKeyStore**

Run: `.venv/bin/python -c "import subprocess; print(subprocess.run(['grep', '-rn', 'APIKeyStore', 'src/', 'tests/'], capture_output=True, text=True).stdout or 'no matches')"`
Expected: no matches.

- [ ] **Step 7: Final commit**

If ruff format or fix-ups in Step 1-3 produced changes, commit them now:

```bash
git add -u
git commit -m "chore: final lint and coverage cleanup after auth completion"
```

If nothing changed, skip this commit. The plan is complete.

---

## Self-Review Checklist (before handoff)

- [ ] Every spec section in the addendum (JWT secret, DynamoDB, key unification, SES, refresh, grace, MFA page, test matrix) maps to at least one task.
- [ ] Every task's code blocks use real identifiers, not placeholders.
- [ ] Function names (`_get_secret`, `register_dev_key`, `mark_verified`, `issue_verification_token`, `consume_verification_token`, `get_mailer`) are used consistently across tasks.
- [ ] Signup flow uses `verify_base_url` from settings (not a hardcoded URL).
- [ ] Tests use `.venv/bin/pytest`, not the unversioned `pytest`.
- [ ] `conftest.py` sets `VINDICARA_JWT_SECRET` and `VINDICARA_STAGE=test` at module top, before any vindicara import.
- [ ] `APIKeyStore` (the old class) is fully removed by Task 9.
- [ ] `APIKeyManager._keys` and `_hash_index` properties in Task 12 preserve the test-helper usage pattern from Task 8.
- [ ] No task marks itself complete without running the relevant tests first.
