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
    def __init__(self, backend: UserStoreBackend) -> None:
        self._backend = backend

    def create_user(self, email: str, password: str) -> User:
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
    global _store
    if _store is None:
        _store = UserStore(backend=InMemoryUserBackend())
    return _store


def _reset_store_for_tests() -> None:
    global _store
    _store = None
