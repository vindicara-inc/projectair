"""Pluggable persistence backends for the user store."""

from datetime import UTC, datetime
from typing import Protocol

from vindicara.dashboard.auth.models import Session, User, VerificationToken


class UserStoreBackend(Protocol):
    def put_user(self, user: User) -> None: ...
    def get_user_by_id(self, user_id: str) -> User | None: ...
    def get_user_by_email(self, email: str) -> User | None: ...
    def put_session(self, session: Session) -> None: ...
    def get_session(self, session_id: str) -> Session | None: ...
    def put_verification_token(self, record: VerificationToken) -> None: ...
    def consume_verification_token(self, token: str) -> str | None: ...


class InMemoryUserBackend:
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
        record = self._verify_tokens.pop(token, None)
        if record is None:
            return None
        if datetime.now(UTC) > datetime.fromisoformat(record.expires_at):
            return None
        return record.user_id
