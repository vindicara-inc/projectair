"""Unit tests for UserStore orchestration."""

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
    assert store.consume_verification_token(token) is None


def test_verification_token_expires(store: UserStore) -> None:
    from vindicara.dashboard.auth.models import VerificationToken
    user = store.create_user("alice@example.com", "StrongPass123!!")
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
