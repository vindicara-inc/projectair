from __future__ import annotations

import os
import re

os.environ.setdefault("VINDICARA_SESSION_SECRET", "test_secret_for_unit_tests_only_0000")

import pytest

from vindicara.cloud.session_token import (
    SessionClaims,
    SessionTokenError,
    create_session_token,
    verify_session_token,
)

_SECRET = "test_secret_for_unit_tests_only_0000"
_CLAIMS = SessionClaims(
    workspace_id="ws-abc123",
    role="admin",
    sub="user-001",
    key_id="key-xyz",
)


def test_roundtrip() -> None:
    token = create_session_token(_CLAIMS, secret=_SECRET)
    result = verify_session_token(token, secret=_SECRET)
    assert result.workspace_id == _CLAIMS.workspace_id
    assert result.role == _CLAIMS.role
    assert result.sub == _CLAIMS.sub
    assert result.key_id == _CLAIMS.key_id


def test_expired_token() -> None:
    token = create_session_token(_CLAIMS, ttl_seconds=-1, secret=_SECRET)
    with pytest.raises(SessionTokenError, match=re.compile("expired", re.IGNORECASE)):
        verify_session_token(token, secret=_SECRET)


def test_tampered_token() -> None:
    token = create_session_token(_CLAIMS, secret=_SECRET)
    tampered = token[:-4] + ("XXXX" if not token.endswith("XXXX") else "YYYY")
    with pytest.raises(SessionTokenError):
        verify_session_token(tampered, secret=_SECRET)


def test_missing_claims() -> None:
    with pytest.raises(SessionTokenError):
        verify_session_token("not.a.jwt", secret=_SECRET)
