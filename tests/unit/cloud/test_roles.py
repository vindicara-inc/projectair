"""Workspace role + capability policy tests (pure unit; no FastAPI)."""
from __future__ import annotations

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from vindicara.cloud.roles import (
    VALID_ROLES,
    Capability,
    Role,
    allows,
    is_valid_role,
    require,
)


def test_role_enum_membership() -> None:
    assert {r.value for r in Role} == VALID_ROLES
    assert is_valid_role("owner")
    assert is_valid_role("admin")
    assert is_valid_role("member")
    assert is_valid_role("viewer")
    assert not is_valid_role("god-mode")


@pytest.mark.parametrize(
    ("role", "capability", "expected"),
    [
        # Owner: everything
        ("owner", Capability.READ_WORKSPACE, True),
        ("owner", Capability.WRITE_CAPSULES, True),
        ("owner", Capability.ISSUE_KEY, True),
        ("owner", Capability.DELETE_WORKSPACE, True),
        # Admin: nearly everything except DELETE_WORKSPACE
        ("admin", Capability.WRITE_CAPSULES, True),
        ("admin", Capability.ISSUE_KEY, True),
        ("admin", Capability.INVITE_MEMBER, True),
        ("admin", Capability.DELETE_WORKSPACE, False),
        # Member: read + ingest, no key management
        ("member", Capability.READ_CAPSULES, True),
        ("member", Capability.WRITE_CAPSULES, True),
        ("member", Capability.LIST_KEYS, False),
        ("member", Capability.ISSUE_KEY, False),
        ("member", Capability.REVOKE_KEY, False),
        ("member", Capability.INVITE_MEMBER, False),
        ("member", Capability.DELETE_WORKSPACE, False),
        # Viewer: read-only
        ("viewer", Capability.READ_CAPSULES, True),
        ("viewer", Capability.READ_WORKSPACE, True),
        ("viewer", Capability.WRITE_CAPSULES, False),
        ("viewer", Capability.LIST_KEYS, False),
        ("viewer", Capability.ISSUE_KEY, False),
        ("viewer", Capability.INVITE_MEMBER, False),
        # Unknown roles fail closed
        ("godmode", Capability.READ_CAPSULES, False),
        ("", Capability.READ_CAPSULES, False),
    ],
)
def test_capability_policy(role: str, capability: Capability, expected: bool) -> None:
    assert allows(role, capability) is expected


def _request_with_role(role: str | None) -> Request:
    """Hand-roll a minimal Request whose ``state.role`` is set as specified."""
    scope: dict[str, object] = {
        "type": "http",
        "method": "GET",
        "path": "/v1/test",
        "headers": [],
    }
    request = Request(scope)
    if role is not None:
        request.state.role = role
    return request


def test_require_passes_when_role_permits() -> None:
    request = _request_with_role("owner")
    require(request, Capability.ISSUE_KEY)  # does not raise


def test_require_raises_403_when_role_denies() -> None:
    request = _request_with_role("viewer")
    with pytest.raises(HTTPException) as exc_info:
        require(request, Capability.WRITE_CAPSULES)
    assert exc_info.value.status_code == 403
    assert "viewer" in exc_info.value.detail
    assert "write_capsules" in exc_info.value.detail


def test_require_raises_500_when_role_missing() -> None:
    """Misconfigured deployment: middleware did not populate state.role."""
    request = _request_with_role(None)
    with pytest.raises(HTTPException) as exc_info:
        require(request, Capability.READ_CAPSULES)
    assert exc_info.value.status_code == 500
