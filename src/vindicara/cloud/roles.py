"""Workspace role model + central authorization helper.

Four roles, ordered by privilege:

- ``owner``   full access; can manage members, issue / revoke any key,
              bootstrap the workspace, delete the workspace.
- ``admin``   can manage members and keys, can ingest, can read.
              Can NOT delete the workspace itself.
- ``member``  the default workspace role for a teammate. Can ingest
              and read; can NOT issue or revoke keys.
- ``viewer``  read-only. Can NOT ingest, can NOT manage keys.

Routes call ``require(role, capability)`` to enforce the policy. The
table below is the single source of truth; routes never inspect role
strings directly.
"""
from __future__ import annotations

from enum import StrEnum

from fastapi import HTTPException, Request, status


class Role(StrEnum):
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    VIEWER = "viewer"


VALID_ROLES: frozenset[str] = frozenset(r.value for r in Role)


class Capability(StrEnum):
    """Discrete actions a key can attempt. Mapped to roles below."""

    READ_WORKSPACE = "read_workspace"
    READ_CAPSULES = "read_capsules"
    WRITE_CAPSULES = "write_capsules"
    LIST_KEYS = "list_keys"
    ISSUE_KEY = "issue_key"
    REVOKE_KEY = "revoke_key"
    INVITE_MEMBER = "invite_member"
    DELETE_WORKSPACE = "delete_workspace"


# Static authorization table. Adding a new capability or role means
# adding a row / column here; route handlers do not encode the policy.
_POLICY: dict[Capability, frozenset[Role]] = {
    Capability.READ_WORKSPACE: frozenset({Role.OWNER, Role.ADMIN, Role.MEMBER, Role.VIEWER}),
    Capability.READ_CAPSULES: frozenset({Role.OWNER, Role.ADMIN, Role.MEMBER, Role.VIEWER}),
    Capability.WRITE_CAPSULES: frozenset({Role.OWNER, Role.ADMIN, Role.MEMBER}),
    Capability.LIST_KEYS: frozenset({Role.OWNER, Role.ADMIN}),
    Capability.ISSUE_KEY: frozenset({Role.OWNER, Role.ADMIN}),
    Capability.REVOKE_KEY: frozenset({Role.OWNER, Role.ADMIN}),
    Capability.INVITE_MEMBER: frozenset({Role.OWNER, Role.ADMIN}),
    Capability.DELETE_WORKSPACE: frozenset({Role.OWNER}),
}


def is_valid_role(role: str) -> bool:
    return role in VALID_ROLES


def allows(role: str, capability: Capability) -> bool:
    """Pure predicate: does ``role`` permit ``capability``?

    Returns ``False`` for unknown role strings. The middleware sets
    ``role`` from the API key it just authenticated, so reaching this
    function with a malformed role indicates store corruption; the
    safe default is to deny.
    """
    if not is_valid_role(role):
        return False
    return Role(role) in _POLICY[capability]


def require(request: Request, capability: Capability) -> None:
    """Middleware-coupled enforcer. Raises 403 if the calling key's role
    does not have ``capability``.

    Routes call this once at the top of the handler. The middleware
    has already populated ``request.state.role``; if it has not, the
    deployment is misconfigured and we deny.
    """
    role: str | None = getattr(request.state, "role", None)
    if role is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="role not populated by auth middleware",
        )
    if not allows(role, capability):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"role {role!r} does not permit {capability.value!r}",
        )


__all__ = [
    "VALID_ROLES",
    "Capability",
    "Role",
    "allows",
    "is_valid_role",
    "require",
]
