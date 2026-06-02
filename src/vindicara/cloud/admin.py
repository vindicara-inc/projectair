"""Operator admin-token gate for privileged AIR Cloud routes (W3.10).

Workspace creation is an operator action, not a tenant action: a brand-new
tenant has no API key yet, so the role-based ``require`` helper cannot gate
it. Instead the deploying operator holds a single secret admin token,
supplied at deploy time via ``AIR_CLOUD_ADMIN_TOKEN`` (or the ``admin_token``
factory kwarg) and compared in constant time.

Fail-closed: if no admin token is configured, the gated route is disabled
entirely (503) rather than left open to any caller. This is the control that
lets the hosted service be exposed on the public internet safely.

OIDC-ready seam: when self-serve signup lands, the OIDC login path can mint
its own provisioning credential and call the same store-backed creation
logic; ``require_admin`` stays the operator escape hatch for provisioning a
tenant out of band.
"""

from __future__ import annotations

import hmac

from fastapi import HTTPException, Request, status

# The HTTP header NAME that carries the admin token. Not a secret itself,
# so the ruff "hardcoded password" heuristic (S105) is a false positive here.
ADMIN_TOKEN_HEADER = "X-Admin-Token"  # noqa: S105


def require_admin(request: Request) -> None:
    """Raise unless the request carries the configured operator admin token.

    Reads ``request.app.state.cloud_admin_token`` (set by the app factory).
    Fail-closed semantics:

    - no admin token configured -> 503 (the route is disabled, not open);
    - missing or mismatched ``X-Admin-Token`` header -> 401.

    The comparison is constant time to avoid leaking the token via timing.
    """
    configured: str | None = getattr(request.app.state, "cloud_admin_token", None)
    if not configured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="workspace creation is disabled: no admin token configured",
        )
    presented = request.headers.get(ADMIN_TOKEN_HEADER, "")
    if not presented or not hmac.compare_digest(presented, configured):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing or invalid admin token",
        )


__all__ = ["ADMIN_TOKEN_HEADER", "require_admin"]
