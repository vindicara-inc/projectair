"""ASGI middleware that authenticates AIR Cloud requests via API key.

The X-API-Key header is mapped to a workspace through the configured
:class:`ApiKeyStore`. On success, ``request.state.workspace_id`` is set
so downstream routes scope their queries to the right tenant. On
failure the request is rejected with 401 before it touches a route.

Routes that are public (health, OpenAPI docs) are listed in
``UNAUTHED_PATHS``.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from starlette.requests import Request
    from starlette.types import ASGIApp

    from vindicara.cloud.workspace import ApiKeyStore

UNAUTHED_PATHS: frozenset[str] = frozenset({
    "/health",
    "/ready",
    "/openapi.json",
    "/docs",
    "/redoc",
    "/docs/oauth2-redirect",
})

API_KEY_HEADER = "X-API-Key"


class AirCloudAuthMiddleware(BaseHTTPMiddleware):
    """Authenticate every non-public AIR Cloud request via an API key.

    The middleware reads the configured :class:`ApiKeyStore` from
    ``app.state.cloud_api_keys``; if the store is missing it returns
    503 (the service is misconfigured, not the caller's fault). On a
    successful auth check ``request.state.workspace_id`` is populated
    and the downstream handler runs.
    """

    def __init__(self, app: ASGIApp, *, prefix: str = "/v1") -> None:
        super().__init__(app)
        self._prefix = prefix

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        path = request.url.path
        if path in UNAUTHED_PATHS:
            return await call_next(request)
        if not path.startswith(self._prefix):
            return await call_next(request)

        store: ApiKeyStore | None = getattr(request.app.state, "cloud_api_keys", None)
        if store is None:
            return JSONResponse(
                {"detail": "AIR Cloud not configured: no api-key store"},
                status_code=503,
            )

        provided = request.headers.get(API_KEY_HEADER)
        if not provided:
            return JSONResponse(
                {"detail": "missing X-API-Key header"},
                status_code=401,
            )
        api_key = store.lookup(provided)
        if api_key is None:
            return JSONResponse(
                {"detail": "invalid or revoked api key"},
                status_code=401,
            )

        request.state.workspace_id = api_key.workspace_id
        request.state.api_key_id = api_key.key_id
        request.state.role = api_key.role
        return await call_next(request)


__all__ = ["API_KEY_HEADER", "UNAUTHED_PATHS", "AirCloudAuthMiddleware"]
