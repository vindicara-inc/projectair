"""API key authentication middleware with hash-based validation."""

import hashlib

import structlog
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from vindicara.config.constants import API_KEY_HEADER, API_KEY_PREFIX

logger = structlog.get_logger()

_PUBLIC_PATHS = {
    "/health",
    "/ready",
    "/docs",
    "/openapi.json",
    "/redoc",
    # Stripe webhook authenticates via the Stripe-Signature header (verified
    # against STRIPE_WEBHOOK_SECRET inside the route), not our API key.
    "/webhooks/stripe",
}


class APIKeyStore:
    """Validates API keys against SHA-256 hashed entries.

    Keys are stored as hashes; raw keys are never persisted.
    """

    def __init__(self) -> None:
        self._key_hashes: dict[str, str] = {}

    def register_key(self, raw_key: str, owner_id: str = "default") -> None:
        """Register a raw API key by storing its SHA-256 hash."""
        key_hash = self._hash_key(raw_key)
        self._key_hashes[key_hash] = owner_id
        logger.info("auth.key_registered", owner_id=owner_id)

    def validate(self, raw_key: str) -> str | None:
        """Validate a raw API key. Returns owner_id if valid, None otherwise."""
        if not raw_key or not raw_key.startswith(API_KEY_PREFIX):
            return None
        key_hash = self._hash_key(raw_key)
        return self._key_hashes.get(key_hash)

    def revoke_key(self, raw_key: str) -> bool:
        """Revoke a key by removing its hash. Returns True if found."""
        key_hash = self._hash_key(raw_key)
        return self._key_hashes.pop(key_hash, None) is not None

    @staticmethod
    def _hash_key(raw_key: str) -> str:
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


class APIKeyAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.url.path in _PUBLIC_PATHS or request.url.path.startswith("/dashboard"):
            return await call_next(request)

        api_key = request.headers.get(API_KEY_HEADER, "")
        key_store: APIKeyStore | None = getattr(request.app.state, "key_store", None)

        if key_store is None:
            logger.error("auth.no_key_store", path=request.url.path)
            return JSONResponse(
                status_code=500,
                content={"detail": "Authentication service unavailable"},
            )

        owner_id = key_store.validate(api_key)
        if owner_id is None:
            return JSONResponse(
                status_code=401,
                content={"detail": f"Invalid API key. Provide a valid key via {API_KEY_HEADER} header."},
            )

        request.state.api_key = api_key
        request.state.owner_id = owner_id
        return await call_next(request)
