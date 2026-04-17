"""In-memory sliding window rate limiter."""

import time

import structlog
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from vindicara.config.constants import API_KEY_HEADER

logger = structlog.get_logger()

_PUBLIC_PATHS = {"/health", "/ready", "/docs", "/openapi.json", "/redoc"}


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding window rate limiter keyed by API key."""

    def __init__(
        self,
        app: object,
        max_requests: int = 100,
        window_seconds: int = 60,
    ) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._buckets: dict[str, list[float]] = {}

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.url.path in _PUBLIC_PATHS or request.url.path.startswith("/dashboard"):
            return await call_next(request)

        api_key = request.headers.get(API_KEY_HEADER, "unknown")
        now = time.monotonic()
        cutoff = now - self._window_seconds

        timestamps = self._buckets.get(api_key, [])
        timestamps = [t for t in timestamps if t > cutoff]

        if len(timestamps) >= self._max_requests:
            retry_after = self._window_seconds - (now - timestamps[0])
            logger.warning(
                "rate_limit.exceeded",
                api_key_prefix=api_key[:8] if len(api_key) >= 8 else "short",
                request_count=len(timestamps),
            )
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded"},
                headers={"Retry-After": str(int(retry_after) + 1)},
            )

        timestamps.append(now)
        self._buckets[api_key] = timestamps
        return await call_next(request)
