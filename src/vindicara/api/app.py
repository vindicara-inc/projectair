"""FastAPI application factory."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from vindicara.api.middleware.auth import APIKeyAuthMiddleware, APIKeyStore
from vindicara.api.middleware.rate_limit import RateLimitMiddleware
from vindicara.api.middleware.request_id import RequestIDMiddleware
from vindicara.api.middleware.security_headers import SecurityHeadersMiddleware
from vindicara.api.routes import (
    agents,
    capsules,
    guard,
    health,
    monitor,
    policies,
    reports,
    scans,
    stripe_webhook,
)
from vindicara.cloud.capsule_store import CapsuleStore, InMemoryCapsuleStore
from vindicara.config.settings import VindicaraSettings


def create_app(
    dev_api_keys: list[str] | None = None,
    *,
    capsule_store: CapsuleStore | None = None,
) -> FastAPI:
    settings = VindicaraSettings()

    app = FastAPI(
        title="Vindicara API",
        description="Runtime security for autonomous AI",
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    key_store = APIKeyStore()
    key_store.register_key("vnd_demo", owner_id="demo")
    if dev_api_keys:
        for key in dev_api_keys:
            key_store.register_key(key, owner_id="dev")
    app.state.key_store = key_store

    app.state.capsule_store = capsule_store if capsule_store is not None else InMemoryCapsuleStore()

    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(APIKeyAuthMiddleware)
    app.add_middleware(
        RateLimitMiddleware,
        max_requests=settings.rate_limit_requests,
        window_seconds=settings.rate_limit_window_seconds,
    )

    cors_origins = settings.cors_origins
    uses_wildcard = "*" in cors_origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=not uses_wildcard,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(health.router)
    app.include_router(guard.router)
    app.include_router(policies.router)
    app.include_router(scans.router)
    app.include_router(agents.router)
    app.include_router(reports.router)
    app.include_router(monitor.router)
    app.include_router(capsules.router)
    app.include_router(stripe_webhook.router)

    from vindicara.dashboard.app import create_dashboard_app
    from vindicara.dashboard.auth.middleware import DashboardAuthMiddleware

    app.add_middleware(DashboardAuthMiddleware)
    app.mount("/dashboard", create_dashboard_app())

    return app
