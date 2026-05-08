"""Application factory for the AIR Cloud hosted ingest service.

Standalone FastAPI app that serves the public ingest surface for
hosted multi-tenant deployments. Distinct from the existing
``vindicara.api.create_app`` which is the Vindicara engine API; this
factory wires only the AIR-Cloud-specific routes (capsules ingest,
capsule list, workspace introspection, key management).

The split lets the AIR Cloud service deploy independently: a single
FastAPI process behind one Lambda or container, with the engine API
deployed alongside or skipped entirely depending on tier.
"""
from __future__ import annotations

from fastapi import FastAPI

from vindicara.cloud.capsule_store import CapsuleStore, InMemoryCapsuleStore
from vindicara.cloud.middleware import AirCloudAuthMiddleware
from vindicara.cloud.routes import capsules, keys, workspaces
from vindicara.cloud.workspace import (
    ApiKeyStore,
    InMemoryApiKeyStore,
    InMemoryWorkspaceStore,
    WorkspaceStore,
)


def create_air_cloud_app(
    *,
    capsule_store: CapsuleStore | None = None,
    workspace_store: WorkspaceStore | None = None,
    api_key_store: ApiKeyStore | None = None,
    title: str = "AIR Cloud",
    version: str = "0.1.0",
) -> FastAPI:
    """Build the AIR Cloud hosted ingest FastAPI app.

    Defaults to in-memory stores for tests / local runs. Production
    deployments inject DynamoDB-backed stores via the keyword args.
    """
    app = FastAPI(
        title=title,
        version=version,
        description=(
            "Hosted ingest service for Project AIR signed forensic chains. "
            "Customers POST signed Intent Capsules to /v1/capsules; the dashboard "
            "and report generators read them back through workspace-scoped GET routes."
        ),
    )

    app.state.capsule_store = capsule_store or InMemoryCapsuleStore()
    app.state.cloud_workspaces = workspace_store or InMemoryWorkspaceStore()
    app.state.cloud_api_keys = api_key_store or InMemoryApiKeyStore()

    app.add_middleware(AirCloudAuthMiddleware, prefix="/v1")

    app.include_router(capsules.router)
    app.include_router(workspaces.router)
    app.include_router(keys.router)

    @app.get("/health")
    async def _health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/ready")
    async def _ready() -> dict[str, str]:
        return {"status": "ready"}

    return app


__all__ = ["create_air_cloud_app"]
