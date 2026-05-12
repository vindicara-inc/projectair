"""Application factory for the AIR Cloud hosted ingest service.

Standalone FastAPI app that serves the public ingest surface for
hosted multi-tenant deployments. Distinct from the existing
``vindicara.api.create_app`` which is the Vindicara engine API; this
factory wires only the AIR-Cloud-specific routes (capsules ingest,
capsule list, workspace introspection, key management).

The split lets the AIR Cloud service deploy independently: a single
FastAPI process behind one Lambda or container, with the engine API
deployed alongside or skipped entirely depending on tier.

When ``AIR_CLOUD_CAPSULES_TABLE``, ``AIR_CLOUD_WORKSPACES_TABLE``, and
``AIR_CLOUD_API_KEYS_TABLE`` env vars are set, the factory auto-wires
DynamoDB-backed stores. Otherwise it falls back to in-memory stores
for tests and local development.
"""
from __future__ import annotations

import logging
import os

from fastapi import FastAPI

from vindicara.cloud.capsule_store import CapsuleStore, InMemoryCapsuleStore
from vindicara.cloud.event_bus import CapsuleEventBus
from vindicara.cloud.middleware import AirCloudAuthMiddleware
from vindicara.cloud.routes import capsules, keys, sso, workspaces
from vindicara.cloud.routes import stream as stream_route
from vindicara.cloud.sso import InMemorySsoConfigStore, SsoConfigStore
from vindicara.cloud.workspace import (
    ApiKeyStore,
    InMemoryApiKeyStore,
    InMemoryWorkspaceStore,
    WorkspaceStore,
)

_log = logging.getLogger(__name__)


def _build_ddb_stores() -> (
    tuple[CapsuleStore, WorkspaceStore, ApiKeyStore] | None
):
    """Build DDB stores if all three table env vars are set."""
    capsules_table = os.environ.get("AIR_CLOUD_CAPSULES_TABLE")
    workspaces_table = os.environ.get("AIR_CLOUD_WORKSPACES_TABLE")
    api_keys_table = os.environ.get("AIR_CLOUD_API_KEYS_TABLE")

    if not all([capsules_table, workspaces_table, api_keys_table]):
        return None

    import boto3

    from vindicara.cloud.ddb_api_key_store import DDBApiKeyStore
    from vindicara.cloud.ddb_capsule_store import DDBCapsuleStore
    from vindicara.cloud.ddb_workspace_store import DDBWorkspaceStore

    ddb = boto3.resource("dynamodb")
    _log.info("air_cloud.ddb_stores.wired", extra={
        "capsules": capsules_table,
        "workspaces": workspaces_table,
        "api_keys": api_keys_table,
    })
    return (
        DDBCapsuleStore(ddb.Table(capsules_table)),
        DDBWorkspaceStore(ddb.Table(workspaces_table)),
        DDBApiKeyStore(ddb.Table(api_keys_table)),
    )


def create_air_cloud_app(
    *,
    capsule_store: CapsuleStore | None = None,
    workspace_store: WorkspaceStore | None = None,
    api_key_store: ApiKeyStore | None = None,
    sso_config_store: SsoConfigStore | None = None,
    title: str = "AIR Cloud",
    version: str = "0.1.0",
) -> FastAPI:
    """Build the AIR Cloud hosted ingest FastAPI app.

    Defaults to in-memory stores for tests / local runs. When DDB table
    env vars are set, auto-wires DynamoDB-backed stores. Explicit kwargs
    always win (for tests).
    """
    ddb_stores = None
    if capsule_store is None and workspace_store is None and api_key_store is None:
        ddb_stores = _build_ddb_stores()

    app = FastAPI(
        title=title,
        version=version,
        description=(
            "Hosted ingest service for Project AIR signed forensic chains. "
            "Customers POST signed Intent Capsules to /v1/capsules; the dashboard "
            "and report generators read them back through workspace-scoped GET routes."
        ),
    )

    if ddb_stores is not None:
        app.state.capsule_store = ddb_stores[0]
        app.state.cloud_workspaces = ddb_stores[1]
        app.state.cloud_api_keys = ddb_stores[2]
    else:
        app.state.capsule_store = capsule_store or InMemoryCapsuleStore()
        app.state.cloud_workspaces = workspace_store or InMemoryWorkspaceStore()
        app.state.cloud_api_keys = api_key_store or InMemoryApiKeyStore()

    app.state.cloud_sso_configs = sso_config_store or InMemorySsoConfigStore()
    app.state.capsule_event_bus = CapsuleEventBus()

    app.add_middleware(AirCloudAuthMiddleware, prefix="/v1")

    app.include_router(capsules.router)
    app.include_router(workspaces.router)
    app.include_router(keys.router)
    app.include_router(sso.router)
    app.include_router(stream_route.router)

    @app.get("/health")
    async def _health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/ready")
    async def _ready() -> dict[str, str]:
        return {"status": "ready"}

    return app


__all__ = ["create_air_cloud_app"]
