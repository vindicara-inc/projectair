"""Capsule ingest + list routes for AIR Cloud.

Distinct from ``vindicara.api.routes.capsules`` (single-tenant engine
substrate); this is the multi-tenant hosted variant. Every route here
relies on ``AirCloudAuthMiddleware`` having already populated
``request.state.workspace_id``.
"""
from __future__ import annotations

from airsdk.agdr import verify_record
from airsdk.types import AgDRRecord
from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, ValidationError

from vindicara.cloud.capsule_store import CapsuleStore, StoredCapsule
from vindicara.cloud.roles import Capability, require

router = APIRouter()


class IngestResponse(BaseModel):
    step_id: str
    stored: bool
    workspace_id: str


class CapsulesPage(BaseModel):
    """One page of capsule records."""

    model_config = ConfigDict(extra="forbid")

    workspace_id: str
    count: int
    records: list[AgDRRecord]


@router.post(
    "/v1/capsules",
    response_model=IngestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest one Signed Intent Capsule",
)
async def ingest(request: Request) -> IngestResponse:
    require(request, Capability.WRITE_CAPSULES)
    body = await request.body()
    try:
        record = AgDRRecord.model_validate_json(body)
    except ValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=exc.errors()) from exc

    ok, reason = verify_record(record)
    if not ok:
        raise HTTPException(
            status_code=getattr(status, "HTTP_422_UNPROCESSABLE_CONTENT", status.HTTP_422_UNPROCESSABLE_ENTITY),
            detail=reason or "record signature verification failed",
        )

    store: CapsuleStore = request.app.state.capsule_store
    workspace_id: str = request.state.workspace_id
    store.append(StoredCapsule(workspace_id=workspace_id, record=record))
    return IngestResponse(step_id=record.step_id, stored=True, workspace_id=workspace_id)


@router.post(
    "/v1/capsules/bulk",
    summary="Ingest a batch of Signed Intent Capsules in one POST (NDJSON body)",
)
async def ingest_bulk(request: Request) -> dict[str, int | str]:
    """Ingest a chain in one request. Body: newline-delimited JSON of AgDR records."""
    require(request, Capability.WRITE_CAPSULES)
    body = (await request.body()).decode("utf-8")
    if not body.strip():
        raise HTTPException(status_code=400, detail="empty body")

    store: CapsuleStore = request.app.state.capsule_store
    workspace_id: str = request.state.workspace_id

    accepted = 0
    for line_no, raw_line in enumerate(body.splitlines(), 1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            record = AgDRRecord.model_validate_json(line)
        except ValidationError as exc:
            raise HTTPException(status_code=400, detail=f"line {line_no}: {exc.errors()}") from exc
        ok, reason = verify_record(record)
        if not ok:
            raise HTTPException(
                status_code=422,
                detail=f"line {line_no}: {reason or 'signature verification failed'}",
            )
        store.append(StoredCapsule(workspace_id=workspace_id, record=record))
        accepted += 1

    return {"workspace_id": workspace_id, "stored": accepted}


@router.get(
    "/v1/capsules",
    response_model=CapsulesPage,
    summary="List capsules in the calling key's workspace",
)
async def list_capsules(
    request: Request,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> CapsulesPage:
    require(request, Capability.READ_CAPSULES)
    store: CapsuleStore = request.app.state.capsule_store
    workspace_id: str = request.state.workspace_id
    items = store.for_workspace(workspace_id)
    page = items[offset : offset + limit]
    return CapsulesPage(
        workspace_id=workspace_id,
        count=store.count(workspace_id),
        records=[c.record for c in page],
    )


@router.get(
    "/v1/capsules/{step_id}",
    response_model=AgDRRecord,
    summary="Fetch one capsule by step_id (within the calling key's workspace)",
)
async def get_capsule(request: Request, step_id: str) -> AgDRRecord:
    require(request, Capability.READ_CAPSULES)
    store: CapsuleStore = request.app.state.capsule_store
    workspace_id: str = request.state.workspace_id
    for capsule in store.for_workspace(workspace_id):
        if capsule.record.step_id == step_id:
            return capsule.record
    raise HTTPException(status_code=404, detail=f"step_id {step_id!r} not found in this workspace")
