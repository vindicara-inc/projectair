"""Capsule ingestion endpoint.

Receives Signed Intent Capsules from OSS ``airsdk.recorder.AIRRecorder``
HTTPTransport instances. Verifies the signature at the door (rejecting
tampered records before they hit storage), then hands the verified record
to the configured :class:`CapsuleStore`.

Endpoint contract::

    POST /v1/capsules
    Content-Type: application/json
    X-API-Key: vnd_...

    <AgDRRecord JSON>

Responses:

- ``201 Created`` with ``{"step_id": ..., "stored": true}`` on success.
- ``400 Bad Request`` if the body is not a valid AgDRRecord.
- ``422 Unprocessable Entity`` with ``{"detail": "<verify reason>"}`` if
  the signature does not verify against the embedded ``signer_key``.
- ``500 Internal Server Error`` if the server has no ``CapsuleStore``
  configured (deployment error, surfaces during startup smoke tests).
"""
from __future__ import annotations

from airsdk.agdr import verify_record
from airsdk.types import AgDRRecord
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, ValidationError

from vindicara.cloud.capsule_store import CapsuleStore, StoredCapsule

router = APIRouter()


class IngestResponse(BaseModel):
    """Body of a successful ``/v1/capsules`` POST."""

    step_id: str
    stored: bool


@router.post(
    "/v1/capsules",
    response_model=IngestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest one Signed Intent Capsule",
)
async def ingest_capsule(request: Request) -> IngestResponse:
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

    store: CapsuleStore | None = getattr(request.app.state, "capsule_store", None)
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="capsule store is not configured on this deployment",
        )

    workspace_id = getattr(request.state, "owner_id", "default")
    store.append(StoredCapsule(workspace_id=workspace_id, record=record))

    return IngestResponse(step_id=record.step_id, stored=True)
