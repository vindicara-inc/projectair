"""API key CRUD endpoints."""

import structlog
from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse

from vindicara.dashboard.keys.manager import get_key_manager

logger = structlog.get_logger()

router = APIRouter(prefix="/api/keys")


@router.post("")
async def create_key(
    request: Request,
    name: str = Form(...),
    scopes: str = Form(default=""),
) -> RedirectResponse:
    user_id = getattr(request.state, "user_id", "demo")
    manager = get_key_manager()
    scope_list = [s.strip() for s in scopes.split(",") if s.strip()]
    raw_key, record = manager.create_key(user_id, name, scope_list)
    logger.info("keys.api.created", key_id=record.key_id)
    return RedirectResponse(url=f"/dashboard/api-keys?new_key={raw_key}", status_code=303)


@router.post("/{key_id}/revoke")
async def revoke_key(request: Request, key_id: str) -> RedirectResponse:
    user_id = getattr(request.state, "user_id", "demo")
    manager = get_key_manager()
    manager.revoke_key(key_id, user_id)
    return RedirectResponse(url="/dashboard/api-keys", status_code=303)


@router.post("/{key_id}/rotate")
async def rotate_key(request: Request, key_id: str) -> RedirectResponse:
    user_id = getattr(request.state, "user_id", "demo")
    manager = get_key_manager()
    result = manager.rotate_key(key_id, user_id)
    if result:
        raw_key, _ = result
        return RedirectResponse(url=f"/dashboard/api-keys?new_key={raw_key}", status_code=303)
    return RedirectResponse(url="/dashboard/api-keys", status_code=303)
