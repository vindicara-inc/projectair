"""Flightdeck console API for the marketing-site /dashboard shell."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from vindicara.api.console.auth import OperatorContext, require_operator
from vindicara.api.console.store import FlightdeckStore
from vindicara.api.deps import get_agent_registry
from vindicara.identity.registry import AgentRegistry

router = APIRouter(tags=["console"])


def _store(request: Request) -> FlightdeckStore:
    state = getattr(request.app.state, "flightdeck_store", None)
    if state is None:
        state = FlightdeckStore()
        request.app.state.flightdeck_store = state
    return state


class FindingActionBody(BaseModel):
    intent: str = Field(min_length=1)


class TransportPatchBody(BaseModel):
    label: str = Field(min_length=1)
    on: bool


@router.get("/v1/console/overview")
def console_overview(
    request: Request,
    operator: Annotated[OperatorContext, Depends(require_operator)],
    registry: Annotated[AgentRegistry, Depends(get_agent_registry)],
) -> dict[str, object]:
    return _store(request).overview(registry, operator)


@router.get("/v1/console/readiness")
def console_readiness(request: Request, _op: Annotated[OperatorContext, Depends(require_operator)]) -> dict[str, object]:
    return _store(request).readiness()


@router.get("/v1/rules")
def list_rules(request: Request, _op: Annotated[OperatorContext, Depends(require_operator)]) -> dict[str, object]:
    return _store(request).rules()


@router.get("/v1/rules/{rule_id}")
def get_rule(
    rule_id: str,
    request: Request,
    _op: Annotated[OperatorContext, Depends(require_operator)],
) -> dict[str, str]:
    return _store(request).rule_doc(rule_id)


@router.get("/v1/plugins")
def list_plugins(request: Request, _op: Annotated[OperatorContext, Depends(require_operator)]) -> dict[str, object]:
    return _store(request).plugins()


@router.post("/v1/plugins/{plugin_id}/connect", status_code=204)
def connect_plugin(
    plugin_id: str,
    request: Request,
    _op: Annotated[OperatorContext, Depends(require_operator)],
) -> None:
    _store(request).connect_plugin(plugin_id)


@router.get("/v1/insurance")
def get_insurance(request: Request, _op: Annotated[OperatorContext, Depends(require_operator)]) -> dict[str, object]:
    return _store(request).insurance()


@router.get("/v1/settings")
def get_settings(
    request: Request,
    operator: Annotated[OperatorContext, Depends(require_operator)],
) -> dict[str, object]:
    return _store(request).settings(operator)


@router.post("/v1/delegations/{agent}/revoke", status_code=204)
def revoke_delegation(
    agent: str,
    request: Request,
    registry: Annotated[AgentRegistry, Depends(get_agent_registry)],
    _op: Annotated[OperatorContext, Depends(require_operator)],
) -> None:
    store = _store(request)
    store.revoke_delegation(agent)
    for entry in registry.list_agents():
        if entry.name == agent:
            registry.suspend(entry.agent_id, reason="Delegation revoked from Flightdeck")


@router.post("/v1/findings/{finding_id}/act", status_code=204)
def act_on_finding(
    finding_id: str,
    body: FindingActionBody,
    request: Request,
    _op: Annotated[OperatorContext, Depends(require_operator)],
) -> None:
    if body.intent not in {"revoke", "require_auth", "quarantine", "evidence", "renew"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unknown finding action intent")
    _store(request).act_on_finding(finding_id)


@router.patch("/v1/insurance/transport", status_code=204)
def patch_transport(
    body: TransportPatchBody,
    request: Request,
    _op: Annotated[OperatorContext, Depends(require_operator)],
) -> None:
    try:
        _store(request).set_transport(body.label, body.on)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post("/v1/insurance/consent/{carrier}/revoke", status_code=204)
def revoke_consent(
    carrier: str,
    request: Request,
    _op: Annotated[OperatorContext, Depends(require_operator)],
) -> None:
    try:
        _store(request).revoke_consent(carrier)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
