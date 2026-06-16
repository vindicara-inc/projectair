"""Reference WebAuthn ceremony server for native passkey delegation (phase 2).

WebAuthn needs a browser and a real origin (rp_id). Deploy this at an origin you
control, e.g. authorize.vindicara.io, serve static/authorize.html, and let a
human authorize an agent with their passkey. Nothing here phones home; the
credential store is the operator's own.

This is a reference, not hardened: the in-memory CHALLENGES and CREDENTIALS
dicts must become a real store, and registration must be gated to known users.
It is intentionally NOT part of the published wheel and requires the optional
extras: ``pip install 'projectair[webauthn]' fastapi uvicorn``.

Run:  uvicorn server.app:app --reload --port 8000  (from packages/projectair)
Then open  http://localhost:8000/  (use https + a real domain for production)
"""
from __future__ import annotations

import os

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from airsdk.delegation.webauthn import (
    StoredCredential,
    authentication_options,
    mint_grant_from_webauthn,
    registration_options,
    verify_registration,
    verify_webauthn_assertion,
)
from airsdk.recorder import AIRRecorder
from airsdk.types import IntentSpec

RP_ID = os.environ.get("AIR_RP_ID", "localhost")
RP_NAME = "Project AIR"
ORIGIN = os.environ.get("AIR_ORIGIN", "http://localhost:8000")

app = FastAPI(title="Project AIR delegation ceremony")

# Reference-only stores. Replace with a real database.
CHALLENGES: dict[str, str] = {}
CREDENTIALS: dict[str, StoredCredential] = {}  # keyed by user_handle


@app.get("/")
def index() -> FileResponse:
    return FileResponse("server/static/authorize.html")


@app.post("/register/options")
async def register_options(req: Request) -> JSONResponse:
    body = await req.json()
    email = body["email"]
    handle = email  # for the MVP, key by email
    options_json, challenge = registration_options(
        rp_id=RP_ID, rp_name=RP_NAME, user_email=email, user_handle=handle
    )
    CHALLENGES[handle] = challenge
    return JSONResponse(content={"options": options_json, "handle": handle})


@app.post("/register/verify")
async def register_verify(req: Request) -> JSONResponse:
    body = await req.json()
    handle = body["handle"]
    cred = verify_registration(
        credential_json=body["credential"],
        expected_challenge_b64=CHALLENGES.pop(handle),
        rp_id=RP_ID,
        origin=ORIGIN,
        user_handle=handle,
        user_email=handle,
    )
    CREDENTIALS[handle] = cred
    return JSONResponse(content={"ok": True})


@app.post("/authorize/options")
async def authorize_options(req: Request) -> JSONResponse:
    body = await req.json()
    handle = body["handle"]
    cred = CREDENTIALS.get(handle)
    if cred is None:
        raise HTTPException(404, "no registered passkey for this user")
    options_json, challenge = authentication_options(
        rp_id=RP_ID, allow_credential_ids=[cred.credential_id]
    )
    CHALLENGES[handle] = challenge
    return JSONResponse(content={"options": options_json})


@app.post("/authorize/verify")
async def authorize_verify(req: Request) -> JSONResponse:
    body = await req.json()
    handle = body["handle"]
    cred = CREDENTIALS[handle]
    new_count = verify_webauthn_assertion(
        credential_json=body["credential"],
        expected_challenge_b64=CHALLENGES.pop(handle),
        rp_id=RP_ID,
        origin=ORIGIN,
        stored=cred,
    )
    cred.sign_count = new_count  # persist in a real store

    scope = IntentSpec(
        goal=body["goal"],
        allowed_tools=body.get("allowed_tools", []),
        allowed_paths=body.get("allowed_paths", []),
        allowed_network=body.get("allowed_network", []),
    )
    grant = mint_grant_from_webauthn(
        stored=cred,
        credential_json=body["credential"],
        agent_id=body["agent_id"],
        policy_id=body["policy_id"],
        policy_hash=body["policy_hash"],
        scope=scope,
        ttl_seconds=body.get("ttl", 3600),
    )

    recorder = AIRRecorder(body.get("chain", "chain.jsonl"))
    record = recorder.open_delegation(grant)
    return JSONResponse(
        content={
            "ok": True,
            "delegation_id": grant.delegation_id,
            "genesis_step_id": record.step_id,
            "authorizer": grant.authorizer_email or grant.authorizer_sub,
        }
    )


app.mount("/static", StaticFiles(directory="server/static"), name="static")
