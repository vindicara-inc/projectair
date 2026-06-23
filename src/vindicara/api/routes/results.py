"""Post-scan results email endpoint (Free-tier first-run delivery).

Unauthenticated (prefix listed in the auth middleware's public paths). The CLI
POSTs a findings *summary* after a scan; we email it to the captured address.

Best-effort by design: if email can't be sent (no Resend key, delivery error),
log and return 202 rather than failing, so a user's scan is never blocked on
email. Carries only detector id / title / severity, never raw payloads.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter
from pydantic import BaseModel, Field, field_validator

from vindicara.config.settings import VindicaraSettings
from vindicara.notifications import EmailDeliveryError, ResultsEmail, send_results_email

router = APIRouter(prefix="/api/v1/results", tags=["results"])
log = logging.getLogger(__name__)


class FindingSummary(BaseModel):
    detector_id: str
    title: str = ""
    severity: str = ""


class ResultsRequest(BaseModel):
    email: str
    records: int = 0
    verification_status: str = ""
    findings: list[FindingSummary] = Field(default_factory=list)

    @field_validator("email")
    @classmethod
    def _validate_email(cls, v: str) -> str:
        v = v.strip()
        if "@" not in v or "." not in v.split("@")[-1]:
            raise ValueError("email must be a valid address")
        return v


@router.post("/send", status_code=202)
async def send(body: ResultsRequest) -> dict[str, str]:
    """Email a post-scan findings summary to the captured address (best-effort)."""
    settings = VindicaraSettings()
    payload = ResultsEmail(
        recipient=body.email,
        records=body.records,
        verification_status=body.verification_status or "unknown",
        findings=tuple((f.detector_id, f.title, f.severity) for f in body.findings),
    )
    try:
        message_id = send_results_email(payload, resend_api_key=settings.resend_api_key)
    except EmailDeliveryError as exc:
        log.warning("results.email_skipped email=%s error=%s", body.email, exc)
        return {"status": "skipped"}
    return {"status": "sent", "message_id": message_id}
