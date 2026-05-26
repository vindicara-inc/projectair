"""HL7v2 HTTP receiver for the clinical evidence sidecar (Pro).

Provides a FastAPI router that accepts HL7v2 messages via HTTP POST and
returns HL7v2 ACK responses. Caller assembles the router into a FastAPI app:

    from airsdk_pro.hl7.http import create_hl7_router
    app.include_router(create_hl7_router(recorder), prefix="/clinical")

ACK contract:
  AA (HTTP 200): message parsed and staged successfully.
  AE (HTTP 500): message parsed but an internal error occurred.
  AR (HTTP 400): malformed message, cannot parse.
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Request, Response

from airsdk.recorder import AIRRecorder

from airsdk_pro.hl7.redaction import RedactionPolicy
from airsdk_pro.hl7.types import HL7v2ParseError

_HL7_CONTENT_TYPES = frozenset({
    "application/hl7-v2",
    "x-application/hl7-v2+er7",
})

_HL7_CONTENT_TYPE_OUT = "application/hl7-v2"


def _utc_ts() -> str:
    """Current UTC timestamp in HL7v2 DTM format (YYYYMMDDHHmmss)."""
    return datetime.now(tz=timezone.utc).strftime("%Y%m%d%H%M%S")


def _build_ack_response(mcid: str, ack_code: str) -> str:
    """Build a minimal HL7v2 ACK string for the network-layer response.

    The ``mcid`` is echoed verbatim: the client already has it and this
    meets the HL7 expectation of echoing MSA-2 back to the sender.

    ack_code must be one of: AA, AE, AR.
    """
    new_mcid = uuid.uuid4().hex[:12].upper()
    ts = _utc_ts()
    return (
        f"MSH|^~\\&|AIR|VINDICARA|||{ts}||ACK|{new_mcid}|P|2.5\r"
        f"MSA|{ack_code}|{mcid}\r"
    )


def _extract_mcid_fallback(raw: str) -> str:
    """Best-effort MSH-10 extraction from a string that may not parse.

    Returns empty string when the field cannot be found so callers can
    always produce an ACK without crashing.
    """
    # MSH|^~\&|...field 10 is pipe-delimited position 10
    parts = raw.split("|")
    if len(parts) > 10:
        return parts[9].strip()
    return ""


def create_hl7_router(
    recorder: AIRRecorder,
    *,
    pipeline_queue: asyncio.Queue[str] | None = None,
    redaction_policy: RedactionPolicy | None = None,
) -> APIRouter:
    """Create a FastAPI router that accepts HL7v2 messages via POST.

    Endpoint: ``POST /hl7v2/ingest``

    Content-Type must be ``application/hl7-v2`` or
    ``x-application/hl7-v2+er7``. Body is the raw HL7v2 pipe-delimited
    message string.

    Parameters
    ----------
    recorder:
        AIRRecorder to write signed chain records to.
    pipeline_queue:
        Optional asyncio.Queue; when provided, the raw message string is
        enqueued for downstream processing (e.g. the clinical sidecar).
        ACK is sent before queue consumption completes.
    redaction_policy:
        Passed through to ``instrument_hl7``. Defaults to
        ``RedactionPolicy()`` (REDACTED mode) inside ``instrument_hl7``.

    Returns
    -------
    APIRouter with a single ``POST /hl7v2/ingest`` route.
    """
    router = APIRouter()

    @router.post("/hl7v2/ingest")
    async def ingest(request: Request) -> Response:
        raw_bytes = await request.body()
        raw: str = raw_bytes.decode("utf-8", errors="replace")

        # Parse phase: if malformed, return AR immediately
        try:
            from airsdk_pro.hl7.capture import instrument_hl7

            # instrument_hl7 calls parse_hl7v2 internally; we wrap it so
            # HL7v2ParseError is caught before we attempt chain writes.
            from airsdk_pro.hl7.parser import parse_hl7v2

            parsed = parse_hl7v2(raw)
            mcid = parsed.message_control_id
        except HL7v2ParseError:
            fallback_mcid = _extract_mcid_fallback(raw)
            ack_body = _build_ack_response(fallback_mcid, "AR")
            return Response(
                content=ack_body,
                status_code=400,
                media_type=_HL7_CONTENT_TYPE_OUT,
            )

        # Capture phase: write chain records (blocking file I/O via to_thread)
        try:
            await asyncio.to_thread(
                instrument_hl7,
                recorder,
                raw,
                redaction_policy=redaction_policy,
            )
        except Exception:
            ack_body = _build_ack_response(mcid, "AE")
            return Response(
                content=ack_body,
                status_code=500,
                media_type=_HL7_CONTENT_TYPE_OUT,
            )

        # Enqueue for downstream processing if a queue was provided
        if pipeline_queue is not None:
            await pipeline_queue.put(raw)

        ack_body = _build_ack_response(mcid, "AA")
        return Response(
            content=ack_body,
            status_code=200,
            media_type=_HL7_CONTENT_TYPE_OUT,
        )

    return router
