"""MLLP (Minimal Lower Layer Protocol) TCP listener for HL7v2 (Pro).

Implements async TCP server using HL7v2 MLLP framing:
  - Start byte: 0x0B (vertical tab)
  - End bytes: 0x1C 0x0D (file separator + carriage return)

Typical usage:

    listener = MLLPListener(host="0.0.0.0", port=2575, recorder=recorder)
    await listener.start()
    # ... serve indefinitely ...
    await listener.stop()

One-connection-per-integration-engine (long-lived connections) is the
intended usage pattern. The server accepts multiple sequential messages
on the same connection and sends an MLLP-framed ACK or NAK after each.
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone

from airsdk.recorder import AIRRecorder

from airsdk_pro.hl7.redaction import RedactionPolicy
from airsdk_pro.hl7.types import HL7v2ParseError

_MLLP_START = b"\x0b"
_MLLP_END = b"\x1c\x0d"

# Per-read timeout so idle connections don't pin a task indefinitely.
_READ_TIMEOUT_SECONDS = 30.0


def _utc_ts() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y%m%d%H%M%S")


def _build_ack_response(mcid: str, ack_code: str) -> str:
    """Build a minimal HL7v2 ACK for the MLLP network layer.

    Mirrors the HTTP module's ACK contract. The mcid is echoed verbatim.
    """
    new_mcid = uuid.uuid4().hex[:12].upper()
    ts = _utc_ts()
    return (
        f"MSH|^~\\&|AIR|VINDICARA|||{ts}||ACK|{new_mcid}|P|2.5\r"
        f"MSA|{ack_code}|{mcid}\r"
    )


def _extract_mcid_fallback(raw: str) -> str:
    """Best-effort MSH-10 extraction from a string that may not parse."""
    parts = raw.split("|")
    if len(parts) > 10:
        return parts[9].strip()
    return ""


def _mllp_wrap(message: str) -> bytes:
    """Wrap a HL7v2 string in MLLP framing bytes."""
    return _MLLP_START + message.encode("utf-8") + _MLLP_END


class MLLPListener:
    """Async TCP server that accepts HL7v2 messages via MLLP framing.

    Parameters
    ----------
    host:
        Interface to bind to. Defaults to ``"0.0.0.0"`` (all interfaces).
    port:
        TCP port. Use ``0`` for OS-assigned ephemeral port (useful in tests).
        After ``start()``, the actual port is available via the ``port`` property.
    recorder:
        AIRRecorder instance. When provided, each successfully parsed message
        is captured as a signed chain record pair via ``instrument_hl7``.
    pipeline_queue:
        Optional asyncio.Queue; when provided, raw message strings are enqueued
        for downstream processing. ACK is sent before queue consumption.
    redaction_policy:
        Passed through to ``instrument_hl7``. Defaults to REDACTED mode inside
        ``instrument_hl7`` when None.
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 2575,
        recorder: AIRRecorder | None = None,
        pipeline_queue: asyncio.Queue[str] | None = None,
        redaction_policy: RedactionPolicy | None = None,
    ) -> None:
        self._host = host
        self._port_requested = port
        self._port_bound: int | None = None
        self._recorder = recorder
        self._pipeline_queue = pipeline_queue
        self._redaction_policy = redaction_policy
        self._server: asyncio.Server | None = None

    @property
    def port(self) -> int:
        """Actual bound TCP port.

        Raises RuntimeError if called before ``start()``.
        """
        if self._port_bound is None:
            raise RuntimeError("MLLPListener.start() must be called before reading port")
        return self._port_bound

    async def start(self) -> None:
        """Start the TCP server and begin accepting connections."""
        self._server = await asyncio.start_server(
            self._handle_connection,
            self._host,
            self._port_requested,
        )
        # Resolve ephemeral port for port=0 case
        sockets = self._server.sockets
        if sockets:
            self._port_bound = sockets[0].getsockname()[1]
        else:
            self._port_bound = self._port_requested
        await self._server.start_serving()

    async def stop(self) -> None:
        """Stop accepting new connections and close the server."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a single long-lived MLLP connection.

        Loops reading MLLP-framed messages until the connection closes.
        Each message gets an MLLP-framed ACK or NAK response.
        """
        try:
            await self._message_loop(reader, writer)
        except (asyncio.TimeoutError, ConnectionResetError, asyncio.IncompleteReadError):
            pass
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _message_loop(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Read and respond to HL7v2 messages until the connection closes."""
        while True:
            # Read until MLLP end bytes, with a per-message timeout
            try:
                framed = await asyncio.wait_for(
                    reader.readuntil(_MLLP_END),
                    timeout=_READ_TIMEOUT_SECONDS,
                )
            except asyncio.TimeoutError:
                # Idle connection; close gracefully
                return
            except asyncio.IncompleteReadError:
                # Client disconnected
                return

            # Strip MLLP framing
            raw_bytes = framed
            if raw_bytes.startswith(_MLLP_START):
                raw_bytes = raw_bytes[len(_MLLP_START):]
            if raw_bytes.endswith(_MLLP_END):
                raw_bytes = raw_bytes[: -len(_MLLP_END)]

            raw = raw_bytes.decode("utf-8", errors="replace")
            ack_str = await self._process_message(raw)
            writer.write(_mllp_wrap(ack_str))
            await writer.drain()

    async def _process_message(self, raw: str) -> str:
        """Parse, capture, and return an HL7v2 ACK string for one message."""
        # Parse phase: check well-formedness
        try:
            from airsdk_pro.hl7.parser import parse_hl7v2

            parsed = parse_hl7v2(raw)
            mcid = parsed.message_control_id
        except HL7v2ParseError:
            fallback_mcid = _extract_mcid_fallback(raw)
            return _build_ack_response(fallback_mcid, "AR")

        # Capture phase: blocking file I/O offloaded to thread pool
        if self._recorder is not None:
            try:
                from airsdk_pro.hl7.capture import instrument_hl7

                await asyncio.to_thread(
                    instrument_hl7,
                    self._recorder,
                    raw,
                    redaction_policy=self._redaction_policy,
                )
            except Exception:
                return _build_ack_response(mcid, "AE")

        # Enqueue for downstream processing if a queue was provided
        if self._pipeline_queue is not None:
            await self._pipeline_queue.put(raw)

        return _build_ack_response(mcid, "AA")
