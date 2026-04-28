"""Transport sinks for ``AIRRecorder`` to write Signed Intent Capsules to.

A transport receives every signed AgDR record the recorder emits and is
responsible for getting it somewhere durable. Two implementations ship in
the OSS package:

- :class:`FileTransport` appends each record as a JSONL line to a local
  log file. This is the historical default behaviour of ``AIRRecorder`` and
  remains what callers get when they pass no ``transports=`` argument.
- :class:`HTTPTransport` POSTs each record to a remote ingestion endpoint
  (AIR Cloud, an in-VPC AIR Enterprise deployment, or any HTTP server that
  accepts the AgDR record schema) on a background worker thread, so the
  agent loop is never blocked on the network.

Recorders accept a list of transports, so callers can compose them: write
to disk *and* push to AIR Cloud, write to disk *and* a custom test sink,
etc. The :class:`Transport` Protocol is intentionally minimal so additional
sinks (S3, Kafka, syslog) can land later without touching the recorder.
"""
from __future__ import annotations

import atexit
import json
import logging
import queue
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Protocol, runtime_checkable

from airsdk.types import AgDRRecord

_log = logging.getLogger(__name__)
_DEFAULT_HTTP_TIMEOUT_SECONDS = 5.0
_DEFAULT_QUEUE_CAPACITY = 10_000
_DEFAULT_DRAIN_TIMEOUT_SECONDS = 5.0


@runtime_checkable
class Transport(Protocol):
    """A sink the recorder hands every signed record to.

    Implementations must be safe to call from any thread the recorder runs
    on. ``emit`` is allowed to be slow on its own time (e.g. disk fsync) but
    must not raise; durability is the implementation's job. ``drain`` is
    called at process shutdown to flush any in-flight work.
    """

    def emit(self, record: AgDRRecord) -> None:
        """Hand a single signed record to this transport."""
        ...

    def drain(self, timeout: float) -> None:
        """Block up to ``timeout`` seconds for in-flight work to complete."""
        ...


class FileTransport:
    """Append each record as a JSONL line to ``log_path``.

    This is the OSS-default transport. Writes are synchronous and durable
    (the file handle is reopened in append-mode for each emit, matching the
    historical behaviour of ``AIRRecorder._emit``). Parent directories are
    created on first write.
    """

    def __init__(self, log_path: str | Path) -> None:
        self._log_path = Path(log_path).expanduser()
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    @property
    def log_path(self) -> Path:
        return self._log_path

    def emit(self, record: AgDRRecord) -> None:
        line = record.model_dump_json(exclude_none=True)
        with self._lock, self._log_path.open("a", encoding="utf-8") as handle:
            handle.write(line)
            handle.write("\n")

    def drain(self, timeout: float) -> None:
        # Disk writes are synchronous; nothing to wait on.
        del timeout


class HTTPTransport:
    """POST each record to a remote ``/v1/capsules`` endpoint on a background worker.

    The customer's agent loop is never blocked on the network: ``emit``
    enqueues the record and returns immediately. A daemon worker thread
    drains the queue and POSTs each record with stdlib ``urllib`` (no
    additional runtime dependency on ``requests`` or ``httpx``).

    The queue is bounded; if the receiver stalls and the queue fills, new
    records are dropped with a structured warning rather than blocking the
    agent or growing memory unbounded. ``FileTransport`` paired with
    ``HTTPTransport`` is the recommended composition for production: disk
    is the durable buffer, HTTP is best-effort.

    Parameters
    ----------
    endpoint:
        Base URL of the receiving server. The path ``/v1/capsules`` is
        appended automatically.
    api_key:
        Optional bearer token sent in the configured auth header. AIR Cloud
        and AIR Enterprise authenticate via ``X-Vindicara-Key`` by default;
        pass ``api_key_header="X-API-Key"`` (or any other name) when pointing
        at a custom receiver that uses a different header.
    api_key_header:
        Name of the header carrying ``api_key``. Defaults to AIR Cloud's
        ``X-Vindicara-Key``.
    timeout:
        Per-request timeout in seconds. Default 5.
    queue_capacity:
        Maximum in-flight records before drops begin. Default 10_000.
    """

    def __init__(
        self,
        endpoint: str,
        api_key: str | None = None,
        *,
        api_key_header: str = "X-Vindicara-Key",
        timeout: float = _DEFAULT_HTTP_TIMEOUT_SECONDS,
        queue_capacity: int = _DEFAULT_QUEUE_CAPACITY,
    ) -> None:
        if not endpoint.startswith(("http://", "https://")):
            raise ValueError(f"endpoint must start with http:// or https://, got {endpoint!r}")
        self._url = endpoint.rstrip("/") + "/v1/capsules"
        self._api_key = api_key
        self._api_key_header = api_key_header
        self._timeout = timeout
        self._queue: queue.Queue[AgDRRecord | None] = queue.Queue(maxsize=queue_capacity)
        self._dropped = 0
        self._worker = threading.Thread(target=self._run, daemon=True, name="airsdk-http-transport")
        self._worker.start()
        atexit.register(self._atexit_drain)

    @property
    def endpoint(self) -> str:
        return self._url

    @property
    def dropped_count(self) -> int:
        """Number of records dropped because the queue was full."""
        return self._dropped

    def emit(self, record: AgDRRecord) -> None:
        try:
            self._queue.put_nowait(record)
        except queue.Full:
            self._dropped += 1
            _log.warning(
                "airsdk.http_transport queue full; dropping record",
                extra={"step_id": record.step_id, "dropped_total": self._dropped},
            )

    def drain(self, timeout: float) -> None:
        """Block up to ``timeout`` seconds for the queue to empty."""
        deadline = threading.Event()
        threading.Timer(timeout, deadline.set).start()
        while not self._queue.empty() and not deadline.is_set():
            deadline.wait(0.05)

    def close(self) -> None:
        """Signal the worker to exit and wait briefly for it to finish."""
        self._queue.put(None)
        self._worker.join(timeout=_DEFAULT_DRAIN_TIMEOUT_SECONDS)

    def _atexit_drain(self) -> None:
        # Best-effort flush at process shutdown so the last few records
        # (precisely the ones an investigator wants most after an incident)
        # are not lost.
        self.drain(_DEFAULT_DRAIN_TIMEOUT_SECONDS)

    def _run(self) -> None:
        while True:
            record = self._queue.get()
            if record is None:
                return
            try:
                self._post(record)
            except Exception as exc:
                # Worker thread must swallow all exceptions: failures are logged,
                # the disk transport (if composed) is the durable path.
                _log.warning(
                    "airsdk.http_transport POST failed",
                    extra={"step_id": record.step_id, "error": str(exc)},
                )
            finally:
                self._queue.task_done()

    def _post(self, record: AgDRRecord) -> None:
        body = record.model_dump_json(exclude_none=True).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers[self._api_key_header] = self._api_key
        request = urllib.request.Request(self._url, data=body, headers=headers, method="POST")  # noqa: S310 - http(s) scheme enforced at construction
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:  # noqa: S310 - http(s) scheme enforced at construction
                # Drain the body so the connection is reusable; we do not
                # parse the response, success is the 2xx status code.
                response.read()
        except urllib.error.HTTPError as exc:
            # 4xx from the server (verification rejection, auth fail, etc.)
            # is logged at warning; 5xx is logged at warning too. Either
                # way the disk transport (if composed) still has the record.
            try:
                detail = exc.read().decode("utf-8", errors="replace")
            except Exception:
                detail = ""
            try:
                detail_obj = json.loads(detail)
                detail_text = detail_obj.get("detail", detail)
            except json.JSONDecodeError:
                detail_text = detail
            _log.warning(
                "airsdk.http_transport server rejected record",
                extra={"step_id": record.step_id, "status": exc.code, "detail": detail_text},
            )
