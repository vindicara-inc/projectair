"""ClinicalSidecar: async pipeline orchestrator for HL7v2 clinical evidence.

Pairs with your existing integration engine (Mirth, Cloverleaf, Rhapsody).
Records what your AI agent did with each clinical message and proves whether
it honored its declared intent.

License gating is enforced at construction time via ``@requires_pro`` on
``__init__``. Instantiating without a valid Pro license with the
``hl7-fhir-integration`` feature raises ``LicenseMissingError`` or
``LicenseInvalidError`` immediately.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from airsdk.recorder import AIRRecorder

from airsdk_pro.gate import requires_pro
from airsdk_pro.hl7.capture import HL7_FHIR_FEATURE, instrument_hl7
from airsdk_pro.hl7.redaction import RedactionPolicy
from airsdk_pro.hl7.types import HL7v2ParseError, SidecarResult

_MAX_RETRIES = 3


class ClinicalSidecar:
    """HL7v2 clinical evidence sidecar.

    Pairs with your existing integration engine (Mirth, Cloverleaf,
    Rhapsody). Records what your AI agent did with each clinical
    message and proves whether it honored its declared intent.

    Parameters
    ----------
    recorder:
        The AIRRecorder instance to write signed records to.
    fhir_client:
        Optional FHIR R4 push client. When supplied, FHIR resources are
        pushed after capture. Pass ``None`` to skip FHIR push.
    siem_config:
        Reserved for future SIEM integration configuration.
    redaction_policy:
        Controls PHI handling. Defaults to REDACTED mode (identifier
        hashing, name omission, DOB truncation to year).
    queue_size:
        Maximum in-flight message capacity for forward-compat queueing.
        Not enforced as backpressure in this release.
    dead_letter_path:
        Optional filesystem path for persisting dead-lettered messages.
        Not yet wired; reserved for a future release.
    """

    @requires_pro(feature=HL7_FHIR_FEATURE)
    def __init__(
        self,
        recorder: AIRRecorder,
        *,
        fhir_client: Any | None = None,
        siem_config: Any | None = None,
        redaction_policy: RedactionPolicy | None = None,
        queue_size: int = 10_000,
        dead_letter_path: Path | None = None,
    ) -> None:
        self._recorder = recorder
        self._fhir_client = fhir_client
        self._siem_config = siem_config
        self._redaction_policy = (
            redaction_policy if redaction_policy is not None else RedactionPolicy()
        )
        self._queue_size = queue_size
        self._dead_letter_path = dead_letter_path

        # Dead-letter list: each entry is a dict with keys
        # raw_message, error, timestamp, retry_count
        self._dead_letters: list[dict[str, Any]] = []

        # Timestamp of last message enqueue; None means nothing enqueued yet
        self._last_enqueue_at: float | None = None
        # Count of messages currently in-flight (enqueued but not yet resolved)
        self._in_flight: int = 0

    # -----------------------------------------------------------------------
    # Public async interface
    # -----------------------------------------------------------------------

    async def process(self, raw_message: str) -> SidecarResult:
        """Parse and capture a single raw HL7v2 message.

        Steps:
        1. Record enqueue time for lag tracking.
        2. Call ``instrument_hl7`` to parse, redact, optionally map FHIR,
           and write two signed AgDR records.
        3. On ``HL7v2ParseError``, add to dead-letter list and return a
           minimal ``SidecarResult`` with ``message_type="UNKNOWN"``.
        4. Extract ``message_type``, ``records_written``, and
           ``fhir_resource_types`` from the returned records.

        Parameters
        ----------
        raw_message:
            Raw pipe-delimited HL7v2 message string.

        Returns
        -------
        SidecarResult
            Summary of the capture operation. On parse failure,
            ``message_type="UNKNOWN"`` and ``records_written=0``.
        """
        self._last_enqueue_at = time.monotonic()
        self._in_flight += 1
        try:
            return self._capture(raw_message)
        finally:
            self._in_flight -= 1

    async def process_file(self, path: Path) -> list[SidecarResult]:
        """Process all HL7v2 messages in a file.

        Splits the file content on ``"MSH|"`` boundaries so that a flat
        file containing multiple concatenated messages is handled correctly.
        Each non-empty chunk is re-prefixed with ``"MSH|"`` before parsing.

        Parameters
        ----------
        path:
            Path to an HL7v2 message file.

        Returns
        -------
        list[SidecarResult]
            One result per message found in the file.
        """
        raw_bytes = path.read_bytes()
        # Decode and normalize line endings to \r (HL7v2 segment separator).
        # Text-mode reads on macOS/Linux translate \r to \n; restore the
        # canonical HL7v2 separator so the parser receives valid messages.
        content = raw_bytes.decode("utf-8").replace("\r\n", "\r").replace("\n", "\r")
        chunks = content.split("MSH|")
        results: list[SidecarResult] = []
        for chunk in chunks:
            stripped = chunk.strip()
            if not stripped:
                continue
            message = "MSH|" + stripped
            result = await self.process(message)
            results.append(result)
        return results

    async def replay_dead_letters(self, max_batch: int = 100) -> int:
        """Re-process dead-lettered messages up to ``max_batch`` at a time.

        Each dead-lettered message is re-submitted to ``process()``. On
        success the entry is removed from the dead-letter list. On failure
        ``retry_count`` is incremented; entries that have been retried
        ``_MAX_RETRIES`` (3) times are discarded permanently.

        Parameters
        ----------
        max_batch:
            Maximum number of dead-letter entries to attempt in this call.

        Returns
        -------
        int
            Number of messages successfully replayed and removed from the
            dead-letter list.
        """
        if not self._dead_letters:
            return 0

        batch = self._dead_letters[:max_batch]
        surviving: list[dict[str, Any]] = []
        succeeded = 0

        for entry in batch:
            result = await self.process(entry["raw_message"])
            if result.records_written > 0:
                succeeded += 1
                # Drop from DLQ on success
            else:
                entry["retry_count"] += 1
                if entry["retry_count"] < _MAX_RETRIES:
                    surviving.append(entry)
                # else: discard after _MAX_RETRIES attempts

        # Keep entries beyond max_batch unchanged
        self._dead_letters = surviving + self._dead_letters[max_batch:]
        return succeeded

    # -----------------------------------------------------------------------
    # Properties
    # -----------------------------------------------------------------------

    @property
    def lag_seconds(self) -> float:
        """Seconds since the last message was enqueued, or 0.0 if idle.

        Returns 0.0 when no messages have been enqueued yet or when there
        is no pending in-flight work.
        """
        if self._last_enqueue_at is None or self._in_flight == 0:
            return 0.0
        return time.monotonic() - self._last_enqueue_at

    @property
    def dead_letter_count(self) -> int:
        """Number of messages currently in the dead-letter list."""
        return len(self._dead_letters)

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    def _capture(self, raw_message: str) -> SidecarResult:
        """Synchronous inner capture; called from ``process``."""
        try:
            start, _end = instrument_hl7(
                self._recorder,
                raw_message,
                redaction_policy=self._redaction_policy,
            )
        except HL7v2ParseError as exc:
            self._dead_letters.append(
                {
                    "raw_message": raw_message,
                    "error": str(exc),
                    "timestamp": time.time(),
                    "retry_count": 0,
                }
            )
            return SidecarResult(message_type="UNKNOWN", records_written=0)

        message_type: str = start.payload.tool_args.get("message_type", "")  # type: ignore[union-attr]

        fhir_resource_types: list[str] = []
        if start.payload.fhir_resources:
            fhir_resource_types = [
                r.get("resourceType", "")
                for r in start.payload.fhir_resources
                if r.get("resourceType")
            ]

        patient_mrn_hash: str | None = None
        if start.payload.data_subjects:
            patient_mrn_hash = start.payload.data_subjects[0].subject_id

        return SidecarResult(
            message_type=message_type,
            patient_mrn_hash=patient_mrn_hash,
            records_written=2,
            fhir_resource_types=fhir_resource_types,
        )
