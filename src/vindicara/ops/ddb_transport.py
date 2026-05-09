"""DynamoDB transport for ``airsdk.AIRRecorder``.

Each signed AgDR record is written as one DynamoDB item. The table is keyed
by ``chain_id`` (partition) + ``ord`` (sort), where ``chain_id`` identifies a
single Lambda invocation or dashboard request and ``ord`` is the
zero-padded record index within that chain.

The transport is intentionally synchronous: a put_item call per record on
the request thread. At Vindicara's traffic profile (under 1k req/day, single
digit records per chain) the DDB latency budget is well under the request
budget. The trade for simplicity is that emit() can raise; the caller
configures whether that fails the request or only logs (see
``failure_mode`` parameter).

The transport never touches the public S3 bucket. Publication is a separate
worker that reads from DDB and applies the redaction policy. This separation
is what lets the on-disk chain stay full-fidelity for internal verification
while the public chain stays redacted.
"""
from __future__ import annotations

import logging
from enum import StrEnum
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from airsdk.types import AgDRRecord
    from mypy_boto3_dynamodb.service_resource import Table

_log = logging.getLogger(__name__)

ORD_WIDTH: Final[int] = 6
"""Zero-padded sort-key width. Six digits supports up to 1M records per chain,
which is far above any realistic per-invocation chain length."""


class FailureMode(StrEnum):
    """How DDBTransport reacts when the put_item call fails."""

    HARD = "hard"
    """Re-raise the underlying exception. The caller (typically the API
    handler) sees the failure and chooses how to respond. Use this in
    development and for high-stakes operator paths where a chain gap is
    not acceptable."""

    SOFT = "soft"
    """Log the exception at WARNING and continue. The chain has a gap;
    AIR-04 will detect it during verification. Use this in the production
    Lambda hot path where availability of the API request matters more
    than chain completeness on a single record."""


class DDBTransport:
    """Writes each signed AgDR record to a DynamoDB table.

    Parameters
    ----------
    table:
        A boto3 DynamoDB Table resource. Construction is the caller's
        responsibility so a single table reference can be shared across
        multiple recorders (e.g. one per request) and so tests can pass
        a moto-backed table without monkeypatching boto3.
    chain_id:
        Identifier for the chain this transport is writing to. All
        records emitted through this transport land under the same
        partition key. Typically the AWS Lambda request id for API
        events; ``f"dashboard:{session_id}"`` for dashboard auth events.
    failure_mode:
        How to react when put_item fails. See :class:`FailureMode`.
    """

    def __init__(
        self,
        table: Table,
        chain_id: str,
        *,
        failure_mode: FailureMode = FailureMode.SOFT,
    ) -> None:
        if not chain_id:
            raise ValueError("chain_id must be a non-empty string")
        self._table = table
        self._chain_id = chain_id
        self._failure_mode = failure_mode
        self._ord = 0

    @property
    def chain_id(self) -> str:
        return self._chain_id

    @property
    def ord(self) -> int:
        """Number of records this transport has accepted so far."""
        return self._ord

    def emit(self, record: AgDRRecord) -> None:
        """Write one signed record to DynamoDB."""
        sort_key = f"{self._ord:0{ORD_WIDTH}d}"
        try:
            self._table.put_item(
                Item={
                    "chain_id": self._chain_id,
                    "ord": sort_key,
                    "step_id": record.step_id,
                    "kind": record.kind.value,
                    "timestamp": record.timestamp,
                    "record_json": record.model_dump_json(exclude_none=True),
                    "anchored": False,
                    "published": False,
                },
                ConditionExpression="attribute_not_exists(chain_id) AND attribute_not_exists(#o)",
                ExpressionAttributeNames={"#o": "ord"},
            )
        except Exception as exc:
            if self._failure_mode is FailureMode.HARD:
                raise
            _log.warning(
                "vindicara.ops.ddb_transport.put_item_failed",
                extra={
                    "chain_id": self._chain_id,
                    "ord": sort_key,
                    "step_id": record.step_id,
                    "error": str(exc),
                },
            )
        finally:
            self._ord += 1

    def drain(self, timeout: float) -> None:
        """No-op; writes are synchronous."""
        del timeout
