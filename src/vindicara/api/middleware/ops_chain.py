"""FastAPI middleware that emits an AgDR chain entry per request.

Each incoming request opens a short signed chain through the
:mod:`vindicara.ops.recorder` helpers; the chain lands in the DynamoDB
ops chain table where the anchorer + publisher cron Lambdas pick it up
asynchronously. The hot-path overhead is one DDB put per request.

Behaviour in three deployment modes:

- **Production Lambda:** ``VINDICARA_OPS_CHAIN_TABLE`` is set by CDK; the
  middleware writes records on every request. The chain_id is the Lambda
  request id when Mangum exposes it; otherwise a fresh UUID4.
- **Local uvicorn dev:** no env var, no DDB available. The middleware
  is a no-op. This keeps `pytest` and `uvicorn --reload` working
  without AWS credentials.
- **Test:** as local dev unless a test fixture explicitly populates
  ``app.state.ops_chain_table``.
"""

import logging
import os
import time
import uuid
from typing import TYPE_CHECKING

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from vindicara.ops.ddb_transport import FailureMode
from vindicara.ops.recorder import OpsRecorder, open_recorder
from vindicara.ops.schema import OpsKind

if TYPE_CHECKING:
    from mypy_boto3_dynamodb.service_resource import Table

_log = logging.getLogger(__name__)
_PUBLIC_PATHS = {"/health", "/ready", "/docs", "/openapi.json", "/redoc"}


def _resolve_table() -> "Table | None":
    """Return a boto3 DynamoDB Table for the ops chain, or None if unavailable.

    No-op in any environment that lacks ``VINDICARA_OPS_CHAIN_TABLE``.
    Boto3 is only imported on the prod path so test environments without
    AWS credentials can still run.
    """
    table_name = os.environ.get("VINDICARA_OPS_CHAIN_TABLE")
    if not table_name:
        return None
    try:
        import boto3
    except ImportError:
        return None
    region = os.environ.get("AWS_REGION", "us-west-2")
    dynamodb = boto3.resource("dynamodb", region_name=region)
    return dynamodb.Table(table_name)


def _request_id(request: Request) -> str:
    """Pick a chain_id for this request.

    Preference order: Lambda request id (under Mangum), then RequestID
    middleware's ``request_id`` state, then a fresh UUID4.
    """
    aws_event = request.scope.get("aws.event")
    if isinstance(aws_event, dict):
        request_context = aws_event.get("requestContext")
        if isinstance(request_context, dict):
            req_id = request_context.get("requestId")
            if isinstance(req_id, str) and req_id:
                return req_id
    state_id = getattr(request.state, "request_id", None)
    if isinstance(state_id, str) and state_id:
        return state_id
    return uuid.uuid4().hex


class OpsChainMiddleware(BaseHTTPMiddleware):
    """Wrap every request in a short signed AgDR chain.

    Skips the public health/docs paths so the chain is not flooded by
    uptime probes.
    """

    def __init__(self, app: object) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self._table = _resolve_table()
        if self._table is None:
            _log.info("vindicara.ops.middleware.disabled_no_table")

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if self._table is None or request.url.path in _PUBLIC_PATHS:
            return await call_next(request)

        chain_id = _request_id(request)
        recorder = open_recorder(chain_id=chain_id, table=self._table, failure_mode=FailureMode.SOFT)
        ops = OpsRecorder(recorder)
        request.state.ops = ops

        start = time.monotonic()
        status_code = 0
        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        finally:
            duration_ms = (time.monotonic() - start) * 1000.0
            try:
                recorder.tool_start(
                    tool_name=OpsKind.API_REQUEST.value,
                    tool_args={
                        "method": request.method,
                        "path_template": request.url.path,
                    },
                    method=request.method,
                    path_template=request.url.path,
                )
                recorder.tool_end(
                    tool_output=str(status_code),
                    tool_name=OpsKind.API_REQUEST.value,
                    method=request.method,
                    path_template=request.url.path,
                    status_code=status_code,
                    duration_ms=duration_ms,
                )
            except Exception as exc:
                _log.warning(
                    "vindicara.ops.middleware.emit_failed",
                    extra={"chain_id": chain_id, "error": str(exc)},
                )
            for transport in recorder.transports:
                transport.drain(timeout=0.5)
