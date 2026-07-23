"""Public first-run lead capture.

The ``air`` CLI collects an email on first run and POSTs it here so the operator
has a record of who installed. This route is intentionally **public** (listed in
``middleware.UNAUTHED_PATHS``): a first-time installer has no API key yet, so
requiring auth would defeat the entire purpose of lead capture.

Best-effort by contract: a storage hiccup must never fail a customer's install,
so a DynamoDB error is logged and swallowed and the caller still gets 200. The
row lands in the ``vindicara-identity-registrations`` table (pk: email,
sk: registered_at).
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from botocore.exceptions import BotoCoreError, ClientError
from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict

if TYPE_CHECKING:
    from mypy_boto3_dynamodb.service_resource import Table

router = APIRouter()
_log = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class IdentityRegistrationStore:
    """DynamoDB-backed store for first-run registrations."""

    def __init__(self, table: Table) -> None:
        self._table = table

    def record(
        self,
        *,
        email: str,
        source: str | None,
        version: str | None,
        platform: str | None,
    ) -> None:
        self._table.put_item(
            Item={
                "email": email,
                "registered_at": _now_iso(),
                "source": source or "",
                "version": version or "",
                "platform": platform or "",
            }
        )


class RegisterRequest(BaseModel):
    # Tolerate unknown fields so any CLI version can register without a 422.
    model_config = ConfigDict(extra="ignore")

    email: str
    source: str | None = None
    version: str | None = None
    platform: str | None = None


@router.post("/v1/identity/register")
async def register(body: RegisterRequest, request: Request) -> dict[str, str]:
    """Record a first-run email. Public and best-effort; always returns 200."""
    email = body.email.strip().lower()
    store: IdentityRegistrationStore | None = getattr(
        request.app.state, "identity_registrations", None
    )
    if store is not None and email:
        try:
            store.record(
                email=email,
                source=body.source,
                version=body.version,
                platform=body.platform,
            )
        except (BotoCoreError, ClientError):
            _log.warning("identity.register.store_failed")
    return {"status": "registered"}
