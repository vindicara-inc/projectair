"""Identity registration endpoint.

Unauthenticated: listed in ``_PUBLIC_PATHS`` prefix bypass in auth middleware.
Stores registrations in DynamoDB (``vindicara-identity-registrations``).
Falls back to in-memory dedup when the table env var is unset (local dev).
"""

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from fastapi import APIRouter
from pydantic import BaseModel, field_validator

if TYPE_CHECKING:
    from mypy_boto3_dynamodb.service_resource import Table

router = APIRouter(prefix="/api/v1/identity", tags=["identity"])
log = logging.getLogger(__name__)

_TABLE_NAME = os.environ.get("VINDICARA_IDENTITY_TABLE", "")

_registered_emails: set[str] = set()


class RegisterRequest(BaseModel):
    email: str
    source: str = "unknown"
    version: str = ""
    platform: str = ""

    @field_validator("email")
    @classmethod
    def _validate_email(cls, v: str) -> str:
        v = v.strip()
        if not v or "@" not in v:
            raise ValueError("email must contain @")
        if "." not in v.split("@")[-1]:
            raise ValueError("email domain must contain .")
        return v


def _get_table() -> Table:
    import boto3

    return boto3.resource("dynamodb").Table(_TABLE_NAME)


@router.post("/register", status_code=201)
async def register(body: RegisterRequest) -> dict[str, str]:
    """Register a CLI identity by email. Persists to DynamoDB."""
    now = datetime.now(UTC).isoformat()

    if _TABLE_NAME:
        try:
            table = _get_table()
            table.put_item(
                Item={
                    "email": body.email,
                    "registered_at": now,
                    "source": body.source,
                    "version": body.version,
                    "platform": body.platform,
                },
                ConditionExpression="attribute_not_exists(email)",
            )
            log.info("identity.register email=%s source=%s", body.email, body.source)
            return {"status": "registered"}
        except Exception as exc:
            if "ConditionalCheckFailedException" in str(type(exc).__name__):
                return {"status": "already_registered"}
            log.warning("identity.register ddb_error: %s", exc)
            return {"status": "registered"}
    else:
        if body.email in _registered_emails:
            return {"status": "already_registered"}
        _registered_emails.add(body.email)
        log.info("identity.register (in-memory) email=%s source=%s", body.email, body.source)
        return {"status": "registered"}
