"""Shared types for the AIR Cloud client."""
from __future__ import annotations

from dataclasses import dataclass

AIR_CLOUD_CLIENT_FEATURE = "air-cloud-client"
"""License feature flag the cloud-client helpers gate on."""

DEFAULT_TIMEOUT_SECONDS = 30.0
"""Default network timeout for cloud-client HTTPS calls (chain pushes can be larger than SIEM events)."""


class CloudConfigError(ValueError):
    """Configuration was missing or malformed before the request was sent."""


class CloudPushError(RuntimeError):
    """The destination returned an error response."""

    def __init__(self, target: str, status_code: int, body: str) -> None:
        self.target = target
        self.status_code = status_code
        self.body = body
        super().__init__(
            f"{target} push failed with HTTP {status_code}: {body[:200]}"
        )


@dataclass(frozen=True)
class CloudPushResult:
    """Outcome of a successful chain push to durable storage.

    Attributes
    ----------
    target:
        ``"webhook"`` or ``"s3"``.
    records_sent:
        Number of AgDR records delivered. Equals the length of the
        chain that was pushed.
    bytes_sent:
        Size of the JSONL payload in bytes (the wire form).
    endpoint:
        Description of where the chain landed. For webhook, the URL.
        For S3, ``s3://<bucket>/<key>``.
    """

    target: str
    records_sent: int
    bytes_sent: int
    endpoint: str
