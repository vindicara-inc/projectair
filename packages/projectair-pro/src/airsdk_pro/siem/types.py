"""Shared types for the SIEM push helpers."""
from __future__ import annotations

from dataclasses import dataclass

SIEM_INTEGRATIONS_FEATURE = "siem-integrations"
"""License feature flag the SIEM helpers gate on."""

DEFAULT_TIMEOUT_SECONDS = 10.0
"""Default network timeout for SIEM HTTPS calls."""


class SiemConfigError(ValueError):
    """Configuration was missing or malformed before the request was sent."""


class SiemPushError(RuntimeError):
    """The vendor's HTTPS endpoint returned an error response."""

    def __init__(self, vendor: str, status_code: int, body: str) -> None:
        self.vendor = vendor
        self.status_code = status_code
        self.body = body
        super().__init__(
            f"{vendor} push failed with HTTP {status_code}: {body[:200]}"
        )


@dataclass(frozen=True)
class SiemPushResult:
    """Outcome of a successful SIEM push.

    Attributes
    ----------
    vendor:
        Which integration produced this result (``"datadog"`` /
        ``"splunk_hec"`` / ``"sumo"`` / ``"sentinel"``).
    events_sent:
        Number of finding-level events delivered to the SIEM.
    http_status:
        HTTP status code returned by the SIEM endpoint (always a 2xx
        for a result; non-2xx raises ``SiemPushError`` instead).
    endpoint:
        The full URL the helper POSTed to. Useful for log correlation.
    """

    vendor: str
    events_sent: int
    http_status: int
    endpoint: str
