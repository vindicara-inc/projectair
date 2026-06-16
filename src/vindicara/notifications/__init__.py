"""Transactional email delivery for Stripe fulfillment."""

from __future__ import annotations

from vindicara.notifications.email import (
    EmailDeliveryError,
    LicenseEmail,
    send_license_email,
)

__all__ = [
    "EmailDeliveryError",
    "LicenseEmail",
    "send_license_email",
]
