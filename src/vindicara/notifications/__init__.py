"""Outbound transactional email."""
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
