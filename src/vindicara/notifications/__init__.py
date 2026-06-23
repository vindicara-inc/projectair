"""Outbound transactional email."""
from vindicara.notifications.email import (
    EmailDeliveryError,
    LicenseEmail,
    ResultsEmail,
    send_license_email,
    send_results_email,
)

__all__ = [
    "EmailDeliveryError",
    "LicenseEmail",
    "ResultsEmail",
    "send_license_email",
    "send_results_email",
]
