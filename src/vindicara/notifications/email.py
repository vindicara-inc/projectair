"""Activation email delivery via Resend for Stripe fulfillment."""
from __future__ import annotations

import json
from dataclasses import dataclass

import resend
import structlog

logger = structlog.get_logger()

_DASHBOARD_URL = "https://dashboard.vindicara.io"
_SENDER = "Vindicara <noreply@vindicara.io>"


class EmailDeliveryError(Exception):
    """Raised when the activation email cannot be sent."""


@dataclass(frozen=True)
class LicenseEmail:
    """All data needed to render and send an activation email."""

    recipient: str
    tier: str
    expires_at: int
    license_token: dict[str, object]
    wheel_download_url: str
    api_key: str | None = None
    workspace_name: str | None = None


def _render_text(email: LicenseEmail) -> str:
    """Render the plain-text activation email body."""
    token_json = json.dumps(email.license_token, indent=2)
    lines = [
        f"Welcome to Project AIR ({email.tier.title()})!",
        "",
        "Your license token (paste into `air login --license`):",
        "",
        token_json,
        "",
    ]
    if email.wheel_download_url:
        lines += [
            "Download your Pro wheel:",
            email.wheel_download_url,
            "",
        ]
    if email.api_key:
        lines += [
            "Your AIR Cloud API key (paste into `air cloud login --api-key`):",
            email.api_key,
            "",
        ]
    if email.workspace_name:
        lines += [f"Workspace: {email.workspace_name}", ""]

    lines += [
        f"Dashboard: {_DASHBOARD_URL}",
        "",
        "Quick start:",
        "  1. pip install projectair",
        "  2. air login --license '<paste token JSON>'",
    ]
    if email.api_key:
        lines.append(f"  3. air cloud login --api-key {email.api_key}")
    lines += ["", "Questions? Reply to this email or reach support@vindicara.io."]
    return "\n".join(lines)


def _render_html(email: LicenseEmail) -> str:
    """Render the HTML activation email body."""
    token_json = json.dumps(email.license_token, indent=2)
    sections: list[str] = []
    sections.append(f"<h2>Welcome to Project AIR ({email.tier.title()})!</h2>")
    sections.append(
        "<h3>License Token</h3>"
        "<p>Paste into <code>air login --license</code>:</p>"
        f"<pre style='background:#1a1a2e;color:#e0e0e0;padding:12px;"
        f"border-radius:4px;font-family:monospace;font-size:13px;"
        f"overflow-x:auto'>{token_json}</pre>"
    )
    if email.wheel_download_url:
        sections.append(
            "<h3>Pro Wheel</h3>"
            f"<p><a href='{email.wheel_download_url}'>Download</a></p>"
        )
    if email.api_key:
        sections.append(
            "<h3>AIR Cloud API Key</h3>"
            "<p>Paste into <code>air cloud login --api-key</code>:</p>"
            f"<pre style='background:#1a1a2e;color:#e0e0e0;padding:12px;"
            f"border-radius:4px;font-family:monospace'>{email.api_key}</pre>"
        )
    if email.workspace_name:
        sections.append(f"<p><strong>Workspace:</strong> {email.workspace_name}</p>")

    sections.append(f"<p><a href='{_DASHBOARD_URL}'>Open Dashboard</a></p>")
    sections.append(
        "<h3>Quick Start</h3><ol>"
        "<li><code>pip install projectair</code></li>"
        "<li><code>air login --license '&lt;paste token JSON&gt;'</code></li>"
    )
    if email.api_key:
        sections.append(
            f"<li><code>air cloud login --api-key {email.api_key}</code></li>"
        )
    sections.append("</ol>")
    return "\n".join(sections)


def send_license_email(email: LicenseEmail, *, api_key: str) -> str:
    """Send the activation email via Resend. Returns the Resend message ID.

    Raises ``EmailDeliveryError`` on misconfiguration or delivery failure.
    Fails closed: a missing API key raises immediately rather than
    silently dropping the email.
    """
    if not api_key:
        raise EmailDeliveryError("Resend API key is not configured")

    resend.api_key = api_key

    params: resend.Emails.SendParams = {
        "from": _SENDER,
        "to": [email.recipient],
        "subject": f"Your Project AIR {email.tier.title()} license is ready",
        "text": _render_text(email),
        "html": _render_html(email),
    }

    try:
        result = resend.Emails.send(params)
    except resend.exceptions.ResendError as exc:
        logger.error("email.send_failed", recipient=email.recipient, error=str(exc))
        raise EmailDeliveryError(f"Resend API error: {exc}") from exc

    msg_id: str = result.get("id", "") if isinstance(result, dict) else ""
    logger.info("email.sent", recipient=email.recipient, message_id=msg_id)
    return msg_id
