"""Send the post-purchase license activation email via Resend.

Webhook handlers call ``send_license_email`` after a successful Stripe
``checkout.session.completed`` event to deliver the signed license token
plus a wheel download URL to the buyer. The function fails closed: if
``resend_api_key`` is empty, it raises rather than silently dropping the
email, since a missed delivery is worse than a webhook retry.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from textwrap import dedent

import resend  # type: ignore[import-untyped]
import structlog

logger = structlog.get_logger(__name__)

_DEFAULT_SENDER = "Vindicara <noreply@vindicara.io>"


class EmailDeliveryError(Exception):
    """Raised when the Resend API rejects or fails to send the activation email."""


@dataclass(frozen=True)
class LicenseEmail:
    """Inputs to the activation email; one per successful checkout session."""

    recipient: str
    tier: str
    expires_at: int
    license_token: dict[str, object]
    wheel_download_url: str


def _render_text(payload: LicenseEmail) -> str:
    token_json = json.dumps(payload.license_token, indent=2, ensure_ascii=False)
    expires_iso = _epoch_to_iso(payload.expires_at)
    return dedent(
        f"""
        You bought {payload.tier.title()} on Vindicara AIR. Welcome.

        Two artifacts below: your license token (signed Ed25519, verifies offline) and the projectair-pro wheel download link.

        ---
        License token (paste this into `air login --license`)
        ---
        {token_json}

        ---
        Install projectair-pro
        ---
        1. Download the wheel: {payload.wheel_download_url}
           (this URL expires in 24h; reply to this email if you need a fresh one)
        2. pip install projectair-pro-<version>-py3-none-any.whl
        3. air login --license '<paste the token above>'
        4. air status

        ---
        License details
        ---
        Tier:        {payload.tier}
        Expires:     {expires_iso} UTC
        Verify:      `air status` checks the signature locally; no phone-home.

        Questions, problems, anything: reply directly to this email and a
        human responds inside business hours.

        Vindicara, Inc.
        696 S New Hampshire Ave, Los Angeles, CA 90005
        https://vindicara.io
        """
    ).strip()


def _render_html(payload: LicenseEmail) -> str:
    text_body = _render_text(payload)
    escaped = (
        text_body.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    )
    return f"<pre style=\"font-family: ui-monospace, SF Mono, Menlo, monospace; font-size: 13px; line-height: 1.5;\">{escaped}</pre>"


def _epoch_to_iso(epoch_seconds: int) -> str:
    import datetime as _dt

    return _dt.datetime.fromtimestamp(epoch_seconds, tz=_dt.timezone.utc).strftime(
        "%Y-%m-%d %H:%M"
    )


def send_license_email(
    payload: LicenseEmail,
    *,
    resend_api_key: str,
    sender: str = _DEFAULT_SENDER,
) -> str:
    """Deliver the activation email; return the Resend message id.

    Raises ``EmailDeliveryError`` if the API rejects the send or if the API
    key is unset. Callers (the webhook handler) treat this as a 5xx response
    so Stripe retries the event rather than silently losing the license.
    """
    if not resend_api_key:
        raise EmailDeliveryError(
            "RESEND_API_KEY is not configured; refusing to silently drop a license email"
        )

    resend.api_key = resend_api_key
    params: dict[str, object] = {
        "from": sender,
        "to": [payload.recipient],
        "subject": f"Your Vindicara AIR {payload.tier.title()} license",
        "text": _render_text(payload),
        "html": _render_html(payload),
    }
    try:
        result = resend.Emails.send(params)
    except Exception as exc:
        logger.error("resend.send_failed", recipient=payload.recipient, error=str(exc))
        raise EmailDeliveryError(f"Resend send failed: {exc}") from exc

    message_id = str(result.get("id", "")) if isinstance(result, dict) else ""
    if not message_id:
        raise EmailDeliveryError(f"Resend returned no message id: {result!r}")
    logger.info(
        "resend.send_ok",
        recipient=payload.recipient,
        tier=payload.tier,
        message_id=message_id,
    )
    return message_id
