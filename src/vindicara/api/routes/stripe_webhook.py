"""Stripe webhook handler for auto-fulfillment of Pro and Team purchases.

Flow: Stripe checkout -> webhook -> license token minted -> AIR Cloud
workspace provisioned -> API key generated -> activation email sent.

Authentication is via Stripe-Signature header verification (not the
standard X-Vindicara-Key middleware, which skips /webhooks/* paths).
"""
from __future__ import annotations

import secrets

import stripe
import structlog
from fastapi import APIRouter, Request
from starlette.responses import JSONResponse, Response

from vindicara.cloud.workspace import (
    ApiKey,
    ApiKeyStore,
    Workspace,
    WorkspaceStore,
    generate_api_key,
)
from vindicara.config.settings import VindicaraSettings
from vindicara.licensing.issuer import (
    LicenseIssuanceError,
    issue_license_token,
    plan_for_price_id,
)
from vindicara.notifications.email import (
    EmailDeliveryError,
    LicenseEmail,
    send_license_email,
)

logger = structlog.get_logger()
router = APIRouter(tags=["webhooks"])


# ------------------------------------------------------------------ #
# Helpers                                                              #
# ------------------------------------------------------------------ #


def _extract_email_from_checkout(session: dict[str, object]) -> str | None:
    """Pull the customer email from a checkout.session.completed event."""
    details = session.get("customer_details")
    if isinstance(details, dict):
        email = details.get("email")
        if isinstance(email, str) and email:
            return email
    # Fallback: top-level customer_email
    fallback = session.get("customer_email")
    if isinstance(fallback, str) and fallback:
        return fallback
    return None


def _extract_email_from_invoice(invoice: dict[str, object]) -> str | None:
    """Pull the customer email from an invoice.paid event."""
    email = invoice.get("customer_email")
    if isinstance(email, str) and email:
        return email
    return None


def _extract_price_id(session_id: str, api_key: str) -> str | None:
    """Fetch the first Price ID from a Checkout Session's line items."""
    stripe.api_key = api_key
    items = stripe.checkout.Session.list_line_items(session_id, limit=1)
    for item in items.data:
        price = getattr(item, "price", None)
        if price is not None:
            price_id: str = getattr(price, "id", "")
            if price_id:
                return price_id
    return None


def _workspace_slug(email: str) -> str:
    """Derive a workspace ID slug from an email address."""
    local = email.split("@")[0].lower().replace(".", "-")
    suffix = secrets.token_hex(4)
    return f"{local}-{suffix}"


def _provision_workspace(
    request: Request,
    email: str,
    tier: str,
) -> tuple[str | None, str | None]:
    """Create an AIR Cloud workspace and bootstrap API key.

    Returns (api_key_string, workspace_name) or (None, None) if the
    cloud stores are not available on this deployment.
    """
    ws_store: WorkspaceStore | None = getattr(request.app.state, "cloud_workspaces", None)
    key_store: ApiKeyStore | None = getattr(request.app.state, "cloud_api_keys", None)

    if ws_store is None or key_store is None:
        logger.warning("stripe.workspace_skip", reason="cloud stores not available")
        return None, None

    ws_id = _workspace_slug(email)
    ws_name = f"{email.split('@')[0]}'s {tier.title()} workspace"

    workspace = Workspace(
        workspace_id=ws_id,
        name=ws_name,
        owner_email=email,
    )
    ws_store.create(workspace)

    raw_key = generate_api_key()
    api_key_obj = ApiKey(
        key_id=f"ak_{secrets.token_hex(8)}",
        workspace_id=ws_id,
        key=raw_key,
        role="owner",
        name="bootstrap",
    )
    key_store.issue(api_key_obj)

    logger.info("stripe.workspace_created", workspace_id=ws_id, email=email)
    return raw_key, ws_name


# ------------------------------------------------------------------ #
# Fulfillment orchestration                                            #
# ------------------------------------------------------------------ #


def _fulfill_checkout(
    event: dict[str, object],
    request: Request,
    settings: VindicaraSettings,
) -> Response:
    """Handle checkout.session.completed: mint license + provision + email."""
    data = event.get("data", {})
    session: dict[str, object] = data.get("object", {}) if isinstance(data, dict) else {}

    email = _extract_email_from_checkout(session)
    if not email:
        logger.error("stripe.no_email", event_type="checkout.session.completed")
        return JSONResponse({"error": "Missing customer email"}, status_code=500)

    session_id = session.get("id", "")
    if not isinstance(session_id, str) or not session_id:
        logger.error("stripe.no_session_id")
        return JSONResponse({"error": "Missing session ID"}, status_code=500)

    price_id = _extract_price_id(session_id, settings.stripe_secret_key)
    if not price_id:
        logger.error("stripe.no_price_id", session_id=session_id)
        return JSONResponse({"error": "No line items found"}, status_code=500)

    plan = plan_for_price_id(price_id)
    token = issue_license_token(email, plan, settings.license_signing_key_pem)

    api_key, ws_name = _provision_workspace(request, email, plan.tier)

    license_email = LicenseEmail(
        recipient=email,
        tier=plan.tier,
        expires_at=token["expires_at"],  # type: ignore[arg-type]
        license_token=token,
        wheel_download_url=settings.pro_wheel_signed_url,
        api_key=api_key,
        workspace_name=ws_name,
    )
    send_license_email(license_email, api_key=settings.resend_api_key)

    logger.info("stripe.fulfilled", email=email, tier=plan.tier)
    return JSONResponse({"status": "fulfilled"})


def _fulfill_renewal(
    event: dict[str, object],
    request: Request,
    settings: VindicaraSettings,
) -> Response:
    """Handle invoice.paid for renewals: re-issue license, skip workspace."""
    data = event.get("data", {})
    invoice: dict[str, object] = data.get("object", {}) if isinstance(data, dict) else {}

    billing_reason = invoice.get("billing_reason", "")
    if billing_reason == "subscription_create":
        logger.info("stripe.invoice_skip", reason="subscription_create handled by checkout")
        return JSONResponse({"status": "skipped"})

    email = _extract_email_from_invoice(invoice)
    if not email:
        logger.error("stripe.no_email", event_type="invoice.paid")
        return JSONResponse({"error": "Missing customer email"}, status_code=500)

    lines = invoice.get("lines", {})
    price_id: str | None = None
    if isinstance(lines, dict):
        line_data = lines.get("data", [])
        if isinstance(line_data, list) and line_data:
            first = line_data[0]
            if isinstance(first, dict):
                price_obj = first.get("price", {})
                if isinstance(price_obj, dict):
                    pid = price_obj.get("id")
                    if isinstance(pid, str):
                        price_id = pid

    if not price_id:
        logger.error("stripe.no_price_in_invoice")
        return JSONResponse({"error": "No price in invoice lines"}, status_code=500)

    plan = plan_for_price_id(price_id)
    token = issue_license_token(email, plan, settings.license_signing_key_pem)

    license_email = LicenseEmail(
        recipient=email,
        tier=plan.tier,
        expires_at=token["expires_at"],  # type: ignore[arg-type]
        license_token=token,
        wheel_download_url=settings.pro_wheel_signed_url,
    )
    send_license_email(license_email, api_key=settings.resend_api_key)

    logger.info("stripe.renewed", email=email, tier=plan.tier)
    return JSONResponse({"status": "renewed"})


# ------------------------------------------------------------------ #
# Route handler                                                        #
# ------------------------------------------------------------------ #


@router.post("/webhooks/stripe")
async def stripe_webhook(request: Request) -> Response:
    """Receive Stripe webhook events and auto-fulfill purchases."""
    settings = VindicaraSettings()

    if not settings.stripe_webhook_secret:
        logger.error("stripe.webhook_secret_missing")
        return JSONResponse(
            {"error": "Webhook secret not configured"}, status_code=503,
        )

    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    try:
        event: dict[str, object] = stripe.Webhook.construct_event(
            payload, sig_header, settings.stripe_webhook_secret,
        )
    except stripe.SignatureVerificationError:
        logger.warning("stripe.bad_signature")
        return JSONResponse({"error": "Invalid signature"}, status_code=400)
    except ValueError:
        logger.warning("stripe.bad_payload")
        return JSONResponse({"error": "Invalid payload"}, status_code=400)

    event_type = event.get("type", "")
    logger.info("stripe.event_received", event_type=event_type)

    try:
        if event_type == "checkout.session.completed":
            return _fulfill_checkout(event, request, settings)
        if event_type == "invoice.paid":
            return _fulfill_renewal(event, request, settings)
    except LicenseIssuanceError as exc:
        logger.error("stripe.license_error", error=str(exc))
        return JSONResponse({"error": str(exc)}, status_code=500)
    except EmailDeliveryError as exc:
        logger.error("stripe.email_error", error=str(exc))
        return JSONResponse({"error": str(exc)}, status_code=500)

    # Unknown event type: acknowledge so Stripe doesn't retry.
    return JSONResponse({"status": "ignored"})
