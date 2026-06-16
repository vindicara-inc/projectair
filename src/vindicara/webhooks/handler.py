"""Stripe webhook Lambda handler.

Receives checkout.session.completed events and provisions:
1. Auth0 user account (password-reset email sent automatically)
2. API key in DynamoDB (SHA-256 hashed, raw key in Auth0 app_metadata)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from typing import Any
from urllib import request as urllib_request
from urllib.error import HTTPError

import boto3

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

STRIPE_WEBHOOK_SECRET = os.environ["STRIPE_WEBHOOK_SECRET"]
AUTH0_DOMAIN = os.environ["AUTH0_DOMAIN"]
AUTH0_MGMT_CLIENT_ID = os.environ["AUTH0_MGMT_CLIENT_ID"]
AUTH0_MGMT_CLIENT_SECRET = os.environ["AUTH0_MGMT_CLIENT_SECRET"]
AUTH0_SPA_CLIENT_ID = os.environ["AUTH0_SPA_CLIENT_ID"]
AUTH0_CONNECTION = os.environ.get("AUTH0_CONNECTION", "Username-Password-Authentication")
API_KEYS_TABLE = os.environ["API_KEYS_TABLE"]

PLAN_MAP: dict[str, str] = {
    "price_individual_monthly": "individual",
    "price_individual_annual": "individual",
    "price_team_monthly": "team",
    "price_team_annual": "team",
}

dynamodb = boto3.resource("dynamodb")


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    body = event.get("body", "")
    sig = event.get("headers", {}).get("stripe-signature", "")
    if not _verify_stripe_sig(body.encode(), sig, STRIPE_WEBHOOK_SECRET):
        return {"statusCode": 400, "body": "Invalid signature"}

    payload = json.loads(body)
    event_type = payload.get("type", "")
    if event_type != "checkout.session.completed":
        return {"statusCode": 200, "body": "ignored"}

    session = payload["data"]["object"]
    email = session.get("customer_email") or session.get("customer_details", {}).get("email")
    if not email:
        logger.error("no email in checkout session")
        return {"statusCode": 400, "body": "no customer email"}

    stripe_customer_id = session.get("customer", "")
    stripe_sub_id = session.get("subscription", "")

    try:
        mgmt_token = _get_mgmt_token()
        api_key = _generate_api_key()
        user_id = _create_auth0_user(mgmt_token, email, api_key, stripe_customer_id, stripe_sub_id)
        _store_api_key(api_key, user_id, email)
        _send_password_reset(email)
        logger.info("provisioned: %s (user_id=%s)", email, user_id)
        return {"statusCode": 200, "body": json.dumps({"provisioned": email})}
    except Exception:
        logger.exception("provisioning failed for %s", email)
        return {"statusCode": 500, "body": "provisioning error"}


def _verify_stripe_sig(payload: bytes, sig_header: str, secret: str) -> bool:
    parts: dict[str, str] = {}
    for item in sig_header.split(","):
        if "=" in item:
            k, v = item.strip().split("=", 1)
            parts[k] = v
    ts = parts.get("t", "")
    sig = parts.get("v1", "")
    if not ts or not sig:
        return False
    signed = f"{ts}.{payload.decode()}".encode()
    expected = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig)


def _get_mgmt_token() -> str:
    body = json.dumps(
        {
            "client_id": AUTH0_MGMT_CLIENT_ID,
            "client_secret": AUTH0_MGMT_CLIENT_SECRET,
            "audience": f"https://{AUTH0_DOMAIN}/api/v2/",
            "grant_type": "client_credentials",
        }
    ).encode()
    req = urllib_request.Request(
        f"https://{AUTH0_DOMAIN}/oauth/token",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib_request.urlopen(req) as resp:
        return str(json.loads(resp.read())["access_token"])


def _generate_api_key() -> str:
    return f"vnd_{secrets.token_hex(24)}"


def _create_auth0_user(
    token: str,
    email: str,
    api_key: str,
    stripe_cust: str,
    stripe_sub: str,
) -> str:
    body = json.dumps(
        {
            "email": email,
            "password": secrets.token_urlsafe(32),
            "connection": AUTH0_CONNECTION,
            "email_verified": True,
            "app_metadata": {
                "api_key": api_key,
                "stripe_customer_id": stripe_cust,
                "stripe_subscription_id": stripe_sub,
                "provisioned_at": int(time.time()),
            },
        }
    ).encode()
    req = urllib_request.Request(
        f"https://{AUTH0_DOMAIN}/api/v2/users",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )
    try:
        with urllib_request.urlopen(req) as resp:
            return str(json.loads(resp.read())["user_id"])
    except HTTPError as e:
        err = e.read().decode()
        if e.code == 409:
            logger.info("user already exists, updating metadata: %s", email)
            return _update_existing_user(token, email, api_key, stripe_cust, stripe_sub)
        raise RuntimeError(f"Auth0 create user failed: {e.code} {err}") from e


def _update_existing_user(
    token: str,
    email: str,
    api_key: str,
    stripe_cust: str,
    stripe_sub: str,
) -> str:
    search_req = urllib_request.Request(
        f"https://{AUTH0_DOMAIN}/api/v2/users-by-email?email={email}",
        headers={"Authorization": f"Bearer {token}"},
    )
    with urllib_request.urlopen(search_req) as resp:
        users = json.loads(resp.read())
    if not users:
        raise RuntimeError(f"user {email} not found after 409")
    user_id: str = users[0]["user_id"]
    body = json.dumps(
        {
            "app_metadata": {
                "api_key": api_key,
                "stripe_customer_id": stripe_cust,
                "stripe_subscription_id": stripe_sub,
                "provisioned_at": int(time.time()),
            },
        }
    ).encode()
    req = urllib_request.Request(
        f"https://{AUTH0_DOMAIN}/api/v2/users/{user_id}",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
        method="PATCH",
    )
    with urllib_request.urlopen(req) as resp:
        resp.read()
    return user_id


def _store_api_key(raw_key: str, owner_id: str, email: str) -> None:
    # raw_key is a high-entropy random token (vnd_ + secrets.token_hex(24) = 192 bits),
    # not a password. SHA-256 is the standard, OWASP-endorsed storage hash for such
    # tokens, enabling O(1) lookup via the DynamoDB by_key_hash GSI. A password KDF
    # (bcrypt/argon2) adds no security for 192-bit secrets and would break that lookup.
    # (Webhook *signature* verification — the integrity-critical path — uses HMAC-SHA256
    # + hmac.compare_digest above.) See CodeQL #17 disposition.
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    table = dynamodb.Table(API_KEYS_TABLE)
    table.put_item(
        Item={
            "pk": key_hash,
            "owner_id": owner_id,
            "email": email,
            "created_at": int(time.time()),
        }
    )


def _send_password_reset(email: str) -> None:
    body = json.dumps(
        {
            "client_id": AUTH0_SPA_CLIENT_ID,
            "email": email,
            "connection": AUTH0_CONNECTION,
        }
    ).encode()
    req = urllib_request.Request(
        f"https://{AUTH0_DOMAIN}/dbconnections/change_password",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib_request.urlopen(req) as resp:
        resp.read()
