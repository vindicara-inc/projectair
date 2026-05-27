"""Ed25519-signed license token issuer for Stripe fulfillment.

Tokens are JSON dicts with a ``signature`` field containing the
base64url-encoded (no padding) Ed25519 signature over the canonical
JSON form of all other fields (sorted keys, no whitespace).  This
encoding survives JSON transport without escaping issues.
"""
from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

# ------------------------------------------------------------------ #
# Plan catalogue                                                      #
# ------------------------------------------------------------------ #

_INDIVIDUAL_FEATURES: tuple[str, ...] = (
    "air-cloud-client",
    "report-nist-ai-rmf",
    "report-soc2-ai",
    "premium-detectors",
    "siem-integrations",
)

_TEAM_FEATURES: tuple[str, ...] = (
    *_INDIVIDUAL_FEATURES,
    "team-workspace",
    "siem-export",
    "incident-workflows",
)


@dataclass(frozen=True)
class LicensePlan:
    """Describes what a Stripe Price ID entitles the buyer to."""

    tier: str
    duration_days: int
    features: tuple[str, ...]


_PRICE_PLANS: dict[str, LicensePlan] = {
    # Individual / Pro
    "price_1TUFKqC4TNI7tWa0kzayypru": LicensePlan("pro", 33, _INDIVIDUAL_FEATURES),
    "price_1TUfRhC4TNI7tWa0v0joo1xG": LicensePlan("pro", 395, _INDIVIDUAL_FEATURES),
    # Team
    "price_1TUfSDC4TNI7tWa0r7AmOjCh": LicensePlan("team", 33, _TEAM_FEATURES),
    "price_1TUfSrC4TNI7tWa0gdHeoFK9": LicensePlan("team", 395, _TEAM_FEATURES),
}


class LicenseIssuanceError(Exception):
    """Raised when a license token cannot be minted."""


# ------------------------------------------------------------------ #
# Public helpers                                                      #
# ------------------------------------------------------------------ #


def plan_for_price_id(price_id: str) -> LicensePlan:
    """Look up the plan for a Stripe Price ID or raise."""
    plan = _PRICE_PLANS.get(price_id)
    if plan is None:
        raise LicenseIssuanceError(f"Unknown Stripe Price ID: {price_id!r}")
    return plan


def issue_license_token(
    email: str,
    plan: LicensePlan,
    signing_key_pem: str,
) -> dict[str, object]:
    """Mint an Ed25519-signed license token.

    Returns a dict suitable for JSON serialization.  The ``signature``
    field is base64url (no-pad) over canonical JSON of all other fields.
    """
    now = int(time.time())
    payload: dict[str, object] = {
        "v": 1,
        "email": email,
        "tier": plan.tier,
        "issued_at": now,
        "expires_at": now + plan.duration_days * 86400,
        "features": list(plan.features),
    }

    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    try:
        raw_key = load_pem_private_key(signing_key_pem.encode(), password=None)
    except (ValueError, TypeError) as exc:
        raise LicenseIssuanceError(f"Invalid signing key PEM: {exc}") from exc

    if not isinstance(raw_key, Ed25519PrivateKey):
        raise LicenseIssuanceError("Signing key is not Ed25519")

    signature_bytes = raw_key.sign(canonical)
    payload["signature"] = base64.urlsafe_b64encode(signature_bytes).rstrip(b"=").decode()
    return payload
