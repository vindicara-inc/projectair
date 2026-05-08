"""Issue Ed25519-signed Vindicara Pro license tokens.

The signing side mirrors ``packages/projectair-pro/tools/issue_license.py``;
this module exists so the FastAPI Lambda can call ``issue_license_token`` in
process and load the private key from a string (env var or Secrets Manager
fetch) rather than a filesystem path.

Every token produced here verifies with ``airsdk_pro.license.verify_token``
on the customer side because both halves use the same canonicalization
(sorted keys, no whitespace, UTF-8) and the same Ed25519 keypair.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

TOKEN_VERSION = 1

# Feature bundles per tier. Mirror these in the pricing-page copy when changes
# ship; the verifier on the customer side enforces them via has_feature().
_INDIVIDUAL_FEATURES: tuple[str, ...] = (
    "air-cloud-client",
    "report-nist-ai-rmf",
    "report-soc2-ai",
    "premium-detectors",
)
_TEAM_FEATURES: tuple[str, ...] = (
    *_INDIVIDUAL_FEATURES,
    "team-workspace",
    "siem-export",
    "incident-workflows",
)


@dataclass(frozen=True)
class LicensePlan:
    """Resolved plan derived from a Stripe Price ID."""

    tier: str
    duration_days: int
    features: tuple[str, ...]


# Price ID → plan mapping. The Price IDs are public (they appear in Stripe
# Checkout URLs); the secret material is the signing key, not these.
_PRICE_TO_PLAN: dict[str, LicensePlan] = {
    "price_1TUFKqC4TNI7tWa0kzayypru": LicensePlan(
        tier="individual", duration_days=33, features=_INDIVIDUAL_FEATURES
    ),
    "price_1TUfRhC4TNI7tWa0v0joo1xG": LicensePlan(
        tier="individual", duration_days=395, features=_INDIVIDUAL_FEATURES
    ),
    "price_1TUfSDC4TNI7tWa0r7AmOjCh": LicensePlan(
        tier="team", duration_days=33, features=_TEAM_FEATURES
    ),
    "price_1TUfSrC4TNI7tWa0gdHeoFK9": LicensePlan(
        tier="team", duration_days=395, features=_TEAM_FEATURES
    ),
}


class LicenseIssuanceError(Exception):
    """Raised when a license cannot be issued (bad config, unknown price, etc.)."""


def plan_for_price_id(price_id: str) -> LicensePlan:
    """Resolve a Stripe Price ID to its license plan; raise if unknown.

    Webhook handlers should treat unknown Price IDs as a hard error rather
    than falling back to a default. An unrecognized Price could be a typo,
    a price the operator created but didn't intend to fulfill, or a probe.
    """
    plan = _PRICE_TO_PLAN.get(price_id)
    if plan is None:
        raise LicenseIssuanceError(
            f"unrecognized Stripe Price ID {price_id!r}; refusing to issue a license"
        )
    return plan


def _canonical_signing_bytes(payload: dict[str, object]) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _load_signing_key(pem: str) -> Ed25519PrivateKey:
    if not pem:
        raise LicenseIssuanceError(
            "license signing key is not configured; set VINDICARA_LICENSE_SIGNING_KEY_PEM"
        )
    key_obj = load_pem_private_key(pem.encode("utf-8"), password=None)
    if not isinstance(key_obj, Ed25519PrivateKey):
        raise LicenseIssuanceError(
            f"configured signing key is not Ed25519 (got {type(key_obj).__name__})"
        )
    return key_obj


def issue_license_token(
    *,
    email: str,
    plan: LicensePlan,
    signing_key_pem: str,
    issued_at: int | None = None,
) -> dict[str, object]:
    """Mint a signed license token for ``email`` under ``plan``.

    Returns the token as a dict, ready to ``json.dumps`` and hand to a
    customer. The verifier on the customer side enforces that the JSON is
    a single object whose signature validates against the embedded vendor
    public key, so callers must not mutate the dict before serialization.
    """
    if not email or "@" not in email:
        raise LicenseIssuanceError(f"invalid customer email: {email!r}")
    issued = issued_at if issued_at is not None else int(time.time())
    expires = issued + plan.duration_days * 86_400
    payload: dict[str, object] = {
        "v": TOKEN_VERSION,
        "email": email,
        "tier": plan.tier,
        "issued_at": issued,
        "expires_at": expires,
        "features": sorted(plan.features),
    }
    private_key = _load_signing_key(signing_key_pem)
    signature = private_key.sign(_canonical_signing_bytes(payload)).hex()
    return {**payload, "signature": signature}
