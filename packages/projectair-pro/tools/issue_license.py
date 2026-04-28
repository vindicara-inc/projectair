"""Mint a Vindicara Pro license token using the vendor private key.

VENDOR-ONLY. This script is intentionally NOT distributed in the
projectair-pro wheel. It uses the Ed25519 private key kept in
``~/.airsdk-vendor/license_signing.key`` (default; override via
``VINDICARA_LICENSE_KEY_PATH``) to sign a license token for a customer.

The signed token is a single JSON line that the customer pastes into
``air login --license <token>``. Verification is local on the customer
machine against the embedded vendor public key.

Usage::

    python packages/projectair-pro/tools/issue_license.py \\
        --email customer@example.com \\
        --tier individual \\
        --duration-days 365 \\
        --features air-cloud-client report-nist-ai-rmf report-soc2-ai

Output is a JSON token printed to stdout. Pipe to ``pbcopy`` (macOS) or
write to a file before sending to the customer. Never commit minted tokens
to git.

Set ``VINDICARA_LICENSE_KEY_PATH`` if your private key lives elsewhere.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

DEFAULT_KEY_PATH = Path.home() / ".airsdk-vendor" / "license_signing.key"
TOKEN_VERSION = 1
VALID_TIERS = ("individual", "team", "enterprise")


def _canonical_signing_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    if not path.exists():
        sys.exit(f"error: vendor private key not found at {path}. Generate one or set VINDICARA_LICENSE_KEY_PATH.")
    key_obj = load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key_obj, Ed25519PrivateKey):
        sys.exit(f"error: {path} does not hold an Ed25519 private key (got {type(key_obj).__name__})")
    return key_obj


def issue(
    *,
    email: str,
    tier: str,
    duration_days: int,
    features: list[str],
    private_key_path: Path,
) -> dict:
    if tier not in VALID_TIERS:
        sys.exit(f"error: tier must be one of {VALID_TIERS}, got {tier!r}")
    if duration_days <= 0:
        sys.exit(f"error: duration-days must be > 0, got {duration_days}")

    issued_at = int(time.time())
    expires_at = issued_at + duration_days * 86_400
    payload = {
        "v": TOKEN_VERSION,
        "email": email,
        "tier": tier,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "features": sorted(features),
    }

    private_key = _load_private_key(private_key_path)
    signature = private_key.sign(_canonical_signing_bytes(payload)).hex()
    return {**payload, "signature": signature}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--email", required=True, help="Customer email (recorded in token).")
    parser.add_argument("--tier", required=True, choices=VALID_TIERS, help="Subscription tier.")
    parser.add_argument("--duration-days", type=int, required=True, help="Days until expiry.")
    parser.add_argument(
        "--features",
        nargs="+",
        default=[],
        help="Feature entitlements (e.g. air-cloud-client report-nist-ai-rmf).",
    )
    parser.add_argument(
        "--key-path",
        default=os.environ.get("VINDICARA_LICENSE_KEY_PATH", str(DEFAULT_KEY_PATH)),
        help="Path to vendor private key (PEM).",
    )
    args = parser.parse_args()

    token = issue(
        email=args.email,
        tier=args.tier,
        duration_days=args.duration_days,
        features=args.features,
        private_key_path=Path(args.key_path).expanduser(),
    )
    print(json.dumps(token, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
