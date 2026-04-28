"""Shared fixtures for projectair-pro tests."""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = ROOT / "tools"
TESTS_DIR = ROOT / "tests"
for extra in (str(TESTS_DIR), str(TOOLS_DIR)):
    if extra not in sys.path:
        sys.path.insert(0, extra)

from issue_license import issue as _issue_token  # noqa: E402

from _helpers import VENDOR_KEY_PATH  # noqa: E402


@pytest.fixture
def issue_token() -> Any:
    """Mint a license token for tests, against the local vendor key."""
    def _mint(
        *,
        email: str = "test@vindicara.io",
        tier: str = "individual",
        duration_days: int = 30,
        features: tuple[str, ...] = ("air-cloud-client",),
    ) -> str:
        token = _issue_token(
            email=email,
            tier=tier,
            duration_days=duration_days,
            features=list(features),
            private_key_path=VENDOR_KEY_PATH,
        )
        return json.dumps(token)

    return _mint


@pytest.fixture
def expired_token() -> str:
    """Mint a license token that is already expired (for negative tests)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    if not VENDOR_KEY_PATH.exists():
        pytest.skip(f"vendor key not present at {VENDOR_KEY_PATH}")
    key_obj = load_pem_private_key(VENDOR_KEY_PATH.read_bytes(), password=None)
    assert isinstance(key_obj, Ed25519PrivateKey)
    payload = {
        "v": 1,
        "email": "test@vindicara.io",
        "tier": "individual",
        "issued_at": int(time.time()) - 86400 * 30,
        "expires_at": int(time.time()) - 60,
        "features": ["air-cloud-client"],
    }
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    signature = key_obj.sign(body).hex()
    return json.dumps({**payload, "signature": signature})
