"""Shared helpers for projectair-pro tests (importable, unlike conftest)."""
from __future__ import annotations

from pathlib import Path

import pytest

VENDOR_KEY_PATH = Path.home() / ".airsdk-vendor" / "license_signing.key"

requires_vendor_key = pytest.mark.skipif(
    not VENDOR_KEY_PATH.exists(),
    reason=f"vendor private key not present at {VENDOR_KEY_PATH}; tests that mint tokens are skipped",
)
