"""Project AIR Pro: licensed commercial features on top of MIT-licensed projectair.

Pro adds AIR Cloud client integration, premium reports (NIST AI RMF, SOC2-AI),
and premium detector additions to the open-source ``projectair`` SDK. All Pro
features are gated behind a locally-verified Ed25519-signed license token.

Free OSS detectors and exports are unaffected and continue to work without a
license.

Buy a subscription at https://vindicara.io/pricing.
"""
from __future__ import annotations

from airsdk_pro.gate import requires_pro
from airsdk_pro.license import (
    LicenseError,
    LicenseExpiredError,
    LicenseInvalidError,
    LicenseMissingError,
    LicenseToken,
    current_license,
    has_feature,
    install_license,
    is_pro_active,
    load_license,
    verify_token,
)

__version__ = "0.1.0"

__all__ = [
    "LicenseError",
    "LicenseExpiredError",
    "LicenseInvalidError",
    "LicenseMissingError",
    "LicenseToken",
    "__version__",
    "current_license",
    "has_feature",
    "install_license",
    "is_pro_active",
    "load_license",
    "requires_pro",
    "verify_token",
]
