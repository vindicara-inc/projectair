"""Self-hosted deployment startup gate (Enterprise / air-gapped tier).

A regulated buyer runs AIR inside their own VPC or fully air-gapped network,
because the data is not allowed to leave their walls. The deployable unit must
therefore enforce entitlement offline and refuse to run without a valid license.

This module is that gate. ``enforce_license_at_startup`` verifies the installed
license against the vendor public key with no network call (Ed25519, see
``airsdk_pro.license``) and requires the Enterprise tier; a missing, invalid,
expired, or wrong-tier license raises and the container entrypoint exits
non-zero, so "no valid license -> it will not run" holds air-gapped.

``preflight`` wraps the gate with a readiness report the entrypoint prints
before starting the workload, including an air-gapped anchoring advisory
(public Sigstore Rekor / FreeTSA are unreachable air-gapped, so anchoring must
be turned off or pointed at a private TSA).
"""
from __future__ import annotations

import importlib.util
from dataclasses import dataclass, field
from pathlib import Path

from airsdk_pro.license import LicenseInvalidError, LicenseToken, load_license

# Self-hosted / air-gapped deployment is the Enterprise tier.
SELF_HOST_TIERS = frozenset({"enterprise"})


def enforce_license_at_startup(
    *,
    allowed_tiers: frozenset[str] = SELF_HOST_TIERS,
    license_path: Path | None = None,
) -> LicenseToken:
    """Verify the offline license and require a self-host-eligible tier.

    Returns the verified :class:`LicenseToken` on success. Raises
    ``LicenseMissingError`` / ``LicenseInvalidError`` / ``LicenseExpiredError``
    (all from :mod:`airsdk_pro.license`) otherwise. The caller (container
    entrypoint) treats any raise as fatal and exits non-zero, so an unlicensed
    or wrong-tier deployment cannot start.
    """
    token = load_license(license_path)  # raises on missing / invalid / expired
    if token.tier not in allowed_tiers:
        raise LicenseInvalidError(
            f"license tier {token.tier!r} is not entitled to self-hosted deployment; "
            f"self-hosting requires one of {sorted(allowed_tiers)}. "
            "Contact Vindicara to upgrade to the Enterprise tier."
        )
    return token


@dataclass(frozen=True)
class StartupReport:
    """Result of a self-hosted deployment preflight."""

    ok: bool
    email: str
    tier: str
    days_remaining: int
    air_gapped: bool
    warnings: tuple[str, ...] = field(default_factory=tuple)


def _anchoring_installed() -> bool:
    """True when the optional [anchoring] extra (sigstore/rfc3161) is importable."""
    return importlib.util.find_spec("airsdk.anchoring") is not None


def preflight(
    *,
    license_path: Path | None = None,
    air_gapped: bool = True,
    allowed_tiers: frozenset[str] = SELF_HOST_TIERS,
) -> StartupReport:
    """Run the startup gate and return a readiness report.

    Raises on any hard failure (missing / invalid / expired / wrong-tier
    license) so the entrypoint fails closed. On success, collects non-fatal
    warnings, notably the air-gapped anchoring advisory: public Sigstore Rekor
    and FreeTSA are unreachable air-gapped, so anchoring must be disabled or
    pointed at a private RFC 3161 TSA (``tsa_url=``) / HSM checkpoint.
    """
    token = enforce_license_at_startup(allowed_tiers=allowed_tiers, license_path=license_path)

    warnings: list[str] = []
    if air_gapped and _anchoring_installed():
        warnings.append(
            "air-gapped: the [anchoring] extra is installed. Public Sigstore Rekor / "
            "FreeTSA are unreachable air-gapped; configure a private TSA via tsa_url= "
            "(or an HSM checkpoint key) or disable anchoring, so chains are not left "
            "unanchored silently."
        )
    if token.days_remaining <= 30:
        warnings.append(
            f"license expires in {token.days_remaining} day(s); air-gapped renewals "
            "must be installed manually via `air install-license` before expiry."
        )

    return StartupReport(
        ok=True,
        email=token.email,
        tier=token.tier,
        days_remaining=token.days_remaining,
        air_gapped=air_gapped,
        warnings=tuple(warnings),
    )
