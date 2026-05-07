"""IdP adapter layer for the AgDR Handoff Protocol (Section 7).

Wave 1 ships the abstract :class:`IdPAdapter` base class and the Auth0
reference adapter. Okta, Microsoft Entra, and SPIFFE/SPIRE adapters are
placeholder modules in v1 and ship in v1.5.

The protocol is identity-provider-agnostic by design: any OIDC-compliant
IdP that can mint signed JWTs with the four ``air_*`` custom claims and
expose a JWKS endpoint can plug in.
"""
from __future__ import annotations

from .base import (
    REQUIRED_AIR_CLAIMS,
    AdapterRouter,
    CapabilityToken,
    IdPAdapter,
    extract_required_air_claims,
)

__all__ = [
    "REQUIRED_AIR_CLAIMS",
    "AdapterRouter",
    "CapabilityToken",
    "IdPAdapter",
    "extract_required_air_claims",
]
