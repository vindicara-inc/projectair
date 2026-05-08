"""Okta IdP adapter — placeholder for v1.5.

The interface exists so enterprise prospects can see the protocol is
identity-provider-agnostic. Production Okta support requires either Token
Inline Hooks or the Authorization Server's claims configuration to inject
the four ``air_*`` custom claims; the integration test for that injector
ships alongside the v1.5 implementation.
"""
from __future__ import annotations

from typing import Any

from ..exceptions import IdPNotImplementedError
from .base import CapabilityToken, IdPAdapter


class OktaAdapter(IdPAdapter):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        raise IdPNotImplementedError(
            "OktaAdapter ships in Layer 4 v1.5; the v1 protocol layer is "
            "IdP-agnostic but Auth0 is the only reference implementation in v1"
        )

    def handled_issuers(self) -> list[str]:
        raise IdPNotImplementedError("OktaAdapter v1.5")

    def issue_capability_token(self, **kwargs: Any) -> CapabilityToken:
        raise IdPNotImplementedError("OktaAdapter v1.5")

    def verify_capability_token(self, **kwargs: Any) -> CapabilityToken:
        raise IdPNotImplementedError("OktaAdapter v1.5")

    def discover_metadata(self, issuer_url: str | None = None) -> dict[str, Any]:
        raise IdPNotImplementedError("OktaAdapter v1.5")


__all__ = ["OktaAdapter"]
