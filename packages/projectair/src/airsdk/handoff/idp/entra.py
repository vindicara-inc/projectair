"""Microsoft Entra ID IdP adapter — placeholder for v1.5.

Production Entra support requires a claims-mapping policy attached to the
service principal to inject the four ``air_*`` custom claims; that policy
ships alongside the v1.5 implementation.
"""
from __future__ import annotations

from typing import Any

from ..exceptions import IdPNotImplementedError
from .base import CapabilityToken, IdPAdapter


class EntraAdapter(IdPAdapter):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        raise IdPNotImplementedError("EntraAdapter ships in Layer 4 v1.5")

    def handled_issuers(self) -> list[str]:
        raise IdPNotImplementedError("EntraAdapter v1.5")

    def issue_capability_token(self, **kwargs: Any) -> CapabilityToken:
        raise IdPNotImplementedError("EntraAdapter v1.5")

    def verify_capability_token(self, **kwargs: Any) -> CapabilityToken:
        raise IdPNotImplementedError("EntraAdapter v1.5")

    def discover_metadata(self, issuer_url: str | None = None) -> dict[str, Any]:
        raise IdPNotImplementedError("EntraAdapter v1.5")


__all__ = ["EntraAdapter"]
