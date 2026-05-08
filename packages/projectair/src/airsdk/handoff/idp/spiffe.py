"""SPIFFE / SPIRE IdP adapter — placeholder for v1.5.

Production SPIFFE support uses workload-defined claims at SVID issuance
time via the SPIRE registration entry's selectors; the integration ships
alongside the v1.5 enterprise federation milestone.
"""
from __future__ import annotations

from typing import Any

from ..exceptions import IdPNotImplementedError
from .base import CapabilityToken, IdPAdapter


class SpiffeAdapter(IdPAdapter):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        raise IdPNotImplementedError("SpiffeAdapter ships in Layer 4 v1.5")

    def handled_issuers(self) -> list[str]:
        raise IdPNotImplementedError("SpiffeAdapter v1.5")

    def issue_capability_token(self, **kwargs: Any) -> CapabilityToken:
        raise IdPNotImplementedError("SpiffeAdapter v1.5")

    def verify_capability_token(self, **kwargs: Any) -> CapabilityToken:
        raise IdPNotImplementedError("SpiffeAdapter v1.5")

    def discover_metadata(self, issuer_url: str | None = None) -> dict[str, Any]:
        raise IdPNotImplementedError("SpiffeAdapter v1.5")


__all__ = ["SpiffeAdapter"]
