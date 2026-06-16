"""Premium detectors (Pro): coverage extensions on top of the OSS taxonomy.

The OSS package ships 14 detectors (10 OWASP Agentic + 3 OWASP LLM + 1
AIR-native). This package adds detectors that go deeper inside an
existing OWASP category. Today, that means three sub-detectors under
ASI04 Agentic Supply Chain Vulnerabilities; the OSS ASI04 detector
covers MCP-naming-convention checks only.

All entry points are gated behind the ``premium-detectors`` Pro
feature flag.
"""
from __future__ import annotations

from airsdk_pro.detectors.asi04_premium import (
    detect_supply_chain_premium,
    run_premium_detectors,
)
from airsdk_pro.detectors.types import PREMIUM_DETECTOR_IDS, PREMIUM_DETECTORS_FEATURE

__all__ = [
    "PREMIUM_DETECTORS_FEATURE",
    "PREMIUM_DETECTOR_IDS",
    "detect_supply_chain_premium",
    "run_premium_detectors",
]
