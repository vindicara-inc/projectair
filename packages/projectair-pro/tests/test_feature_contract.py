"""Contract: every feature the gates ENFORCE matches the canonical registry.

The license issuer mints tokens whose feature strings come from
``airsdk.features`` (the single source of truth). The ``@requires_pro`` gates in
this package enforce features by string. If those two ever disagree, a paying
customer is silently denied (or wrongly granted) a feature. This test compares
every gate constant against the registry so any drift fails the build here,
before it can reach a customer.
"""
from __future__ import annotations

from airsdk import features as F
from airsdk_pro.alerts.types import INCIDENT_WORKFLOWS_FEATURE
from airsdk_pro.cloud.types import AIR_CLOUD_CLIENT_FEATURE
from airsdk_pro.detectors.types import PREMIUM_DETECTORS_FEATURE
from airsdk_pro.governance.types import GOVERNANCE_FEATURE
from airsdk_pro.hl7.capture import HL7_FHIR_FEATURE
from airsdk_pro.report_nist_rmf import NIST_RMF_FEATURE
from airsdk_pro.report_soc2_ai import SOC2_AI_FEATURE
from airsdk_pro.siem.types import SIEM_INTEGRATIONS_FEATURE

# (gate constant, canonical registry constant) — these MUST be equal.
_GATE_REGISTRY_PAIRS = [
    (AIR_CLOUD_CLIENT_FEATURE, F.AIR_CLOUD_CLIENT),
    (PREMIUM_DETECTORS_FEATURE, F.PREMIUM_DETECTORS),
    (NIST_RMF_FEATURE, F.REPORT_NIST_AI_RMF),
    (SOC2_AI_FEATURE, F.REPORT_SOC2_AI),
    (SIEM_INTEGRATIONS_FEATURE, F.SIEM_INTEGRATIONS),
    (INCIDENT_WORKFLOWS_FEATURE, F.INCIDENT_WORKFLOWS),
    (HL7_FHIR_FEATURE, F.HL7_FHIR),
    (GOVERNANCE_FEATURE, F.DATA_GOVERNANCE),
]


def test_gate_constants_match_registry() -> None:
    for gate_value, registry_value in _GATE_REGISTRY_PAIRS:
        assert gate_value == registry_value, (
            f"gate enforces {gate_value!r} but registry defines {registry_value!r}; "
            "mint and enforce have drifted"
        )


def test_every_gate_feature_is_a_known_registry_feature() -> None:
    for gate_value, _ in _GATE_REGISTRY_PAIRS:
        assert F.is_known_feature(gate_value), (
            f"gate enforces {gate_value!r}, which is not in airsdk.features.ALL_FEATURES"
        )
