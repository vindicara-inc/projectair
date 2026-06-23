"""Canonical entitlement-feature vocabulary — the single source of truth.

Every feature flag the product gates on is defined here exactly once, in the
OSS base package that all three enforcement sites depend on:

  - the license issuer (server, mints signed tokens)  -> ``vindicara.licensing``
  - the ``@requires_pro`` gates (SDK, enforces at call time) -> ``airsdk_pro``
  - the hosted console (UI, gates surfaces)

Because each site imports these constants instead of typing a bare string, the
string that GRANTS a feature can never drift from the string that CHECKS it.
``tests`` assert the contract so any divergence fails the build, not a customer.

If you add a feature: add the constant here, add it to ``ALL_FEATURES``, then
reference the constant everywhere. Never introduce a bare feature string.
"""
from __future__ import annotations

from typing import Final

# --- Enforced in the SDK by airsdk_pro @requires_pro(feature=...) -------------
AIR_CLOUD_CLIENT: Final = "air-cloud-client"
PREMIUM_DETECTORS: Final = "premium-detectors"
REPORT_NIST_AI_RMF: Final = "report-nist-ai-rmf"
REPORT_SOC2_AI: Final = "report-soc2-ai"
SIEM_INTEGRATIONS: Final = "siem-integrations"
INCIDENT_WORKFLOWS: Final = "incident-workflows"
HL7_FHIR: Final = "hl7-fhir-integration"
DATA_GOVERNANCE: Final = "data_governance"

# --- Enforced by the hosted console / hosted API -----------------------------
ANCHOR: Final = "anchor"
AUDIT: Final = "audit"
PROVE: Final = "prove"
EVIDENCE_PACKS: Final = "evidence-packs"
FLIGHTDECK_HOSTED: Final = "flightdeck-hosted"
MONITOR: Final = "monitor"
PROTECT: Final = "protect"
DUAL_CONTROL: Final = "dual-control"
COHORT_SCOPE: Final = "cohort-scope"
FLEET_SCOPE: Final = "fleet-scope"
MULTI_SEAT: Final = "multi-seat"
ADMISSIBILITY: Final = "admissibility"
REPORT_FLEET_POSTURE: Final = "report-fleet-posture"

ALL_FEATURES: Final[frozenset[str]] = frozenset(
    {
        AIR_CLOUD_CLIENT,
        PREMIUM_DETECTORS,
        REPORT_NIST_AI_RMF,
        REPORT_SOC2_AI,
        SIEM_INTEGRATIONS,
        INCIDENT_WORKFLOWS,
        HL7_FHIR,
        DATA_GOVERNANCE,
        ANCHOR,
        AUDIT,
        PROVE,
        EVIDENCE_PACKS,
        FLIGHTDECK_HOSTED,
        MONITOR,
        PROTECT,
        DUAL_CONTROL,
        COHORT_SCOPE,
        FLEET_SCOPE,
        MULTI_SEAT,
        ADMISSIBILITY,
        REPORT_FLEET_POSTURE,
    }
)


def is_known_feature(feature: str) -> bool:
    """Return True if *feature* is a defined entitlement feature."""
    return feature in ALL_FEATURES
