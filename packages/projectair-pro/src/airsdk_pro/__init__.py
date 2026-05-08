"""Project AIR Pro: licensed commercial features on top of MIT-licensed projectair.

Pro adds AIR Cloud client integration, premium reports (NIST AI RMF, SOC2-AI),
and premium detector additions to the open-source ``projectair`` SDK. All Pro
features are gated behind a locally-verified Ed25519-signed license token.

Free OSS detectors and exports are unaffected and continue to work without a
license.

Buy a subscription at https://vindicara.io/pricing.
"""
from __future__ import annotations

from airsdk_pro.alerts import (
    INCIDENT_WORKFLOWS_FEATURE,
    AlertConfigError,
    AlertPushError,
    AlertResult,
    alert_to_pagerduty,
    alert_to_slack,
    alert_to_webhook,
)
from airsdk_pro.cloud import (
    AIR_CLOUD_CLIENT_FEATURE,
    CloudConfigError,
    CloudPushError,
    CloudPushResult,
    push_chain_to_s3,
    push_chain_to_webhook,
)
from airsdk_pro.detectors import (
    PREMIUM_DETECTOR_IDS,
    PREMIUM_DETECTORS_FEATURE,
    detect_supply_chain_premium,
    run_premium_detectors,
)
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
from airsdk_pro.report_nist_rmf import NIST_RMF_FEATURE, generate_nist_rmf_report
from airsdk_pro.report_soc2_ai import SOC2_AI_FEATURE, generate_soc2_ai_report
from airsdk_pro.siem import (
    SIEM_INTEGRATIONS_FEATURE,
    SiemConfigError,
    SiemPushError,
    SiemPushResult,
    push_to_datadog,
    push_to_sentinel,
    push_to_splunk_hec,
    push_to_sumo,
)

__version__ = "0.7.0"

__all__ = [
    "AIR_CLOUD_CLIENT_FEATURE",
    "INCIDENT_WORKFLOWS_FEATURE",
    "NIST_RMF_FEATURE",
    "PREMIUM_DETECTORS_FEATURE",
    "PREMIUM_DETECTOR_IDS",
    "SIEM_INTEGRATIONS_FEATURE",
    "SOC2_AI_FEATURE",
    "AlertConfigError",
    "AlertPushError",
    "AlertResult",
    "CloudConfigError",
    "CloudPushError",
    "CloudPushResult",
    "LicenseError",
    "LicenseExpiredError",
    "LicenseInvalidError",
    "LicenseMissingError",
    "LicenseToken",
    "SiemConfigError",
    "SiemPushError",
    "SiemPushResult",
    "__version__",
    "alert_to_pagerduty",
    "alert_to_slack",
    "alert_to_webhook",
    "current_license",
    "detect_supply_chain_premium",
    "generate_nist_rmf_report",
    "generate_soc2_ai_report",
    "has_feature",
    "install_license",
    "is_pro_active",
    "load_license",
    "push_chain_to_s3",
    "push_chain_to_webhook",
    "push_to_datadog",
    "push_to_sentinel",
    "push_to_splunk_hec",
    "push_to_sumo",
    "requires_pro",
    "run_premium_detectors",
    "verify_token",
]
