"""Vindicara: Runtime security for autonomous AI."""

from vindicara.sdk.client import VindicaraClient as Client
from vindicara.sdk.exceptions import (
    PolicyNotFoundError,
    VindicaraAgentSuspended,
    VindicaraAuthError,
    VindicaraConnectionError,
    VindicaraError,
    VindicaraMCPRiskDetected,
    VindicaraPolicyViolation,
    VindicaraRateLimited,
    VindicaraValidationError,
)
from vindicara.sdk.types import GuardResult, PolicyInfo, RuleResult, Severity, Verdict

__all__ = [
    "Client",
    "GuardResult",
    "PolicyInfo",
    "PolicyNotFoundError",
    "RuleResult",
    "Severity",
    "Verdict",
    "VindicaraAgentSuspended",
    "VindicaraAuthError",
    "VindicaraConnectionError",
    "VindicaraError",
    "VindicaraMCPRiskDetected",
    "VindicaraPolicyViolation",
    "VindicaraRateLimited",
    "VindicaraValidationError",
]

__version__ = "0.1.0"
