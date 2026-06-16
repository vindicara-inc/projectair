"""airsdk: signed forensic records for AI agents.

    from airsdk import AIRCallbackHandler
    handler = AIRCallbackHandler(key="...")
    agent = AgentExecutor(callbacks=[handler])
"""
from airsdk.agdr import Signer, load_chain, verify_chain, verify_record
from airsdk.article72 import generate_article72_report
from airsdk.callback import AIRCallbackHandler
from airsdk.delegation import mint_grant_from_auth0, open_delegation
from airsdk.detections import (
    UNIMPLEMENTED_DETECTORS,
    detect_cascading_failures,
    detect_goal_hijack,
    detect_human_agent_trust_exploitation,
    detect_identity_privilege_abuse,
    detect_insecure_inter_agent_communication,
    detect_mcp_supply_chain_risk,
    detect_memory_context_poisoning,
    detect_nemoguard_corroboration,
    detect_nemoguard_safety,
    detect_prompt_injection,
    detect_resource_consumption,
    detect_rogue_agent,
    detect_sensitive_data_exposure,
    detect_tool_misuse,
    detect_unexpected_code_execution,
    detect_untraceable_action,
    run_detectors,
)
from airsdk.exports import export_json, export_pdf, export_siem
from airsdk.integrations.adk import instrument_adk, make_air_callbacks
from airsdk.integrations.gemini import instrument_gemini
from airsdk.integrations.nemo_guardrails import instrument_nemo_guardrails
from airsdk.integrations.nemoclaw import instrument_nemoclaw
from airsdk.integrations.nemoguard import NemoGuardClient
from airsdk.key_custody import (
    KeyCustodyResult,
    KeyCustodyStatus,
    rotate_signer,
    verify_key_custody,
)
from airsdk.recorder import AIRRecorder, resolve_signing_key
from airsdk.registry import (
    AgentDescriptor,
    AgentRegistry,
    BehavioralScope,
    load_registry,
)
from airsdk.transport import FileTransport, HTTPTransport, Transport
from airsdk.types import (
    AGDR_VERSION,
    AgDRPayload,
    AgDRRecord,
    AuthMethod,
    DataAssetRef,
    DataSubjectRef,
    DelegationGrant,
    EntityScope,
    Finding,
    ForensicReport,
    GPUAttestation,
    IntentSpec,
    KeyTransition,
    SigningAlgorithm,
    StepKind,
    VerificationResult,
    VerificationStatus,
)
from airsdk.verification import (
    IntentSource,
    IntentVerdict,
    IntentVerificationResult,
    Violation,
    verify_intent,
)
from airsdk.verification.checks.delegation import check_delegation

__version__ = "1.0.1"

__all__ = [
    "AGDR_VERSION",
    "UNIMPLEMENTED_DETECTORS",
    "AIRCallbackHandler",
    "AIRRecorder",
    "AgDRPayload",
    "AgDRRecord",
    "AgentDescriptor",
    "AgentRegistry",
    "AuthMethod",
    "BehavioralScope",
    "DataAssetRef",
    "DataSubjectRef",
    "DelegationGrant",
    "EntityScope",
    "FileTransport",
    "Finding",
    "ForensicReport",
    "GPUAttestation",
    "HTTPTransport",
    "IntentSource",
    "IntentSpec",
    "IntentVerdict",
    "IntentVerificationResult",
    "KeyCustodyResult",
    "KeyCustodyStatus",
    "KeyTransition",
    "NemoGuardClient",
    "Signer",
    "SigningAlgorithm",
    "StepKind",
    "Transport",
    "VerificationResult",
    "VerificationStatus",
    "Violation",
    "__version__",
    "check_delegation",
    "detect_cascading_failures",
    "detect_goal_hijack",
    "detect_human_agent_trust_exploitation",
    "detect_identity_privilege_abuse",
    "detect_insecure_inter_agent_communication",
    "detect_mcp_supply_chain_risk",
    "detect_memory_context_poisoning",
    "detect_nemoguard_corroboration",
    "detect_nemoguard_safety",
    "detect_prompt_injection",
    "detect_resource_consumption",
    "detect_rogue_agent",
    "detect_sensitive_data_exposure",
    "detect_tool_misuse",
    "detect_unexpected_code_execution",
    "detect_untraceable_action",
    "export_json",
    "export_pdf",
    "export_siem",
    "generate_article72_report",
    "instrument_adk",
    "instrument_gemini",
    "instrument_nemo_guardrails",
    "instrument_nemoclaw",
    "load_chain",
    "load_registry",
    "make_air_callbacks",
    "mint_grant_from_auth0",
    "open_delegation",
    "resolve_signing_key",
    "rotate_signer",
    "run_detectors",
    "verify_chain",
    "verify_intent",
    "verify_key_custody",
    "verify_record",
]
