"""Compliance framework definitions with control mappings."""

from dataclasses import dataclass, field

from vindicara.compliance.models import (
    ComplianceFramework,
    EvidenceType,
    FrameworkInfo,
)


@dataclass(frozen=True)
class ControlDefinition:
    """Definition of a single compliance control."""

    control_id: str
    control_name: str
    description: str
    required_evidence_types: list[EvidenceType] = field(default_factory=list)
    min_evidence_count: int = 1


@dataclass(frozen=True)
class FrameworkDefinition:
    """Full framework with its control definitions."""

    framework_id: ComplianceFramework
    name: str
    description: str
    version: str
    controls: list[ControlDefinition] = field(default_factory=list)


EU_AI_ACT_ARTICLE_72 = FrameworkDefinition(
    framework_id=ComplianceFramework.EU_AI_ACT_ARTICLE_72,
    name="EU AI Act Article 72",
    description="Post-market monitoring requirements for high-risk AI systems",
    version="1.0",
    controls=[
        ControlDefinition(
            control_id="ART72-1",
            control_name="System Performance Monitoring",
            description="Continuous monitoring of AI system performance in production",
            required_evidence_types=[EvidenceType.GUARD_EVALUATION],
            min_evidence_count=10,
        ),
        ControlDefinition(
            control_id="ART72-2",
            control_name="Incident Detection and Response",
            description="Detection and handling of AI system incidents",
            required_evidence_types=[EvidenceType.AGENT_SUSPENSION],
            min_evidence_count=1,
        ),
        ControlDefinition(
            control_id="ART72-3",
            control_name="Risk Assessment",
            description="Ongoing risk evaluation of AI system components",
            required_evidence_types=[EvidenceType.MCP_SCAN],
            min_evidence_count=1,
        ),
        ControlDefinition(
            control_id="ART72-4",
            control_name="Audit Trail Maintenance",
            description="Immutable logging of all AI system decisions",
            required_evidence_types=[EvidenceType.GUARD_EVALUATION],
            min_evidence_count=5,
        ),
        ControlDefinition(
            control_id="ART72-5",
            control_name="Data Quality Monitoring",
            description="Monitoring input and output data quality",
            required_evidence_types=[EvidenceType.GUARD_EVALUATION],
            min_evidence_count=5,
        ),
        ControlDefinition(
            control_id="ART72-6",
            control_name="Post-Market Surveillance",
            description="Active surveillance of AI system behavior",
            required_evidence_types=[
                EvidenceType.GUARD_EVALUATION,
                EvidenceType.AGENT_ACTION,
            ],
            min_evidence_count=5,
        ),
        ControlDefinition(
            control_id="ART72-7",
            control_name="Corrective Actions Documentation",
            description="Documentation of corrective measures taken",
            required_evidence_types=[
                EvidenceType.AGENT_SUSPENSION,
                EvidenceType.POLICY_CHANGE,
            ],
            min_evidence_count=1,
        ),
        ControlDefinition(
            control_id="ART72-8",
            control_name="Regulatory Reporting",
            description="Evidence generation for regulatory submissions",
            required_evidence_types=[EvidenceType.GUARD_EVALUATION],
            min_evidence_count=10,
        ),
    ],
)

NIST_AI_RMF = FrameworkDefinition(
    framework_id=ComplianceFramework.NIST_AI_RMF,
    name="NIST AI Risk Management Framework",
    description="Risk management controls for AI systems per NIST AI RMF",
    version="1.0",
    controls=[
        ControlDefinition(
            control_id="MAP-1.1",
            control_name="Risk Identification",
            description="Identify risks in AI system components",
            required_evidence_types=[EvidenceType.MCP_SCAN],
            min_evidence_count=1,
        ),
        ControlDefinition(
            control_id="MAP-1.2",
            control_name="Threat Assessment",
            description="Assess threats to AI system security",
            required_evidence_types=[EvidenceType.MCP_SCAN],
            min_evidence_count=1,
        ),
        ControlDefinition(
            control_id="MEASURE-2.1",
            control_name="Performance Measurement",
            description="Measure AI system performance metrics",
            required_evidence_types=[EvidenceType.GUARD_EVALUATION],
            min_evidence_count=10,
        ),
        ControlDefinition(
            control_id="MEASURE-2.2",
            control_name="Audit Logging",
            description="Comprehensive logging of AI operations",
            required_evidence_types=[EvidenceType.GUARD_EVALUATION],
            min_evidence_count=5,
        ),
        ControlDefinition(
            control_id="MANAGE-3.1",
            control_name="Risk Monitoring",
            description="Continuous monitoring of identified risks",
            required_evidence_types=[
                EvidenceType.GUARD_EVALUATION,
                EvidenceType.AGENT_ACTION,
            ],
            min_evidence_count=5,
        ),
        ControlDefinition(
            control_id="MANAGE-3.2",
            control_name="Incident Management",
            description="Process for managing AI incidents",
            required_evidence_types=[EvidenceType.AGENT_SUSPENSION],
            min_evidence_count=1,
        ),
        ControlDefinition(
            control_id="GOVERN-4.1",
            control_name="Governance Policies",
            description="Established governance policies for AI systems",
            required_evidence_types=[EvidenceType.POLICY_CHANGE],
            min_evidence_count=1,
        ),
        ControlDefinition(
            control_id="GOVERN-4.2",
            control_name="Access Control",
            description="Access control for AI agent operations",
            required_evidence_types=[EvidenceType.AGENT_ACTION],
            min_evidence_count=1,
        ),
    ],
)

SOC2_AI = FrameworkDefinition(
    framework_id=ComplianceFramework.SOC2_AI,
    name="SOC 2 AI Controls",
    description="SOC 2 Trust Services Criteria adapted for AI systems",
    version="1.0",
    controls=[
        ControlDefinition(
            control_id="SOC2-AI-1",
            control_name="Access Control",
            description="Agent identity and permission management",
            required_evidence_types=[EvidenceType.AGENT_ACTION],
            min_evidence_count=1,
        ),
        ControlDefinition(
            control_id="SOC2-AI-2",
            control_name="Change Management",
            description="Policy and configuration change tracking",
            required_evidence_types=[EvidenceType.POLICY_CHANGE],
            min_evidence_count=1,
        ),
        ControlDefinition(
            control_id="SOC2-AI-3",
            control_name="System Monitoring",
            description="Continuous monitoring of AI system operations",
            required_evidence_types=[EvidenceType.GUARD_EVALUATION],
            min_evidence_count=10,
        ),
        ControlDefinition(
            control_id="SOC2-AI-4",
            control_name="Incident Response",
            description="Response procedures for AI system incidents",
            required_evidence_types=[EvidenceType.AGENT_SUSPENSION],
            min_evidence_count=1,
        ),
        ControlDefinition(
            control_id="SOC2-AI-5",
            control_name="Data Protection",
            description="Protection of data processed by AI systems",
            required_evidence_types=[EvidenceType.GUARD_EVALUATION],
            min_evidence_count=5,
        ),
        ControlDefinition(
            control_id="SOC2-AI-6",
            control_name="Audit Logging",
            description="Comprehensive audit trail for AI operations",
            required_evidence_types=[EvidenceType.GUARD_EVALUATION],
            min_evidence_count=5,
        ),
        ControlDefinition(
            control_id="SOC2-AI-7",
            control_name="Availability Monitoring",
            description="Monitoring AI system availability and health",
            required_evidence_types=[EvidenceType.GUARD_EVALUATION],
            min_evidence_count=5,
        ),
        ControlDefinition(
            control_id="SOC2-AI-8",
            control_name="Confidentiality Controls",
            description="Confidentiality enforcement in AI pipelines",
            required_evidence_types=[
                EvidenceType.GUARD_EVALUATION,
                EvidenceType.MCP_SCAN,
            ],
            min_evidence_count=3,
        ),
    ],
)

HIPAA_SECURITY = FrameworkDefinition(
    framework_id=ComplianceFramework.HIPAA_SECURITY,
    name="HIPAA Security Rule (2026 NPRM)",
    description=(
        "Technical and administrative safeguards for electronic protected "
        "health information (ePHI) under the HIPAA Security Rule. Controls "
        "reflect the 2026 NPRM which eliminates addressable safeguards and "
        "mandates MFA, encryption, and annual penetration testing. AIR "
        "provides cryptographic evidence for these controls; full HIPAA "
        "compliance also requires BAAs, physical safeguards, workforce "
        "training, and encryption at rest, which are outside agent-action "
        "scope."
    ),
    version="2026-nprm",
    controls=[
        ControlDefinition(
            control_id="HIPAA-1",
            control_name="Access Control",
            description=(
                "45 CFR 164.312(a)(1): unique user identification and "
                "role-based access for ePHI systems. 2026 NPRM mandates MFA."
            ),
            required_evidence_types=[EvidenceType.AGENT_ACTION],
            min_evidence_count=1,
        ),
        ControlDefinition(
            control_id="HIPAA-2",
            control_name="Audit Controls",
            description=(
                "45 CFR 164.312(b): hardware, software, and procedural "
                "mechanisms to record and examine ePHI access."
            ),
            required_evidence_types=[EvidenceType.GUARD_EVALUATION],
            min_evidence_count=10,
        ),
        ControlDefinition(
            control_id="HIPAA-3",
            control_name="Integrity Controls",
            description=(
                "45 CFR 164.312(c)(1): protect ePHI from improper "
                "alteration or destruction. 2026 NPRM mandates encryption."
            ),
            required_evidence_types=[EvidenceType.GUARD_EVALUATION],
            min_evidence_count=5,
        ),
        ControlDefinition(
            control_id="HIPAA-4",
            control_name="Person or Entity Authentication",
            description=(
                "45 CFR 164.312(d): verify identity of persons or entities "
                "seeking access to ePHI."
            ),
            required_evidence_types=[EvidenceType.AGENT_ACTION],
            min_evidence_count=1,
        ),
        ControlDefinition(
            control_id="HIPAA-5",
            control_name="Transmission Security",
            description=(
                "45 CFR 164.312(e)(1): guard against unauthorized access to "
                "ePHI during electronic transmission."
            ),
            required_evidence_types=[EvidenceType.GUARD_EVALUATION],
            min_evidence_count=5,
        ),
        ControlDefinition(
            control_id="HIPAA-6",
            control_name="Minimum Necessary Enforcement",
            description=(
                "45 CFR 164.502(b): limit ePHI access to the minimum "
                "necessary for the intended purpose."
            ),
            required_evidence_types=[EvidenceType.AGENT_SUSPENSION],
            min_evidence_count=1,
        ),
        ControlDefinition(
            control_id="HIPAA-7",
            control_name="Security Incident Procedures",
            description=(
                "45 CFR 164.308(a)(6): identify, respond to, and mitigate "
                "security incidents involving ePHI."
            ),
            required_evidence_types=[
                EvidenceType.AGENT_SUSPENSION,
                EvidenceType.POLICY_CHANGE,
            ],
            min_evidence_count=1,
        ),
        ControlDefinition(
            control_id="HIPAA-8",
            control_name="Security Evaluation",
            description=(
                "45 CFR 164.308(a)(8): periodic technical and nontechnical "
                "evaluation. 2026 NPRM mandates annual penetration testing."
            ),
            required_evidence_types=[EvidenceType.MCP_SCAN],
            min_evidence_count=1,
        ),
    ],
)

FRAMEWORKS: dict[ComplianceFramework, FrameworkDefinition] = {
    ComplianceFramework.EU_AI_ACT_ARTICLE_72: EU_AI_ACT_ARTICLE_72,
    ComplianceFramework.NIST_AI_RMF: NIST_AI_RMF,
    ComplianceFramework.SOC2_AI: SOC2_AI,
    ComplianceFramework.HIPAA_SECURITY: HIPAA_SECURITY,
}


def get_framework(framework_id: ComplianceFramework) -> FrameworkDefinition:
    """Get a framework definition by ID."""
    return FRAMEWORKS[framework_id]


def get_framework_info(framework_id: ComplianceFramework) -> FrameworkInfo:
    """Get framework metadata."""
    fw = FRAMEWORKS[framework_id]
    return FrameworkInfo(
        framework_id=fw.framework_id,
        name=fw.name,
        description=fw.description,
        control_count=len(fw.controls),
        version=fw.version,
    )


def list_frameworks() -> list[FrameworkInfo]:
    """List all available compliance frameworks."""
    return [get_framework_info(fw_id) for fw_id in FRAMEWORKS]
