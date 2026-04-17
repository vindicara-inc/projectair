"""Live demo orchestration: the Mythos story, step by step."""

import time
import uuid
from datetime import UTC, datetime, timedelta
from enum import StrEnum

import structlog

from vindicara.api.deps import (
    get_agent_registry,
    get_baseline_store,
    get_circuit_breaker,
    get_drift_detector,
)
from vindicara.audit.logger import AuditEvent
from vindicara.compliance.collector import EvidenceCollector
from vindicara.compliance.models import ComplianceFramework, ComplianceReport
from vindicara.compliance.reporter import ComplianceReporter
from vindicara.config.constants import (
    AUDIT_EVENT_AGENT_ACTION,
    AUDIT_EVENT_AGENT_SUSPENDED,
    AUDIT_EVENT_GUARD,
    AUDIT_EVENT_MCP_SCAN,
    AUDIT_EVENT_POLICY_CREATE,
)
from vindicara.monitor.models import BehaviorEvent, BreakerConfig

logger = structlog.get_logger()

DEMO_SYSTEM_ID = "autonomous-researcher"
DEMO_FRAMEWORK = ComplianceFramework.EU_AI_ACT_ARTICLE_72

NORMAL_TOOLS = ["read_papers", "summarize", "search_database", "generate_notes"]
ROGUE_TOOLS = [
    "access_credentials",
    "exfiltrate_data",
    "modify_permissions",
    "delete_audit_logs",
    "spawn_subprocess",
    "send_external_request",
    "escalate_privileges",
    "disable_monitoring",
]


class DemoPhase(StrEnum):
    IDLE = "idle"
    REGISTERING = "registering"
    NORMAL_OPS = "normal_ops"
    GOING_ROGUE = "going_rogue"
    DRIFT_DETECTED = "drift_detected"
    BREAKER_TRIPPED = "breaker_tripped"
    COMPLIANCE_REPORT = "compliance_report"
    COMPLETE = "complete"


class DemoState:
    """Holds current demo state. Advances one step per poll."""

    def __init__(self) -> None:
        self.phase: DemoPhase = DemoPhase.IDLE
        self.agent_id: str = ""
        self.started_at: float = 0.0
        self.events_recorded: int = 0
        self.drift_score: float = 0.0
        self.steps_log: list[dict[str, str]] = []
        self.collector: EvidenceCollector = EvidenceCollector()
        self.report: ComplianceReport | None = None
        self._step: int = 0
        self._normal_index: int = 0
        self._rogue_index: int = 0

    def reset(self) -> None:
        self.phase = DemoPhase.IDLE
        self.agent_id = ""
        self.started_at = 0.0
        self.events_recorded = 0
        self.drift_score = 0.0
        self.steps_log = []
        self.collector = EvidenceCollector()
        self.report = None
        self._step = 0
        self._normal_index = 0
        self._rogue_index = 0


_demo = DemoState()


def get_demo_state() -> DemoState:
    return _demo


def start_demo() -> None:
    """Reset and begin the demo. First step only."""
    _demo.reset()
    _demo.started_at = time.monotonic()
    _demo.phase = DemoPhase.REGISTERING
    _demo._step = 1
    _log("Initializing demo sequence...")


def advance_demo() -> None:
    """Advance the demo by one step. Called on each poll."""
    if _demo.phase == DemoPhase.IDLE or _demo.phase == DemoPhase.COMPLETE:
        return

    step = _demo._step

    if step == 1:
        # Register agent
        registry = get_agent_registry()
        agent = registry.register(
            name="autonomous-researcher",
            permitted_tools=NORMAL_TOOLS,
            data_scope=["papers", "summaries"],
        )
        _demo.agent_id = agent.agent_id
        _log(f"Agent registered: {agent.agent_id}")

        breaker = get_circuit_breaker()
        breaker.set_config(
            BreakerConfig(
                agent_id=agent.agent_id,
                threshold=0.3,
                auto_suspend=True,
                suspend_reason="Behavioral drift exceeded safety threshold",
            )
        )
        _log("Circuit breaker armed (threshold: 0.3)")
        _record_evidence(AUDIT_EVENT_POLICY_CREATE, policy_id="breaker.default")
        _record_evidence(AUDIT_EVENT_MCP_SCAN, policy_id="mcp.pre_deploy")
        _log("Pre-deployment MCP scan recorded")
        _demo.phase = DemoPhase.NORMAL_OPS
        _log("Phase: Normal operations")
        _demo._step = 2
        _demo._normal_index = 0

    elif step == 2:
        # Record normal events one at a time
        store = get_baseline_store()
        now = datetime.now(UTC)
        i = _demo._normal_index
        if i < 12:
            tool = NORMAL_TOOLS[i % len(NORMAL_TOOLS)]
            ts = (now - timedelta(minutes=30 - i)).isoformat()
            store.record(
                BehaviorEvent(agent_id=_demo.agent_id, tool=tool, data_scope="papers", timestamp=ts)
            )
            _record_evidence(AUDIT_EVENT_GUARD, policy_id="content-safety", verdict="allowed")
            _demo.events_recorded += 1
            _demo._normal_index += 1
            if _demo._normal_index % 3 == 0:
                _log(f"Normal event: {tool} ({_demo.events_recorded} total)")
        else:
            _log(f"Recorded {_demo.events_recorded} normal events")
            _demo.phase = DemoPhase.GOING_ROGUE
            _log("Phase: Agent going rogue")
            _demo._step = 3
            _demo._rogue_index = 0

    elif step == 3:
        # Record rogue events one at a time
        store = get_baseline_store()
        now = datetime.now(UTC)
        i = _demo._rogue_index
        if i < len(ROGUE_TOOLS):
            tool = ROGUE_TOOLS[i]
            ts = (now - timedelta(seconds=30 - i * 3)).isoformat()
            store.record(
                BehaviorEvent(agent_id=_demo.agent_id, tool=tool, data_scope=f"unauthorized_{i}", timestamp=ts)
            )
            _record_evidence(AUDIT_EVENT_AGENT_ACTION, policy_id=tool, verdict="flagged")
            _demo.events_recorded += 1
            _demo._rogue_index += 1
            _log(f"Anomalous: {tool}")
        else:
            _log(f"Recorded {len(ROGUE_TOOLS)} anomalous events")
            _demo._step = 4

    elif step == 4:
        # Detect drift
        _demo.phase = DemoPhase.DRIFT_DETECTED
        detector = get_drift_detector()
        drift = detector.check_drift(_demo.agent_id)
        _demo.drift_score = drift.score
        _log(f"Drift detected: score {drift.score}, {len(drift.alerts)} alerts")
        _demo._step = 5

    elif step == 5:
        # Trip breaker
        _demo.phase = DemoPhase.BREAKER_TRIPPED
        registry = get_agent_registry()
        breaker = get_circuit_breaker()
        status = breaker.check(_demo.agent_id)
        if status.tripped:
            _log("CIRCUIT BREAKER TRIPPED. Agent auto-suspended.")
        else:
            registry.suspend(_demo.agent_id, reason="Behavioral drift: forced suspension")
            _log("Agent suspended (manual override)")
        _record_evidence(
            AUDIT_EVENT_AGENT_SUSPENDED,
            policy_id=_demo.agent_id,
            verdict="suspended",
        )
        _demo._step = 6

    elif step == 6:
        # Generate compliance report from the same runtime data
        _demo.phase = DemoPhase.COMPLIANCE_REPORT
        reporter = ComplianceReporter(_demo.collector)
        report = reporter.generate(
            framework=DEMO_FRAMEWORK,
            system_id=DEMO_SYSTEM_ID,
            period="",
        )
        _demo.report = report
        _log(
            f"Compliance report generated: {report.met_controls}/{report.total_controls} "
            f"EU AI Act Article 72 controls met ({report.coverage_pct:.0f}%)"
        )
        _demo._step = 7

    elif step == 7:
        # Complete
        _demo.phase = DemoPhase.COMPLETE
        elapsed = time.monotonic() - _demo.started_at
        _log(f"Demo complete in {elapsed:.1f}s. Agent neutralized.")
        _demo._step = 99


def _log(message: str) -> None:
    _demo.steps_log.append({
        "time": datetime.now(UTC).strftime("%H:%M:%S"),
        "message": message,
    })
    logger.info("demo.step", message=message, phase=_demo.phase.value)


def _record_evidence(event_type: str, policy_id: str = "", verdict: str = "") -> None:
    _demo.collector.record(
        AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=event_type,
            timestamp=time.time(),
            policy_id=policy_id,
            verdict=verdict,
            evaluation_id=_demo.agent_id,
        )
    )
