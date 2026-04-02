# Compliance-as-Code Engine & Behavioral Drift Detection Design Spec

**Date:** 2026-04-01
**Pillars:** 4 (Compliance) and 5 (Behavioral Drift)
**Goal:** Complete the Vindicara platform with all 5 revenue pillars functional for Product Hunt launch.

---

## Pillar 4: Compliance-as-Code Engine

### Purpose

Turns runtime data already flowing through Vindicara (guard evaluations, agent actions, MCP scans) into structured compliance evidence for EU AI Act Article 72, NIST AI RMF, and SOC 2 AI controls. No new data collection; reads from the existing audit system.

### File Structure

```
src/vindicara/compliance/
    __init__.py           # Public exports
    models.py             # ComplianceReport, ControlEvidence, FrameworkInfo, enums
    frameworks.py         # Framework definitions: EU AI Act, NIST, SOC 2 control mappings
    collector.py          # Evidence collector: pulls from AuditStorage, aggregates by control
    reporter.py           # Report generator: maps evidence to controls, computes coverage
src/vindicara/api/routes/
    reports.py            # POST /v1/compliance/reports, GET /v1/compliance/frameworks
src/vindicara/sdk/
    client.py             # (modify) add compliance property with ComplianceNamespace
src/vindicara/api/
    app.py                # (modify) register reports router
    deps.py               # (modify) add get_reporter, get_collector dependencies
tests/unit/compliance/
    __init__.py
    test_models.py
    test_frameworks.py
    test_collector.py
    test_reporter.py
tests/integration/api/
    test_reports_endpoint.py
```

### Models

```python
class ComplianceFramework(StrEnum):
    EU_AI_ACT_ARTICLE_72 = "eu-ai-act-article-72"
    NIST_AI_RMF = "nist-ai-rmf"
    SOC2_AI = "soc2-ai"

class EvidenceType(StrEnum):
    GUARD_EVALUATION = "guard_evaluation"
    AGENT_ACTION = "agent_action"
    MCP_SCAN = "mcp_scan"
    POLICY_CHANGE = "policy_change"
    AGENT_SUSPENSION = "agent_suspension"

class ControlStatus(StrEnum):
    MET = "met"
    PARTIAL = "partial"
    NOT_MET = "not_met"
    NOT_APPLICABLE = "not_applicable"

class ControlEvidence(BaseModel):
    control_id: str           # e.g. "ART72-1" or "MAP-1.1"
    control_name: str
    status: ControlStatus
    evidence_count: int
    evidence_types: list[EvidenceType]
    summary: str              # Human-readable evidence summary
    last_evidence_at: str     # ISO timestamp

class FrameworkInfo(BaseModel):
    framework_id: ComplianceFramework
    name: str
    description: str
    control_count: int
    version: str

class ComplianceReport(BaseModel):
    report_id: str
    framework: ComplianceFramework
    system_id: str
    period: str               # e.g. "2026-Q1"
    generated_at: str
    total_controls: int
    met_controls: int
    partial_controls: int
    not_met_controls: int
    coverage_pct: float       # 0.0-100.0
    controls: list[ControlEvidence]
    summary: str              # Executive summary
```

### Framework Definitions

Each framework defines a list of controls with:
- control_id, control_name, description
- required_evidence_types: which EvidenceType(s) satisfy the control
- minimum_evidence_count: how many events needed for "met" status (below = "partial")

**EU AI Act Article 72** (Post-market monitoring): 8 controls covering system performance monitoring, incident detection, risk assessment, audit trails, user feedback, corrective actions, documentation, and reporting.

**NIST AI RMF**: 8 controls covering risk identification, measurement, monitoring, management, governance, transparency, accountability, and documentation.

**SOC 2 AI Controls**: 8 controls covering access control, change management, system monitoring, incident response, data protection, audit logging, availability, and confidentiality.

### Collector

Pulls from AuditStorage (in-memory for now, DynamoDB later). Filters by system_id and time period. Aggregates events by type. Returns evidence summaries keyed by EvidenceType.

### Reporter

Takes framework definition + collected evidence. For each control, checks if required evidence types are present and counts meet thresholds. Produces ComplianceReport with per-control status and overall coverage percentage.

### SDK Interface

```python
vc.compliance.generate(
    framework="eu-ai-act-article-72",
    system_id="sales-assistant-v2",
    period="2026-Q1"
) -> ComplianceReport

vc.compliance.frameworks() -> list[FrameworkInfo]
```

### API Endpoints

- `POST /v1/compliance/reports` - Generate a compliance report
- `GET /v1/compliance/frameworks` - List available frameworks

---

## Pillar 5: Behavioral Drift Detection

### Purpose

Baselines agent behavior in production, detects anomalies by comparing live behavior to baselines, and enforces circuit breakers that auto-suspend agents via the existing kill switch (AgentRegistry.suspend()).

### File Structure

```
src/vindicara/monitor/
    __init__.py           # Public exports
    models.py             # BehaviorEvent, Baseline, DriftScore, DriftAlert, BreakerConfig
    baseline.py           # Records events, computes statistical baselines
    drift.py              # Compares live behavior to baseline, produces drift scores
    breaker.py            # Circuit breaker: auto-suspends on threshold breach
src/vindicara/api/routes/
    monitor.py            # POST /v1/monitor/events, GET /v1/monitor/drift/{agent_id}, POST /v1/monitor/breakers
src/vindicara/sdk/
    client.py             # (modify) add monitor property with MonitorNamespace
src/vindicara/api/
    app.py                # (modify) register monitor router
    deps.py               # (modify) add get_baseline_store, get_drift_detector, get_breaker dependencies
tests/unit/monitor/
    __init__.py
    test_models.py
    test_baseline.py
    test_drift.py
    test_breaker.py
tests/integration/api/
    test_monitor_endpoint.py
```

### Models

```python
class BehaviorEvent(BaseModel):
    agent_id: str
    tool: str
    timestamp: str          # ISO timestamp
    data_scope: str = ""
    metadata: dict[str, str] = Field(default_factory=dict)

class MetricBaseline(BaseModel):
    metric_name: str        # e.g. "tool_call_count", "unique_tools"
    mean: float
    stddev: float
    sample_count: int
    last_updated: str

class Baseline(BaseModel):
    agent_id: str
    metrics: list[MetricBaseline]
    window_minutes: int     # Baseline window (e.g. 60 minutes)
    created_at: str
    event_count: int

class DriftCategory(StrEnum):
    FREQUENCY = "frequency"       # Tool call rate change
    SCOPE = "scope"               # New tools or data scopes
    PATTERN = "pattern"           # Sequence anomalies

class DriftAlert(BaseModel):
    category: DriftCategory
    metric: str
    baseline_value: float
    current_value: float
    deviation: float        # Number of stddevs from mean
    message: str

class DriftScore(BaseModel):
    agent_id: str
    score: float            # 0.0 (normal) to 1.0 (extreme drift)
    alerts: list[DriftAlert]
    checked_at: str
    baseline_event_count: int
    current_event_count: int

class BreakerConfig(BaseModel):
    agent_id: str
    threshold: float = 0.8       # Drift score that triggers suspension
    window_minutes: int = 60     # Monitoring window
    enabled: bool = True
    auto_suspend: bool = True    # If true, auto-calls registry.suspend()
    suspend_reason: str = "Behavioral drift exceeded threshold"

class BreakerStatus(BaseModel):
    agent_id: str
    config: BreakerConfig
    current_drift: float
    tripped: bool
    last_checked: str
```

### Baseline Engine

In-memory store of BehaviorEvents per agent. On `record(event)`, stores the event. On `get_baseline(agent_id, window_minutes)`, computes:
- tool_call_count: total calls in window
- unique_tools: distinct tools used
- calls_per_tool: per-tool frequency
- unique_scopes: distinct data scopes accessed

Returns Baseline with MetricBaseline for each metric (mean, stddev computed from rolling windows).

### Drift Detector

Given an agent_id and window, computes current metrics and compares to baseline:
- For each metric, calculates z-score: (current - mean) / stddev
- Maps z-scores to drift categories (frequency, scope, pattern)
- Produces overall drift score: max z-score normalized to 0.0-1.0 via sigmoid
- Generates DriftAlerts for any metric exceeding 2.0 stddevs

### Circuit Breaker

Stores BreakerConfig per agent. On `check(agent_id)`:
1. Gets drift score from drift detector
2. If score >= threshold and auto_suspend is true, calls `AgentRegistry.suspend(agent_id, reason)`
3. Returns BreakerStatus with current state

### SDK Interface

```python
# Record agent behavior
vc.monitor.record(agent_id="...", tool="crm_read", data_scope="accounts.sales")

# Check drift
drift = vc.monitor.get_drift(agent_id="...") -> DriftScore

# Configure circuit breaker
vc.monitor.set_breaker(agent_id="...", threshold=0.8, auto_suspend=True) -> BreakerConfig

# Check breaker status
status = vc.monitor.check_breaker(agent_id="...") -> BreakerStatus
```

### API Endpoints

- `POST /v1/monitor/events` - Record a behavior event
- `GET /v1/monitor/drift/{agent_id}` - Get drift score for an agent
- `POST /v1/monitor/breakers` - Configure a circuit breaker
- `GET /v1/monitor/breakers/{agent_id}` - Get breaker status (runs check)

---

## Integration Points

Both pillars follow existing patterns exactly:
- Pydantic v2 models, structlog logging, no print()
- Namespace on VindicaraClient (vc.compliance, vc.monitor)
- FastAPI routes with Depends() DI from deps.py
- @lru_cache(maxsize=1) singletons in deps.py
- Routers registered in app.py create_app()
- Unit tests mirror src/ structure, integration tests use AsyncClient + ASGITransport
- No new dependencies beyond what's already installed

## Cross-Pillar Integration

- Monitor's circuit breaker calls identity's AgentRegistry.suspend() for kill switch
- Compliance collector reads from audit storage (guard evaluations, agent actions)
- Monitor events could feed into compliance evidence (agent_action type)
