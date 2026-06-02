# Data Governance Module Design

Date: 2026-05-18
Status: Draft

## Problem

Healthcare AI governance is a land grab. Data governance programs must answer "where did this data come from, who touched it, what transformed it." For agentic systems, that question is currently unanswerable. Existing catalog tools (Collibra, Alation, Atlan) cannot produce lineage, access evidence, or policy enforcement proof for autonomous agents.

AIR already has the building blocks across its four layers, but lacks the schema, query surface, and export format to present them as governance capabilities.

## Customer-facing value

"AIR Governance gives compliance teams auditable proof of which agents accessed which data, who authorized it, and whether policy was enforced, with a single query instead of weeks of manual investigation."

## Decisions locked

- **Schema extensions in OSS** (`airsdk.types`, AgDR v0.6). `data_assets` and `data_subjects` fields on `AgDRPayload`. Anyone can tag records; the fields are structural, not behavioral.
- **All governance features in Pro** (`airsdk_pro.governance/`). Query engine, DSAR report generator, OpenLineage exporter, data-asset registry.
- **Regulation-neutral data model.** Generic sensitivity tagging at the schema level. Regulation-specific mapping (HIPAA PHI categories, GDPR Article 30, CCPA) at the report/export layer.
- **OpenLineage export** (Linux Foundation standard). Vendor-neutral; Collibra, Atlan, and others consume it. No single catalog vendor lock-in.
- **DSAR: query in v1, simulation in v2.** Chain-index query ("show all records where agent touched subject X") ships first. Counterfactual replay ("what if the agent hadn't accessed X") is a research-grade v2 feature.
- **NVIDIA leverage.** NemoGuard NIM classifiers (already integrated in 0.9.0) can feed data-sensitivity classification into governance tagging. No new NVIDIA integration module needed; wire existing `NemoGuardClient` output into the tagging flow.

## Architecture

### Layer 1: Schema extensions (OSS, `airsdk.types`)

New types added to `airsdk/types.py`:

```python
class DataAssetRef(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_id: str              # opaque identifier, caller-defined
    asset_type: str            # "table", "file", "api_endpoint", "bucket", etc.
    namespace: str = ""        # optional grouping (database name, service name)
    sensitivity: str = ""      # "public", "internal", "confidential", "restricted"

class DataSubjectRef(BaseModel):
    model_config = ConfigDict(extra="forbid")
    subject_id: str            # opaque identifier (patient ID, user ID)
    subject_type: str = ""     # "patient", "employee", "customer", etc.
    jurisdiction: str = ""     # "HIPAA", "GDPR", "CCPA", or empty
```

New optional fields on `AgDRPayload`:

```python
data_assets: list[DataAssetRef] | None = None
data_subjects: list[DataSubjectRef] | None = None
```

AgDR version bumps to `"0.6"`. Backward compatibility: v0.5 records lacking these fields verify unchanged (both fields default to `None`). This follows the same pattern as `signature_algorithm` in v0.5.

### Layer 2: Recorder integration (OSS, `airsdk/recorder.py`)

`AIRRecorder.tool_start()` and `AIRRecorder.llm_start()` accept optional `data_assets` and `data_subjects` kwargs. These flow through to the payload. No containment or policy logic; just tagging.

```python
recorder.tool_start(
    tool_name="query_patients",
    tool_args={"query": "SELECT * FROM patients WHERE id = 42"},
    data_assets=[DataAssetRef(asset_id="patients", asset_type="table", namespace="clinic_db", sensitivity="restricted")],
    data_subjects=[DataSubjectRef(subject_id="patient-42", subject_type="patient", jurisdiction="HIPAA")],
)
```

Framework integrations (`instrument_openai`, etc.) do not auto-tag. Tagging is explicit by the caller. Auto-classification from NemoGuard NIM is a Pro feature (see below).

### Layer 3: Governance module (Pro, `airsdk_pro/governance/`)

Seven files, each under 300 lines:

#### `types.py` (governance-specific types)

```python
class GovernanceFeature:
    DATA_GOVERNANCE = "data_governance"

class AccessType(StrEnum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    TRANSFORM = "transform"
    UNKNOWN = "unknown"

class DataAccessRecord(BaseModel):
    """Flattened view of one agent data access, derived from AgDR records."""
    step_id: str
    timestamp: str
    agent_id: str | None
    tool_name: str
    access_type: AccessType       # inferred from tool_name patterns or explicit caller annotation
    data_assets: list[DataAssetRef]
    data_subjects: list[DataSubjectRef]
    identity_proof: str | None    # L4 signer_key or handoff identity
    policy_decision: str | None   # "allowed", "blocked", "stepped_up"
    approval: HumanApproval | None

class SubjectAccessReport(BaseModel):
    """DSAR response: all agent actions touching a specific data subject."""
    subject: DataSubjectRef
    generated_at: str
    total_accesses: int
    accesses: list[DataAccessRecord]
    chains_searched: int
    jurisdiction_notes: str

class GovernanceReport(BaseModel):
    """Full governance report across multiple chains."""
    generated_at: str
    total_chains: int
    total_accesses: int
    assets_accessed: list[str]
    subjects_affected: list[str]
    policy_enforcements: int
    violations: int
```

#### `registry.py` (data asset registry)

A `DataAssetRegistry` that loads from YAML/JSON (same pattern as `airsdk.registry`). Maps asset IDs to metadata: sensitivity level, owning team, retention policy, applicable regulations. Used by the query engine and report generator to enrich results.

```yaml
# data-assets.yaml
assets:
  - id: patients
    type: table
    namespace: clinic_db
    sensitivity: restricted
    regulations: [HIPAA]
    retention_days: 2555  # 7 years
    owner: data-eng
  - id: appointment_logs
    type: table
    namespace: clinic_db
    sensitivity: confidential
    regulations: [HIPAA]
```

#### `indexer.py` (chain indexer)

Walks one or more AgDR chains and builds an in-memory index of data accesses. Extracts `DataAccessRecord` instances from TOOL_START/TOOL_END records that carry `data_assets` or `data_subjects`. Also indexes L3 containment decisions and L4 identity/handoff records to attach policy and identity proof to each access.

Key function: `index_chains(chains: list[list[AgDRRecord]], registry: DataAssetRegistry | None = None) -> GovernanceIndex`.

`GovernanceIndex` is a pydantic model holding `list[DataAccessRecord]` plus dict-based secondary indexes (`by_subject: dict[str, list[int]]`, `by_asset: dict[str, list[int]]`, `by_agent: dict[str, list[int]]`) mapping IDs to positions in the access list. Built once, queried many times.

`access_type` inference: the indexer checks for an explicit `access_type` field in the tool_args (callers can set it). When absent, it applies heuristic rules: tool names containing "read", "get", "fetch", "query", "select" map to READ; "write", "put", "insert", "update", "create" map to WRITE; "delete", "remove", "drop" map to DELETE. Everything else maps to UNKNOWN. The heuristic is best-effort; explicit annotation is preferred.

#### `query.py` (query engine)

Query DSL over `GovernanceIndex`. Supports:

- `query_by_subject(index, subject_id)` returns all accesses touching a data subject.
- `query_by_asset(index, asset_id)` returns all accesses to a data asset.
- `query_by_agent(index, agent_id)` returns all data accesses by an agent identity.
- `query_by_time_range(index, from_dt, to_dt)` returns accesses in a window.
- Compound: `query(index, subject_id=, asset_id=, agent_id=, from_dt=, to_dt=)`.

All queries return `list[DataAccessRecord]`.

#### `dsar.py` (DSAR report generator, v1: query)

Generates a `SubjectAccessReport` for a given subject ID across a set of chains. This is the "did any agent process this individual's data, and how" answer.

v1 scope: query and report generation only. Returns structured data and a human-readable Markdown summary.

v2 scope (future, not in this release): counterfactual replay. "What would have happened if we removed subject X's data from the input?" Requires an execution model; tracked as a roadmap item.

#### `openlineage.py` (OpenLineage exporter)

Converts governance-indexed data into OpenLineage events.

**Mapping:**

| AgDR concept | OpenLineage concept |
|---|---|
| Agent session (one chain) | `Run` |
| Agent identity (signer_key or L4 handoff) | `Job` (the producer/consumer) |
| `DataAssetRef` on a TOOL_START | `InputDataset` |
| `DataAssetRef` on a TOOL_END | `OutputDataset` |
| L3 containment decision | Custom facet on `RunEvent` |
| L4 handoff | `ParentRunFacet` linking parent and child runs |

Emits OpenLineage `RunEvent` JSON that any OpenLineage-compatible catalog can ingest. The mapping treats each agent session as a Job Run, each tagged data asset as a Dataset, and uses custom facets for AIR-specific metadata (containment decisions, verification status, signing proof).

Output format: JSONL of OpenLineage `RunEvent` objects, compatible with Marquez, Atlan, and any OpenLineage consumer.

#### `classifier.py` (NemoGuard auto-classification, optional)

Wraps the existing `NemoGuardClient` (from `airsdk.integrations.nemoguard`) to auto-classify data sensitivity in agent payloads. When enabled, scans tool arguments and LLM responses for PII/PHI patterns and suggests `DataAssetRef.sensitivity` and `DataSubjectRef.jurisdiction` values.

This is an optional enrichment step, not a gate. Classification suggestions are advisory; the caller decides whether to apply them to their tags.

### Layer 4: CLI surface (Pro, `projectair/governance_cli.py`)

Pro-gated CLI subcommands:

```
air governance index <chain> [<chain>...]    Build governance index from chains
air governance query --subject <id>          Query accesses by data subject
air governance query --asset <id>            Query accesses by data asset
air governance dsar --subject <id> <chain>   Generate DSAR report
air governance export --openlineage <chain>  Export as OpenLineage events
air governance classify <chain>              Run NemoGuard auto-classification
```

All commands defer-import `airsdk_pro.governance` and display a clean install message when Pro is absent (same pattern as existing `alert_cli.py`, `siem_cli.py`).

## Backward compatibility

- v0.5 chains without `data_assets`/`data_subjects` fields verify unchanged. The new fields default to `None`.
- The governance module can index v0.5 chains; records without tags simply produce no `DataAccessRecord` entries. No crash, no error.
- `AgDRPayload.model_config = ConfigDict(extra="allow")` is unchanged.
- Existing detectors, L1-L4 layers, and verification module are not modified.

## What this does NOT include

- Auto-instrumentation of framework integrations (no automatic tagging in `instrument_openai` etc.). Tagging is explicit.
- Counterfactual replay/simulation (v2, requires execution model).
- Per-regulation report templates (HIPAA Breach Notification, GDPR Article 30 RoPA). These are future report generators that consume the same `GovernanceIndex`.
- Persistent storage or database for the governance index. v1 is in-memory, built on demand from chain files.
- GraphQL or REST API for governance queries. v1 is CLI and Python API only.

## Testing

- Unit tests for each module in `packages/projectair-pro/tests/governance/`.
- Schema backward-compatibility test: load a v0.5 chain, verify it passes, index it (should produce empty results, no errors).
- OpenLineage output validation against the OpenLineage JSON schema.
- DSAR report generation from a test chain with known subjects.
- NemoGuard classifier integration test (mocked NIM endpoint).
- End-to-end demo script: `packages/projectair-pro/scripts/e2e_governance.py`.

## File inventory

OSS (`packages/projectair/`):
- `src/airsdk/types.py` (modified: add `DataAssetRef`, `DataSubjectRef`, payload fields)
- `src/airsdk/recorder.py` (modified: accept `data_assets`/`data_subjects` kwargs)

Pro (`packages/projectair-pro/`):
- `src/airsdk_pro/governance/__init__.py`
- `src/airsdk_pro/governance/types.py`
- `src/airsdk_pro/governance/registry.py`
- `src/airsdk_pro/governance/indexer.py`
- `src/airsdk_pro/governance/query.py`
- `src/airsdk_pro/governance/dsar.py`
- `src/airsdk_pro/governance/openlineage.py`
- `src/airsdk_pro/governance/classifier.py`
- `src/airsdk_pro/__init__.py` (modified: add governance exports)
- `src/projectair/governance_cli.py` (new CLI subcommands)
- `tests/governance/` (test directory)
- `scripts/e2e_governance.py` (demo)

## Release plan

**Phase 1 (0.10.0 OSS + Pro 0.2.0):** Schema extensions + full governance module. This is a single coordinated release since Pro depends on the new schema fields.

**Phase 2 (future):** Regulation-specific report packs (HIPAA, GDPR, CCPA), counterfactual replay engine, persistent governance index with search.
