# Implementation Plan: Data Governance Module

Date: 2026-05-18
Spec: `docs/superpowers/specs/2026-05-18-data-governance-module-design.md`
Scope: AgDR v0.6 schema extensions (OSS) + governance module (Pro)
Note: The canonicalization/Merkle spec and sealed report verification spec are parked as v0.7 design. This plan ships governance on the existing v0.5 schema.

---

## Task 1: Schema extensions (OSS, `airsdk/types.py`)

**Files:** `packages/projectair/src/airsdk/types.py`

Steps:
1. Add `DataAssetRef` model after `IntentSpec`:
   - Fields: `asset_id: str`, `asset_type: str`, `namespace: str = ""`, `sensitivity: str = ""`
   - `model_config = ConfigDict(extra="forbid")`
2. Add `DataSubjectRef` model after `DataAssetRef`:
   - Fields: `subject_id: str`, `subject_type: str = ""`, `jurisdiction: str = ""`
   - `model_config = ConfigDict(extra="forbid")`
3. Add two optional fields to `AgDRPayload`:
   - `data_assets: list[DataAssetRef] | None = None`
   - `data_subjects: list[DataSubjectRef] | None = None`
4. Bump `AGDR_VERSION` from `"0.5"` to `"0.6"` in `airsdk/types.py`.
5. Export `DataAssetRef` and `DataSubjectRef` from `airsdk/__init__.py`.

**Verify:** `pytest packages/projectair/tests -x` passes. Existing chains still load and verify (the new fields default to `None` and are omitted from the canonical JSON, so `content_hash` is unchanged).

---

## Task 2: Recorder integration (OSS, `airsdk/recorder.py`)

**Files:** `packages/projectair/src/airsdk/recorder.py`

Steps:
1. Add `data_assets` and `data_subjects` kwargs to `tool_start()`:
   ```python
   def tool_start(
       self,
       *,
       tool_name: str,
       tool_args: dict[str, Any] | None = None,
       prior_findings: list[Finding] | None = None,
       data_assets: list[DataAssetRef] | None = None,
       data_subjects: list[DataSubjectRef] | None = None,
       **extra: Any,
   ) -> AgDRRecord:
   ```
   Pass them through to the payload dict: `"data_assets": data_assets, "data_subjects": data_subjects` (None values get stripped by existing `exclude_none` in serialization).
2. Add the same kwargs to `llm_start()` with the same pass-through pattern.
3. Do NOT touch `llm_end()`, `tool_end()`, or `agent_finish()`. Data tagging happens at the start of an operation, not the end.

**Verify:** Write a quick test that creates a recorder, calls `tool_start` with `data_assets` and `data_subjects`, loads the chain, and confirms the fields are present on the deserialized record's payload.

---

## Task 3: OSS schema tests

**Files:** `packages/projectair/tests/test_governance_schema.py` (new)

Steps:
1. Test `DataAssetRef` construction and validation (extra fields rejected, required fields enforced).
2. Test `DataSubjectRef` construction and validation.
3. Test `AgDRPayload` with `data_assets` and `data_subjects` populated serializes and deserializes correctly.
4. **Backward compatibility test:** Load a v0.5 chain (use the existing demo chain from `_concrete_demo.py`), verify it, confirm all records load without error and `data_assets`/`data_subjects` are `None`.
5. Test that a record with `data_assets` populated produces a valid signature and verifies (the new fields are included in the payload, so the content_hash covers them).

**Verify:** `pytest packages/projectair/tests/test_governance_schema.py -v` passes.

---

## Task 4: Governance types (Pro, `airsdk_pro/governance/types.py`)

**Files:** `packages/projectair-pro/src/airsdk_pro/governance/__init__.py` (new), `packages/projectair-pro/src/airsdk_pro/governance/types.py` (new)

Steps:
1. Create `packages/projectair-pro/src/airsdk_pro/governance/` directory with `__init__.py`.
2. Create `types.py` with:
   - `GOVERNANCE_FEATURE = "data_governance"` (license feature flag)
   - `AccessType(StrEnum)`: `READ`, `WRITE`, `DELETE`, `TRANSFORM`, `UNKNOWN`
   - `DataAccessRecord(BaseModel)`: `step_id`, `timestamp`, `agent_id: str | None`, `tool_name`, `access_type: AccessType`, `data_assets: list[DataAssetRef]`, `data_subjects: list[DataSubjectRef]`, `identity_proof: str | None`, `policy_decision: str | None`, `approval: HumanApproval | None`. All with `ConfigDict(extra="forbid")`.
   - `GovernanceIndex(BaseModel)`: `accesses: list[DataAccessRecord]`, `by_subject: dict[str, list[int]]`, `by_asset: dict[str, list[int]]`, `by_agent: dict[str, list[int]]`. The dicts map IDs to indices into `accesses`.
   - `SubjectAccessReport(BaseModel)`: `subject: DataSubjectRef`, `generated_at: str`, `total_accesses: int`, `accesses: list[DataAccessRecord]`, `chains_searched: int`, `jurisdiction_notes: str`.
   - `GovernanceReport(BaseModel)`: `generated_at: str`, `total_chains: int`, `total_accesses: int`, `assets_accessed: list[str]`, `subjects_affected: list[str]`, `policy_enforcements: int`, `violations: int`.
3. `__init__.py` exports the feature flag and all public types.

**Verify:** Import test: `python -c "from airsdk_pro.governance.types import DataAccessRecord, GovernanceIndex"` succeeds.

---

## Task 5: Data asset registry (Pro, `airsdk_pro/governance/registry.py`)

**Files:** `packages/projectair-pro/src/airsdk_pro/governance/registry.py` (new)

Steps:
1. Define `AssetDefinition(BaseModel)`: `id: str`, `type: str`, `namespace: str = ""`, `sensitivity: str = ""`, `regulations: list[str] = []`, `retention_days: int | None = None`, `owner: str = ""`.
2. Define `DataAssetRegistry`:
   - `__init__(self, assets: list[AssetDefinition])`.
   - `lookup(self, asset_id: str) -> AssetDefinition | None`.
   - `@classmethod from_yaml(cls, path: str | Path) -> DataAssetRegistry` using `yaml.safe_load`.
   - `@classmethod from_json(cls, path: str | Path) -> DataAssetRegistry` using `json.loads`.
3. Follow the `airsdk.registry` pattern (YAML/JSON loader, pydantic validation, frozen after load).

**Verify:** Unit test loading a YAML fixture, looking up assets by ID.

---

## Task 6: Chain indexer (Pro, `airsdk_pro/governance/indexer.py`)

**Files:** `packages/projectair-pro/src/airsdk_pro/governance/indexer.py` (new)

Steps:
1. Define `index_chains(chains: list[list[AgDRRecord]], registry: DataAssetRegistry | None = None) -> GovernanceIndex`.
2. Walk each chain. For each TOOL_START record with `data_assets` or `data_subjects` on its payload:
   - Extract a `DataAccessRecord` with the tool name, timestamp, step_id.
   - Infer `access_type` from tool name patterns: "read/get/fetch/query/select" -> READ, "write/put/insert/update/create" -> WRITE, "delete/remove/drop" -> DELETE, else UNKNOWN. Check `tool_args.get("access_type")` first for explicit annotation.
   - Attach `identity_proof` from the record's `signer_key`.
   - Check if the record has `blocked=True` or `challenge_id` set for `policy_decision`.
   - If the next record is a `HUMAN_APPROVAL` with matching `challenge_id`, attach the `HumanApproval`.
3. Build secondary indexes: `by_subject` (subject_id -> list of positions), `by_asset` (asset_id -> list of positions), `by_agent` (signer_key -> list of positions).
4. If `registry` is provided, enrich `DataAccessRecord` with sensitivity from the registry lookup.

**Verify:** Unit test with a manually constructed chain containing tagged tool_starts, confirm index contains the right records and secondary indexes are correct.

---

## Task 7: Query engine (Pro, `airsdk_pro/governance/query.py`)

**Files:** `packages/projectair-pro/src/airsdk_pro/governance/query.py` (new)

Steps:
1. `query_by_subject(index: GovernanceIndex, subject_id: str) -> list[DataAccessRecord]`.
2. `query_by_asset(index: GovernanceIndex, asset_id: str) -> list[DataAccessRecord]`.
3. `query_by_agent(index: GovernanceIndex, agent_id: str) -> list[DataAccessRecord]`.
4. `query_by_time_range(index: GovernanceIndex, from_dt: datetime | None = None, to_dt: datetime | None = None) -> list[DataAccessRecord]`.
5. `query(index: GovernanceIndex, *, subject_id: str | None = None, asset_id: str | None = None, agent_id: str | None = None, from_dt: datetime | None = None, to_dt: datetime | None = None) -> list[DataAccessRecord]`. Intersects results from all provided filters.
6. All functions gated with `@requires_pro(feature=GOVERNANCE_FEATURE)`.

**Verify:** Unit tests: single filter, compound filter, empty result, time range filter.

---

## Task 8: DSAR report generator (Pro, `airsdk_pro/governance/dsar.py`)

**Files:** `packages/projectair-pro/src/airsdk_pro/governance/dsar.py` (new)

Steps:
1. `generate_dsar(index: GovernanceIndex, subject_id: str, subject_type: str = "", jurisdiction: str = "") -> SubjectAccessReport`.
   - Query the index by `subject_id`.
   - Build `SubjectAccessReport` with the matching accesses, timestamp, chain count.
   - `jurisdiction_notes`: generate a brief note based on jurisdiction ("HIPAA: subject has right to accounting of disclosures per 45 CFR 164.528", "GDPR: subject has right of access per Article 15", "CCPA: consumer has right to know per Section 1798.100", or generic).
2. `render_dsar_markdown(report: SubjectAccessReport) -> str`.
   - Human-readable Markdown summary: header, subject info, table of accesses (timestamp, tool, access type, assets, policy decision), jurisdiction notes.
3. Gate with `@requires_pro(feature=GOVERNANCE_FEATURE)`.

**Verify:** Unit test generating a DSAR from a test index, confirm correct accesses returned, Markdown renders without error.

---

## Task 9: OpenLineage exporter (Pro, `airsdk_pro/governance/openlineage.py`)

**Files:** `packages/projectair-pro/src/airsdk_pro/governance/openlineage.py` (new)

Steps:
1. Define OpenLineage event models (minimal, no external dependency):
   - `OLDataset(BaseModel)`: `namespace: str`, `name: str`, `facets: dict[str, Any] = {}`.
   - `OLJob(BaseModel)`: `namespace: str`, `name: str`, `facets: dict[str, Any] = {}`.
   - `OLRun(BaseModel)`: `runId: str`, `facets: dict[str, Any] = {}`.
   - `OLRunEvent(BaseModel)`: `eventType: str`, `eventTime: str`, `run: OLRun`, `job: OLJob`, `inputs: list[OLDataset] = []`, `outputs: list[OLDataset] = []`, `producer: str`.
2. `export_openlineage(index: GovernanceIndex, chain_id: str, agent_id: str = "unknown") -> list[OLRunEvent]`.
   - Map each `DataAccessRecord` to an OpenLineage RunEvent.
   - TOOL_START with data_assets -> InputDataset per asset.
   - Group by chain_id for the Run, agent identity for the Job.
   - Add AIR-specific custom facets: `air_policy_decision`, `air_identity_proof`, `air_containment`.
   - `producer` = `"https://vindicara.io/air"`.
3. `export_openlineage_jsonl(events: list[OLRunEvent]) -> str`.
   - Serialize to JSONL string.
4. Gate with `@requires_pro(feature=GOVERNANCE_FEATURE)`.

**Verify:** Unit test producing OpenLineage events from a test index, confirm JSON structure matches OpenLineage spec shape.

---

## Task 10: NemoGuard auto-classifier (Pro, `airsdk_pro/governance/classifier.py`)

**Files:** `packages/projectair-pro/src/airsdk_pro/governance/classifier.py` (new)

Steps:
1. `classify_sensitivity(records: list[AgDRRecord], client: NemoGuardClient) -> list[SensitivitySuggestion]`.
   - `SensitivitySuggestion(BaseModel)`: `step_id: str`, `suggested_sensitivity: str`, `suggested_jurisdiction: str`, `confidence: float`, `matched_categories: list[str]`.
   - For each TOOL_START/LLM_END record with payload text, run `client.content_safety(text)`.
   - Map NemoGuard safety classifications to sensitivity levels: content flagged as containing PII/PHI -> "restricted" + "HIPAA"; financial data -> "confidential"; etc.
   - Return suggestions; caller decides whether to apply them.
2. This is advisory only. Does not modify records.
3. Gate with `@requires_pro(feature=GOVERNANCE_FEATURE)`.

**Verify:** Unit test with mocked NemoGuardClient, confirm suggestions are generated for records containing PII-like content.

---

## Task 11: CLI subcommands (Pro-gated, `projectair/governance_cli.py`)

**Files:** `packages/projectair/src/projectair/governance_cli.py` (new), `packages/projectair/src/projectair/cli.py` (modified)

Steps:
1. Create `governance_cli.py` with a `governance_app = typer.Typer(name="governance", ...)`.
2. Subcommands (all defer-import `airsdk_pro.governance` with clean install message):
   - `air governance index <chain_paths>`: load chains, run `index_chains`, print summary.
   - `air governance query --subject <id>` / `--asset <id>`: load chains, index, query, print results.
   - `air governance dsar --subject <id> <chain_paths>`: load chains, index, generate DSAR, print Markdown.
   - `air governance export --openlineage <chain_paths>`: load chains, index, export, write JSONL to stdout or file.
   - `air governance classify <chain_paths>`: load chains, run classifier, print suggestions.
3. Register in `cli.py`:
   ```python
   from projectair.governance_cli import register as _register_governance_cli
   _register_governance_cli(app)
   ```
   Follow the exact pattern used by `siem_cli.py`, `cloud_cli.py`, etc.

**Verify:** `air governance --help` shows subcommands. Each subcommand without Pro installed shows clean install message.

---

## Task 12: Wire governance into Pro `__init__.py`

**Files:** `packages/projectair-pro/src/airsdk_pro/__init__.py`

Steps:
1. Add governance imports:
   ```python
   from airsdk_pro.governance import (
       GOVERNANCE_FEATURE,
       DataAccessRecord,
       GovernanceIndex,
       ...
   )
   ```
2. Add `GOVERNANCE_FEATURE` to `__all__`.
3. Add `"data_governance"` to the license feature list documentation.

**Verify:** `python -c "from airsdk_pro import GOVERNANCE_FEATURE"` succeeds.

---

## Task 13: Pro governance tests

**Files:** `packages/projectair-pro/tests/governance/` (new directory)

Steps:
1. Create `conftest.py` with fixtures:
   - `sample_tagged_chain()`: builds a short chain with `data_assets` and `data_subjects` on tool_start records, using the existing `Signer` from `airsdk.agdr`.
   - `sample_registry()`: a `DataAssetRegistry` with 3 test assets.
   - `sample_index()`: runs `index_chains` over the sample chain.
2. `test_indexer.py`: index a tagged chain, confirm correct DataAccessRecords, secondary indexes populated, access_type inference works.
3. `test_query.py`: query by subject, asset, agent, time range, compound filter.
4. `test_dsar.py`: generate DSAR, confirm report fields, Markdown rendering.
5. `test_openlineage.py`: export, confirm OLRunEvent structure, facets populated.
6. `test_classifier.py`: mock NemoGuardClient, confirm suggestions generated.
7. `test_registry.py`: load from YAML fixture, lookup by ID.
8. `test_backward_compat.py`: index a v0.5 chain (no governance tags), confirm empty results, no errors.

**Verify:** `pytest packages/projectair-pro/tests/governance/ -v` passes.

---

## Task 14: E2E demo script

**Files:** `packages/projectair-pro/scripts/e2e_governance.py` (new)

Steps:
1. Build a demo chain: agent queries a patients table (tagged with DataAssetRef + DataSubjectRef), reads appointment logs, gets blocked by containment on an SSH exfil attempt.
2. Index the chain with a registry.
3. Run a DSAR query for the patient subject.
4. Export to OpenLineage.
5. Print summary: "Governance indexed N accesses across M chains. DSAR for patient-42: K accesses found. OpenLineage: L events exported."
6. Runs in under 60 seconds with no external dependencies.

**Verify:** `python packages/projectair-pro/scripts/e2e_governance.py` runs clean.

---

## Task 15: Lint, type check, final verification

Steps:
1. Run `./scripts/lint.sh` (ruff + mypy strict). Fix any issues.
2. Run `pytest packages/projectair/tests -x` (OSS tests pass with schema changes).
3. Run `pytest packages/projectair-pro/tests -x` (Pro tests pass with governance module).
4. Confirm no `Any` types, no bare `except`, no `print` in production paths.
5. Confirm every new file is under 300 lines.

**Verify:** All green. Ready for version bump and release.

---

## Dependency order

```
Task 1 (schema) -> Task 2 (recorder) -> Task 3 (OSS tests)
Task 4 (types) -> Task 5 (registry) -> Task 6 (indexer) -> Task 7 (query) -> Task 8 (dsar)
Task 4 (types) -> Task 9 (openlineage)
Task 4 (types) -> Task 10 (classifier)
Task 7 + 8 + 9 + 10 -> Task 11 (CLI)
Task 11 -> Task 12 (Pro init)
Task 12 -> Task 13 (tests) -> Task 14 (e2e) -> Task 15 (lint)
```

Tasks 5, 9, and 10 are independent of each other once Task 4 is done.
Tasks 1-3 (OSS) are independent of Tasks 4+ (Pro) and can run in parallel.
