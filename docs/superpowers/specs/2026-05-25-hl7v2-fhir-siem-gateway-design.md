# HL7v2 + FHIR R4 + SIEM Gateway Design

Date: 2026-05-25
Status: Draft
Tier: Pro (`airsdk_pro.hl7/`)

## Problem

Healthcare orgs deploying clinical AI agents need forensic evidence that flows into their existing infrastructure. Hospital integration engines speak HL7v2 (pipe-delimited, MLLP/HTTP). Modern clinical data platforms speak FHIR R4. Security teams watch Splunk/Datadog/Sentinel. Today these are disconnected: the AI agent acts, the EHR records the order, and the SIEM gets a generic log line with no clinical context.

AIR already captures agent actions as signed capsules and pushes findings to SIEM. What's missing is the clinical protocol layer: parsing HL7v2 messages into the chain, mapping them to FHIR R4 resources for structured evidence, and enriching SIEM events with clinical context.

## Customer-facing value

"AIR captures every HL7v2 message your clinical AI agent sends or receives as a signed, tamper-evident forensic record, maps it to FHIR R4 for structured evidence, and pushes clinical-context-enriched alerts to your SIEM. One integration replaces months of custom compliance wiring."

## Decisions locked

- **All HL7v2/FHIR/Gateway code in Pro** (`airsdk_pro.hl7/`). Healthcare customers are paying customers.
- **Own the parser.** No third-party HL7v2 parsing libraries (`hl7apy`, `python-hl7`). HL7v2 pipe-delimited format is well-specified and simple. Owning the parser means zero supply-chain risk in the evidence path.
- **Own the FHIR models.** Pydantic models for the subset of FHIR R4 resources we map to. No `fhir.resources` dependency. Same reasoning: compliance customers need to audit the full path.
- **File + HTTP transport in v1.** MLLP (TCP) listener ships in v1.5.
- **FHIR server push in v1.** SMART on FHIR / OAuth2 client credentials auth. Supports HAPI FHIR, Azure Health Data Services, GCP Healthcare API.
- **SIEM gateway in v1.** Full pipeline orchestrator composing parser + FHIR mapper + capsule capture + detectors + SIEM push.
- **Pro-gated via `@requires_pro(feature="hl7-fhir-integration")`.**

## Architecture

### Module layout

```
airsdk_pro/hl7/
  __init__.py       -- public API re-exports
  parser.py         -- HL7v2 message parsing (pipe-delimited)
  fhir.py           -- HL7v2 segment -> FHIR R4 resource mapping
  capture.py        -- instrument_hl7() capsule capture
  fhir_client.py    -- FHIR R4 server push (SMART on FHIR)
  http.py           -- HTTP endpoint for receiving HL7v2 messages
  gateway.py        -- HL7 SIEM Gateway pipeline orchestrator
  types.py          -- Pydantic models: segments, FHIR resources, config
```

Each module has zero coupling to the others except through types. The gateway composes them.

### Layer 1: HL7v2 Parser (`parser.py`)

Parses raw HL7v2 pipe-delimited messages into typed Pydantic models.

#### Supported message types

| Message Type | Trigger Event | Clinical Use |
|---|---|---|
| ADT (Admit/Discharge/Transfer) | A01, A02, A03, A04, A08 | Patient movement events |
| ORM (Order) | O01 | Lab, imaging, medication orders |
| ORU (Observation Result) | R01 | Lab results, imaging reports |
| MDM (Medical Document Mgmt) | T02, T04 | Clinical notes, AI-generated summaries |

#### Parsed segments

| Segment | What it carries | Model |
|---|---|---|
| MSH | Message header: sending facility, message type, timestamp, encoding | `MSHSegment` |
| PID | Patient identification: MRN, name, DOB, gender, address | `PIDSegment` |
| PV1 | Patient visit: class (inpatient/outpatient), location, attending | `PV1Segment` |
| OBX | Observation: code (LOINC), value, units, status, reference range | `OBXSegment` |
| ORC | Order control: order number, status, requester | `ORCSegment` |
| OBR | Observation request: procedure code, ordering provider, priority | `OBRSegment` |
| TXA | Document header: type, status, author, authentication | `TXASegment` |
| NK1 | Next of kin (parsed but not mapped to FHIR in v1) | `NK1Segment` |

#### Parsing contract

```python
def parse_hl7v2(raw: str) -> HL7v2Message:
    """Parse a raw HL7v2 pipe-delimited message.

    Splits on segment terminators (\\r, \\n, or \\r\\n).
    Each segment is split on the field separator from MSH-1 (default |).
    Component separator from MSH-2 (default ^) splits composite fields.

    Raises HL7v2ParseError for malformed messages (missing MSH,
    invalid segment structure, encoding violations).
    """
```

`HL7v2Message` is a Pydantic model:

```python
class HL7v2Message(BaseModel):
    model_config = ConfigDict(extra="forbid")

    raw: str
    message_type: str          # e.g. "ORU^R01"
    message_control_id: str    # MSH-10
    timestamp: str             # MSH-7, ISO 8601 converted
    sending_facility: str      # MSH-4
    receiving_facility: str    # MSH-6
    msh: MSHSegment
    pid: PIDSegment | None = None
    pv1: PV1Segment | None = None
    obx: list[OBXSegment] = Field(default_factory=list)
    orc: ORCSegment | None = None
    obr: OBRSegment | None = None
    txa: TXASegment | None = None
    nk1: list[NK1Segment] = Field(default_factory=list)
```

### Layer 2: FHIR R4 Resource Mapping (`fhir.py`)

Deterministic mapping from HL7v2 segments to FHIR R4 resources. Each mapping function takes a parsed segment and returns a Pydantic model following the FHIR R4 spec.

#### Mapping table

| HL7v2 Segment | FHIR R4 Resource | Key fields mapped |
|---|---|---|
| MSH | MessageHeader | source, destination, event coding, timestamp |
| PID | Patient | identifier (MRN), name (HumanName), birthDate, gender |
| OBX | Observation | code (LOINC CodeableConcept), value, units, status, referenceRange |
| ORC | ServiceRequest | identifier, status, intent, requester |
| OBR | DiagnosticReport | code, status, resultsInterpreter |
| PV1 | Encounter | class, period, location, participant (attending) |
| TXA | DocumentReference | type, status, author, date |

#### Mapping contract

```python
def map_to_fhir(message: HL7v2Message) -> list[FHIRResource]:
    """Map parsed HL7v2 segments to FHIR R4 resources.

    Returns one resource per mappable segment. OBX segments produce
    one Observation each. All resources share a common subject
    reference derived from PID (Patient).

    Resources are Pydantic models with resourceType, id, and
    the mapped fields. Unmapped fields are omitted (not nulled).
    """
```

#### FHIR resource models (subset)

```python
class FHIRResource(BaseModel):
    model_config = ConfigDict(extra="forbid")
    resourceType: str
    id: str = Field(default_factory=lambda: str(uuid4()))

class FHIRPatient(FHIRResource):
    resourceType: str = "Patient"
    identifier: list[FHIRIdentifier] = Field(default_factory=list)
    name: list[FHIRHumanName] = Field(default_factory=list)
    birthDate: str | None = None
    gender: str | None = None

class FHIRObservation(FHIRResource):
    resourceType: str = "Observation"
    status: str = "final"
    code: FHIRCodeableConcept
    subject: FHIRReference | None = None
    valueQuantity: FHIRQuantity | None = None
    valueString: str | None = None
    referenceRange: list[FHIRReferenceRange] = Field(default_factory=list)
```

Full set: `FHIRPatient`, `FHIRObservation`, `FHIRServiceRequest`, `FHIRDiagnosticReport`, `FHIREncounter`, `FHIRDocumentReference`, `FHIRMessageHeader`. Supporting types: `FHIRIdentifier`, `FHIRHumanName`, `FHIRCodeableConcept`, `FHIRCoding`, `FHIRReference`, `FHIRQuantity`, `FHIRReferenceRange`, `FHIRPeriod`.

### Layer 3: Capsule Capture (`capture.py`)

Wires HL7v2 message processing into the AIR forensic chain.

```python
@requires_pro(feature="hl7-fhir-integration")
def instrument_hl7(
    recorder: AIRRecorder,
    raw_message: str,
    *,
    map_fhir: bool = True,
    data_subjects: list[DataSubjectRef] | None = None,
) -> tuple[AgDRRecord, AgDRRecord]:
    """Parse an HL7v2 message and record it as signed capsules.

    Emits a TOOL_START record with tool_name="hl7v2_receive",
    the parsed message type, patient MRN, sending facility, and
    optionally the FHIR R4 resource mappings in the payload.

    Emits a TOOL_END record with the HL7v2 ACK message.

    If PID is present and data_subjects is not provided, auto-creates
    a DataSubjectRef from the patient MRN with jurisdiction="HIPAA".

    Returns (tool_start_record, tool_end_record).
    """
```

Auto-tagging: when a PID segment is present, the capture function automatically creates a `DataSubjectRef(subject_id=mrn, subject_type="patient", jurisdiction="HIPAA")` and a `DataAssetRef` for each OBX observation. This wires into the existing data governance module for DSAR queries.

### Layer 4: FHIR R4 Server Push (`fhir_client.py`)

Pushes FHIR R4 resources to a FHIR server. Each push is itself recorded as a signed capsule for full chain of custody.

```python
@requires_pro(feature="hl7-fhir-integration")
class FHIRClient:
    """Push FHIR R4 resources to a FHIR server.

    Supports SMART on FHIR (OAuth2 client credentials) auth.
    Tested against HAPI FHIR, Azure Health Data Services,
    GCP Healthcare API.
    """

    def __init__(
        self,
        fhir_url: str,
        *,
        client_id: str | None = None,
        client_secret: str | None = None,
        token_url: str | None = None,
        scopes: list[str] | None = None,
        recorder: AIRRecorder | None = None,
        timeout: float = 30.0,
    ) -> None: ...

    def push_bundle(
        self,
        resources: list[FHIRResource],
    ) -> FHIRPushResult: ...

    def push_resource(
        self,
        resource: FHIRResource,
    ) -> FHIRPushResult: ...
```

Auth flow:
1. If `token_url` + `client_id` + `client_secret` provided: OAuth2 client credentials grant, token cached until expiry.
2. If no auth params: unauthenticated (for local HAPI FHIR dev servers).
3. Token refresh is automatic; 401 triggers one retry with fresh token.

`FHIRPushResult`:
```python
class FHIRPushResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    success: bool
    status_code: int
    resources_created: int
    resources_failed: int
    server_response: dict | None = None
    error: str | None = None
```

### Layer 5: HTTP Receiver (`http.py`)

Lightweight FastAPI router for receiving HL7v2 messages over HTTP.

```python
def create_hl7_router(
    recorder: AIRRecorder,
    *,
    fhir_client: FHIRClient | None = None,
    siem_targets: list[SiemTarget] | None = None,
) -> APIRouter:
    """Create a FastAPI router for HL7v2 message ingestion.

    POST /hl7v2/ingest
      Content-Type: application/hl7-v2 or x-application/hl7-v2+er7
      Body: raw HL7v2 message

    Returns HL7v2 ACK (MSA segment) on success, NAK on parse failure.
    """
```

Mountable into any FastAPI app:
```python
from airsdk_pro.hl7 import create_hl7_router
app.include_router(create_hl7_router(recorder), prefix="/clinical")
```

### Layer 6: SIEM Gateway (`gateway.py`)

Full pipeline orchestrator. Composes all layers into a single `process()` call.

```python
@requires_pro(feature="hl7-fhir-integration")
class HL7SIEMGateway:
    """HL7v2 -> Parse -> FHIR Map -> Sign -> Detect -> SIEM push.

    Sits between clinical systems and security infrastructure.
    Every HL7v2 message becomes a signed forensic record; every
    finding becomes a SIEM event with clinical context.
    """

    def __init__(
        self,
        recorder: AIRRecorder,
        *,
        fhir_client: FHIRClient | None = None,
        siem_config: GatewayConfig | None = None,
    ) -> None: ...

    def process(self, raw_message: str) -> GatewayResult: ...

    def process_file(self, path: Path) -> list[GatewayResult]: ...
```

`GatewayConfig`:
```python
class GatewayConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    splunk: SplunkConfig | None = None
    datadog: DatadogConfig | None = None
    sentinel: SentinelConfig | None = None
    sumo: SumoConfig | None = None
    push_fhir: bool = True
    run_detectors: bool = True
    auto_tag_subjects: bool = True
```

`GatewayResult`:
```python
class GatewayResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message_type: str
    patient_mrn: str | None
    records_written: int
    fhir_resources: list[FHIRResource]
    findings: list[Finding]
    siem_push_results: list[SiemPushResult]
    fhir_push_result: FHIRPushResult | None
```

#### SIEM event enrichment

When findings are pushed to SIEM, the gateway enriches each event with clinical context:

| SIEM field | Source | Example |
|---|---|---|
| `sourcetype` | hardcoded | `vindicara_air:clinical` |
| `patient_mrn` | PID-3 | `20260511-0042` |
| `message_type` | MSH-9 | `ORU^R01` |
| `sending_facility` | MSH-4 | `EPIC_PROD` |
| `fhir_resource_types` | mapped resources | `["Patient", "Observation"]` |
| `clinician` | step-up approver (if any) | `dr.chen@hospital.org` |

Standard AIR finding fields (detector_id, severity, evidence, step_id, chain_hash) are included alongside the clinical fields.

### AgDR payload extensions

New optional fields on `AgDRPayload` (in OSS `airsdk/types.py`, matching governance pattern):

```python
hl7v2_message_type: str | None = None       # e.g. "ORU^R01"
hl7v2_segments: dict[str, Any] | None = None # parsed segment data
fhir_resources: list[dict[str, Any]] | None = None  # FHIR R4 resource dicts
```

These are structural schema fields (like `data_assets` and `data_subjects`). The parsing and mapping logic lives in Pro; the fields are available to anyone reading the chain.

### CLI surface

New subcommand group under `air hl7` (Pro-gated):

```
air hl7 parse <file.hl7>                           Parse and display HL7v2 messages
air hl7 capture <file.hl7> --chain <chain.jsonl>   Parse, map to FHIR, write signed capsules
air hl7 push --fhir-url <url> --chain <chain.jsonl> Push FHIR resources from chain to server
air hl7 gateway --config gateway.yaml               Run the full SIEM gateway pipeline
```

### E2E demo script

`packages/projectair-pro/scripts/e2e_hl7_fhir.py`:

1. Generate sample ORU^R01 message (lab results for a diabetic patient)
2. Parse into typed segments
3. Map to FHIR R4 (Patient, 3x Observation)
4. Capture as signed capsules
5. Run detectors (should flag nothing for in-scope access)
6. Inject an unauthorized patient MRN in a second message
7. Re-run detectors (SV-ENTITY-01 fires)
8. Print gateway result with SIEM event preview
9. Optionally push to a local HAPI FHIR server (`--live-fhir`)

Runtime: under 30 seconds without live FHIR. Under 60 with.

## Marketing updates

### Pricing page (`site/src/routes/pricing/+page.svelte`)

Add to Team tier feature list:
- "HL7v2 + FHIR R4 clinical interop"

Add to Enterprise tier feature list:
- "HL7v2 + FHIR R4 clinical interop"
- "Clinical SIEM gateway"

Add to feature comparison table:
- Row: "Clinical interop (HL7v2 / FHIR R4)" with checkmarks on Team + Enterprise

### Healthcare solutions page (`site/src/routes/solutions/healthcare/+page.svelte`)

Add two capability cards:
- "HL7v2 Message Capture": every ADT, ORM, ORU, MDM message your clinical AI agent handles is parsed and recorded as a signed capsule with patient MRN, sending facility, and message control ID.
- "FHIR R4 Evidence": HL7v2 segments are mapped to FHIR R4 resources (Patient, Observation, ServiceRequest, DiagnosticReport) stored in the forensic chain. Auditors see structured clinical data, not raw pipes.

Update quick-start code sample to show `instrument_hl7()`.

### README (`packages/projectair/README.md`)

Add to framework integrations table:
- HL7v2 / FHIR R4 | `instrument_hl7` (Pro) | 1.1.0

### Blog

New post: "HL7v2 Forensic Evidence: Cryptographic Audit Trails for Clinical AI Messages" covering the pipeline, FHIR mapping, SIEM gateway, and HIPAA compliance story.

## Test plan

### Unit tests (`packages/projectair-pro/tests/hl7/`)

- `test_parser.py`: parse each message type (ADT A01, ORM O01, ORU R01, MDM T02), malformed messages, encoding edge cases (custom delimiters, escape sequences, empty segments, multi-line OBX)
- `test_fhir.py`: each segment-to-resource mapping, missing optional fields, multiple OBX segments, LOINC code extraction, value type dispatch (quantity vs string vs coded)
- `test_capture.py`: message in -> signed capsule out, chain verifies, auto-tagging of DataSubjectRef/DataAssetRef, FHIR resources in payload
- `test_fhir_client.py`: mock FHIR server, bundle create, single resource create, auth flow (token request, refresh, 401 retry), error handling
- `test_http.py`: POST endpoint, content-type handling, ACK/NAK response, malformed input
- `test_gateway.py`: full pipeline with mock SIEM targets, clinical enrichment fields, detector integration, config variants
- `test_types.py`: Pydantic model validation, extra="forbid" enforcement, serialization round-trips

### Integration tests

- `test_capture_integration.py`: end-to-end from raw HL7v2 string through capture to verified chain with FHIR resources in payload
- `test_gateway_integration.py`: gateway with mock Splunk HEC endpoint, verify SIEM event contains clinical fields

### E2E

- `scripts/e2e_hl7_fhir.py`: full demo (see above)
- `--live-fhir` flag for testing against a real HAPI FHIR server

### Coverage target

80% floor (matching repo standard). Parser and FHIR mapping should be near 100% since they are pure deterministic logic.

## Dependencies

No new external dependencies for parsing or FHIR models (pure Pydantic). `httpx` (already a dependency) for FHIR server push and HTTP receiver. `fastapi` (already a dependency) for the HTTP router.

## Versioning

- AgDR schema stays at **v0.6**. The new payload fields (`hl7v2_message_type`, `hl7v2_segments`, `fhir_resources`) are optional; existing chains verify unchanged.
- Ships as part of `projectair-pro` (no OSS version bump needed for the Pro module).
- Target release: **projectair-pro 1.1.0**.

## Future (v1.5, not in this spec)

- **MLLP (TCP) listener**: persistent TCP server with HL7v2 framing (`\x0b`...`\x1c\x0d`), ACK/NAK, connection management.
- **HL7v2 ADT event detector**: flag unusual patient transfer patterns (rapid readmission, cross-facility transfers outside declared scope).
- **FHIR Subscription**: subscribe to FHIR server change notifications and capture them as signed capsules.
- **CDA (Clinical Document Architecture)** mapping alongside FHIR R4 for orgs still on CDA.
