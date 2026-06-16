# HL7v2 + FHIR R4 Clinical Evidence Sidecar Design

Date: 2026-05-25
Status: Draft (v3, post-review)
Tier: Pro (`airsdk_pro.hl7/`), Enterprise pricing

## Problem

Healthcare orgs deploying clinical AI agents need forensic evidence that flows into their existing infrastructure. Hospital integration engines (Mirth Connect, Cloverleaf, Rhapsody, Iguana) already handle HL7v2 routing. Modern clinical data platforms speak FHIR R4. Security teams watch Splunk/Datadog/Sentinel. Today these are disconnected: the AI agent acts, the EHR records the order, and the SIEM gets a generic log line with no clinical context and no proof of what the agent intended vs. what it did.

AIR already captures agent actions as signed capsules and pushes findings to SIEM. What's missing is the clinical protocol layer: recording HL7v2 messages the agent emits or consumes into the chain, mapping them to FHIR R4 resources for structured evidence, and enriching SIEM events with clinical context.

## Positioning: evidence sidecar, not integration engine

AIR is not a replacement for Mirth Connect, Cloverleaf, or Rhapsody. Those engines have 15+ years of vendor-specific routing, transformation, and HL7v2 quirk handling. Competing on feature completeness is a losing position.

AIR is the **evidence sidecar** that an existing integration engine taps. Mirth has channels with HTTP/TCP destinations; point a copy of the message stream at AIR. Cloverleaf has scripted destinations. Redox has webhooks. AIR's value is "we record what your AI agent did with the message and prove whether it honored its declared intent," not "we receive and route the message."

The primary integration pattern is:

```
Integration Engine (Mirth/Cloverleaf/Rhapsody)
    |
    | copy of message stream (HTTP POST or MLLP tap)
    v
AIR Clinical Sidecar
    |-- parse + sign (forensic record)
    |-- map to FHIR R4 (structured evidence)
    |-- verify intent-vs-action (SV-ENTITY)
    |-- push clinical-enriched findings to SIEM
    |-- optionally push FHIR resources to FHIR server
```

MLLP listener ships for orgs without a modern integration engine (small clinics, academic research labs). But lead with the sidecar pattern in all external messaging.

## Customer-facing value

"AIR records every HL7v2 message your clinical AI agent emits or consumes as a signed, tamper-evident forensic record that proves intent-vs-action conformance, paired with your existing integration engine, not replacing it."

## Decisions locked

- **All HL7v2/FHIR/Gateway code in Pro** (`airsdk_pro.hl7/`). Healthcare customers are paying customers.
- **Vendor the parser.** HL7v2 has four separator characters (MSH-2: `^~\&`), eight escape sequences (`\F\`, `\S\`, `\T\`, `\R\`, `\E\`, `\X..\`, `\Z..\`, `\H\/\N\`), variable-precision datetimes, MSH-18 character set declarations, and a long tail of vendor Z-segments (Epic, Cerner, Meditech). `python-hl7` and `hl7apy` exist because this is harder than it looks. Owning the parser eliminates supply-chain risk but replaces it with maintenance risk that compounds with every EHR vendor quirk. Fix: vendor `hl7apy`, pin the hash, mirror the source into the repo for audit. Write a thin typed Pydantic wrapper (`parser.py`) that gives strict models at the AIR boundary. We own the envelope and the wrapper; hl7apy carries the long-tail parsing bugs.
- **Use `fhir.resources` for FHIR models.** FHIR R4 has ~145 resources; we map 7. `fhir.resources` is auto-generated from the HL7 spec and handles extensions, contained resources, `_meta`, and US Core profile constraints. `extra="forbid"` on our own models would reject real FHIR server responses the first time HAPI/Azure/GCP returns a field we didn't anticipate. Fix: use `fhir.resources` for off-the-shelf models, layer strict Pydantic schemas only at the AIR-chain boundary, use `extra="ignore"` on inbound FHIR from servers. Strictness inside the chain where it matters for evidence; tolerance on inbound where real-world FHIR is messy.
- **PHI redaction by default.** Patient MRN is PHI under HIPAA. Rekor stores hashes, not payloads, but the on-disk chain contains the payload. Default behavior: redacted projection (hashed MRN, hashed patient name, structured clinical codes without free-text). Raw mode (`phi_mode="raw"`) requires explicit opt-in and a `baa_acknowledged=True` flag. Without this, hospital InfoSec kills the deal in legal review.
- **MLLP ships in v1** (not deferred to v1.5). Without MLLP at GA, the only v1 customer is a net-new HTTP-native deployment, which is vanishingly few in healthcare integration. MLLP is the deal-maker for real hospital deployments.
- **Enterprise-only pricing.** No hospital pays $599 for clinical interop infrastructure. Mirth Connect Pro starts mid-five-figures; Redox is higher. Clinical interop justifies a per-bed or PMPM pricing axis above the current Enterprise band. Putting it in Team commoditizes the most strategically important capability in the release.
- **Async pipeline after ACK.** A 500-bed hospital does 100K-1M HL7v2 messages/day. ORU bursts at lab result times. ACK on receipt-and-parse-and-stage only (truly commit-level; no fsync on the ACK path). Signing runs on a separate write thread that batches fsync calls (real-time HL7 receivers, including Mirth Connect, do not fsync per message). Everything downstream (FHIR mapping, detection, SIEM push, FHIR server push) is async with bounded queues, dead-letter handling, and a `gateway_lag_seconds` metric exposed to SIEM. The HL7v2 ACK means "we accepted the message," not "we signed it" or "we completed the pipeline."
- **Intent capsule declares patient scope.** The SV-ENTITY detection only works if the signed intent capsule declares authorized MRNs/facilities/message types at run start. Without this, the detector has no ground truth. Make this explicit in the API and the demo.
- **Pro-gated via `@requires_pro(feature="hl7-fhir-integration")`.**

## Architecture

### Module layout

```
airsdk_pro/hl7/
  __init__.py        -- public API re-exports
  parser.py          -- thin Pydantic wrapper over vendored hl7apy
  fhir.py            -- HL7v2 segment -> FHIR R4 resource mapping
  capture.py         -- instrument_hl7() capsule capture + PHI redaction
  fhir_client.py     -- FHIR R4 server push (SMART on FHIR)
  http.py            -- HTTP endpoint for receiving HL7v2 messages
  mllp.py            -- MLLP (TCP) listener with async framing
  gateway.py         -- clinical evidence sidecar pipeline orchestrator
  redaction.py       -- PHI redaction policy (default: redacted projection)
  types.py           -- Pydantic models: parsed segments, config, results

_vendor/
  hl7apy/            -- vendored, hash-pinned, version-locked
```

### PHI safety model (P0)

This section is non-negotiable. Getting PHI handling wrong ships a HIPAA breach as a feature.

#### All clinical chains contain PHI; BAA is always required

A BLAKE3-hashed MRN is pseudonymized data, not de-identified data under HIPAA Safe Harbor (45 CFR 164.514(b)). Safe Harbor requires removal of the 18 identifiers, not pseudonymization. The MRN namespace at any hospital is small and known-format (often sequential or checksum-validated), so a hash is reversibly correlatable. Under HIPAA, hashed identifiers constitute a "limited data set" at best, which still requires either a BAA or a Data Use Agreement.

**Consequence: `baa_acknowledged=True` is a precondition of `instrument_hl7()` for all clinical chains regardless of PHI mode.** The `PHIMode` enum controls exposure reduction within the BAA scope (less data at risk if the chain is exfiltrated), not whether a BAA is required. Marketing copy must say: "PHI is redacted by default to minimize exposure; BAA required for all clinical deployments."

#### Rekor stores hashes, not payloads

When anchoring runs (Layer 1), the `AnchoringOrchestrator` computes BLAKE3 over chain roots and submits the hash to Sigstore Rekor. No payload data, no patient identifiers, no clinical content reaches the public transparency log. The hash is a commitment; the payload stays on disk under the customer's control. This is already true for all AIR chains; spell it out explicitly for clinical chains because the question will come up in every hospital security review.

#### Network egress disclosure

Hospital InfoSec will ask exactly what leaves the network. Pre-answer for the healthcare page FAQ: "The only data that leaves your network is a BLAKE3 hash (32 bytes) submitted to Sigstore Rekor for timestamping. No PHI, no clinical content, no patient identifiers, no message payloads. The hash is a one-way cryptographic commitment that proves the chain existed at a point in time. It cannot be reversed to recover any clinical data."

#### PHI redaction policy

`capture.py` applies a `RedactionPolicy` before writing clinical data to the chain:

```python
class PHIMode(StrEnum):
    REDACTED = "redacted"    # default: hashed MRN, omitted name, reduced DOB, codes only
    RAW = "raw"              # all fields preserved as-is

# Fields classified as PHI under Safe Harbor (18 identifiers).
# Used by the model validator to prevent un-redaction without BAA.
PHI_CLASS_FIELDS: frozenset[str] = frozenset({
    "mrn", "name", "family_name", "given_name", "date_of_birth",
    "ssn", "address", "phone", "email", "medical_record_number",
    "account_number", "visit_number", "device_serial",
})

class RedactionPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    phi_mode: PHIMode = PHIMode.REDACTED
    baa_acknowledged: bool = True   # required True for all clinical chains
    allowed_fields: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_phi_safety(self) -> RedactionPolicy:
        if not self.baa_acknowledged:
            raise ValueError(
                "baa_acknowledged must be True for clinical chains. "
                "All HL7v2 chains contain PHI-derived data regardless "
                "of redaction mode."
            )
        if self.phi_mode == PHIMode.REDACTED and self.allowed_fields:
            phi_leak = PHI_CLASS_FIELDS & set(self.allowed_fields)
            if phi_leak:
                raise ValueError(
                    f"allowed_fields contains PHI-class fields "
                    f"{sorted(phi_leak)} in REDACTED mode. Either "
                    f"switch to PHIMode.RAW or remove these fields."
                )
        return self
```

In `REDACTED` mode (default):
- Patient MRN: BLAKE3 hash of the MRN (reduces exposure; still PHI)
- Patient name: omitted entirely
- DOB: year only; ages 90+ aggregated to "90+" (Safe Harbor 164.514(b)(2)(i)(C))
- Clinical codes (LOINC, ICD-10, CPT): preserved (not identifiers under Safe Harbor)
- Free-text fields (OBX-5 text observations, TXA document content): preserved when `baa_acknowledged=True` (the realistic case; omitting free-text defeats AI-scribe value props)
- Sending/receiving facility: preserved (not an individual identifier)
- Message control IDs: date components stripped if present (MCIDs that embed dates like "20260511-0042" are a partial Safe Harbor concern)

In `RAW` mode:
- All fields preserved as-is, including clear MRN, name, full DOB
- Same `baa_acknowledged=True` requirement (already enforced by validator)
- Higher exposure surface if the chain is exfiltrated

The `allowed_fields` list lets customers selectively un-redact specific non-PHI fields in REDACTED mode. The model validator prevents un-redacting PHI-class fields in REDACTED mode (use RAW mode instead; the distinction is intentional so the mode label is honest).

### Layer 1: HL7v2 Parser (`parser.py`)

Thin typed wrapper over vendored `hl7apy`. Delegates all parsing (separator handling, escape sequences, character set decoding, Z-segment passthrough) to the vendored library. Surfaces results as strict Pydantic models at the AIR boundary.

#### Supported message types

| Message Type | Trigger Event | Clinical Use |
|---|---|---|
| ADT (Admit/Discharge/Transfer) | A01, A02, A03, A04, A08 | Patient movement events |
| ORM (Order) | O01 | Lab, imaging, medication orders |
| ORU (Observation Result) | R01 | Lab results, imaging reports |
| MDM (Medical Document Mgmt) | T02, T04 | Clinical notes, AI-generated summaries |

#### Parsed segments

| Segment | What it carries | Notes |
|---|---|---|
| MSH | Message header, encoding characters, sending facility | MSH-7 timestamp: variable precision (YYYY through YYYYMMDDHHMMSS.ssss+ZZZZ), parsed to ISO 8601 with precision preserved |
| PID | Patient identifiers (plural: MRN, SSN, account, visit number, each with assigning authority), name, DOB, gender | Multiple identifiers preserved with assigning authority; not flattened to single MRN |
| PV1 | Patient visit: class, location, attending | |
| OBX | Observation value | OBX-2 type dispatch: NM (numeric), ST (string), CWE (coded with exceptions), TS (timestamp), DT (date), TX (text), FT (formatted text), SN (structured numeric). OBX-3 code system: not always LOINC; may be local codes, SNOMED, CPT, or mixed. Code system identifier preserved as-is with normalization to URN where recognizable |
| ORC | Order control | |
| OBR | Observation request | |
| TXA | Document header | |
| NK1 | Next of kin | Parsed but not mapped to FHIR in v1 |
| Z-segments | Vendor-specific (Epic ZPM, Cerner ZCS, etc.) | Preserved as opaque key-value blobs in `z_segments` dict. Not dropped, not strictly modeled. Dropping = data loss the customer audits and finds |

#### Parsing contract

```python
def parse_hl7v2(raw: str) -> HL7v2Message:
    """Parse a raw HL7v2 pipe-delimited message.

    Delegates to vendored hl7apy for separator handling, escape
    sequences, character set decoding, and segment parsing.
    Wraps the result in strict Pydantic models.

    Raises HL7v2ParseError for malformed messages (missing MSH,
    invalid segment structure).
    """
```

```python
class HL7v2Message(BaseModel):
    model_config = ConfigDict(extra="forbid")

    raw: str
    message_type: str               # e.g. "ORU^R01"
    message_control_id: str         # MSH-10
    timestamp: str                  # MSH-7, ISO 8601 with original precision
    timestamp_precision: str        # "year" | "month" | "day" | "second" | "millisecond"
    sending_facility: str           # MSH-4
    receiving_facility: str         # MSH-6
    character_set: str              # MSH-18, default "ASCII"
    msh: MSHSegment
    pid: PIDSegment | None = None
    pv1: PV1Segment | None = None
    obx: list[OBXSegment] = Field(default_factory=list)
    orc: ORCSegment | None = None
    obr: OBRSegment | None = None
    txa: TXASegment | None = None
    nk1: list[NK1Segment] = Field(default_factory=list)
    z_segments: dict[str, list[list[str]]] = Field(default_factory=dict)
```

#### PID identifier model

```python
class PatientIdentifier(BaseModel):
    model_config = ConfigDict(extra="forbid")
    value: str                       # the identifier value
    type_code: str                   # MR (MRN), SS (SSN), AN (account), VN (visit), etc.
    assigning_authority: str = ""    # which system issued this ID

class PIDSegment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    identifiers: list[PatientIdentifier]   # all identifiers, not flattened
    primary_mrn: str | None = None         # convenience: first MR-type identifier
    family_name: str | None = None
    given_name: str | None = None
    date_of_birth: str | None = None       # ISO 8601, precision preserved
    gender: str | None = None
    # ... other PID fields
```

#### OBX value dispatch

```python
class OBXSegment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    set_id: int
    value_type: str                  # OBX-2: NM, ST, CWE, TS, DT, TX, FT, SN
    observation_id: str              # OBX-3.1 (code)
    observation_id_system: str       # OBX-3.3 (coding system: LN, SCT, CPT, LOCAL, etc.)
    observation_id_text: str         # OBX-3.2 (display text)
    value_numeric: float | None = None        # when OBX-2 = NM or SN
    value_string: str | None = None           # when OBX-2 = ST, TX, FT
    value_coded: str | None = None            # when OBX-2 = CWE (code)
    value_coded_system: str | None = None     # CWE coding system
    value_coded_text: str | None = None       # CWE display text
    value_datetime: str | None = None         # when OBX-2 = TS or DT
    units: str | None = None
    reference_range: str | None = None
    abnormal_flags: str | None = None
    observation_status: str | None = None
```

### Layer 2: FHIR R4 Resource Mapping (`fhir.py`)

Uses `fhir.resources` (auto-generated from the HL7 FHIR R4 spec) for the resource models. Strict Pydantic schemas apply only at the AIR-chain boundary (what gets written to the capsule payload). Inbound FHIR from servers uses `extra="ignore"` to tolerate fields we don't map.

#### Mapping table

| HL7v2 Segment | FHIR R4 Resource | Key fields mapped |
|---|---|---|
| MSH | MessageHeader | source, destination, event coding, timestamp |
| PID | Patient | identifier (all, with assigning authority), name (HumanName), birthDate, gender |
| OBX | Observation | code (CodeableConcept with original coding system, not assumed LOINC), value (dispatched by OBX-2 type), units, status, referenceRange |
| ORC | ServiceRequest | identifier, status, intent, requester (ORC-12 ordering provider; most evidentiarily important field) |
| OBR | DiagnosticReport | code, status, resultsInterpreter |
| PV1 | Encounter | class, period, location, participant (attending) |
| TXA | DocumentReference | type, status, author, date |

#### Code system normalization

OBX-3 is not always LOINC. The mapping preserves the original coding system from OBX-3.3:

| OBX-3.3 value | FHIR Coding.system | Notes |
|---|---|---|
| `LN` or `LOINC` | `http://loinc.org` | Standard |
| `SCT` or `SNOMED` | `http://snomed.info/sct` | |
| `CPT` or `CPT4` | `http://www.ama-assn.org/go/cpt` | |
| `I10` or `ICD10` | `http://hl7.org/fhir/sid/icd-10-cm` | |
| anything else | `urn:oid:2.16.840.1.113883.6.LOCAL` with original value | Unknown/local passthrough |

#### Mapping contract

```python
def map_to_fhir(
    message: HL7v2Message,
    *,
    redaction_policy: RedactionPolicy | None = None,
) -> list[FHIRResource]:
    """Map parsed HL7v2 segments to FHIR R4 resources.

    Uses fhir.resources models. Returns one resource per mappable
    segment. OBX segments produce one Observation each. All resources
    share a common subject reference derived from PID (Patient).

    When redaction_policy is REDACTED (default), Patient.identifier
    values are BLAKE3-hashed, Patient.name is omitted, and
    Patient.birthDate is truncated to year.
    """
```

#### AIR-chain boundary models

At the chain boundary (what gets serialized into `AgDRPayload.fhir_resources`), we project each `fhir.resources` object into a strict dict with `extra="forbid"`:

```python
class ChainFHIRProjection(BaseModel):
    """Strict projection of a FHIR resource for chain storage."""
    model_config = ConfigDict(extra="forbid")
    resourceType: str
    id: str
    # only the fields we explicitly mapped; everything else stripped
```

This gives us: tolerance on inbound (real-world FHIR), strictness in the chain (evidence integrity).

### Layer 3: Capsule Capture (`capture.py`)

```python
@requires_pro(feature="hl7-fhir-integration")
def instrument_hl7(
    recorder: AIRRecorder,
    raw_message: str,
    *,
    map_fhir: bool = True,
    redaction_policy: RedactionPolicy | None = None,
    data_subjects: list[DataSubjectRef] | None = None,
) -> tuple[AgDRRecord, AgDRRecord]:
    """Parse an HL7v2 message and record it as signed capsules.

    Emits a TOOL_START record with tool_name="hl7v2_receive",
    the parsed message type, sending facility, and optionally
    the FHIR R4 resource mappings in the payload.

    PHI redaction applies by default. Patient MRN in the chain
    payload is BLAKE3-hashed unless phi_mode="raw".
    baa_acknowledged=True is required for all clinical chains
    regardless of PHI mode (enforced by RedactionPolicy validator).

    If PID is present and data_subjects is not provided, auto-creates
    a DataSubjectRef from the (hashed or raw) patient MRN with
    jurisdiction="HIPAA".

    Returns (tool_start_record, tool_end_record).
    """
```

#### Intent capsule integration

The SV-ENTITY detector fires when an agent accesses entities outside its declared scope. For clinical chains, the intent capsule must declare authorized patient scope. A static list works for per-patient consults, but real clinical workflows require broader scope mechanisms.

**Scope mechanisms (in order of specificity):**

```python
# 1. Static list: per-patient consult
spec = IntentSpec(
    goal="Review patient MRN-0042 lab results",
    allowed_entities=["MRN-0042"],
    allowed_tools=["ehr_query", "hl7v2_receive"],
)

# 2. Facility scope: AI scribe handling ward 5-East admissions
spec = IntentSpec(
    goal="Transcribe clinical encounters for ward 5-East",
    entity_scope=EntityScope(
        scope_type="facility",
        facility="HOSP-MAIN",
        unit="5-EAST",
        time_window_hours=12,
    ),
    allowed_tools=["ehr_query", "hl7v2_receive", "transcribe"],
)

# 3. Roster source: CDS agent processing ICU patient roster
spec = IntentSpec(
    goal="Clinical decision support for ICU roster",
    entity_scope=EntityScope(
        scope_type="roster",
        roster_source="fhir://hospital.org/List/icu-active",
        refresh_interval_seconds=300,
    ),
    allowed_tools=["ehr_query", "hl7v2_receive"],
)

# 4. Predicate: lab-result agent processing results for a service line
spec = IntentSpec(
    goal="Process lab results for endocrinology service",
    entity_scope=EntityScope(
        scope_type="predicate",
        predicate="message_type == 'ORU^R01' AND ordering_service == 'ENDO'",
    ),
    allowed_tools=["hl7v2_receive"],
)
```

```python
class EntityScope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scope_type: str       # "static" | "facility" | "roster" | "predicate"
    facility: str | None = None
    unit: str | None = None
    time_window_hours: int | None = None
    roster_source: str | None = None
    refresh_interval_seconds: int = 300
    predicate: str | None = None
```

`IntentSpec.allowed_entities` (static list) and `IntentSpec.entity_scope` are mutually exclusive. If neither is set, SV-ENTITY has no ground truth and the detector is skipped (no false positives on legitimate access, but no scope enforcement either; log a warning).

This is the intent expressiveness moat. The clinical demo should show at minimum the static list and the facility scope to prove both work.

### Layer 4: FHIR R4 Server Push (`fhir_client.py`)

Pushes FHIR R4 resources to a FHIR server. Each push is recorded as a signed capsule.

```python
@requires_pro(feature="hl7-fhir-integration")
class FHIRClient:
    """Push FHIR R4 resources to a FHIR server.

    Supports SMART on FHIR (OAuth2 client credentials) auth.
    Tested against HAPI FHIR, Azure Health Data Services,
    GCP Healthcare API.

    Uses fhir.resources models on inbound (extra="ignore" tolerates
    unknown fields from server responses). Outbound bundles use the
    same fhir.resources models for spec compliance.
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
```

Auth flow:
1. `token_url` + `client_id` + `client_secret`: SMART on FHIR client credentials grant, token cached until expiry.
2. No auth params: unauthenticated (local HAPI FHIR dev servers).
3. 401 triggers one retry with fresh token.

### Layer 5: HTTP Receiver (`http.py`)

Lightweight FastAPI router. **ACK is commit-level, not application-level.**

```python
def create_hl7_router(
    recorder: AIRRecorder,
    *,
    pipeline_queue: asyncio.Queue | None = None,
    redaction_policy: RedactionPolicy | None = None,
) -> APIRouter:
    """Create a FastAPI router for HL7v2 message ingestion.

    POST /hl7v2/ingest
      Content-Type: application/hl7-v2 or x-application/hl7-v2+er7
      Body: raw HL7v2 message

    ACK contract:
      - AA (Application Accept): message parsed and staged to signing
        queue. Signing (batched fsync) and all downstream processing
        (FHIR mapping, detection, SIEM push, FHIR push) happen async.
      - AE (Application Error): message parsed but staging failed
        (queue full, internal error).
      - AR (Application Reject): message malformed, cannot parse.

    The ACK means "we accepted and staged the message." It does NOT
    mean "we signed it" or "we completed the FHIR push." Downstream
    failures go to dead-letter queue and surface as gateway_lag_seconds
    metric and SIEM alert events.
    """
```

### Layer 6: MLLP Listener (`mllp.py`)

Persistent TCP server with HL7v2 framing for hospitals without a modern integration engine.

```python
@requires_pro(feature="hl7-fhir-integration")
class MLLPListener:
    """Async MLLP (Minimum Lower Layer Protocol) TCP server.

    Framing: start byte 0x0b, end bytes 0x1c 0x0d.
    ACK on parse-and-sign only; downstream is async.
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 2575,
        recorder: AIRRecorder | None = None,
        pipeline_queue: asyncio.Queue | None = None,
        redaction_policy: RedactionPolicy | None = None,
    ) -> None: ...

    async def start(self) -> None: ...
    async def stop(self) -> None: ...
```

Connection handling:
- One connection per integration engine (long-lived)
- Framing validation: reject messages without proper start/end bytes
- ACK/NAK per the same contract as HTTP (AA/AE/AR)
- Backpressure: if `pipeline_queue` is full, NAK with AR and let the sender retry

### Layer 7: Clinical Evidence Sidecar (`gateway.py`)

Async pipeline orchestrator. ACK is synchronous (parse + sign). Everything else is queued.

```python
@requires_pro(feature="hl7-fhir-integration")
class ClinicalSidecar:
    """HL7v2 clinical evidence sidecar.

    Pairs with your existing integration engine (Mirth, Cloverleaf,
    Rhapsody). Records what your AI agent did with each clinical
    message and proves whether it honored its declared intent.

    Synchronous path (before ACK):
      parse -> stage to signing queue

    Async path (after ACK, bounded queue):
      sign (batched fsync) -> FHIR map -> detect -> SIEM push -> FHIR server push
    """

    def __init__(
        self,
        recorder: AIRRecorder,
        *,
        fhir_client: FHIRClient | None = None,
        siem_config: SidecarConfig | None = None,
        redaction_policy: RedactionPolicy | None = None,
        queue_size: int = 10_000,
        dead_letter_path: Path | None = None,
    ) -> None: ...

    async def process(self, raw_message: str) -> SidecarResult: ...
    async def process_file(self, path: Path) -> list[SidecarResult]: ...
    async def start_workers(self, count: int = 4) -> None: ...
    async def shutdown(self, timeout: float = 30.0) -> None: ...

    @property
    def lag_seconds(self) -> float: ...
    @property
    def dead_letter_count(self) -> int: ...
    async def replay_dead_letters(self, max_batch: int = 100) -> int: ...
```

`SidecarConfig`:
```python
class SidecarConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    splunk: SplunkConfig | None = None
    datadog: DatadogConfig | None = None
    sentinel: SentinelConfig | None = None
    sumo: SumoConfig | None = None
    push_fhir: bool = True
    run_detectors: bool = True
    auto_tag_subjects: bool = True
    queue_size: int = 10_000
    worker_count: int = 4
    dead_letter_path: str | None = None
```

#### Dead-letter operations

Dead-lettered messages are messages that parsed successfully but failed somewhere in the async pipeline (signing error, FHIR server timeout, SIEM push failure). They are PHI and require the same encryption, access controls, and retention as the chain itself.

- **Storage**: dead-letter files live alongside the chain at `dead_letter_path` (default: `<chain_dir>/dead-letter/`). Each file is a JSON record containing the raw HL7v2 message, the failure reason, the timestamp, and a retry count. Files are encrypted at rest using the same key material as the chain.
- **Alerting**: when `dead_letter_count` exceeds a configurable threshold (default: 10), the sidecar emits a `vindicara_air:clinical_dead_letter` SIEM event to all configured SIEM targets. This is the paging signal for ops teams.
- **Replay**: `replay_dead_letters(max_batch=100)` re-processes dead-lettered messages through the full async pipeline. Failed replays increment the retry count; messages exceeding `max_retries` (default: 3) are moved to a permanent dead-letter archive and generate a critical SIEM alert.
- **Retention**: dead-letter files follow the same retention policy as the chain. HIPAA minimum retention is 6 years (45 CFR 164.530(j)). The sidecar does not auto-delete; retention enforcement is the customer's responsibility (documented in the operator runbook), matching the chain retention model.
- **Monitoring**: `lag_seconds` (time between oldest queued message and now) and `dead_letter_count` are exposed as properties for health checks and SIEM metric events. Both are included in the `vindicara_air:clinical` sourcetype as enrichment fields.

#### SIEM event enrichment

Clinical-enriched SIEM events use sourcetype `vindicara_air:clinical`:

| SIEM field | Source | Example |
|---|---|---|
| `sourcetype` | hardcoded | `vindicara_air:clinical` |
| `patient_mrn_hash` | BLAKE3(PID-3) in redacted mode | `a7f3c2...` |
| `patient_mrn` | PID-3 in raw mode only | `20260511-0042` |
| `message_type` | MSH-9 | `ORU^R01` |
| `sending_facility` | MSH-4 | `EPIC_PROD` |
| `fhir_resource_types` | mapped resources | `["Patient", "Observation"]` |
| `clinician` | step-up approver (if any) | `dr.chen@hospital.org` |
| `gateway_lag_seconds` | pipeline lag metric | `0.34` |

### AgDR payload extensions

New optional fields on `AgDRPayload` (in OSS `airsdk/types.py`, matching governance pattern):

```python
hl7v2_message_type: str | None = None
hl7v2_segments: dict[str, Any] | None = None   # redacted by default
fhir_resources: list[dict[str, Any]] | None = None  # chain-boundary projection
```

These are structural schema fields. AgDR schema stays at **v0.6**; the new fields are optional and existing chains verify unchanged.

### CLI surface

New subcommand group under `air hl7` (Pro-gated):

```
air hl7 parse <file.hl7>                              Parse and display HL7v2 messages
air hl7 capture <file.hl7> --chain <chain.jsonl>      Parse, map to FHIR, write signed capsules
air hl7 push --fhir-url <url> --chain <chain.jsonl>   Push FHIR resources from chain to server
air hl7 sidecar --config sidecar.yaml                 Run the full clinical evidence sidecar
```

## Marketing updates

### Pricing page (`site/src/routes/pricing/+page.svelte`)

**Enterprise tier only.** Add:
- "HL7v2 + FHIR R4 clinical interop"
- "Clinical evidence sidecar (SIEM gateway)"

Do NOT add to Team tier. Clinical interop is the most strategically important capability in this release. Commoditizing it at $599 undercuts the pricing axis that justifies Enterprise contracts.

### Healthcare solutions page (`site/src/routes/solutions/healthcare/+page.svelte`)

Add two capability cards:
- "HL7v2 Clinical Evidence": every ADT, ORM, ORU, MDM message your clinical AI agent handles is parsed and recorded as a signed capsule. PHI is redacted by default to minimize exposure; BAA required for all clinical deployments.
- "FHIR R4 Structured Evidence": HL7v2 segments are mapped to FHIR R4 resources (Patient, Observation, ServiceRequest, DiagnosticReport) using the HL7-published spec models. Auditors see structured clinical data with proper coding system attribution.

Add FAQ entry to healthcare page:
- "What data leaves my network?" -> "The only data that leaves your network is a BLAKE3 hash (32 bytes) submitted to Sigstore Rekor for timestamping. No PHI, no clinical content, no patient identifiers, no message payloads. The hash is a one-way cryptographic commitment that proves the chain existed at a point in time."

Update quick-start code sample to show `instrument_hl7()` with intent capsule declaring patient scope.

### README (`packages/projectair/README.md`)

Add to framework integrations table:
- HL7v2 / FHIR R4 | `instrument_hl7` (Pro) | 1.1.0

### Blog

New post: "Clinical Evidence Sidecar: Cryptographic Audit Trails for HL7v2 and FHIR R4" covering the sidecar pattern, PHI redaction, intent-vs-action verification, and SIEM enrichment.

## E2E demo script

`packages/projectair-pro/scripts/e2e_hl7_fhir.py`:

1. Declare intent capsule with `allowed_entities=["MRN-0042"]` (static scope demo)
2. Create `RedactionPolicy(baa_acknowledged=True)` (BAA always required)
3. Generate sample ORU^R01 message (lab results, MRN-0042, mixed LOINC + local codes, OBX-2 type variety)
4. Parse via vendored hl7apy wrapper
5. Map to FHIR R4 (Patient with hashed MRN, 3x Observation with proper code system normalization)
6. Capture as signed capsules with default PHI redaction (hashed MRN, DOB year-only, free-text preserved under BAA)
7. Run detectors (nothing fires: in-scope access)
8. Inject second ORU^R01 with MRN-9999 (unauthorized)
9. SV-ENTITY-01 fires: "entity access outside declared scope"
10. Re-run with `EntityScope(scope_type="facility", facility="HOSP-MAIN", unit="5-EAST")` to demonstrate facility scope
11. Print sidecar result with SIEM event preview showing clinical enrichment
12. Optionally push to local HAPI FHIR server (`--live-fhir`)
13. Optionally run with `--phi-raw` to show unredacted mode (still BAA-required)

Runtime: under 30 seconds without live FHIR.

## Dependencies

- `hl7apy`: vendored into `_vendor/hl7apy/`, hash-pinned, version-locked. Parser and segment handling. **Re-vendoring policy**: check upstream releases quarterly. Pull security fixes immediately. Pull feature releases on next minor version. Each re-vendor is a tracked commit with the upstream version, commit hash, and diff summary. Owner: whoever ships the next `projectair-pro` minor release.
- `fhir.resources`: PyPI dependency. FHIR R4 resource models auto-generated from HL7 spec.
- `httpx` (already a dependency): FHIR server push, HTTP receiver.
- `fastapi` (already a dependency): HTTP router.

## Test plan

### Unit tests (`packages/projectair-pro/tests/hl7/`)

- `test_parser.py`: each message type (ADT A01, ORM O01, ORU R01, MDM T02), custom delimiters (MSH-1/MSH-2), all eight escape sequences, variable-precision timestamps (YYYY through YYYYMMDDHHMMSS.ssss+ZZZZ), MSH-18 character sets (ASCII, UTF-8, ISO-8859-1), Z-segment preservation as opaque blobs, multiple PID identifiers with assigning authority, malformed messages
- `test_obx_dispatch.py`: OBX-2 type dispatch for NM, ST, CWE, TS, DT, TX, FT, SN. OBX-3 code system normalization for LOINC, SNOMED, CPT, ICD-10, local/unknown
- `test_fhir.py`: each segment-to-resource mapping, missing optional fields, multiple OBX segments, code system attribution, US Core profile field coverage, `extra="ignore"` on inbound FHIR
- `test_redaction.py`: default mode hashes MRN/omits name/truncates DOB, raw mode requires BAA flag, `allowed_fields` selective un-redaction, chain payload verification
- `test_capture.py`: message in -> signed capsule out, chain verifies, auto-tagging DataSubjectRef with hashed MRN, FHIR resources in chain-boundary projection
- `test_fhir_client.py`: mock FHIR server, bundle create, SMART on FHIR auth flow (token request, refresh, 401 retry), error handling, `extra="ignore"` on server response
- `test_http.py`: POST endpoint, content-type handling, ACK types (AA/AE/AR), async pipeline decoupling, malformed input
- `test_mllp.py`: TCP framing (0x0b start, 0x1c 0x0d end), ACK/NAK, connection lifecycle, backpressure when queue full
- `test_gateway.py`: full sidecar pipeline with mock SIEM, clinical enrichment fields, intent capsule scope verification, dead-letter handling, lag metric
- `test_types.py`: Pydantic model validation, serialization round-trips

### Integration tests

- `test_capture_integration.py`: raw HL7v2 -> capture -> verified chain with redacted FHIR resources
- `test_sidecar_integration.py`: sidecar with mock Splunk HEC, verify clinical SIEM event fields
- `test_intent_scope.py`: intent capsule with allowed_entities, inject out-of-scope MRN, verify SV-ENTITY-01 fires

### E2E

- `scripts/e2e_hl7_fhir.py` (see above)
- `--live-fhir` for HAPI FHIR server
- `--phi-raw --baa` for unredacted mode demo

### Coverage target

80% floor. Parser wrapper and FHIR mapping near 100% (deterministic logic). Redaction logic 100% (safety-critical).

## Versioning

- AgDR schema stays at **v0.6**.
- Ships as part of `projectair-pro`. Target release: **projectair-pro 1.1.0**.
- New dependency: `fhir.resources` added to `projectair-pro` pyproject.toml.
- Vendored `hl7apy` does not appear in dependency list; it is in-tree.

## Future (not in this spec)

- **HL7v2 ADT event detector**: flag unusual patient transfer patterns (rapid readmission, cross-facility transfers outside declared scope).
- **FHIR Subscription**: subscribe to FHIR server change notifications and capture them as signed capsules.
- **CDA (Clinical Document Architecture)** mapping alongside FHIR R4 for orgs still on CDA.
- **US Core conformance validation**: validate that mapped FHIR resources meet US Core profile requirements before push.
- **Per-bed / PMPM pricing model**: pricing axis for payer-vertical SKU above current Enterprise band.
