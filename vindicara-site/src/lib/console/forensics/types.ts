// Forensic chain types for the Project AIR console.
//
// These mirror the airsdk AgDR record shape (packages/projectair/src/airsdk/types.py)
// so Demo Mode (local fixtures) and Live Mode (real API) render through the SAME
// components. The record/finding/violation/verdict shapes match the SDK exactly;
// the console adds plain-English surface copy alongside the technical fields so the
// UI can read plain on top, technical-on-demand (see Finding.plainTitle etc.).

export type StepKind =
  | 'llm_start'
  | 'llm_end'
  | 'tool_start'
  | 'tool_end'
  | 'agent_finish'
  | 'agent_message'
  | 'human_approval'
  | 'intent_declaration'
  | 'delegation';

// Authenticated human decision recorded into the chain (HumanApproval in types.py).
// Binds an action not just to "what the agent did" but to "who authorized it".
export interface HumanApproval {
  challenge_id: string;
  decision: 'approve' | 'deny';
  approver_sub: string; // IdP subject claim
  approver_email?: string;
  approver_name?: string; // surface convenience (display)
  approver_org?: string; // surface convenience (display)
  issuer: string;
  audience: string;
  issued_at: number; // unix seconds
  expires_at: number; // unix seconds
  signed_token: string; // JWT, for offline re-verification
}

// Kind-specific payload. Structured but extensible (extra allowed), matching
// AgDRPayload in types.py. content_hash covers ONLY this payload object.
export interface AgDRPayload {
  prompt?: string;
  response?: string;
  tool_name?: string;
  tool_args?: Record<string, unknown>;
  tool_output?: string;
  user_intent?: string;
  final_output?: string;
  // Containment (Layer 3): set on tool_start when a policy rule trips.
  blocked?: boolean;
  blocked_reason?: string;
  challenge_id?: string;
  // Human approval: set when kind === 'human_approval'.
  human_approval?: HumanApproval;
  [key: string]: unknown;
}

// One signed entry in the forensic chain (AgDRRecord in types.py).
export interface AgDRRecord {
  version: string;
  step_id: string;
  timestamp: string;
  kind: StepKind;
  payload: AgDRPayload;
  prev_hash: string; // content_hash of previous record, or 64 zeros for genesis
  content_hash: string; // BLAKE3 of canonical(payload)
  signature: string; // Ed25519(prev_hash || content_hash)
  signer_key: string; // Ed25519 public key, hex
  signature_algorithm: 'ed25519' | 'ml-dsa-65';
}

export type VerificationStatus = 'ok' | 'tampered' | 'broken_chain';

export interface VerificationResult {
  status: VerificationStatus;
  records_verified: number;
  failed_index?: number; // console addition, for highlighting the broken record
  failed_step_id?: string;
  reason?: string;
}

export type Severity = 'critical' | 'high' | 'medium' | 'low';

// A detection surfaced over the chain (Finding in types.py), plus plain-English
// surface copy. The technical fields (detector_id, owasp, title) live in the
// "Technical details" expander; plainTitle + whyItMatters render on the surface.
export interface Finding {
  detector_id: string; // ASI02 / AIR-01 ... (technical, expander only)
  owasp?: string; // e.g. "OWASP LLM01"
  title: string; // technical title (expander)
  plainTitle: string; // surface, plain English
  whyItMatters: string; // one-line plain consequence
  severity: Severity;
  step_index: number;
  step_id?: string;
}

// A structural violation found during intent verification (Violation in
// verification/types.py), with plain-English surface copy.
export interface Violation {
  check_id: string; // SV-... (technical, expander only)
  title: string; // technical
  plainTitle: string; // surface
  whyItMatters: string;
  severity: Severity;
  step_index: number;
  expected: string;
  actual: string;
  causal_path: number[]; // step ordinals the violation depends on
}

export type IntentVerdict = 'verified' | 'failed' | 'inconclusive';

// Output of structural verification (IntentVerificationResult in verification/types.py),
// plus plain-English surface copy.
export interface IntentVerification {
  verdict: IntentVerdict;
  intent: string; // declared intent — surface label: "What the agent was asked to do"
  plainVerdict: string; // surface
  technicalVerdict: string; // expander, e.g. "FAILED BY AIR (violated declared intent)"
  violations: Violation[];
  summary: string;
}

// ---- console-level wrappers ------------------------------------------------ //

export type IncidentStatus = 'clean' | 'flagged' | 'contained';

// A step as authored in a scenario fixture: the signed payload plus the plain
// labels the timeline shows on the surface.
export interface StepSpec {
  kind: StepKind;
  payload: AgDRPayload;
  plain: string; // "Agent read the patient's chart"
  detail?: string; // optional plain sub-line
  legitimate?: boolean; // green tick vs flagged
}

// Live containment state for a halted chain (Scenario 2).
export interface ContainmentState {
  blocked: boolean;
  blockedStepIndex: number;
  blockedAction: string; // plain: what the agent tried to do
  blockedReasonPlain: string; // plain
  blockedReasonTechnical: string; // expander: "Layer 3 circuit breaker halted"
  challengeId: string;
  patientContext: string;
}

// How to tamper this chain for the "Simulate tamper" showcase. mutate() alters a
// payload field on the narratively-loaded record so verification fails at exactly
// that step (content_hash covers payload only — never timestamp/kind).
export interface TamperSpec {
  stepIndex: number;
  fieldLabel: string; // plain: "the record of what was sent out"
  mutate: (payload: AgDRPayload) => void;
  plainNote: string;
}

export interface Scenario {
  id: string;
  title: string; // plain title for the feed/header
  plainHeadline: string; // 1-2 sentence plain summary at top of incident
  agentDescription: string;
  tools: string[];
  industryTag: string; // "Healthcare"
  declaredIntent: string; // "What the agent was asked to do"
  kind: 'forensics' | 'containment';
  status: IncidentStatus;
  severity: Severity;
  occurredAt: string; // display timestamp
  agentLabel: string; // short agent id for the feed row
  steps: StepSpec[];
  findings: Finding[];
  verdict: IntentVerification;
  containment?: ContainmentState;
  tamper?: TamperSpec;
  seedHex: string; // deterministic Ed25519 signing seed (64 hex chars)
}

// A scenario with its signed chain materialized (built at module load).
export interface BuiltScenario extends Scenario {
  records: AgDRRecord[];
  signerKey: string;
}
