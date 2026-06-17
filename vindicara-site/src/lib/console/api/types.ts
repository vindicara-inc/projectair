// Typed contracts for the Project AIR console.
// These mirror the shapes the backend already produces (airsdk + the insurance
// package): PostureSummary, Scope, evidence packs, delegation coverage, findings.
// Keep this file the single source of truth; the mock and live clients both
// satisfy ApiClient below.

export type CoverageStatus = 'covered' | 'expiring' | 'expired' | 'uncovered';
export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type Scope = 'posture' | 'evidence' | 'incident';
export type PremiumSignal = 'strong' | 'adequate' | 'weak';

export interface Stat {
  label: string;
  value: string;
  meta: string;
  tone: 'vio' | 'teal' | 'amber' | 'blue';
}

export interface Delegation {
  authorizer: { name: string; role: string; sub: string };
  agent: string;
  policy: string | null;
  method: 'passkey' | 'auth0' | 'none';
  expires: string;          // human label, e.g. "2h 41m", "11m", "renew", "—"
  status: CoverageStatus;
}

export interface EnforcementEvent {
  kind: 'blocked' | 'stepup' | 'authorized' | 'sealed' | 'revoked' | 'verified';
  text: string;
  at: string;               // "now", "12s", "1m"
}

export interface FindingAction {
  label: string;
  intent: 'revoke' | 'require_auth' | 'quarantine' | 'evidence' | 'renew';
  tone?: 'crit' | 'warn' | 'ok' | 'ghost';
}

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  check: string;            // e.g. "SV-AUTH-01"
  response: { state: 'contained' | 'awaiting'; label: string };
  actions: FindingAction[];
}

export interface ProofStatus {
  chainIntact: boolean;
  records: number;
  tampered: number;
  signature: string;        // "ml-dsa-65"
  lastAnchor: string;       // "41s ago"
  rekorIndex: string;
}

export interface Operator {
  name: string;
  role: string;
  authMethod: 'passkey' | 'auth0';
  sessionExpires: string;   // "42m"
  grantsAuthorized: number;
}

export interface FlightDeckSummary {
  fleetAgents: number;
  activeNodes: number;
  haltedAgents: number;
  criticalIncidents: number;
  detectors: string;
}

export interface OnDutyOperator {
  name: string;
  position: string;
  department: string;
  employeeNumber: string;
}

export interface OverviewData {
  stats: Stat[];
  delegations: Delegation[];
  enforcement: EnforcementEvent[];
  findings: Finding[];
  proof: ProofStatus;
  operator: Operator;
  flightDeck?: FlightDeckSummary;
  onDuty?: OnDutyOperator;
}

// --- readiness (Larry's four questions, answered) -------------------------- //
export interface ReadinessQuestion {
  id: string;
  question: string;
  proof: string;            // may contain a single <b>...</b> emphasis
  status: 'yes' | 'attest' | 'gap';
}
export interface ComplianceRing {
  framework: string;
  detail: string;
  pct: number;              // 0..100
  state: 'good' | 'progress';
}
export interface ReadinessData {
  scoreYes: number;
  scoreTotal: number;
  questions: ReadinessQuestion[];
  compliance: ComplianceRing[];
}

// --- rules (policy as markdown) -------------------------------------------- //
export interface Ruleset {
  id: string;
  name: string;             // "hipaa-claims-v3.md"
  layer: 'floor' | 'dept' | 'individual';
}
export interface RuleDoc {
  id: string;
  name: string;
  layerNote: string;        // "inherits company-floor · stricter only"
  content: string;          // raw markdown/yaml body
}

// --- plugins --------------------------------------------------------------- //
export interface Plugin {
  id: string;
  name: string;
  category: string;         // "SIEM", "Identity", "Insurance"...
  description: string;
  status: 'connected' | 'available' | 'optional';
  icon: { label: string; from: string; to: string };
}
export interface PluginGroups {
  core: Plugin[];
  insurance: Plugin[];
}

// --- insurance ------------------------------------------------------------- //
export interface InsuranceTransportItem {
  label: string;
  detail: string;
  on: boolean;
  locked?: boolean;         // e.g. raw PHI: forced off
}
export interface CarrierConsent {
  authorizer: string;       // "dr.okafor authorized Coalition"
  detail: string;
  status: 'active' | 'pending';
}
export interface InsuranceData {
  transport: InsuranceTransportItem[];
  consents: CarrierConsent[];
  connectedActive: number;
  connectedPending: number;
  lastPackSent: string;
  format: string;
  premiumSignal: PremiumSignal;
}

// --- settings -------------------------------------------------------------- //
export interface SettingRow {
  label: string;
  detail?: string;
  kind: 'value' | 'toggle';
  value?: string;
  on?: boolean;
  accent?: 'teal' | 'vio';
}
export interface SettingsSection {
  title: string;
  accent: string;
  rows: SettingRow[];
}
export interface SettingsData {
  plan: string;
  sections: SettingsSection[];
}

// --- the client contract --------------------------------------------------- //
export interface ApiClient {
  getOverview(): Promise<OverviewData>;
  getReadiness(): Promise<ReadinessData>;
  getRules(): Promise<{ rulesets: Ruleset[]; selected: RuleDoc }>;
  getRuleDoc(id: string): Promise<RuleDoc>;
  getPlugins(): Promise<PluginGroups>;
  getInsurance(): Promise<InsuranceData>;
  getSettings(): Promise<SettingsData>;

  // mutations (return the new state or void; live client wires to real endpoints)
  revokeDelegation(agent: string): Promise<void>;
  actOnFinding(findingId: string, intent: FindingAction['intent']): Promise<void>;
  setTransport(label: string, on: boolean): Promise<void>;
  revokeConsent(carrier: string): Promise<void>;
}
