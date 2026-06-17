// Mock client. Satisfies ApiClient with the same data the HTML mockup showed,
// so the app runs end-to-end with no backend. Swap to LiveClient by setting
// PUBLIC_AIR_API_MODE=live. Small artificial latency exercises loading states.
import type {
  ApiClient,
  FindingAction,
  InsuranceData,
  OverviewData,
  PluginGroups,
  ReadinessData,
  RuleDoc,
  Ruleset,
  SettingsData
} from './types';

const delay = (ms = 220) => new Promise((r) => setTimeout(r, ms));

const RULE_DOCS: Record<string, RuleDoc> = {
  'hipaa-claims-v3': {
    id: 'hipaa-claims-v3',
    name: 'hipaa-claims-v3.md',
    layerNote: 'inherits company-floor · stricter only',
    content: `# hipaa-claims-v3   layer: department   inherits: company-floor
# A delegation under this policy lets an agent act on a human's behalf.

goal: "adjudicate inbound insurance claims"

require_delegation: true      # no authorizer, no run (enforced on the floor)
human_auth:
  method: passkey             # FIDO2 / WebAuthn, bound to a named person
  max_session: 4h

allowed_tools:
  - claims.read
  - claims.adjudicate
  - ehr.read

allowed_paths:
  - /phi/claims/**

allowed_network:
  - internal-only             # external egress denied -> SV-EXFIL

secret_access: none
redaction: default-deny       # hash every non-whitelisted field`
  },
  'company-floor': {
    id: 'company-floor',
    name: 'company-floor.md',
    layerNote: 'non-overridable · applies to every agent',
    content: `# company-floor   layer: floor   non-overridable
# The floor every department and individual policy inherits. Stricter only:
# a child policy may tighten these, never loosen them.

require_delegation: true
allowed_network:
  - internal-only
secret_access: none
redaction: default-deny`
  }
};

export class MockClient implements ApiClient {
  async getOverview(): Promise<OverviewData> {
    await delay();
    return {
      stats: [
        { label: 'Active delegations', value: '312', meta: 'live grants', tone: 'vio' },
        { label: 'Chains anchored', value: '2.04M', meta: '0 tampered', tone: 'teal' },
        { label: 'Open findings', value: '3', meta: '2 high · 1 critical', tone: 'amber' },
        { label: 'Evidence packs', value: '12', meta: 'FRE 902 ready', tone: 'blue' }
      ],
      delegations: [
        { authorizer: { name: 'dr.okafor', role: 'Clinical ops', sub: 'auth0|okafor' }, agent: 'claims-bot', policy: 'hipaa-claims-v3', method: 'passkey', expires: '2h 41m', status: 'covered' },
        { authorizer: { name: 'k.minn', role: 'Engineering', sub: 'auth0|kminn' }, agent: 'refactor-bot', policy: 'eng-refactor-v2', method: 'passkey', expires: 'renew', status: 'expired' },
        { authorizer: { name: 'a.rivera', role: 'Intake', sub: 'auth0|arivera' }, agent: 'intake-agent', policy: 'intake-v1', method: 'auth0', expires: '11m', status: 'expiring' },
        { authorizer: { name: 'ops-team', role: 'Operations', sub: 'auth0|ops' }, agent: 'scheduler-3', policy: 'sched-v4', method: 'passkey', expires: '5h 02m', status: 'covered' },
        { authorizer: { name: 'none', role: 'no authorizer', sub: '' }, agent: 'billing-bot', policy: null, method: 'none', expires: '—', status: 'uncovered' }
      ],
      enforcement: [
        { kind: 'blocked', text: '<b>Blocked</b> external POST · refactor-bot', at: 'now' },
        { kind: 'stepup', text: '<b>Step-up</b> requested · intake-agent', at: '12s' },
        { kind: 'authorized', text: '<b>Authorized</b> claims-bot by dr.okafor', at: '1m' },
        { kind: 'sealed', text: '<b>Sealed</b> + anchored chain root', at: '1m' }
      ],
      findings: [
        { id: 'f1', severity: 'critical', title: 'billing-bot ran with no authorizer', check: 'SV-AUTH-01', response: { state: 'contained', label: 'AIR paused the agent' }, actions: [{ label: 'Revoke', intent: 'revoke', tone: 'crit' }, { label: 'Require auth', intent: 'require_auth' }] },
        { id: 'f2', severity: 'high', title: 'refactor-bot read a secret, then tried to egress', check: 'SV-EXFIL', response: { state: 'contained', label: 'AIR blocked the call' }, actions: [{ label: 'Quarantine', intent: 'quarantine', tone: 'warn' }, { label: 'Evidence', intent: 'evidence', tone: 'ok' }] },
        { id: 'f3', severity: 'high', title: 'intake-agent acted 4m after grant expiry', check: 'SV-AUTH-05', response: { state: 'awaiting', label: 'Awaiting your decision' }, actions: [{ label: 'Renew grant', intent: 'renew' }, { label: 'Revoke', intent: 'revoke', tone: 'ghost' }] }
      ],
      proof: { chainIntact: true, records: 2041118, tampered: 0, signature: 'ml-dsa-65', lastAnchor: '41s ago', rekorIndex: '1466351923' },
      operator: { name: 'Kevin Minn', role: 'Founder · root authority', authMethod: 'passkey', sessionExpires: '42m', grantsAuthorized: 3 },
      flightDeck: {
        fleetAgents: 212,
        activeNodes: 9,
        haltedAgents: 5,
        criticalIncidents: 5,
        detectors: '16+'
      },
      onDuty: {
        name: 'John Smith',
        position: 'Department Director',
        department: 'Emergency',
        employeeNumber: 'EMP-0047'
      }
    };
  }

  async getReadiness(): Promise<ReadinessData> {
    await delay();
    return {
      scoreYes: 4,
      scoreTotal: 4,
      questions: [
        { id: 'phi', question: 'Is PHI encrypted?', status: 'yes', proof: 'Default-deny redaction hashes every non-whitelisted field before it is recorded; transport and storage are encrypted. <b>PHI never enters the evidence chain in the clear.</b>' },
        { id: 'logs', question: 'Can it produce logs?', status: 'yes', proof: 'Every agent action is a signed, tamper-evident record, RFC 3161 timestamped and anchored to Rekor. <b>HIPAA audit trail requirements (45 CFR 164.312(b)).</b>' },
        { id: 'access', question: 'Does it have access controls?', status: 'yes', proof: 'Every agent runs under a least-privilege delegation a named human authorized, enforced on the deterministic floor. <b>Identity via Auth0, Entra, Okta, or SPIFFE.</b>' },
        { id: 'baa', question: 'BAA with hosting?', status: 'yes', proof: 'Executed with your cloud provider and surfaced on file alongside the evidence. <b>The signed BAA travels with the audit trail.</b>' }
      ],
      compliance: [
        { framework: 'EU AI Act', detail: 'Art 12·72', pct: 92, state: 'good' },
        { framework: 'HIPAA', detail: '164.312(b)', pct: 96, state: 'good' },
        { framework: 'NIST RMF', detail: 'in progress', pct: 74, state: 'progress' },
        { framework: 'AB 316', detail: 'autonomy defense', pct: 90, state: 'good' }
      ]
    };
  }

  async getRules() {
    await delay();
    const rulesets: Ruleset[] = [
      { id: 'company-floor', name: 'company-floor.md', layer: 'floor' },
      { id: 'hipaa-claims-v3', name: 'hipaa-claims-v3.md', layer: 'dept' },
      { id: 'eng-refactor-v2', name: 'eng-refactor-v2.md', layer: 'dept' },
      { id: 'intake-v1', name: 'intake-v1.md', layer: 'dept' },
      { id: 'okafor-personal', name: 'okafor-personal.md', layer: 'individual' }
    ];
    return { rulesets, selected: RULE_DOCS['hipaa-claims-v3'] };
  }

  async getRuleDoc(id: string): Promise<RuleDoc> {
    await delay(120);
    return RULE_DOCS[id] ?? { id, name: `${id}.md`, layerNote: 'inherits company-floor', content: `# ${id}\n# (not in mock fixtures)` };
  }

  async getPlugins(): Promise<PluginGroups> {
    await delay();
    return {
      core: [
        { id: 'datadog', name: 'Datadog', category: 'SIEM', description: 'Stream signed records as log events for your SOC.', status: 'connected', icon: { label: 'D', from: '#7b4dff', to: '#a98bff' } },
        { id: 'splunk', name: 'Splunk', category: 'SIEM', description: 'Forward AIR findings and chain roots to Splunk indexes.', status: 'connected', icon: { label: 'S', from: '#19b27a', to: '#48e6a4' } },
        { id: 'sumo', name: 'Sumo Logic', category: 'SIEM', description: 'Ship evidence events to Sumo Logic for retention.', status: 'available', icon: { label: 'SL', from: '#2b8bff', to: '#6db5ff' } },
        { id: 'sentinel', name: 'Microsoft Sentinel', category: 'SIEM', description: 'Surface findings as Sentinel incidents.', status: 'available', icon: { label: 'MS', from: '#0a5fd4', to: '#3a9bff' } },
        { id: 'slack', name: 'Slack', category: 'Alerts', description: 'Post step-up requests and critical findings to a channel.', status: 'connected', icon: { label: 'SK', from: '#c0392b', to: '#E63946' } },
        { id: 'auth0', name: 'Auth0', category: 'Identity', description: 'Bind delegations to passkey-verified humans; revoke on lock.', status: 'connected', icon: { label: 'A0', from: '#e8722a', to: '#ffb454' } },
        { id: 'rekor', name: 'Sigstore Rekor', category: 'Anchoring', description: 'Publicly anchor chain roots so anyone can verify them.', status: 'connected', icon: { label: 'SG', from: '#13c08a', to: '#6db5ff' } },
        { id: 'stripe', name: 'Stripe', category: 'Billing', description: 'The payment processor for your plan and usage.', status: 'connected', icon: { label: '$', from: '#635bff', to: '#9b8cff' } },
        { id: 'nim', name: 'NVIDIA NIM', category: 'Detectors', description: 'Optional. Only the 2 NemoGuard detectors need it; the other 14 run offline.', status: 'optional', icon: { label: 'NV', from: '#5a8f1e', to: '#76b900' } }
      ],
      insurance: [
        { id: 'coalition', name: 'Coalition', category: 'Cyber / AI liability', description: 'Share posture and evidence packs for underwriting an active-risk cyber policy.', status: 'available', icon: { label: 'CO', from: '#0a6cff', to: '#5aa0ff' } },
        { id: 'atbay', name: 'At-Bay', category: 'Cyber / AI liability', description: 'Continuous risk signal from delegation coverage and findings.', status: 'available', icon: { label: 'AT', from: '#1f8f6f', to: '#3fd6a4' } },
        { id: 'munichre', name: 'Munich Re (aiSure)', category: 'AI performance', description: 'Evidence of due care and incident reconstruction for AI-specific cover.', status: 'available', icon: { label: 'MN', from: '#6b3df0', to: '#a98bff' } },
        { id: 'vouch', name: 'Vouch', category: 'Startup / tech E&O', description: 'Lower-friction cover for teams shipping agents; posture feed on connect.', status: 'available', icon: { label: 'VC', from: '#c0392b', to: '#E63946' } }
      ]
    };
  }

  async getInsurance(): Promise<InsuranceData> {
    await delay();
    return {
      transport: [
        { label: 'Signed evidence pack', detail: 'FRE 902(13) self-authenticating, hash-only', on: true },
        { label: 'Posture feed', detail: 'delegation coverage, findings, anchoring health', on: true },
        { label: 'Incident reconstruction', detail: 'causal replay + qualified-person attestation', on: true },
        { label: 'Raw PHI / payloads', detail: 'never leaves your VPC; redacted by default', on: false, locked: true }
      ],
      consents: [
        { authorizer: 'dr.okafor authorized Coalition', detail: 'Scope: posture feed + evidence on incident. Passkey-signed, expires in 30 days.', status: 'active' },
        { authorizer: 'Pending: Vouch (broker request)', detail: 'Carrier requested read access. Waiting on buyer approval.', status: 'pending' }
      ],
      connectedActive: 1,
      connectedPending: 1,
      lastPackSent: 'Coalition · 2d ago',
      format: 'AIR evidence API v1',
      premiumSignal: 'strong'
    };
  }

  async getSettings(): Promise<SettingsData> {
    await delay();
    return {
      plan: 'Enterprise plan',
      sections: [
        { title: 'Organization', accent: 'var(--vio)', rows: [
          { label: 'Legal entity', detail: 'Delaware C-Corp', kind: 'value', value: 'Vindicara Inc.' },
          { label: 'Workspace', kind: 'value', value: 'vindicara.io' },
          { label: 'Seats', detail: 'authorizers + viewers', kind: 'value', value: '14 / 25' },
          { label: 'Owner', kind: 'value', value: 'Kevin Minn · root' }
        ]},
        { title: 'Identity & security', accent: 'var(--blue)', rows: [
          { label: 'SSO via Auth0', detail: 'org-wide single sign-on', kind: 'toggle', on: true, accent: 'vio' },
          { label: 'Require passkey for authorizers', detail: 'no delegation without FIDO2', kind: 'toggle', on: true },
          { label: 'Identity providers', kind: 'value', value: 'Auth0 · Entra · Okta · SPIFFE' },
          { label: 'Session timeout', kind: 'value', value: '4h' }
        ]},
        { title: 'Evidence & anchoring', accent: 'var(--teal)', rows: [
          { label: 'Public anchoring to Rekor', detail: 'externally verifiable roots', kind: 'toggle', on: true },
          { label: 'Post-quantum signatures', detail: 'ML-DSA-65 (FIPS 204)', kind: 'toggle', on: true },
          { label: 'Storage', detail: 'hash-only in your cloud', kind: 'value', value: 'customer VPC · us-west-2' },
          { label: 'Retention', kind: 'value', value: '7 years' }
        ]},
        { title: 'Compliance & billing', accent: 'var(--amber)', rows: [
          { label: 'Frameworks', kind: 'value', value: 'EU AI Act · HIPAA · NIST · AB 316' },
          { label: 'Payment processor', kind: 'value', value: 'Stripe' },
          { label: 'Plan', kind: 'value', value: 'Enterprise · custom' },
          { label: 'Insurance API', detail: 'roadmap, late 2026', kind: 'toggle', on: false }
        ]}
      ]
    };
  }

  async revokeDelegation(_agent: string) { await delay(120); }
  async actOnFinding(_id: string, _intent: FindingAction['intent']) { await delay(120); }
  async setTransport(_label: string, _on: boolean) { await delay(80); }
  async revokeConsent(_carrier: string) { await delay(120); }
}
