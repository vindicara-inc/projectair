import type { EnforcementEvent, Finding, FindingAction, OverviewData } from '$lib/console/api/types';
import { seriousIncidents } from '$lib/console/forensics/feed';
import type { Mode } from '$lib/console/stores/mode';

export interface AtcAgent {
  name: string;
  behavior: string;
  findingId?: string;
  scenarioId?: string;
  actions?: Finding['actions'];
}

export interface TimelineEvent {
  t: string;
  title: string;
  actor: string;
  status: 'ok' | 'pending';
}

export interface CryptoCard {
  name: string;
  metric: string;
  label: string;
  status: string;
  tone: 'cyan' | 'violet' | 'amber' | 'emerald';
}

const stripHtml = (html: string) => html.replace(/<[^>]+>/g, '').trim();

export function atcAgents(mode: Mode, overview: OverviewData | null): AtcAgent[] {
  if (mode === 'demo') {
    return seriousIncidents.map((s) => ({
      name: s.agent,
      behavior: s.title,
      scenarioId: s.scenarioId
    }));
  }
  return (overview?.findings ?? []).map((f) => ({
    name: f.check,
    behavior: f.title,
    findingId: f.id,
    actions: f.actions
  }));
}

const timelineSkip = (text: string) => {
  const plain = stripHtml(text).toLowerCase();
  return (
    (plain.includes('billing-bot') && plain.includes('revoked')) ||
    (plain.includes('intake-v1') && plain.includes('verified'))
  );
};

export function timelineFromEnforcement(events: EnforcementEvent[]): TimelineEvent[] {
  return events
    .filter((e) => !timelineSkip(e.text))
    .slice(0, 4)
    .map((e) => ({
    t: e.at,
    title: stripHtml(e.text),
    actor:
      e.kind === 'authorized'
        ? 'Human authorizer'
        : e.kind === 'verified' || e.kind === 'sealed'
          ? 'AIR proof'
          : 'AIR enforcement',
    status: e.kind === 'blocked' || e.kind === 'revoked' ? 'pending' : 'ok'
  }));
}

export function fleetCryptoFromProof(proof: OverviewData['proof']): CryptoCard[] {
  return [
    {
      name: 'Ed25519',
      metric: 'Signed',
      label: 'chain signatures',
      status: proof.chainIntact ? 'Verified' : 'Alert',
      tone: 'cyan'
    },
    {
      name: 'BLAKE3',
      metric: 'Chained',
      label: 'content hashes',
      status: proof.tampered === 0 ? 'Active' : 'Review',
      tone: 'violet'
    }
  ];
}

export function incidentsCryptoFromProof(proof: OverviewData['proof']): CryptoCard[] {
  return [
    {
      name: 'RFC3161',
      metric: 'Sealed',
      label: 'TSA timestamps',
      status: 'Anchored',
      tone: 'amber'
    },
    {
      name: 'Sigstore',
      metric: 'Rekor',
      label: 'public anchor',
      status: proof.lastAnchor ? 'Connected' : 'Pending',
      tone: 'emerald'
    }
  ];
}

export function actionLabel(intent: FindingAction['intent']): string {
  const labels: Record<FindingAction['intent'], string> = {
    revoke: 'Revoke',
    require_auth: 'Require auth',
    quarantine: 'Quarantine',
    evidence: 'Evidence',
    renew: 'Renew'
  };
  return labels[intent];
}

export function actionTone(intent: FindingAction['intent']): 'revoke' | 'quarantine' | 'renew' {
  if (intent === 'revoke') return 'revoke';
  if (intent === 'renew' || intent === 'require_auth') return 'renew';
  return 'quarantine';
}

export function haltedCount(overview: OverviewData | null): number {
  return overview?.flightDeck?.haltedAgents ?? seriousIncidents.length;
}

export function fleetAgentCount(overview: OverviewData | null): number {
  return overview?.flightDeck?.fleetAgents ?? 212;
}

export function criticalIncidentCount(overview: OverviewData | null): number {
  return overview?.flightDeck?.criticalIncidents ?? seriousIncidents.length;
}

export function activeNodeCount(overview: OverviewData | null): number {
  return overview?.flightDeck?.activeNodes ?? 9;
}

export function detectorCount(overview: OverviewData | null): string {
  return overview?.flightDeck?.detectors ?? '16+';
}

const demoIntentByButton: Record<'revoke' | 'quarantine' | 'renew', FindingAction['intent']> = {
  revoke: 'revoke',
  quarantine: 'quarantine',
  renew: 'renew'
};

export function demoAtcIntent(button: 'revoke' | 'quarantine' | 'renew'): FindingAction['intent'] {
  return demoIntentByButton[button];
}