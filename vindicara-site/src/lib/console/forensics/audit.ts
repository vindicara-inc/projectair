// Query-driven audit: flatten every signed step across all sessions into one
// chronological event log a compliance officer can filter by patient, agent,
// department, and date range — including the allowed actions, not just the halted
// ones. Integrity is proven over the whole filtered trail.
import { verifyChain } from './crypto';
import { scenarios } from './scenarios';
import { seriousIncidents, alertIncidents } from './feed';
import type { BuiltScenario } from './types';

export interface AuditEvent {
  time: string; // ISO
  agent: string;
  department: string;
  patient: string; // "Jane D. · MRN 0042" or "—"
  action: string; // plain-English
  type: 'allowed' | 'flagged' | 'halted';
  scenarioId: string;
  chainOk: boolean;
}

export interface AuditFilters {
  patient: string; // 'all' or a patient label
  agent: string; // 'all' or agent id
  department: string; // 'all' or department
  from: string;
  to: string;
}

// agent id -> department, from the board feed.
const deptByAgent: Record<string, string> = {};
for (const f of [...seriousIncidents, ...alertIncidents]) deptByAgent[f.agent] = f.domain;

function patientOf(s: BuiltScenario): string {
  for (const r of s.records) {
    const args = r.payload.tool_args as Record<string, unknown> | undefined;
    const mrn = args?.mrn;
    if (typeof mrn === 'string') {
      const name = (args?.patient as string) ?? (mrn === '0042' ? 'Jane D.' : '');
      return name ? `${name} · MRN ${mrn}` : `MRN ${mrn}`;
    }
  }
  return '—';
}

export function allAuditEvents(): AuditEvent[] {
  const events: AuditEvent[] = [];
  for (const s of scenarios) {
    const chainOk = verifyChain(s.records).status === 'ok';
    const patient = patientOf(s);
    const dept = deptByAgent[s.agentLabel] ?? s.agentDescription;
    s.records.forEach((r, i) => {
      const step = s.steps[i];
      const type: AuditEvent['type'] = step?.legitimate
        ? 'allowed'
        : r.payload.blocked
          ? 'halted'
          : 'flagged';
      events.push({
        time: r.timestamp,
        agent: s.agentLabel,
        department: dept,
        patient,
        action: step?.plain ?? r.kind,
        type,
        scenarioId: s.id,
        chainOk
      });
    });
  }
  return events.sort((a, b) => Date.parse(a.time) - Date.parse(b.time));
}

export interface AuditFacets {
  patients: string[];
  agents: string[];
  departments: string[];
}

export function auditFacets(): AuditFacets {
  const events = allAuditEvents();
  return {
    patients: [...new Set(events.map((e) => e.patient))].filter((p) => p !== '—').sort(),
    agents: [...new Set(events.map((e) => e.agent))].sort(),
    departments: [...new Set(events.map((e) => e.department))].sort()
  };
}

export function filterAuditEvents(filters: AuditFilters): AuditEvent[] {
  const from = Date.parse(filters.from);
  const to = Date.parse(filters.to);
  return allAuditEvents().filter((e) => {
    const t = Date.parse(e.time);
    if (!Number.isNaN(from) && t < from) return false;
    if (!Number.isNaN(to) && t > to) return false;
    if (filters.patient !== 'all' && e.patient !== filters.patient) return false;
    if (filters.agent !== 'all' && e.agent !== filters.agent) return false;
    if (filters.department !== 'all' && e.department !== filters.department) return false;
    return true;
  });
}

export interface AuditSummary {
  total: number;
  allowed: number;
  flagged: number;
  halted: number;
  sessions: number;
  allIntact: boolean;
}

export function summarize(events: AuditEvent[]): AuditSummary {
  const sessions = new Set(events.map((e) => e.scenarioId));
  return {
    total: events.length,
    allowed: events.filter((e) => e.type === 'allowed').length,
    flagged: events.filter((e) => e.type === 'flagged').length,
    halted: events.filter((e) => e.type === 'halted').length,
    sessions: sessions.size,
    allIntact: events.every((e) => e.chainOk)
  };
}
