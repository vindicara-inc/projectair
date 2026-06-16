/**
 * Triage store — alert prioritization, agent grouping, and incident lifecycle.
 *
 * Pure functions (prioritizeFindings, groupByAgent) are exported separately so
 * they can be unit-tested without a Svelte component context.
 * The TriageStore class uses $state runes and must only be used inside components.
 */

import type { Finding, AgDRRecord } from '../agdr/types.ts';
import type { IncidentStatus } from '../templates/types.ts';

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2 };

export function prioritizeFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const sevDiff = (SEVERITY_ORDER[a.severity] ?? 3) - (SEVERITY_ORDER[b.severity] ?? 3);
    if (sevDiff !== 0) return sevDiff;
    return b.step_index - a.step_index;
  });
}

export interface IncidentGroup {
  agentName: string;
  findings: Finding[];
  worstSeverity: Finding['severity'];
}

export function groupByAgent(findings: Finding[], records: AgDRRecord[]): IncidentGroup[] {
  const map = new Map<string, Finding[]>();
  for (const f of findings) {
    const record = records[f.step_index];
    const agent = (record?.payload?.source_agent_id as string) ?? 'unknown';
    const list = map.get(agent) ?? [];
    list.push(f);
    map.set(agent, list);
  }
  return [...map.entries()].map(([agentName, agentFindings]) => ({
    agentName,
    findings: agentFindings,
    worstSeverity: prioritizeFindings(agentFindings)[0]?.severity ?? 'medium'
  }));
}

class TriageStore {
  statuses = $state<Map<string, IncidentStatus>>(new Map());

  getStatus(findingStepId: string): IncidentStatus {
    return this.statuses.get(findingStepId) ?? 'new';
  }

  setStatus(findingStepId: string, status: IncidentStatus): void {
    const next = new Map(this.statuses);
    next.set(findingStepId, status);
    this.statuses = next;
  }

  acknowledge(findingStepId: string): void {
    this.setStatus(findingStepId, 'acknowledged');
  }

  investigate(findingStepId: string): void {
    this.setStatus(findingStepId, 'investigating');
  }

  resolve(findingStepId: string): void {
    this.setStatus(findingStepId, 'resolved');
  }

  reset(): void {
    this.statuses = new Map();
  }
}

export const triageStore = new TriageStore();
