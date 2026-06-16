// Lightweight detail pages for the flagged (no-halt) alerts, generated from the feed
// so they stay in sync. Each is a real signed chain (Verify works), with a
// "stayed within bounds — logged for awareness" verdict and no containment/tamper.
import type { Scenario } from '../types';
import { alertIncidents, type FeedItem } from '../feed';

const toolFor: Record<string, string> = {
  'Clinical docs': 'write_note',
  Billing: 'submit_claim',
  Admissions: 'read_records',
  Discharge: 'draft_summary',
  Laboratory: 'route_result'
};

function alertScenario(item: FeedItem, i: number): Scenario {
  const tool = toolFor[item.domain] ?? 'run_task';
  const domainLc = item.domain.toLowerCase();
  return {
    id: item.id,
    title: item.title,
    plainHeadline: `${item.summary} Project AIR logged this for awareness — it stayed within bounds, so nothing was blocked. The record is signed and cannot be altered.`,
    agentDescription: `${item.domain} agent`,
    tools: [tool],
    industryTag: 'Healthcare',
    declaredIntent: `Carry out routine ${domainLc} tasks within its assigned scope.`,
    kind: 'forensics',
    status: 'flagged',
    severity: item.severity,
    occurredAt: `2026-05-12T1${i}:30:00Z`,
    agentLabel: item.agent,
    seedHex: `alert-${item.id}-flagged-monitoring-v1`,
    steps: [
      {
        kind: 'llm_start',
        legitimate: true,
        plain: 'Agent started its assigned task',
        detail: `Working within ${domainLc}.`,
        payload: { prompt: `Carry out routine ${domainLc} tasks.`, user_intent: `Carry out routine ${domainLc} tasks within scope.` }
      },
      {
        kind: 'tool_start',
        legitimate: true,
        plain: 'Agent carried out the task',
        detail: 'Performed the routine work it was asked to do.',
        payload: { tool_name: tool, tool_args: { routine: true } }
      },
      {
        kind: 'tool_end',
        plain: item.title,
        detail: item.summary,
        payload: { tool_name: tool, tool_output: item.summary }
      },
      {
        kind: 'agent_finish',
        legitimate: true,
        plain: 'Agent finished',
        payload: { final_output: 'Task complete; nothing blocked.' }
      }
    ],
    findings: [
      {
        detector_id: 'ASI10',
        owasp: 'OWASP ASI10: Behavioral scope (advisory)',
        title: 'Behavioral scope note',
        plainTitle: item.title,
        whyItMatters: item.summary,
        severity: item.severity,
        step_index: 2
      }
    ],
    verdict: {
      verdict: 'verified',
      intent: `Carry out routine ${domainLc} tasks within its assigned scope.`,
      plainVerdict: 'It stayed within what it was allowed to do. Project AIR flagged this only for awareness — no action was needed.',
      technicalVerdict: 'Within declared scope; flagged for monitoring (no violation, no containment).',
      summary: item.summary,
      violations: []
    }
  };
}

export const alertScenarios: Scenario[] = alertIncidents.map(alertScenario);
