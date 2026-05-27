import { describe, expect, it } from 'vitest';
import {
  prioritizeFindings,
  groupByAgent,
  type IncidentGroup
} from '../../src/lib/stores/triage.svelte.ts';
import type { Finding } from '../../src/lib/agdr/types.ts';

function makeFinding(
  overrides: Partial<Finding> & { detector_id: string; severity: Finding['severity'] }
): Finding {
  return {
    title: `${overrides.detector_id} finding`,
    step_id: 'step-1',
    step_index: 0,
    description: 'test finding',
    ...overrides
  };
}

describe('prioritizeFindings', () => {
  it('sorts critical before high before medium', () => {
    const findings: Finding[] = [
      makeFinding({ detector_id: 'ASI02', severity: 'medium', step_index: 0 }),
      makeFinding({ detector_id: 'ASI05', severity: 'critical', step_index: 1 }),
      makeFinding({ detector_id: 'AIR-04', severity: 'high', step_index: 2 })
    ];
    const sorted = prioritizeFindings(findings);
    expect(sorted[0]!.severity).toBe('critical');
    expect(sorted[1]!.severity).toBe('high');
    expect(sorted[2]!.severity).toBe('medium');
  });

  it('within same severity, later step_index comes first', () => {
    const findings: Finding[] = [
      makeFinding({ detector_id: 'ASI02', severity: 'critical', step_index: 3 }),
      makeFinding({ detector_id: 'ASI05', severity: 'critical', step_index: 10 })
    ];
    const sorted = prioritizeFindings(findings);
    expect(sorted[0]!.step_index).toBe(10);
    expect(sorted[1]!.step_index).toBe(3);
  });
});

describe('groupByAgent', () => {
  it('groups findings by agent name from records', () => {
    const findings: Finding[] = [
      makeFinding({ detector_id: 'ASI02', severity: 'critical', step_index: 0 }),
      makeFinding({ detector_id: 'ASI05', severity: 'high', step_index: 1 }),
      makeFinding({ detector_id: 'AIR-02', severity: 'critical', step_index: 2 })
    ];
    const records = [
      { payload: { source_agent_id: 'agent-a' } },
      { payload: { source_agent_id: 'agent-a' } },
      { payload: { source_agent_id: 'agent-b' } }
    ];
    const groups = groupByAgent(findings, records as any);
    expect(groups).toHaveLength(2);
    const agentA = groups.find((g: IncidentGroup) => g.agentName === 'agent-a');
    expect(agentA!.findings).toHaveLength(2);
  });

  it('uses "unknown" for records without source_agent_id', () => {
    const findings: Finding[] = [
      makeFinding({ detector_id: 'ASI02', severity: 'critical', step_index: 0 })
    ];
    const records = [{ payload: {} }];
    const groups = groupByAgent(findings, records as any);
    expect(groups[0]!.agentName).toBe('unknown');
  });
});
