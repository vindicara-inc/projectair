import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { TemplateRegistry } from '../../src/lib/templates/registry.ts';
import { fillTemplate } from '../../src/lib/templates/fill.ts';
import { checkEntailment } from '../../src/lib/templates/entailment.ts';
import type { AgDRRecord } from '../../src/lib/agdr/types.ts';
import type { FindingTemplate } from '../../src/lib/templates/types.ts';

const MOCK_TEMPLATE: FindingTemplate = {
  template_id: 'ASI03-scope-violation',
  version: '1.0.0',
  detector_id: 'ASI03',
  finding_type: 'scope_violation',
  layer1: 'Agent {agent_name} attempted to {action_description} without authorization at {timestamp}.',
  layer2: [
    { framework: 'HIPAA', reference: '45 CFR 164.502(b)', description: 'Minimum necessary access violation.' },
    { framework: 'OWASP', reference: 'ASI03', description: 'Identity and privilege abuse.' }
  ],
  layer3: {
    primary: { label: 'Investigate', action: 'open_detail_drawer' },
    secondary: [
      { label: 'Approve Scope', action: 'approve_scope_expansion', requires_step_up: true },
      { label: 'Quarantine Agent', action: 'quarantine_agent' },
      { label: 'Acknowledge', action: 'acknowledge' }
    ]
  },
  slots: [
    { name: 'agent_name', source: 'payload.source_agent_id' },
    { name: 'action_description', source: 'payload.tool_name' },
    { name: 'timestamp', source: 'timestamp' }
  ]
};

describe('TemplateRegistry', () => {
  it('registers and retrieves a template by detector ID', () => {
    const registry = new TemplateRegistry();
    registry.register(MOCK_TEMPLATE);
    const result = registry.get('ASI03');
    expect(result).toBeDefined();
    expect(result!.template_id).toBe('ASI03-scope-violation');
  });

  it('returns undefined for unknown detector ID', () => {
    const registry = new TemplateRegistry();
    expect(registry.get('UNKNOWN')).toBeUndefined();
  });

  it('lists all registered detector IDs', () => {
    const registry = new TemplateRegistry();
    registry.register(MOCK_TEMPLATE);
    expect(registry.detectorIds()).toEqual(['ASI03']);
  });

  it('all() returns every registered template', () => {
    const registry = new TemplateRegistry();
    registry.register(MOCK_TEMPLATE);
    expect(registry.all()).toHaveLength(1);
    expect(registry.all()[0].template_id).toBe('ASI03-scope-violation');
  });

  it('supports multiple registrations', () => {
    const registry = new TemplateRegistry();
    registry.register(MOCK_TEMPLATE);
    const second: FindingTemplate = { ...MOCK_TEMPLATE, detector_id: 'ASI01', template_id: 'ASI01-goal-hijack' };
    registry.register(second);
    expect(registry.detectorIds()).toContain('ASI03');
    expect(registry.detectorIds()).toContain('ASI01');
    expect(registry.all()).toHaveLength(2);
  });
});

const MOCK_RECORD: AgDRRecord = {
  version: '0.2',
  step_id: 'abc-123',
  timestamp: '2026-05-27T11:34:00.000Z',
  kind: 'tool_start',
  payload: {
    source_agent_id: 'prescribing-assistant',
    tool_name: 'query_patient_db',
    tool_args: { patient_id: 'P-9921' }
  },
  prev_hash: '0'.repeat(64),
  content_hash: 'a'.repeat(64),
  signature: 'b'.repeat(128),
  signer_key: 'c'.repeat(64)
};

describe('fillTemplate', () => {
  it('fills slots from record fields', () => {
    const result = fillTemplate(MOCK_TEMPLATE, MOCK_RECORD);
    expect(result.text).toBe(
      'Agent prescribing-assistant attempted to query_patient_db without authorization at 2026-05-27T11:34:00.000Z.'
    );
    expect(result.slotValues.agent_name).toBe('prescribing-assistant');
    expect(result.slotValues.action_description).toBe('query_patient_db');
    expect(result.slotValues.timestamp).toBe('2026-05-27T11:34:00.000Z');
  });

  it('leaves unfilled slots as {slot_name} when source path missing', () => {
    const emptyRecord: AgDRRecord = { ...MOCK_RECORD, payload: {} };
    const result = fillTemplate(MOCK_TEMPLATE, emptyRecord);
    expect(result.text).toContain('{agent_name}');
    expect(result.slotValues.agent_name).toBe('');
  });

  it('returns all slot names in slotValues even when empty', () => {
    const emptyRecord: AgDRRecord = { ...MOCK_RECORD, payload: {} };
    const result = fillTemplate(MOCK_TEMPLATE, emptyRecord);
    expect(Object.keys(result.slotValues)).toContain('agent_name');
    expect(Object.keys(result.slotValues)).toContain('action_description');
    expect(Object.keys(result.slotValues)).toContain('timestamp');
  });
});

describe('checkEntailment', () => {
  it('returns passed=true when all slots match record', () => {
    const slotValues = {
      agent_name: 'prescribing-assistant',
      action_description: 'query_patient_db',
      timestamp: '2026-05-27T11:34:00.000Z'
    };
    const result = checkEntailment(slotValues, MOCK_TEMPLATE.slots, MOCK_RECORD);
    expect(result.passed).toBe(true);
    expect(result.failures).toHaveLength(0);
  });

  it('returns passed=false when slot value not in record', () => {
    const slotValues = {
      agent_name: 'HALLUCINATED-AGENT',
      action_description: 'query_patient_db',
      timestamp: '2026-05-27T11:34:00.000Z'
    };
    const result = checkEntailment(slotValues, MOCK_TEMPLATE.slots, MOCK_RECORD);
    expect(result.passed).toBe(false);
    expect(result.failures).toContainEqual(
      expect.objectContaining({ slot: 'agent_name' })
    );
  });

  it('skips empty slot values (no failure for unfilled slots)', () => {
    const slotValues = {
      agent_name: '',
      action_description: 'query_patient_db',
      timestamp: '2026-05-27T11:34:00.000Z'
    };
    const result = checkEntailment(slotValues, MOCK_TEMPLATE.slots, MOCK_RECORD);
    expect(result.passed).toBe(true);
    expect(result.failures.some((f) => f.slot === 'agent_name')).toBe(false);
  });

  it('captures expected_source, filled_value, and actual_value in failures', () => {
    const slotValues = {
      agent_name: 'WRONG-AGENT',
      action_description: 'query_patient_db',
      timestamp: '2026-05-27T11:34:00.000Z'
    };
    const result = checkEntailment(slotValues, MOCK_TEMPLATE.slots, MOCK_RECORD);
    const failure = result.failures.find((f) => f.slot === 'agent_name');
    expect(failure).toBeDefined();
    expect(failure!.expected_source).toBe('payload.source_agent_id');
    expect(failure!.filled_value).toBe('WRONG-AGENT');
    expect(failure!.actual_value).toBe('prescribing-assistant');
  });
});

describe('static template files', () => {
  const templateDir = resolve(__dirname, '../../static/templates');
  const templateIds = [
    'ASI01', 'ASI02', 'ASI03', 'ASI04', 'ASI05',
    'ASI06', 'ASI07', 'ASI08', 'ASI09', 'ASI10',
    'AIR-01', 'AIR-02', 'AIR-03', 'AIR-04', 'AIR-05', 'AIR-06'
  ];

  for (const id of templateIds) {
    it(`${id}.json is valid and has required fields`, () => {
      const raw = readFileSync(resolve(templateDir, `${id}.json`), 'utf-8');
      const template = JSON.parse(raw) as FindingTemplate;
      expect(template.template_id).toBeTruthy();
      expect(template.detector_id).toBe(id);
      expect(template.layer1).toBeTruthy();
      expect(template.layer2.length).toBeGreaterThan(0);
      expect(template.layer3.primary.label).toBeTruthy();
      expect(template.slots.length).toBeGreaterThan(0);
    });
  }
});
