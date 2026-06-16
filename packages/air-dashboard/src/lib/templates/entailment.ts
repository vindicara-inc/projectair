import type { SlotDefinition } from './types.ts';
import type { AgDRRecord } from '../agdr/types.ts';

export interface EntailmentFailure {
  slot: string;
  expected_source: string;
  filled_value: string;
  actual_value: string;
}

export interface EntailmentResult {
  passed: boolean;
  failures: EntailmentFailure[];
}

function resolvePath(obj: Record<string, unknown>, path: string): string {
  const parts = path.split('.');
  let current: unknown = obj;
  for (const part of parts) {
    if (current === null || current === undefined) return '';
    if (typeof current !== 'object') return '';
    current = (current as Record<string, unknown>)[part];
  }
  if (current === null || current === undefined) return '';
  return String(current);
}

export function checkEntailment(
  slotValues: Record<string, string>,
  slots: SlotDefinition[],
  record: AgDRRecord
): EntailmentResult {
  const failures: EntailmentFailure[] = [];
  for (const slot of slots) {
    const filled = slotValues[slot.name] ?? '';
    if (!filled) continue;
    const actual = resolvePath(record as unknown as Record<string, unknown>, slot.source);
    if (filled !== actual) {
      failures.push({
        slot: slot.name,
        expected_source: slot.source,
        filled_value: filled,
        actual_value: actual
      });
    }
  }
  return { passed: failures.length === 0, failures };
}
