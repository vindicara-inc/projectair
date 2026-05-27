import type { FindingTemplate } from './types.ts';
import type { AgDRRecord } from '../agdr/types.ts';

export interface FillResult {
  text: string;
  slotValues: Record<string, string>;
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

export function fillTemplate(template: FindingTemplate, record: AgDRRecord): FillResult {
  const slotValues: Record<string, string> = {};
  let text = template.layer1;
  for (const slot of template.slots) {
    const value = resolvePath(record as unknown as Record<string, unknown>, slot.source);
    slotValues[slot.name] = value;
    if (value) {
      text = text.replaceAll(`{${slot.name}}`, value);
    }
  }
  return { text, slotValues };
}
