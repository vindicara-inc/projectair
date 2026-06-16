// Incident data provider. Demo Mode renders from local fixtures (zero network);
// Live Mode uses the real forensic data path — not yet wired, so it honestly returns
// nothing and the UI shows an empty state rather than fabricating records.
import { scenarios } from './scenarios';
import type { BuiltScenario } from './types';
import type { Mode } from '$lib/console/stores/mode';

export function incidentsFor(mode: Mode): BuiltScenario[] {
  return mode === 'demo' ? scenarios : [];
}

export function incidentFor(mode: Mode, id: string): BuiltScenario | undefined {
  return mode === 'demo' ? scenarios.find((s) => s.id === id) : undefined;
}
