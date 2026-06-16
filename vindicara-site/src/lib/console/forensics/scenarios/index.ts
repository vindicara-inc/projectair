// Scenario registry. Add a scenario by importing its fixture and appending it here;
// each is signed into a real AgDR chain at module load (deterministic, offline).
import { buildScenario } from './build';
import type { BuiltScenario } from '../types';
import { scenario1PhiExfil } from './scenario1-phi-exfil';
import { scenario2MedOrder } from './scenario2-med-order';
import { triageDischarge, opioidRefill, chemoCancel } from './halted-extra';
import { alertScenarios } from './alerts';

export const scenarios: BuiltScenario[] = [
  scenario1PhiExfil,
  scenario2MedOrder,
  triageDischarge,
  opioidRefill,
  chemoCancel,
  ...alertScenarios
].map(buildScenario);

export function getScenario(id: string): BuiltScenario | undefined {
  return scenarios.find((s) => s.id === id);
}

export const defaultScenarioId = scenarios[0].id;
