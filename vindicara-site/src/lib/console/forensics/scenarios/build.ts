// Turn an authored Scenario into a signed BuiltScenario: deterministic UUIDv7-shaped
// step ids, deterministic timestamps, and a real signed AgDR chain. Pure + offline.
import { blake3 } from '@noble/hashes/blake3.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import { buildSignedChain, type StepInput } from '../crypto';
import type { BuiltScenario, Scenario } from '../types';

// Stable UUIDv7-shaped id derived from the scenario + step index (no randomness).
export function deterministicStepId(scenarioId: string, index: number): string {
  const h = bytesToHex(blake3(utf8ToBytes(`${scenarioId}:step:${index}`)));
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-7${h.slice(13, 16)}-8${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

function deterministicTimestamp(baseMs: number, index: number): string {
  return new Date(baseMs + index * 4000).toISOString().replace('.000Z', 'Z');
}

export function buildScenario(scenario: Scenario): BuiltScenario {
  const baseMs = Date.parse(scenario.occurredAt);
  const steps: StepInput[] = scenario.steps.map((step, index) => ({
    kind: step.kind,
    step_id: deterministicStepId(scenario.id, index),
    timestamp: deterministicTimestamp(baseMs, index),
    payload: step.payload
  }));
  const { records, signerKey } = buildSignedChain(steps, scenario.seedHex);

  // Backfill each finding's step_id from the signed records so the surface can link.
  const findings = scenario.findings.map((f) => ({
    ...f,
    step_id: records[f.step_index]?.step_id ?? f.step_id
  }));

  return { ...scenario, findings, records, signerKey };
}
