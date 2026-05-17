/**
 * Detector registry — runs the browser-portable subset against an AgDRRecord[]
 * and returns the merged finding list. Mirrors the public API of
 * packages/projectair/src/airsdk/detections.py:run_detectors.
 *
 * Browser MVP runs:
 *   - ASI02 Tool Misuse & Exploitation
 *   - ASI05 Unexpected Code Execution
 *   - AIR-02 Sensitive Data Exposure
 *   - AIR-04 Untraceable Action
 *   - ASI10 Rogue Agents (partial: expected_tools + budget only)
 *
 * Skipped (require Python in Live mode):
 *   - ASI01 fuzzy token-overlap
 *   - ASI03 registry attribution
 *   - ASI04 MCP supply-chain naming
 *   - ASI06 memory-tool semantic detection
 *   - ASI07 inter-agent communication
 *   - ASI08 sliding-window oscillation/fan-out
 *   - ASI09 manipulation-language NLP
 *   - AIR-01 prompt injection (deferred — need full INJECTION_PATTERNS)
 *   - AIR-03 resource consumption (deferred — sliding window stats)
 */

import type { AgDRRecord, Finding } from '../agdr/types';

import { detectToolMisuse } from './asi02';
import { detectUnexpectedCodeExecution } from './asi05';
import { detectSensitiveDataExposure } from './air02';
import { detectUntraceableAction } from './air04';
import { detectRogueAgent, type AgentRegistry } from './asi10';

export type { AgentRegistry, AgentDescriptor, BehavioralScope } from './asi10';

export interface DetectorEntity {
	id: string;
	title: string;
	personality: 'sentinel' | 'reaper' | 'whisper' | 'archivist' | 'warden';
	scanScope: 'tool_args' | 'tool_name' | 'all_text' | 'chain_structure' | 'agent_scope';
	severity: 'critical' | 'high' | 'medium';
}

/**
 * Detector swarm metadata — drives the LEFT-rail visualization. Every entity
 * in this list maps to a function above; the order here is the visual order
 * in the swarm panel.
 */
export const DETECTOR_SWARM: readonly DetectorEntity[] = [
	{ id: 'ASI02', title: 'Tool Misuse & Exploitation', personality: 'reaper', scanScope: 'tool_args', severity: 'critical' },
	{ id: 'ASI05', title: 'Unexpected Code Execution', personality: 'reaper', scanScope: 'tool_name', severity: 'critical' },
	{ id: 'AIR-02', title: 'Sensitive Data Exposure', personality: 'whisper', scanScope: 'all_text', severity: 'critical' },
	{ id: 'AIR-04', title: 'Untraceable Action', personality: 'archivist', scanScope: 'chain_structure', severity: 'high' },
	{ id: 'ASI10', title: 'Rogue Agents (partial)', personality: 'warden', scanScope: 'agent_scope', severity: 'high' }
] as const;

export function runDetectors(records: AgDRRecord[], registry: AgentRegistry | null = null): Finding[] {
	return [
		...detectToolMisuse(records),
		...detectUnexpectedCodeExecution(records),
		...detectSensitiveDataExposure(records),
		...detectUntraceableAction(records),
		...detectRogueAgent(records, registry)
	];
}
