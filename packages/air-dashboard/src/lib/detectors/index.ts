/**
 * Detector registry -- runs all 16 detectors against an AgDRRecord[]
 * and returns the merged finding list. Mirrors the public API of
 * packages/projectair/src/airsdk/detections.py:run_detectors.
 *
 * Taxonomy:
 *   - 10 OWASP Agentic (ASI01..ASI10)
 *   - 3 OWASP LLM (AIR-01, AIR-02, AIR-03)
 *   - 3 AIR-native (AIR-04, AIR-05, AIR-06)
 */

import type { AgDRRecord, Finding } from '../agdr/types';

import { detectGoalHijack } from './asi01';
import { detectToolMisuse } from './asi02';
import { detectIdentityPrivilegeAbuse } from './asi03';
import { detectMcpSupplyChainRisk } from './asi04';
import { detectUnexpectedCodeExecution } from './asi05';
import { detectMemoryContextPoisoning } from './asi06';
import { detectInsecureInterAgentCommunication } from './asi07';
import { detectCascadingFailures } from './asi08';
import { detectHumanAgentTrustExploitation } from './asi09';
import { detectRogueAgent, type AgentRegistry } from './asi10';
import { detectPromptInjection } from './air01';
import { detectSensitiveDataExposure } from './air02';
import { detectResourceConsumption } from './air03';
import { detectUntraceableAction } from './air04';
import { detectNemoGuardSafety } from './air05';
import { detectNemoGuardCorroboration } from './air06';

export type { AgentRegistry, AgentDescriptor, BehavioralScope } from './asi10';

export interface DetectorEntity {
	id: string;
	title: string;
	personality: 'sentinel' | 'reaper' | 'whisper' | 'archivist' | 'warden';
	scanScope: 'tool_args' | 'tool_name' | 'all_text' | 'chain_structure' | 'agent_scope' | 'prompt' | 'agent_message' | 'llm_response' | 'tool_budget' | 'nemoguard';
	severity: 'critical' | 'high' | 'medium';
}

/**
 * Detector swarm metadata -- drives the LEFT-rail visualization. Every entity
 * in this list maps to a function above; the order here is the visual order
 * in the swarm panel.
 */
export const DETECTOR_SWARM: readonly DetectorEntity[] = [
	{ id: 'ASI01', title: 'Agent Goal Hijack', personality: 'sentinel', scanScope: 'all_text', severity: 'high' },
	{ id: 'ASI02', title: 'Tool Misuse & Exploitation', personality: 'reaper', scanScope: 'tool_args', severity: 'critical' },
	{ id: 'ASI03', title: 'Identity & Privilege Abuse', personality: 'warden', scanScope: 'agent_scope', severity: 'critical' },
	{ id: 'ASI04', title: 'Agentic Supply Chain', personality: 'sentinel', scanScope: 'tool_name', severity: 'medium' },
	{ id: 'ASI05', title: 'Unexpected Code Execution', personality: 'reaper', scanScope: 'tool_name', severity: 'critical' },
	{ id: 'ASI06', title: 'Memory & Context Poisoning', personality: 'whisper', scanScope: 'all_text', severity: 'critical' },
	{ id: 'ASI07', title: 'Insecure Inter-Agent Comms', personality: 'archivist', scanScope: 'agent_message', severity: 'high' },
	{ id: 'ASI08', title: 'Cascading Failures', personality: 'sentinel', scanScope: 'agent_message', severity: 'critical' },
	{ id: 'ASI09', title: 'Trust Exploitation', personality: 'whisper', scanScope: 'llm_response', severity: 'high' },
	{ id: 'ASI10', title: 'Rogue Agents', personality: 'warden', scanScope: 'agent_scope', severity: 'high' },
	{ id: 'AIR-01', title: 'Prompt Injection', personality: 'sentinel', scanScope: 'prompt', severity: 'high' },
	{ id: 'AIR-02', title: 'Sensitive Data Exposure', personality: 'whisper', scanScope: 'all_text', severity: 'critical' },
	{ id: 'AIR-03', title: 'Resource Consumption', personality: 'reaper', scanScope: 'tool_budget', severity: 'high' },
	{ id: 'AIR-04', title: 'Untraceable Action', personality: 'archivist', scanScope: 'chain_structure', severity: 'high' },
	{ id: 'AIR-05', title: 'NemoGuard Safety', personality: 'sentinel', scanScope: 'nemoguard', severity: 'high' },
	{ id: 'AIR-06', title: 'NemoGuard Corroboration', personality: 'sentinel', scanScope: 'nemoguard', severity: 'critical' }
] as const;

/**
 * Run all 16 detectors. Orchestration order matters:
 *   1. All 14 heuristic detectors run first
 *   2. AIR-05 (NemoGuard Safety) runs over tool_end records
 *   3. AIR-06 (NemoGuard Corroboration) cross-references heuristic + AIR-05
 *      findings against NemoGuard entries
 */
export function runDetectors(records: AgDRRecord[], registry: AgentRegistry | null = null): Finding[] {
	const heuristicFindings: Finding[] = [
		...detectGoalHijack(records),
		...detectToolMisuse(records),
		...detectIdentityPrivilegeAbuse(records, registry),
		...detectPromptInjection(records),
		...detectSensitiveDataExposure(records),
		...detectMcpSupplyChainRisk(records),
		...detectResourceConsumption(records),
		...detectUntraceableAction(records),
		...detectUnexpectedCodeExecution(records),
		...detectMemoryContextPoisoning(records),
		...detectHumanAgentTrustExploitation(records),
		...detectInsecureInterAgentCommunication(records),
		...detectCascadingFailures(records),
		...detectRogueAgent(records, registry)
	];

	const nemoguardFindings = detectNemoGuardSafety(records);

	const corroborationFindings = detectNemoGuardCorroboration(
		records,
		[...heuristicFindings, ...nemoguardFindings]
	);

	return [...heuristicFindings, ...nemoguardFindings, ...corroborationFindings];
}
