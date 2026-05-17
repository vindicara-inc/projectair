/**
 * ASI10 Rogue Agents — partial TypeScript port (browser MVP).
 *
 * Source: packages/projectair/src/airsdk/detections.py:detect_rogue_agent
 * (line 1309). The Python detector enforces a full BehavioralScope:
 * unexpected_tools, max_session_tool_calls, max_fan_out_targets, and
 * allowed_hours_utc. This MVP ports the first two only — they are the
 * checks that matter for single-agent traces. Fan-out and off-hours
 * require multi-agent or timezone-aware logic and are deferred to the
 * Python backend in Live mode.
 *
 * Attribution is by signer_key match (not the full _attribute_agent
 * reconciliation in the Python detector). For the dashboard's curated
 * scenarios this is sufficient; production deployments should round-trip
 * to the Python detector for accuracy.
 */

import type { AgDRRecord, Finding } from '../agdr/types';

export interface BehavioralScope {
	expected_tools?: string[];
	max_session_tool_calls?: number;
}

export interface AgentDescriptor {
	id: string;
	signer_key: string;
	behavioral_scope?: BehavioralScope;
}

export interface AgentRegistry {
	agents: AgentDescriptor[];
}

export function detectRogueAgent(records: AgDRRecord[], registry: AgentRegistry | null): Finding[] {
	if (!registry || registry.agents.length === 0) return [];

	const bySignerKey = new Map<string, AgentDescriptor>();
	for (const agent of registry.agents) {
		bySignerKey.set(agent.signer_key.toLowerCase(), agent);
	}

	const findings: Finding[] = [];
	const toolCount = new Map<string, number>();
	const flaggedUnexpected = new Set<string>();
	const flaggedBudget = new Set<string>();

	for (let index = 0; index < records.length; index++) {
		const record = records[index]!;
		const agent = bySignerKey.get(record.signer_key.toLowerCase());
		if (!agent || !agent.behavioral_scope) continue;
		const scope = agent.behavioral_scope;
		const agentId = agent.id;

		if (record.kind !== 'tool_start') continue;
		const toolName = record.payload.tool_name ?? '';
		if (!toolName) continue;

		const nextCount = (toolCount.get(agentId) ?? 0) + 1;
		toolCount.set(agentId, nextCount);

		if (scope.expected_tools && scope.expected_tools.length > 0 && !scope.expected_tools.includes(toolName)) {
			const dedupKey = `${agentId}::${toolName}`;
			if (!flaggedUnexpected.has(dedupKey)) {
				flaggedUnexpected.add(dedupKey);
				findings.push({
					detector_id: 'ASI10',
					title: 'Rogue Agents',
					severity: 'high',
					step_id: record.step_id,
					step_index: index,
					description: `Agent \`${agentId}\` invoked tool \`${toolName}\`, which is outside its declared expected_tools operational scope. Zero-Trust behavioral-scope breach (OWASP ASI10 Rogue Agents).`
				});
			}
		}

		if (
			scope.max_session_tool_calls !== undefined &&
			nextCount > scope.max_session_tool_calls &&
			!flaggedBudget.has(agentId)
		) {
			flaggedBudget.add(agentId);
			findings.push({
				detector_id: 'ASI10',
				title: 'Rogue Agents',
				severity: 'high',
				step_id: record.step_id,
				step_index: index,
				description: `Agent \`${agentId}\` issued ${nextCount} tool invocations, exceeding its declared max_session_tool_calls of ${scope.max_session_tool_calls}. Zero-Trust session budget breached (OWASP ASI10 Rogue Agents).`
			});
		}
	}

	return findings;
}
