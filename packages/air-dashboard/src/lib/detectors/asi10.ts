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
import { attributeAgent } from './attribution';

export interface BehavioralScope {
	expected_tools?: string[];
	max_session_tool_calls?: number;
	max_fan_out_targets?: number;
	allowed_hours_utc?: number[];
}

export interface AgentDescriptor {
	id: string;
	signer_key: string;
	permitted_tools?: string[];
	privilege_tier?: number;
	behavioral_scope?: BehavioralScope;
}

export interface AgentRegistry {
	agents: AgentDescriptor[];
	tool_privilege_tiers?: Record<string, number>;
}

export function allowsTool(agent: AgentDescriptor, toolName: string): boolean {
	if (!agent.permitted_tools || agent.permitted_tools.length === 0) return true;
	if (agent.permitted_tools.includes('*')) return true;
	return agent.permitted_tools.includes(toolName);
}

export function requiredTierForTool(registry: AgentRegistry, toolName: string): number {
	return registry.tool_privilege_tiers?.[toolName] ?? 0;
}

function parseHourUtc(timestamp: string): number | null {
	if (!timestamp) return null;
	const ms = Date.parse(timestamp);
	if (!Number.isFinite(ms)) return null;
	return new Date(ms).getUTCHours();
}

export function detectRogueAgent(records: AgDRRecord[], registry: AgentRegistry | null): Finding[] {
	if (!registry || registry.agents.length === 0) return [];

	const findings: Finding[] = [];
	const toolCount = new Map<string, number>();
	const fanOutTargets = new Map<string, Set<string>>();
	const flaggedUnexpected = new Set<string>();
	const flaggedBudget = new Set<string>();
	const flaggedFanOut = new Set<string>();

	for (let index = 0; index < records.length; index++) {
		const record = records[index]!;
		const attributed = attributeAgent(record, registry);
		if (!attributed || !attributed.behavioral_scope) continue;
		const scope = attributed.behavioral_scope;
		const agentId = attributed.id;

		// Off-hours check (all record kinds)
		if (scope.allowed_hours_utc && scope.allowed_hours_utc.length > 0) {
			const hour = parseHourUtc(record.timestamp);
			if (hour !== null && !scope.allowed_hours_utc.includes(hour)) {
				findings.push({
					detector_id: 'ASI10',
					title: 'Rogue Agents',
					severity: 'medium',
					step_id: record.step_id,
					step_index: index,
					description: `Agent \`${agentId}\` acted at hour ${String(hour).padStart(2, '0')} UTC, outside its declared allowed_hours_utc window. Zero-Trust behavioral-scope breach (OWASP ASI10 Rogue Agents).`
				});
			}
		}

		if (record.kind === 'tool_start') {
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

		// Fan-out check on agent_message records
		if (record.kind === 'agent_message') {
			const target = record.payload.target_agent_id;
			if (target) {
				const targets = fanOutTargets.get(agentId) ?? new Set<string>();
				targets.add(target);
				fanOutTargets.set(agentId, targets);

				if (
					scope.max_fan_out_targets !== undefined &&
					targets.size > scope.max_fan_out_targets &&
					!flaggedFanOut.has(agentId)
				) {
					flaggedFanOut.add(agentId);
					findings.push({
						detector_id: 'ASI10',
						title: 'Rogue Agents',
						severity: 'high',
						step_id: record.step_id,
						step_index: index,
						description: `Agent \`${agentId}\` messaged ${targets.size} distinct targets in the session, exceeding its declared max_fan_out_targets of ${scope.max_fan_out_targets}. Zero-Trust behavioral envelope breached (OWASP ASI10 Rogue Agents).`
					});
				}
			}
		}
	}

	return findings;
}
