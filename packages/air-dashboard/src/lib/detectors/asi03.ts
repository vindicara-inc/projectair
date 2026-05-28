/**
 * ASI03 Identity & Privilege Abuse -- TypeScript port of
 * packages/projectair/src/airsdk/detections.py:detect_identity_privilege_abuse.
 *
 * Zero-Trust-for-agents enforcement against an operator-declared
 * AgentRegistry. Four finding types: identity forgery, unknown agent,
 * out-of-scope tool, privilege escalation.
 */

import type { AgDRRecord, Finding } from '../agdr/types';
import type { AgentDescriptor, AgentRegistry } from './asi10';
import { allowsTool, requiredTierForTool } from './asi10';
import { attributeAgentFromMaps } from './attribution';

export function detectIdentityPrivilegeAbuse(
	records: AgDRRecord[],
	registry: AgentRegistry | null
): Finding[] {
	if (!registry || registry.agents.length === 0) return [];

	const findings: Finding[] = [];
	const byId = new Map<string, AgentDescriptor>();
	const bySignerKey = new Map<string, AgentDescriptor>();
	for (const agent of registry.agents) {
		byId.set(agent.id, agent);
		bySignerKey.set(agent.signer_key.toLowerCase(), agent);
	}
	const flaggedUnknown = new Set<string>();

	for (let index = 0; index < records.length; index++) {
		const record = records[index]!;
		const src = record.payload.source_agent_id;

		if (src) {
			const registered = byId.get(src);
			if (registered === undefined) {
				if (!flaggedUnknown.has(src)) {
					flaggedUnknown.add(src);
					findings.push({
						detector_id: 'ASI03',
						title: 'Identity & Privilege Abuse',
						severity: 'medium',
						step_id: record.step_id,
						step_index: index,
						description:
							`Record claims source_agent_id \`${src}\` but no agent ` +
							`with that id is declared in the registry. Unregistered ` +
							`agent activity in a policed environment (OWASP ASI03).`
					});
				}
			} else if (registered.signer_key.toLowerCase() !== record.signer_key.toLowerCase()) {
				findings.push({
					detector_id: 'ASI03',
					title: 'Identity & Privilege Abuse',
					severity: 'critical',
					step_id: record.step_id,
					step_index: index,
					description:
						`Record claims source_agent_id \`${src}\`, registered with ` +
						`signer_key ${registered.signer_key.slice(0, 16)}..., but the ` +
						`record is signed with ${record.signer_key.slice(0, 16)}.... ` +
						`Possible agent impersonation or stolen key (OWASP ASI03 example #1).`
				});
			}
		}

		const attributed = attributeAgentFromMaps(record, byId, bySignerKey);
		if (record.kind !== 'tool_start' || attributed === null) continue;

		const toolName = record.payload.tool_name ?? '';
		if (!toolName) continue;

		if (!allowsTool(attributed, toolName)) {
			findings.push({
				detector_id: 'ASI03',
				title: 'Identity & Privilege Abuse',
				severity: 'high',
				step_id: record.step_id,
				step_index: index,
				description:
					`Agent \`${attributed.id}\` invoked tool \`${toolName}\`, which ` +
					`is not in its declared permitted_tools list. Scope creep beyond ` +
					`declared authorisation (OWASP ASI03 example #4).`
			});
		}

		const requiredTier = requiredTierForTool(registry, toolName);
		const agentTier = attributed.privilege_tier ?? 0;
		if (requiredTier > agentTier) {
			findings.push({
				detector_id: 'ASI03',
				title: 'Identity & Privilege Abuse',
				severity: 'critical',
				step_id: record.step_id,
				step_index: index,
				description:
					`Agent \`${attributed.id}\` (tier ${agentTier}) invoked tool ` +
					`\`${toolName}\`, which requires tier ${requiredTier}. Privilege ` +
					`escalation via delegated task (OWASP ASI03 example #3).`
			});
		}
	}

	return findings;
}
